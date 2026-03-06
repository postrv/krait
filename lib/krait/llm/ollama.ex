defmodule Krait.LLM.Ollama do
  @moduledoc """
  Local LLM client via Ollama, implementing Krait.LLM.Behaviour.

  Translates between Krait's internal message format (Claude-style) and
  Ollama's OpenAI-compatible /api/chat endpoint.

  ## Configuration

      config :krait, Krait.LLM.Ollama,
        base_url: "http://localhost:11434",
        model: "qwen2.5-coder:14b",
        request_timeout: 120_000
  """

  @behaviour Krait.LLM.Behaviour

  require Logger

  @default_base_url "http://localhost:11434"
  @default_model "qwen2.5-coder:14b"
  @default_timeout 120_000

  @impl true
  def complete(messages, opts \\ []) do
    case do_chat(messages, [], opts) do
      {:ok, %{text: text}} -> {:ok, text}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def complete_with_tools(messages, tools, opts \\ []) do
    do_chat(messages, tools, opts)
  end

  @impl true
  def stream(_messages, _opts) do
    {:error, :not_implemented}
  end

  # ---------------------------------------------------------------------------
  # Core request
  # ---------------------------------------------------------------------------

  defp do_chat(messages, tools, opts) do
    base_url = config(:base_url, opts, @default_base_url)

    with :ok <- validate_base_url(base_url) do
      model = config(:model, opts, @default_model)
      timeout = config(:request_timeout, opts, @default_timeout)

      body =
        %{
          model: model,
          messages: normalize_messages(messages),
          stream: false
        }
        |> maybe_add_tools(tools)

      Logger.debug("Ollama request", model: model, message_count: length(messages))

      case Req.post("#{base_url}/api/chat",
             json: body,
             receive_timeout: timeout,
             redirect: false
           ) do
        {:ok, %{status: 200, body: response_body}} ->
          parse_response(response_body)

        {:ok, %{status: status, body: body}} ->
          Logger.error("Ollama error", status: status)
          {:error, {:ollama_error, status, body}}

        {:error, %Req.TransportError{reason: :econnrefused}} ->
          Logger.error("Ollama not reachable — is it running?", url: base_url)
          {:error, :ollama_unavailable}

        {:error, reason} ->
          Logger.error("Ollama request failed",
            reason: Exception.message(reason)
          )

          {:error, {:request_failed, reason}}
      end
    end
  end

  defp validate_base_url(url), do: Krait.LLM.Router.validate_ollama_url(url)

  # ---------------------------------------------------------------------------
  # Message normalization (Claude format -> Ollama/OpenAI format)
  # ---------------------------------------------------------------------------

  defp normalize_messages(messages) do
    Enum.flat_map(messages, &normalize_message/1)
  end

  defp normalize_message(%{"role" => role, "content" => content}) when is_binary(content) do
    [%{"role" => role, "content" => content}]
  end

  defp normalize_message(%{role: role, content: content}) when is_binary(content) do
    [%{"role" => to_string(role), "content" => content}]
  end

  defp normalize_message(%{"role" => "assistant", "content" => blocks}) when is_list(blocks) do
    text =
      blocks
      |> Enum.filter(&(&1["type"] == "text"))
      |> Enum.map_join("", & &1["text"])

    tool_calls =
      blocks
      |> Enum.filter(&(&1["type"] == "tool_use"))
      |> Enum.map(fn tc ->
        %{
          "id" => tc["id"],
          "type" => "function",
          "function" => %{
            "name" => tc["name"],
            "arguments" => tc["input"]
          }
        }
      end)

    msg = %{"role" => "assistant", "content" => text}

    msg =
      if tool_calls != [] do
        Map.put(msg, "tool_calls", tool_calls)
      else
        msg
      end

    [msg]
  end

  defp normalize_message(%{"role" => "user", "content" => blocks}) when is_list(blocks) do
    Enum.map(blocks, fn
      %{"type" => "tool_result", "tool_use_id" => id, "content" => content} ->
        %{"role" => "tool", "content" => to_string(content), "tool_call_id" => id}

      %{"type" => "text", "text" => text} ->
        %{"role" => "user", "content" => text}

      other ->
        %{"role" => "user", "content" => inspect(other)}
    end)
  end

  defp normalize_message(msg) do
    [%{"role" => msg["role"] || "user", "content" => inspect(msg["content"] || msg)}]
  end

  # ---------------------------------------------------------------------------
  # Tool formatting
  # ---------------------------------------------------------------------------

  defp maybe_add_tools(body, []), do: body

  defp maybe_add_tools(body, tools) do
    ollama_tools =
      Enum.map(tools, fn tool ->
        %{
          "type" => "function",
          "function" => %{
            "name" => tool["name"] || tool[:name],
            "description" => tool["description"] || tool[:description] || "",
            "parameters" =>
              tool["input_schema"] || tool[:input_schema] ||
                %{"type" => "object", "properties" => %{}}
          }
        }
      end)

    Map.put(body, :tools, ollama_tools)
  end

  # ---------------------------------------------------------------------------
  # Response parsing
  # ---------------------------------------------------------------------------

  defp parse_response(%{"message" => message}) do
    text = message["content"] || ""

    tool_calls =
      (message["tool_calls"] || [])
      |> Enum.with_index()
      |> Enum.map(fn {tc, idx} ->
        func = tc["function"] || %{}

        %{
          id: tc["id"] || "ollama_tool_#{idx}",
          name: func["name"],
          input: parse_arguments(func["arguments"])
        }
      end)

    {:ok, %{text: text, tool_calls: tool_calls}}
  end

  defp parse_response(%{"error" => error}) do
    {:error, {:ollama_error, error}}
  end

  defp parse_response(other) do
    Logger.warning("Unexpected Ollama response shape")
    {:error, {:unexpected_response, other}}
  end

  defp parse_arguments(args) when is_map(args), do: args

  defp parse_arguments(args) when is_binary(args) do
    case Jason.decode(args) do
      {:ok, parsed} -> parsed
      {:error, _} -> %{"raw" => args}
    end
  end

  defp parse_arguments(_), do: %{}

  # ---------------------------------------------------------------------------
  # Config helpers
  # ---------------------------------------------------------------------------

  defp config(key, opts, default) do
    Keyword.get(opts, key) ||
      get_in(Application.get_env(:krait, __MODULE__, []), [key]) ||
      default
  end
end
