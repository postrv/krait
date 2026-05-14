defmodule Krait.LLM.OpenRouter do
  @moduledoc """
  OpenRouter API client implementing Krait.LLM.Behaviour.

  Uses the OpenAI-compatible chat completions endpoint via OpenRouter,
  supporting multi-model selection, provider preferences, and cost tracking.

  ## Configuration

      config :krait, Krait.LLM.OpenRouter,
        base_url: "https://openrouter.ai/api/v1",
        model: "anthropic/claude-sonnet-4.5",
        site_url: "",
        site_name: "Krait",
        request_timeout: 120_000,
        default_provider: %{data_collection: "deny"}
  """

  @behaviour Krait.LLM.Behaviour

  require Logger

  @default_base_url "https://openrouter.ai/api/v1"
  @default_model "anthropic/claude-sonnet-4.5"
  @default_max_tokens 32_768
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

  @doc """
  Check remaining credits on the OpenRouter account.

  Returns `{:ok, %{balance: float, limit: float | nil}}` or `{:error, reason}`.
  """
  def check_credits(opts \\ []) do
    api_key = Keyword.fetch!(opts, :api_key)
    base_url = config(:base_url, opts, @default_base_url)

    case Req.get("#{base_url}/key",
           headers: auth_headers(api_key, opts),
           receive_timeout: 10_000,
           redirect: false
         ) do
      {:ok, %{status: 200, body: %{"data" => data}}} ->
        {:ok,
         %{
           balance: data["balance"] || 0.0,
           limit: data["limit"],
           usage: data["usage"] || 0.0,
           limit_remaining: data["limit_remaining"]
         }}

      {:ok, %{status: status, body: body}} ->
        {:error, {status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ---------------------------------------------------------------------------
  # Core request
  # ---------------------------------------------------------------------------

  defp do_chat(messages, tools, opts) do
    api_key = Keyword.fetch!(opts, :api_key)
    base_url = config(:base_url, opts, @default_base_url)
    model = config(:model, opts, @default_model)
    timeout = config(:request_timeout, opts, @default_timeout)
    max_tokens = Keyword.get(opts, :max_tokens, @default_max_tokens)

    body =
      %{
        model: model,
        max_tokens: max_tokens,
        messages: normalize_messages(messages)
      }
      |> maybe_add_tools(tools)
      |> maybe_add_models(opts)
      |> maybe_add_provider(opts)

    Logger.debug("OpenRouter request", model: model, message_count: length(messages))

    case Req.post("#{base_url}/chat/completions",
           json: body,
           headers: auth_headers(api_key, opts),
           receive_timeout: timeout,
           redirect: false
         ) do
      {:ok, %{status: 200, body: response_body}} ->
        parse_response(response_body)

      {:ok, %{status: 402, body: body}} ->
        Logger.error("OpenRouter insufficient credits")
        {:error, {:insufficient_credits, body}}

      {:ok, %{status: status, body: body}} ->
        Logger.error("OpenRouter error", status: status)
        {:error, {:openrouter_error, status, body}}

      {:error, %Req.TransportError{reason: :econnrefused}} ->
        Logger.error("OpenRouter not reachable", url: base_url)
        {:error, :openrouter_unavailable}

      {:error, reason} ->
        Logger.error("OpenRouter request failed", reason: request_failure_reason(reason))
        {:error, {:request_failed, reason}}
    end
  end

  defp request_failure_reason(reason) do
    Exception.message(reason)
  rescue
    FunctionClauseError -> inspect(reason)
  end

  # ---------------------------------------------------------------------------
  # Headers
  # ---------------------------------------------------------------------------

  defp auth_headers(api_key, opts) do
    site_url = config(:site_url, opts, "")
    site_name = config(:site_name, opts, "Krait")

    headers = [
      {"authorization", "Bearer #{api_key}"},
      {"content-type", "application/json"}
    ]

    headers =
      if site_url != "" do
        [{"HTTP-Referer", site_url} | headers]
      else
        headers
      end

    if site_name != "" do
      [{"X-Title", site_name} | headers]
    else
      headers
    end
  end

  # ---------------------------------------------------------------------------
  # Message normalization (Anthropic/internal format -> OpenAI format)
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
            "arguments" => Jason.encode!(tc["input"] || %{})
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
  # Tool formatting (Anthropic format -> OpenAI format)
  # ---------------------------------------------------------------------------

  defp maybe_add_tools(body, []), do: body

  defp maybe_add_tools(body, tools) do
    openai_tools =
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

    Map.put(body, :tools, openai_tools)
  end

  # ---------------------------------------------------------------------------
  # OpenRouter-specific features
  # ---------------------------------------------------------------------------

  defp maybe_add_models(body, opts) do
    case Keyword.get(opts, :models) do
      nil ->
        body

      [] ->
        body

      models when is_list(models) ->
        body |> Map.put(:models, models) |> Map.put(:route, "fallback")
    end
  end

  defp maybe_add_provider(body, opts) do
    default_provider = config(:default_provider, opts, %{})
    explicit_provider = Keyword.get(opts, :provider, %{})

    provider = Map.merge(default_provider, explicit_provider)

    if provider == %{} do
      body
    else
      Map.put(body, :provider, provider)
    end
  end

  # ---------------------------------------------------------------------------
  # Response parsing
  # ---------------------------------------------------------------------------

  defp parse_response(%{"choices" => [first | _]} = response_body) do
    message = first["message"] || %{}
    text = message["content"] || ""

    tool_calls =
      (message["tool_calls"] || [])
      |> Enum.map(fn tc ->
        func = tc["function"] || %{}

        %{
          id: tc["id"],
          name: func["name"],
          input: parse_arguments(func["arguments"])
        }
      end)

    cost = get_in(response_body, ["usage", "cost"])

    {:ok, %{text: text, tool_calls: tool_calls, cost: cost}}
  end

  defp parse_response(%{"error" => error}) do
    message = if is_map(error), do: error["message"] || inspect(error), else: inspect(error)
    {:error, {:openrouter_error, message}}
  end

  defp parse_response(other) do
    Logger.warning("Unexpected OpenRouter response shape")
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
