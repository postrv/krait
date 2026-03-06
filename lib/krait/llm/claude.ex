defmodule Krait.LLM.Claude do
  @moduledoc """
  DEPRECATED: Direct Anthropic Claude API client.

  Use `Krait.LLM.OpenRouter` instead, which routes through OpenRouter
  for multi-model support, provider preferences, and cost tracking.

  This module is retained for backward compatibility during the migration
  period and will be removed in a future release.
  """
  @behaviour Krait.LLM.Behaviour

  require Logger

  @default_model "claude-sonnet-4-5-20250929"
  @default_max_tokens 4096
  @default_base_url "https://api.anthropic.com"

  @impl true
  def complete(messages, opts \\ []) do
    api_key = Keyword.fetch!(opts, :api_key)
    base_url = Keyword.get(opts, :base_url, @default_base_url)
    model = Keyword.get(opts, :model, @default_model)
    max_tokens = Keyword.get(opts, :max_tokens, @default_max_tokens)

    body = %{
      model: model,
      max_tokens: max_tokens,
      messages: messages
    }

    case post_messages(base_url, api_key, body) do
      {:ok, %{status: 200, body: response_body}} ->
        text =
          response_body["content"]
          |> Enum.find(&(&1["type"] == "text"))
          |> case do
            %{"text" => text} -> text
            nil -> ""
          end

        {:ok, text}

      {:ok, %{status: status, body: body}} ->
        {:error, {status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def complete_with_tools(messages, tools, opts \\ []) do
    api_key = Keyword.fetch!(opts, :api_key)
    base_url = Keyword.get(opts, :base_url, @default_base_url)
    model = Keyword.get(opts, :model, @default_model)
    max_tokens = Keyword.get(opts, :max_tokens, @default_max_tokens)

    body =
      %{
        model: model,
        max_tokens: max_tokens,
        messages: messages
      }
      |> maybe_add_tools(tools)

    case post_messages(base_url, api_key, body) do
      {:ok, %{status: 200, body: response_body}} ->
        content_blocks = response_body["content"] || []

        text =
          content_blocks
          |> Enum.filter(&(&1["type"] == "text"))
          |> Enum.map_join("", & &1["text"])

        tool_calls =
          content_blocks
          |> Enum.filter(&(&1["type"] == "tool_use"))
          |> Enum.map(fn tc ->
            %{
              id: tc["id"],
              name: tc["name"],
              input: tc["input"]
            }
          end)

        {:ok, %{text: text, tool_calls: tool_calls}}

      {:ok, %{status: status, body: body}} ->
        {:error, {status, body}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @impl true
  def stream(_messages, _opts) do
    {:error, :not_implemented}
  end

  defp post_messages(base_url, api_key, body) do
    Req.post(
      "#{base_url}/v1/messages",
      json: body,
      headers: [
        {"x-api-key", api_key},
        {"anthropic-version", "2023-06-01"},
        {"content-type", "application/json"}
      ],
      receive_timeout: 120_000,
      redirect: false
    )
  end

  defp maybe_add_tools(body, []), do: body
  defp maybe_add_tools(body, tools), do: Map.put(body, :tools, tools)
end
