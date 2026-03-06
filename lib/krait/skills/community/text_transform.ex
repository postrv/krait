defmodule Krait.Skills.Community.TextTransform do
  @moduledoc "Text transformation utilities — case conversion, slugification, word counting"
  @behaviour Krait.Skills.CapableSkill

  @impl true
  def name, do: "text_transform"

  @impl true
  def description,
    do:
      "Transform text: uppercase, lowercase, reverse, word_count, slug, snake_case, title_case, truncate"

  @impl true
  def required_capabilities, do: []

  @impl true
  def execute(%{"action" => "truncate", "text" => text} = params, _caps) when is_binary(text) do
    max = parse_int(Map.get(params, "max_length"), 100)
    {:ok, %{result: truncate(text, max)}}
  end

  def execute(%{"action" => action, "text" => text}, _caps) when is_binary(text) do
    case action do
      "uppercase" -> {:ok, %{result: String.upcase(text)}}
      "lowercase" -> {:ok, %{result: String.downcase(text)}}
      "reverse" -> {:ok, %{result: String.reverse(text)}}
      "word_count" -> {:ok, %{result: word_count(text)}}
      "slug" -> {:ok, %{result: slugify(text)}}
      "snake_case" -> {:ok, %{result: to_snake_case(text)}}
      "title_case" -> {:ok, %{result: title_case(text)}}
      _ -> {:error, "Unknown action: #{action}"}
    end
  end

  def execute(%{"action" => _, "text" => _}, _caps), do: {:error, "text must be a string"}
  def execute(%{"action" => _}, _caps), do: {:error, "Missing required parameter: text"}
  def execute(_params, _caps), do: {:error, "Missing required parameter: action"}

  defp word_count(""), do: 0

  defp word_count(text) do
    text |> String.split(~r/\s+/, trim: true) |> length()
  end

  defp slugify(text) do
    text
    |> String.downcase()
    |> String.replace(~r/[^a-z0-9\s-]/, "")
    |> String.replace(~r/[\s-]+/, "-")
    |> String.trim("-")
  end

  defp to_snake_case(text) do
    text
    |> String.replace(~r/([a-z])([A-Z])/, "\\1_\\2")
    |> String.replace(~r/[\s-]+/, "_")
    |> String.downcase()
    |> String.replace(~r/_+/, "_")
    |> String.trim("_")
  end

  defp title_case(text) do
    text
    |> String.split(~r/\s+/, trim: true)
    |> Enum.map_join(" ", fn word ->
      {first, rest} = String.split_at(word, 1)
      String.upcase(first) <> rest
    end)
  end

  defp truncate(text, max) when is_binary(text) do
    if String.length(text) <= max, do: text, else: String.slice(text, 0, max) <> "..."
  end

  defp parse_int(nil, default), do: default
  defp parse_int(val, _default) when is_integer(val), do: val

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {n, ""} -> n
      _ -> default
    end
  end

  defp parse_int(_, default), do: default
end
