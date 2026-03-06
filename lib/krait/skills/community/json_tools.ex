defmodule Krait.Skills.Community.JsonTools do
  @moduledoc "JSON manipulation utilities — validation, extraction, formatting, flattening"
  @behaviour Krait.Skills.CapableSkill

  @impl true
  def name, do: "json_tools"

  @impl true
  def description, do: "JSON tools: validate, extract_path, keys, pretty_print, flatten"

  @impl true
  def required_capabilities, do: []

  @impl true
  def execute(%{"action" => "validate", "json" => json}, _caps) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, _} -> {:ok, %{valid: true}}
      {:error, err} -> {:ok, %{valid: false, error: Exception.message(err)}}
    end
  end

  def execute(%{"action" => "extract_path", "json" => json, "path" => path}, _caps)
      when is_binary(json) and is_binary(path) do
    case Jason.decode(json) do
      {:ok, decoded} ->
        value = get_nested(decoded, String.split(path, "."))
        {:ok, %{value: value}}

      {:error, _} ->
        {:error, "Invalid JSON input"}
    end
  end

  def execute(%{"action" => action, "json" => json}, _caps) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, decoded} -> dispatch(action, decoded)
      {:error, _} -> {:error, "Invalid JSON input"}
    end
  end

  def execute(%{"action" => _}, _caps), do: {:error, "Missing required parameter: json"}
  def execute(_params, _caps), do: {:error, "Missing required parameter: action"}

  defp dispatch("keys", decoded) when is_map(decoded) do
    {:ok, %{keys: Map.keys(decoded)}}
  end

  defp dispatch("keys", _decoded), do: {:error, "keys action requires a JSON object"}

  defp dispatch("pretty_print", decoded) do
    {:ok, %{result: Jason.encode!(decoded, pretty: true)}}
  end

  defp dispatch("flatten", decoded) when is_map(decoded) do
    {:ok, %{result: flatten_map(decoded, "")}}
  end

  defp dispatch("flatten", _decoded), do: {:error, "flatten action requires a JSON object"}

  defp dispatch(action, _decoded), do: {:error, "Unknown action: #{action}"}

  defp get_nested(nil, _keys), do: nil
  defp get_nested(value, []), do: value

  defp get_nested(map, [key | rest]) when is_map(map) do
    get_nested(Map.get(map, key), rest)
  end

  defp get_nested(_value, _keys), do: nil

  defp flatten_map(map, prefix) when is_map(map) do
    Enum.reduce(map, %{}, fn {key, value}, acc ->
      full_key = if prefix == "", do: key, else: "#{prefix}.#{key}"

      case value do
        nested when is_map(nested) ->
          Map.merge(acc, flatten_map(nested, full_key))

        nested when is_list(nested) ->
          nested
          |> Enum.with_index()
          |> Enum.reduce(acc, fn {item, idx}, inner_acc ->
            indexed_key = "#{full_key}.#{idx}"

            case item do
              m when is_map(m) -> Map.merge(inner_acc, flatten_map(m, indexed_key))
              _ -> Map.put(inner_acc, indexed_key, item)
            end
          end)

        _ ->
          Map.put(acc, full_key, value)
      end
    end)
  end
end
