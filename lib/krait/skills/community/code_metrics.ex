defmodule Krait.Skills.Community.CodeMetrics do
  @moduledoc "Elixir code metrics — line count, function count, module count, comment ratio"
  @behaviour Krait.Skills.CapableSkill

  @impl true
  def name, do: "code_metrics"

  @impl true
  def description,
    do: "Analyze Elixir files: line_count, function_count, module_count, comment_ratio"

  @impl true
  def required_capabilities, do: [:filesystem]

  @impl true
  def execute(%{"action" => action, "path" => path}, %{filesystem: fs})
      when is_binary(path) do
    case fs.read(path) do
      {:ok, %{content: content}} -> dispatch(action, content)
      {:error, reason} -> {:error, "Failed to read file: #{inspect(reason)}"}
    end
  end

  def execute(%{"action" => _}, _caps), do: {:error, "Missing required parameter: path"}
  def execute(_params, _caps), do: {:error, "Missing required parameter: action"}

  defp dispatch("line_count", content) do
    lines = content |> String.split("\n") |> length()
    {:ok, %{line_count: lines}}
  end

  defp dispatch("function_count", content) do
    lines = String.split(content, "\n")
    public = Enum.count(lines, &Regex.match?(~r/^\s*def\s+/, &1))
    private = Enum.count(lines, &Regex.match?(~r/^\s*defp\s+/, &1))
    {:ok, %{function_count: public + private, public: public, private: private}}
  end

  defp dispatch("module_count", content) do
    count =
      content
      |> String.split("\n")
      |> Enum.count(&Regex.match?(~r/^\s*defmodule\s+/, &1))

    {:ok, %{module_count: count}}
  end

  defp dispatch("comment_ratio", content) do
    lines = String.split(content, "\n")
    total = length(lines)
    comments = Enum.count(lines, &Regex.match?(~r/^\s*#/, &1))
    ratio = if total > 0, do: comments / total, else: 0.0
    {:ok, %{comment_ratio: Float.round(ratio, 4), comment_lines: comments, total_lines: total}}
  end

  defp dispatch(action, _content), do: {:error, "Unknown action: #{action}"}
end
