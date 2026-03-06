defmodule Krait.Analyzer.Policy do
  @moduledoc """
  Policy engine composing quick and deep analysis results into pass/fail/review decisions.
  Pure functions — no state.
  """

  @doc "Load the immutable manifest from .krait-immutable"
  def load_immutable_manifest do
    path = Application.get_env(:krait, :immutable_manifest_path, ".krait-immutable")

    case File.read(path) do
      {:ok, content} ->
        content
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.reject(fn line -> line == "" or String.starts_with?(line, "#") end)

      {:error, _} ->
        # Fallback to hardcoded defaults
        [
          "native/",
          "rules/krait-agent.yaml",
          ".krait-immutable",
          "lib/krait/analyzer/",
          "lib/krait/evolution/validator.ex",
          "lib/krait/evolution/deployer.ex",
          "lib/krait/sandbox/",
          "config/",
          "mix.exs"
        ]
    end
  end

  @doc "Check if code string references any immutable paths"
  def check_immutable_manifest(code) do
    immutable_paths = load_immutable_manifest()

    case Enum.find(immutable_paths, fn path -> path_referenced_in_code?(code, path) end) do
      nil -> :ok
      path -> {:rejected, "KRAIT-006", "Code references immutable path: #{path}"}
    end
  end

  # Use path boundary matching to reduce false positives from comments/strings,
  # while still catching paths in string literals (which is the primary threat)
  defp path_referenced_in_code?(code, path) do
    escaped = Regex.escape(path)
    Regex.match?(~r/(?:^|["'\s\/])#{escaped}/, code)
  end

  @doc "Check if a target path falls within any immutable path prefix"
  def check_target_path(target_path) do
    # Normalize the path to prevent traversal attacks
    normalized = Path.expand(target_path, "/") |> Path.relative_to("/")
    immutable_paths = load_immutable_manifest()

    if Enum.any?(immutable_paths, fn immutable ->
         String.starts_with?(normalized, immutable) or
           normalized == String.trim_trailing(immutable, "/")
       end) do
      {:rejected, :immutable_path}
    else
      :ok
    end
  end

  @doc "Check if complexity delta is within budget"
  def check_complexity_budget(delta, opts \\ []) do
    max_delta =
      Keyword.get(opts, :max_delta, Application.get_env(:krait, :max_complexity_delta, 100))

    if delta > max_delta do
      {:rejected, :complexity_exceeded, "Complexity delta #{delta} exceeds budget #{max_delta}"}
    else
      :ok
    end
  end

  @doc "Check if dependency changes need review"
  def check_dependency_changes(%{added: added}) when added != [] do
    {:review_required, :new_dependencies, "New dependencies introduced: #{inspect(added)}"}
  end

  def check_dependency_changes(%{added: [], removed: _, changed: _}), do: :ok
end
