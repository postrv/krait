defmodule Krait.Evolution.Spec do
  @moduledoc "Evolution specification struct with validation"

  @enforce_keys [
    :skill_name,
    :description,
    :trigger,
    :target_path,
    :test_path,
    :branch_name,
    :language
  ]
  defstruct [
    :skill_name,
    :description,
    :trigger,
    :target_path,
    :test_path,
    :branch_name,
    :language
  ]

  alias Krait.Analyzer.Policy

  def new(params) do
    target_path = params[:target_path] || params["target_path"]
    test_path = params[:test_path] || params["test_path"]

    with :ok <- Policy.check_target_path(target_path),
         :ok <- Policy.check_target_path(test_path) do
      skill_name = params[:skill_name] || params["skill_name"]
      timestamp = System.system_time(:second)

      {:ok,
       %__MODULE__{
         skill_name: skill_name,
         description: params[:description] || params["description"],
         trigger: params[:trigger] || params["trigger"],
         target_path: target_path,
         test_path: test_path,
         branch_name: "krait/evolve-#{skill_name}-#{timestamp}",
         language: detect_language(target_path, params)
       }}
    else
      {:rejected, :immutable_path} -> {:error, :immutable_path}
    end
  end

  defp detect_language(target_path, params) do
    explicit = params[:language] || params["language"]

    if explicit do
      explicit
    else
      case Path.extname(target_path || "") do
        ext when ext in [".ex", ".exs"] -> "elixir"
        ".py" -> "python"
        ext when ext in [".js", ".jsx"] -> "javascript"
        ext when ext in [".ts", ".tsx"] -> "typescript"
        ".go" -> "go"
        ".rs" -> "rust"
        _ -> "elixir"
      end
    end
  end
end
