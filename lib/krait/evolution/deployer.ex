defmodule Krait.Evolution.Deployer do
  @moduledoc "Orchestrates the sandbox lifecycle and PR creation"

  require Logger

  alias Krait.Evolution.Workspace

  @spec propose_evolution(%Krait.Evolution.ValidatedProposal{}) ::
          {:ok, String.t()} | {:error, term()}
  def propose_evolution(validated_proposal) do
    github = Application.get_env(:krait, :github_client, Krait.GitHub.Client)
    repo = Application.get_env(:krait, :repo_name, "postrv/krait")
    sandbox_enabled = Application.get_env(:krait, :sandbox_enabled, true)

    spec = validated_proposal.spec

    branch_name =
      Map.get(
        spec,
        :branch_name,
        "krait/evolve-#{System.unique_integer([:positive, :monotonic])}"
      )

    skill_name = Map.get(spec, :skill_name, "unknown")
    target_path = Map.get(spec, :target_path, "")
    test_path = Map.get(spec, :test_path, "")

    files = [
      %{path: target_path, content: validated_proposal.code},
      %{path: test_path, content: validated_proposal.test_code}
    ]

    with :ok <- validate_deploy_paths(files),
         :ok <- maybe_sandbox(sandbox_enabled, branch_name, files, skill_name),
         {:ok, base_sha} <- github.get_default_branch_sha(repo),
         {:ok, _} <- github.create_branch(repo, branch_name, base_sha),
         {:ok, _} <- github.push_files(repo, branch_name, files),
         {:ok, pr} <-
           github.create_pull_request(repo, %{
             title: "Evolution: #{skill_name}",
             body: Krait.GitHub.PRRenderer.render(validated_proposal),
             head: branch_name,
             base: "main",
             labels: ["krait-evolution", "needs-human-review"],
             draft: false
           }) do
      {:ok, pr["html_url"] || pr[:html_url]}
    end
  end

  defp validate_deploy_paths(files) do
    Enum.reduce_while(files, :ok, fn file, _acc ->
      case Workspace.validate_file_path(file.path) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp maybe_sandbox(false, _branch_name, _files, _skill_name), do: :ok

  defp maybe_sandbox(true, branch_name, files, skill_name) do
    repo_url = Application.get_env(:krait, :repo_url, "https://github.com/postrv/krait")
    Logger.info("Running sandbox validation", skill_name: skill_name)

    case Workspace.setup(repo_url, branch_name) do
      {:ok, workspace_dir} ->
        try do
          with :ok <- Workspace.apply_files(workspace_dir, files),
               :ok <- Workspace.compile_and_test(workspace_dir),
               :ok <- Workspace.commit(workspace_dir, "krait: evolution #{skill_name}") do
            :ok
          else
            {:error, reason} -> {:error, {:sandbox_failed, reason}}
          end
        rescue
          e ->
            Logger.error("Sandbox exception", reason: Exception.message(e))
            {:error, {:sandbox_failed, Exception.message(e)}}
        after
          Workspace.cleanup(workspace_dir)
        end

      {:error, reason} ->
        Logger.error("Sandbox setup failed",
          reason: if(is_atom(reason), do: reason, else: "setup_error")
        )

        {:error, {:sandbox_failed, reason}}
    end
  end
end
