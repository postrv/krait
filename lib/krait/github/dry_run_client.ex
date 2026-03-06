defmodule Krait.GitHub.DryRunClient do
  @moduledoc "Logs GitHub operations without making API calls — for dev/demo use"
  @behaviour Krait.GitHub.ClientBehaviour

  require Logger

  @impl true
  def get_default_branch_sha(_repo) do
    Logger.info("DryRun: get_default_branch_sha")
    {:ok, "dry-run-sha-#{System.unique_integer([:positive])}"}
  end

  @impl true
  def create_branch(_repo, branch, _sha) do
    Logger.info("DryRun: create_branch #{branch}")
    {:ok, %{}}
  end

  @impl true
  def push_files(_repo, branch, files) do
    paths = Enum.map_join(files, ", ", & &1.path)
    Logger.info("DryRun: push_files to #{branch}: #{paths}")
    {:ok, %{}}
  end

  @impl true
  def create_pull_request(_repo, params) do
    pr_number = System.unique_integer([:positive])
    Logger.info("DryRun: create_pull_request ##{pr_number}: #{params.title}")

    {:ok,
     %{
       "html_url" => "https://github.com/dry-run/krait/pull/#{pr_number}",
       "number" => pr_number
     }}
  end
end
