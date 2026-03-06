defmodule Krait.GitHub.ClientBehaviour do
  @moduledoc "Contract for GitHub API client implementations"

  @callback create_branch(repo :: String.t(), branch :: String.t(), base_sha :: String.t()) ::
              {:ok, map()} | {:error, term()}
  @callback create_pull_request(repo :: String.t(), params :: map()) ::
              {:ok, map()} | {:error, term()}
  @callback push_files(repo :: String.t(), branch :: String.t(), files :: [map()]) ::
              {:ok, map()} | {:error, term()}
  @callback get_default_branch_sha(repo :: String.t()) ::
              {:ok, String.t()} | {:error, term()}
end
