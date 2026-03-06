defmodule Krait.GitHub.Client do
  @moduledoc "GitHub API client using Req + GitHub REST API"
  @behaviour Krait.GitHub.ClientBehaviour

  @base_url "https://api.github.com"

  @doc false
  def encode_path(path) do
    path
    |> String.split("/")
    |> Enum.map_join("/", fn segment -> URI.encode(segment, &URI.char_unreserved?/1) end)
  end

  @impl true
  def get_default_branch_sha(repo) do
    with {:ok, token} <- get_token() do
      case api_get(token, "/repos/#{encode_path(repo)}") do
        {:ok, %{"default_branch" => branch}} ->
          case api_get(token, "/repos/#{encode_path(repo)}/git/ref/heads/#{encode_path(branch)}") do
            {:ok, %{"object" => %{"sha" => sha}}} -> {:ok, sha}
            {:error, reason} -> {:error, reason}
          end

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  @impl true
  def create_branch(repo, branch, base_sha) do
    with {:ok, token} <- get_token() do
      body = %{ref: "refs/heads/#{branch}", sha: base_sha}

      case api_post(token, "/repos/#{encode_path(repo)}/git/refs", body) do
        {:ok, result} -> {:ok, result}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  @impl true
  def push_files(repo, branch, files) do
    with {:ok, token} <- get_token(),
         {:ok, base_sha} <- get_branch_sha(token, repo, branch),
         {:ok, tree_sha} <- create_tree(token, repo, base_sha, files),
         {:ok, commit_sha} <- create_commit(token, repo, base_sha, tree_sha),
         {:ok, _} <- update_ref(token, repo, branch, commit_sha) do
      {:ok, %{sha: commit_sha}}
    end
  end

  @impl true
  def create_pull_request(repo, params) do
    with {:ok, token} <- get_token() do
      body =
        %{
          title: params[:title] || params["title"],
          body: params[:body] || params["body"],
          head: params[:head] || params["head"],
          base: params[:base] || params["base"],
          draft: params[:draft] || params["draft"] || false
        }

      case api_post(token, "/repos/#{encode_path(repo)}/pulls", body) do
        {:ok, result} -> {:ok, result}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  # --- Private helpers ---

  defp get_token do
    Krait.GitHub.Auth.generate_installation_token()
  end

  defp get_branch_sha(token, repo, branch) do
    case api_get(token, "/repos/#{encode_path(repo)}/git/ref/heads/#{encode_path(branch)}") do
      {:ok, %{"object" => %{"sha" => sha}}} -> {:ok, sha}
      {:error, reason} -> {:error, reason}
    end
  end

  defp create_tree(token, repo, base_sha, files) do
    tree_items =
      Enum.map(files, fn file ->
        path = file[:path] || file["path"]
        content = file[:content] || file["content"]

        %{
          path: path,
          mode: "100644",
          type: "blob",
          content: content
        }
      end)

    body = %{base_tree: base_sha, tree: tree_items}

    case api_post(token, "/repos/#{encode_path(repo)}/git/trees", body) do
      {:ok, %{"sha" => sha}} -> {:ok, sha}
      {:error, reason} -> {:error, reason}
    end
  end

  defp create_commit(token, repo, parent_sha, tree_sha) do
    body = %{
      message: "krait: automated evolution commit",
      tree: tree_sha,
      parents: [parent_sha]
    }

    case api_post(token, "/repos/#{encode_path(repo)}/git/commits", body) do
      {:ok, %{"sha" => sha}} -> {:ok, sha}
      {:error, reason} -> {:error, reason}
    end
  end

  defp update_ref(token, repo, branch, commit_sha) do
    body = %{sha: commit_sha, force: false}

    case api_patch(
           token,
           "/repos/#{encode_path(repo)}/git/refs/heads/#{encode_path(branch)}",
           body
         ) do
      {:ok, result} -> {:ok, result}
      {:error, reason} -> {:error, reason}
    end
  end

  defp api_get(token, path) do
    case Req.get("#{@base_url}#{path}", headers: auth_headers(token), redirect: false) do
      {:ok, %{status: status, body: body}} when status in 200..299 -> {:ok, body}
      {:ok, %{status: status, body: body}} -> {:error, {:github_api, status, body}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp api_post(token, path, body) do
    case Req.post("#{@base_url}#{path}",
           json: body,
           headers: auth_headers(token),
           redirect: false
         ) do
      {:ok, %{status: status, body: resp_body}} when status in 200..299 -> {:ok, resp_body}
      {:ok, %{status: status, body: resp_body}} -> {:error, {:github_api, status, resp_body}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp api_patch(token, path, body) do
    case Req.patch("#{@base_url}#{path}",
           json: body,
           headers: auth_headers(token),
           redirect: false
         ) do
      {:ok, %{status: status, body: resp_body}} when status in 200..299 -> {:ok, resp_body}
      {:ok, %{status: status, body: resp_body}} -> {:error, {:github_api, status, resp_body}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp auth_headers(token) do
    [
      {"authorization", "Bearer #{token}"},
      {"accept", "application/vnd.github+json"},
      {"x-github-api-version", "2022-11-28"}
    ]
  end
end
