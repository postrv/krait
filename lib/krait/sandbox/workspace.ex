defmodule Krait.Sandbox.Workspace do
  @moduledoc """
  Git operations inside the sandbox container.

  Manages ephemeral workspaces for code evolution: cloning repositories,
  creating branches, applying file changes, and running build/test cycles.

  All operations create temporary directories under `System.tmp_dir!/0`
  prefixed with `krait-workspace-` for easy identification and cleanup.
  """

  require Logger

  alias Krait.Security.AtomicWrite

  # Only allow alphanumeric, dots, underscores, hyphens, and forward slashes.
  # Must start with alphanumeric. Max 200 chars.
  @branch_name_pattern ~r/^[a-zA-Z0-9][a-zA-Z0-9._\/-]{0,199}$/

  @doc """
  Sets up a fresh workspace by cloning a repo and creating a new branch.

  Returns `{:ok, workspace_path}` on success.
  """
  @spec setup(String.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def setup(repo_url, branch_name) do
    with :ok <- validate_branch_name(branch_name),
         {:ok, workspace} <- clone(repo_url),
         :ok <- create_branch(workspace, branch_name) do
      Logger.info("Workspace ready at #{workspace} on branch #{branch_name}")
      {:ok, workspace}
    end
  end

  @doc """
  Applies a list of file changes to the workspace.

  Each file map must have `:path` (relative to workspace root) and `:content` keys.
  Intermediate directories are created automatically.
  """
  @spec apply_files(String.t(), [%{path: String.t(), content: String.t()}]) ::
          :ok | {:error, {:path_traversal, String.t()}}
  def apply_files(workspace, files) do
    Enum.reduce_while(files, :ok, fn %{path: path, content: content}, :ok ->
      case validate_sandbox_path(workspace, path) do
        :ok ->
          case AtomicWrite.write_safe(workspace, path, content) do
            :ok ->
              Logger.debug("Applied file: #{path}")
              {:cont, :ok}

            {:error, _} = err ->
              {:halt, err}
          end

        {:error, _} = err ->
          {:halt, err}
      end
    end)
  end

  defp validate_sandbox_path(workspace, path) do
    cond do
      String.contains?(path, "..") ->
        {:error, {:path_traversal, path}}

      Path.type(path) == :absolute ->
        {:error, {:path_traversal, path}}

      true ->
        full_path = Path.join(workspace, path) |> Path.expand()
        workspace_abs = Path.expand(workspace)

        # Check basic path containment
        if String.starts_with?(full_path, workspace_abs <> "/") do
          # Additionally resolve symlinks in existing parent dirs to catch
          # symlink-based escapes (e.g., workspace/escape -> /etc)
          check_symlink_escape(workspace_abs, full_path, path)
        else
          {:error, {:path_traversal, path}}
        end
    end
  end

  # Walk existing path segments and resolve symlinks to detect escape
  defp check_symlink_escape(workspace_abs, full_path, original_path) do
    # Only check directories that already exist — new dirs are fine
    dir = Path.dirname(full_path)

    if File.exists?(dir) do
      # Use File.stat to follow symlinks and compare real paths
      case {File.stat(workspace_abs), File.stat(dir)} do
        {{:ok, _ws_stat}, {:ok, _dir_stat}} ->
          # If both are on the same device and dir's inode path starts with workspace,
          # we're safe. But simpler: just resolve the real dir path
          alias Krait.Security.PathResolver

          with {:ok, real_dir} <- PathResolver.safe_realpath(dir),
               {:ok, real_ws} <- PathResolver.safe_realpath(workspace_abs) do
            if String.starts_with?(real_dir, real_ws <> "/") or real_dir == real_ws do
              :ok
            else
              {:error, {:path_traversal, original_path}}
            end
          else
            {:error, _} ->
              # Fail-closed: if realpath is unavailable, reject the path
              {:error, {:path_traversal, original_path}}
          end

        _ ->
          # Can't stat — directory doesn't exist yet, that's fine for new files
          :ok
      end
    else
      # Directory doesn't exist yet — will be created, no symlinks to worry about
      :ok
    end
  end

  @doc """
  Runs `mix deps.get`, `mix compile --warnings-as-errors`, and `mix test`
  in the workspace directory.

  Returns `{:ok, test_output}` if all steps succeed, or
  `{:error, {:build_failed, exit_code, output}}` on failure.
  """
  @default_cmd_timeout 120_000

  @spec compile_and_test(String.t()) :: {:ok, String.t()} | {:error, term()}
  def compile_and_test(workspace) do
    Logger.info("Running compile_and_test in #{workspace}")

    # v22 SEC-09: Snapshot lockfile before deps.get, verify integrity after
    lockfile = Path.join(workspace, "mix.lock")
    pre_checksum = lockfile_checksum(lockfile)

    with {:ok, _} <- run_cmd("mix", ["deps.get"], cd: workspace, timeout: 60_000),
         :ok <- verify_lockfile_integrity(lockfile, pre_checksum),
         {:ok, _} <-
           run_cmd("mix", ["compile", "--warnings-as-errors"], cd: workspace, timeout: 60_000) do
      run_cmd("mix", ["test"], cd: workspace, timeout: 180_000)
    end
  end

  @doc "SHA-256 checksum of a lockfile. Returns nil if the file doesn't exist."
  @spec lockfile_checksum(String.t()) :: String.t() | nil
  def lockfile_checksum(lockfile) do
    case File.read(lockfile) do
      {:ok, content} -> :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
      {:error, _} -> nil
    end
  end

  @doc """
  Verify lockfile integrity after deps.get.

  Returns `:ok` if the lockfile hasn't changed (or didn't exist before),
  `{:error, :lockfile_modified}` if deps.get modified it.
  """
  @spec verify_lockfile_integrity(String.t(), String.t() | nil) ::
          :ok | {:error, :lockfile_modified}
  def verify_lockfile_integrity(_lockfile, nil), do: :ok

  def verify_lockfile_integrity(lockfile, pre_checksum) do
    post_checksum = lockfile_checksum(lockfile)

    if post_checksum == pre_checksum do
      :ok
    else
      Logger.error("mix.lock was modified by deps.get — possible supply chain attack")
      {:error, :lockfile_modified}
    end
  end

  @doc """
  Stages all changes and creates a commit in the workspace.

  Returns `:ok` on success.
  """
  @spec commit(String.t(), String.t()) :: :ok | {:error, term()}
  def commit(workspace, message) do
    with {:ok, _} <- run_cmd("git", ["add", "-A"], cd: workspace),
         {:ok, _} <- run_cmd("git", ["commit", "-m", message], cd: workspace) do
      :ok
    end
  end

  @doc """
  Removes the workspace directory and all its contents.
  """
  @spec cleanup(String.t()) :: :ok | {:error, :invalid_cleanup_path}
  def cleanup(workspace) do
    # v24 F-07: TOCTOU-safe cleanup with three-step verification
    # v24 F-11: starts_with? instead of contains? for basename check
    alias Krait.Security.PathResolver
    tmp_dir = System.tmp_dir!()

    with {:ok, resolved} <- PathResolver.safe_realpath(workspace),
         {:ok, resolved_tmp} <- PathResolver.safe_realpath(tmp_dir),
         true <- String.starts_with?(resolved, resolved_tmp <> "/"),
         true <- String.starts_with?(Path.basename(resolved), "krait-"),
         # Step 2: File.lstat (not File.stat) to detect symlinks without following
         {:ok, %{type: :directory}} <- File.lstat(resolved),
         # Step 3: Re-resolve to detect TOCTOU symlink swap between step 1 and now
         {:ok, ^resolved} <- PathResolver.safe_realpath(workspace) do
      File.rm_rf!(resolved)
      Logger.info("Cleaned up workspace: #{resolved}")
      :ok
    else
      {:ok, %{type: type}} when type != :directory ->
        Logger.error("[SECURITY] Rejected cleanup — path is #{type}, not directory: #{workspace}")

        {:error, :invalid_cleanup_path}

      {:ok, reresolved} when is_binary(reresolved) ->
        Logger.error(
          "[SECURITY] TOCTOU detected — path changed between resolutions: #{workspace}"
        )

        {:error, :invalid_cleanup_path}

      false ->
        Logger.error("Rejected cleanup of path outside workspace scope: #{workspace}")
        {:error, :invalid_cleanup_path}

      {:error, _} ->
        Logger.error("Rejected cleanup — could not resolve path: #{workspace}")
        {:error, :invalid_cleanup_path}
    end
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  defp clone(repo_url) do
    with :ok <- validate_repo_url(repo_url) do
      workspace =
        Path.join(System.tmp_dir!(), "krait-workspace-#{System.unique_integer([:positive])}")

      Logger.info("Cloning #{repo_url} into #{workspace}")

      case run_cmd("git", ["clone", "--depth", "1", repo_url, workspace]) do
        {:ok, _} -> {:ok, workspace}
        {:error, reason} -> {:error, {:clone_failed, reason}}
      end
    end
  end

  defp validate_repo_url(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} ->
        :ok

      %URI{scheme: "http"} ->
        if Application.get_env(:krait, :env, :dev) == :prod do
          {:error, {:invalid_repo_url, "Only https:// repo URLs are allowed in production"}}
        else
          :ok
        end

      _ ->
        if Application.get_env(:krait, :allow_local_network, false) do
          # Allow local paths/file:// URLs in dev/test
          :ok
        else
          {:error, {:invalid_repo_url, "Only https:// repo URLs are allowed"}}
        end
    end
  end

  defp validate_branch_name(name) when is_binary(name) and byte_size(name) > 0 do
    if Regex.match?(@branch_name_pattern, name), do: :ok, else: {:error, :invalid_branch_name}
  end

  defp validate_branch_name(_), do: {:error, :invalid_branch_name}

  defp create_branch(workspace, branch_name) do
    case run_cmd("git", ["checkout", "-b", branch_name], cd: workspace) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, {:branch_failed, reason}}
    end
  end

  defp run_cmd(cmd, args, opts \\ []) do
    cd = Keyword.get(opts, :cd)
    timeout = Keyword.get(opts, :timeout, @default_cmd_timeout)

    cmd_opts =
      [stderr_to_stdout: true]
      |> then(fn o -> if cd, do: Keyword.put(o, :cd, cd), else: o end)

    task =
      Task.async(fn ->
        System.cmd(cmd, args, cmd_opts)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {output, 0}} -> {:ok, output}
      {:ok, {output, code}} -> {:error, {:cmd_failed, cmd, code, String.trim(output)}}
      nil -> {:error, {:cmd_timeout, cmd, timeout}}
    end
  rescue
    e in [ErlangError, ArgumentError, SystemLimitError] ->
      {:error, {:cmd_error, cmd, Exception.message(e)}}
  end
end
