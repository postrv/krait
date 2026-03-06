defmodule Krait.Security.AtomicWrite do
  @moduledoc """
  TOCTOU-safe file writes for workspace operations.

  Writes to a temp file first, validates the target path's parent
  resolves inside the workspace, then renames atomically. Cleans up
  temp files on failure or exception.
  """

  require Logger

  @doc """
  Atomically write a file within a workspace directory.

  1. Write content to a temp file in the workspace
  2. mkdir_p the target's parent directory
  3. Validate the parent's realpath resolves inside workspace
  4. Rename temp → target (atomic on same filesystem)
  5. Clean up temp on any failure

  Returns :ok or {:error, reason}.
  """
  @spec write_safe(String.t(), String.t(), String.t()) :: :ok | {:error, term()}
  def write_safe(workspace, relative_path, content) do
    workspace_abs = Path.expand(workspace)
    target = Path.join(workspace_abs, relative_path)
    target_dir = Path.dirname(target)

    # v23 M-3: Pre-mkdir validation — ensure target resolves inside workspace
    # BEFORE creating any directories (prevents directory creation outside workspace)
    expanded_target = Path.expand(target)

    if String.starts_with?(expanded_target, workspace_abs <> "/") do
      # Create target directory
      File.mkdir_p!(target_dir)

      # Pre-write: validate target dir resolves inside workspace (symlink check)
      do_write_safe(workspace_abs, target, target_dir, content)
    else
      {:error, {:path_escape, "target outside workspace"}}
    end
  rescue
    e ->
      {:error, {:write_failed, Exception.message(e)}}
  end

  defp do_write_safe(workspace_abs, target, target_dir, content) do
    case validate_post_write(workspace_abs, target_dir) do
      :ok ->
        # Write temp file in target directory (same filesystem = atomic rename)
        temp_name = ".krait_tmp_#{random_suffix()}"
        temp_path = Path.join(target_dir, temp_name)

        try do
          File.write!(temp_path, content)

          # Atomic rename
          File.rename!(temp_path, target)

          # Post-rename: validate final file resolves inside workspace
          case validate_post_write(workspace_abs, target) do
            :ok ->
              :ok

            {:error, reason} ->
              # Path escaped after rename — delete and report
              File.rm(target)
              {:error, reason}
          end
        rescue
          e ->
            File.rm(temp_path)
            {:error, {:write_failed, Exception.message(e)}}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_post_write(workspace_abs, target_dir) do
    alias Krait.Security.PathResolver

    case PathResolver.safe_realpath(target_dir) do
      {:ok, real_dir} ->
        case PathResolver.safe_realpath(workspace_abs) do
          {:ok, real_ws} ->
            if String.starts_with?(real_dir, real_ws <> "/") or real_dir == real_ws do
              :ok
            else
              {:error, {:path_escape, "target resolves outside workspace"}}
            end

          {:error, _} ->
            {:error, {:path_escape, "cannot resolve workspace path"}}
        end

      {:error, _} ->
        {:error, {:path_escape, "cannot resolve target directory"}}
    end
  end

  defp random_suffix do
    :crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)
  end
end
