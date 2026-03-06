defmodule Krait.Security.PathResolver do
  @moduledoc """
  Pure-Elixir path resolution with symlink following.

  Replaces 4 duplicate `System.cmd("realpath", ...)` calls with a portable
  implementation using `File.read_link/1`. No OS subprocess overhead.
  """

  @max_hops 10

  @doc """
  Resolve a path to its real location, following all symlinks.

  Returns `{:ok, resolved_path}` on success, or an error tuple:
  - `{:error, :enoent}` — path does not exist
  - `{:error, :symlink_loop}` — circular symlink or too many hops (>#{@max_hops})
  - `{:error, reason}` — other filesystem error
  """
  @spec safe_realpath(String.t()) :: {:ok, String.t()} | {:error, atom()}
  def safe_realpath(path) do
    resolve(Path.expand(path), @max_hops)
  end

  @doc """
  Check if `path` resolves to a location within `container_dir`.

  Both paths are resolved through `safe_realpath/1` before comparison.
  Returns `false` if either path cannot be resolved.
  """
  @spec path_within?(String.t(), String.t()) :: boolean()
  def path_within?(path, container_dir) do
    with {:ok, real_path} <- safe_realpath(path),
         {:ok, real_container} <- safe_realpath(container_dir) do
      real_container_prefix = real_container <> "/"
      real_path == real_container or String.starts_with?(real_path, real_container_prefix)
    else
      _ -> false
    end
  end

  # Walk each component of the path, resolving symlinks at every level.
  # This handles chains and relative symlink targets correctly.
  defp resolve(path, hops_remaining) when hops_remaining <= 0 do
    # Guard: check if the path still contains symlinks
    case File.read_link(path) do
      {:ok, _} -> {:error, :symlink_loop}
      {:error, :einval} -> {:ok, path}
      {:error, reason} -> {:error, reason}
    end
  end

  defp resolve(path, hops_remaining) do
    case File.read_link(path) do
      {:ok, target} ->
        # It's a symlink — resolve the target
        resolved =
          if Path.type(target) == :absolute do
            Path.expand(target)
          else
            Path.expand(target, Path.dirname(path))
          end

        resolve(resolved, hops_remaining - 1)

      {:error, :einval} ->
        # Not a symlink — check parent components
        resolve_parent(path)

      {:error, :enoent} ->
        # Path doesn't exist — try resolving parent to catch symlinks in dir components
        parent = Path.dirname(path)
        basename = Path.basename(path)

        if parent == path do
          {:error, :enoent}
        else
          case resolve(parent, hops_remaining) do
            {:ok, real_parent} ->
              final = Path.join(real_parent, basename)

              if File.exists?(final) or final == path do
                {:error, :enoent}
              else
                {:error, :enoent}
              end

            error ->
              error
          end
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # Resolve parent directories to handle symlinks in intermediate path components
  defp resolve_parent(path) do
    parent = Path.dirname(path)
    basename = Path.basename(path)

    if parent == path do
      # We're at the root
      {:ok, path}
    else
      case safe_realpath(parent) do
        {:ok, real_parent} ->
          real_path = Path.join(real_parent, basename)

          # Check if this combined path is itself a symlink
          case File.read_link(real_path) do
            {:ok, _target} ->
              # Shouldn't happen since we already checked the original path,
              # but handle for safety
              safe_realpath(real_path)

            {:error, :einval} ->
              {:ok, real_path}

            {:error, :enoent} ->
              {:ok, real_path}

            {:error, reason} ->
              {:error, reason}
          end

        error ->
          error
      end
    end
  end
end
