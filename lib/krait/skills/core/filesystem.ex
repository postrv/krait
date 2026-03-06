defmodule Krait.Skills.Core.Filesystem do
  @moduledoc "Sandboxed filesystem operations — read-only, restricted paths"
  @behaviour Krait.Skills.Skill

  @blocked_prefixes [
    "/etc",
    "/var",
    "/tmp",
    "/usr",
    "/bin",
    "/sbin",
    "/root",
    "/proc",
    "/sys",
    "/dev"
  ]

  # v21 M-14: Block sensitive project files from being read via LLM prompt injection
  @blocked_filenames ~w(.env .env.local .env.production .env.dev .env.test .env.staging)
  @blocked_extensions ~w(.pem .key .p12 .pfx .keystore .jks)
  @blocked_basenames ~w(credentials.json service-account.json id_rsa id_ed25519 id_ecdsa)

  @impl true
  def name, do: "filesystem"

  @impl true
  def description, do: "Read files within the project sandbox (read-only)"

  @impl true
  @spec execute(map()) :: {:ok, term()} | {:error, term()}
  def execute(%{"action" => "read", "path" => path}) do
    with :ok <- validate_path(path),
         {:ok, content} <- safe_read(path) do
      {:ok, %{path: path, content: content}}
    else
      {:error, :path_rejected} -> {:error, "Path rejected: outside sandbox or restricted"}
      {:error, :symlink_traversal} -> {:error, "Path rejected: symlink escapes sandbox"}
      {:error, reason} -> {:error, "File read error: #{inspect(reason)}"}
    end
  end

  def execute(%{"action" => "list", "path" => path}) do
    with :ok <- validate_path(path),
         {:ok, entries} <- File.ls(path) do
      {:ok, %{path: path, entries: entries}}
    else
      {:error, :path_rejected} -> {:error, "Path rejected: outside sandbox or restricted"}
      {:error, :symlink_traversal} -> {:error, "Path rejected: symlink escapes sandbox"}
      {:error, reason} -> {:error, "Directory list error: #{inspect(reason)}"}
    end
  end

  def execute(%{action: action, path: path}),
    do: execute(%{"action" => to_string(action), "path" => path})

  def execute(_), do: {:error, "Missing required parameters: action, path"}

  defp sandbox_root do
    Application.get_env(:krait, :filesystem_sandbox_root, File.cwd!()) |> Path.expand()
  end

  defp validate_path(path) do
    normalized = Path.expand(path)
    sandbox_root = sandbox_root()

    cond do
      String.contains?(path, "..") ->
        {:error, :path_rejected}

      sensitive_file?(normalized) ->
        {:error, :path_rejected}

      Enum.any?(@blocked_prefixes, &String.starts_with?(normalized, Path.expand(&1))) ->
        {:error, :path_rejected}

      not String.starts_with?(normalized, sandbox_root) ->
        {:error, :path_rejected}

      true ->
        # v20 M-2: Use PathResolver.path_within? which resolves intermediate directory symlinks
        check_symlink(normalized, sandbox_root)
    end
  end

  # v21 M-14: Detect sensitive filenames, extensions, and basenames
  defp sensitive_file?(path) do
    basename = Path.basename(path)
    ext = Path.extname(path)

    basename in @blocked_filenames or
      ext in @blocked_extensions or
      basename in @blocked_basenames
  end

  # v27 H-2: Re-resolve path immediately before open to minimize TOCTOU window.
  # The `:raw` flag is Erlang raw mode (not POSIX O_NOFOLLOW). We re-verify that
  # the path resolves inside the sandbox right before opening. Residual TOCTOU
  # window is microseconds between realpath and open — acceptable risk.
  defp safe_read(path) do
    root = sandbox_root()

    # v27 H-2: Re-resolve symlinks immediately before open
    case Krait.Security.PathResolver.safe_realpath(path) do
      {:ok, real_path} ->
        if String.starts_with?(real_path, root <> "/") or real_path == root do
          do_safe_read(real_path)
        else
          {:error, :symlink_traversal}
        end

      {:error, :enoent} ->
        # File doesn't exist — let File.open return the error naturally
        do_safe_read(path)

      {:error, _reason} ->
        # Fail closed: if realpath fails, reject
        {:error, :symlink_traversal}
    end
  end

  defp do_safe_read(path) do
    case File.open(path, [:read, :binary, :raw]) do
      {:ok, io_device} ->
        try do
          case IO.binread(io_device, :eof) do
            data when is_binary(data) -> {:ok, data}
            :eof -> {:ok, ""}
            {:error, reason} -> {:error, reason}
          end
        after
          File.close(io_device)
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp check_symlink(path, sandbox_root) do
    # Check if the file itself exists yet (if not, validate parent directory)
    target =
      if File.exists?(path) do
        path
      else
        Path.dirname(path)
      end

    if Krait.Security.PathResolver.path_within?(target, sandbox_root) do
      :ok
    else
      {:error, :symlink_traversal}
    end
  end
end
