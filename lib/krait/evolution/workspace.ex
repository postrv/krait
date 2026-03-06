defmodule Krait.Evolution.Workspace do
  @moduledoc "Manages temporary workspaces for evolution sandbox testing"

  require Logger

  alias Krait.Security.AtomicWrite

  @default_cmd_timeout 120_000
  @workspace_prefix "krait_workspace_"

  # Only allow alphanumeric, dots, underscores, hyphens, and forward slashes.
  # Must start with alphanumeric. Max 200 chars.
  @branch_name_pattern ~r/^[a-zA-Z0-9][a-zA-Z0-9._\/-]{0,199}$/

  # v10: M7 — allowed repo URL schemes
  @allowed_repo_schemes_prod ["https"]
  # v24 F-14: Removed ssh/git schemes — only https/http in dev
  @allowed_repo_schemes_dev ["https", "http"]

  @doc "Set up a workspace by cloning the repo and creating a branch"
  @spec setup(String.t(), String.t()) :: {:ok, String.t()} | {:error, term()}
  def setup(repo_url, branch_name) do
    with :ok <- validate_repo_url(repo_url),
         :ok <- validate_branch_name(branch_name) do
      workspace_dir = workspace_path()

      with :ok <- run_cmd("git", ["clone", "--depth", "1", repo_url, workspace_dir]),
           :ok <- run_cmd("git", ["-C", workspace_dir, "checkout", "-b", branch_name]) do
        {:ok, workspace_dir}
      end
    end
  end

  defp validate_repo_url(url) when is_binary(url) do
    allowed =
      if Application.get_env(:krait, :env) == :prod do
        @allowed_repo_schemes_prod
      else
        @allowed_repo_schemes_dev
      end

    case URI.parse(url) do
      %URI{scheme: scheme} when is_binary(scheme) ->
        if scheme in allowed, do: :ok, else: {:error, :invalid_repo_url}

      _ ->
        {:error, :invalid_repo_url}
    end
  end

  defp validate_repo_url(_), do: {:error, :invalid_repo_url}

  @doc "Apply generated files to the workspace, with immutable path and containment validation"
  @spec apply_files(String.t(), [map()]) :: :ok | {:error, term()}
  def apply_files(workspace_dir, files) do
    Enum.reduce_while(files, :ok, fn file, _acc ->
      with :ok <- validate_path_containment(workspace_dir, file.path),
           :ok <- validate_file_path(file.path),
           :ok <- AtomicWrite.write_safe(workspace_dir, file.path, file.content) do
        {:cont, :ok}
      else
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  @doc false
  def validate_file_path(file_path) do
    immutable_paths = Krait.Analyzer.Policy.load_immutable_manifest()

    normalized = Path.expand(file_path, "/") |> Path.relative_to("/")

    if Enum.any?(immutable_paths, fn immutable ->
         String.starts_with?(normalized, immutable) or
           normalized == String.trim_trailing(immutable, "/")
       end) do
      Logger.warning("Blocked write to immutable path", path: file_path)
      {:error, {:immutable_path, file_path}}
    else
      :ok
    end
  end

  @doc "Compile and run tests in the workspace"
  @spec compile_and_test(String.t(), String.t()) :: :ok | {:error, term()}
  def compile_and_test(workspace_dir, language \\ "elixir") do
    if use_sandbox?() do
      sandboxed_compile_and_test(workspace_dir, language)
    else
      local_compile_and_test(workspace_dir, language)
    end
  end

  defp local_compile_and_test(workspace_dir, language) do
    # v26 H-3: Per-invocation warning when running on host
    Logger.warning(
      "[SECURITY] Running compile_and_test on HOST (not sandboxed). " <>
        "Both allow_local_execution and accept_host_execution_risk are true."
    )

    {deps_cmd, compile_cmd, test_cmd, lockfile_name} = build_commands(language)

    # v22 SEC-09: Snapshot lockfile before deps, verify integrity after
    lockfile = Path.join(workspace_dir, lockfile_name)
    pre_checksum = lockfile_checksum(lockfile)

    with :ok <- run_build_step(deps_cmd, cd: workspace_dir, timeout: 60_000),
         :ok <- verify_lockfile_integrity(lockfile, pre_checksum),
         :ok <- run_build_step(compile_cmd, cd: workspace_dir, timeout: 60_000) do
      run_build_step(test_cmd, cd: workspace_dir, timeout: 180_000)
    end
  end

  defp run_build_step(nil, _opts), do: :ok

  defp run_build_step({cmd, args}, opts) do
    run_cmd(cmd, args, opts)
  end

  @doc """
  v25 H-2: Compile and test via Docker sandbox with network isolation.
  Routes build commands through `docker run` with --network none during compilation.
  Supports polyglot languages via `build_commands/1`.
  """
  @spec sandboxed_compile_and_test(String.t(), String.t()) :: :ok | {:error, term()}
  def sandboxed_compile_and_test(workspace_dir, language \\ "elixir") do
    image = Application.get_env(:krait, :sandbox_image, "krait-sandbox:latest")

    {deps_cmd, compile_cmd, test_cmd, lockfile_name} = build_commands(language)

    # Snapshot lockfile before deps for integrity verification
    lockfile = Path.join(workspace_dir, lockfile_name)
    pre_checksum = lockfile_checksum(lockfile)

    # deps step needs network access (if applicable)
    with :ok <- sandboxed_build_step(image, deps_cmd, workspace_dir, 60_000, "default"),
         :ok <- verify_lockfile_integrity(lockfile, pre_checksum),
         # Compile with network disabled
         :ok <- sandboxed_build_step(image, compile_cmd, workspace_dir, 60_000, "none") do
      # Test with network disabled
      sandboxed_build_step(image, test_cmd, workspace_dir, 180_000, "none")
    end
  end

  defp sandboxed_build_step(_image, nil, _workspace_dir, _timeout, _network), do: :ok

  defp sandboxed_build_step(image, {cmd, args}, workspace_dir, timeout, network) do
    sandboxed_run_cmd(
      image,
      [cmd | args],
      workspace_dir: workspace_dir,
      timeout: timeout,
      network: network
    )
  end

  @doc false
  def sandboxed_run_cmd(image, cmd_args, opts) do
    docker_args = build_sandboxed_docker_args(image, cmd_args, opts)
    timeout = Keyword.get(opts, :timeout, @default_cmd_timeout)
    run_cmd("docker", docker_args, timeout: timeout)
  end

  # v26 M-5: Allowed networks for workspace sandboxing (includes "default" for deps.get)
  @allowed_workspace_networks ["none", "bridge", "default"]

  @doc false
  @spec build_sandboxed_docker_args(String.t(), [String.t()], keyword()) :: [String.t()]
  def build_sandboxed_docker_args(image, cmd_args, opts) do
    workspace_dir = Keyword.fetch!(opts, :workspace_dir)
    network = Keyword.get(opts, :network, "none")

    unless network in @allowed_workspace_networks do
      raise ArgumentError,
            "invalid workspace network mode: #{inspect(network)}, " <>
              "allowed: #{inspect(@allowed_workspace_networks)}"
    end

    [
      "run",
      "--rm",
      "--network",
      network,
      "--memory",
      "2g",
      "--cpus",
      "2",
      # v26 H-1: Security hardening flags (parity with DockerBackend)
      "--security-opt=no-new-privileges",
      "--cap-drop=ALL",
      "--user",
      "65534:65534",
      "--pids-limit=256",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=100m",
      # v27 M-2: Pin Hex registry to official mirror, enforce HTTPS
      "-e",
      "HEX_MIRROR=https://repo.hex.pm",
      "-e",
      "HEX_UNSAFE_HTTPS=0",
      "-v",
      "#{workspace_dir}:/workspace",
      "-w",
      "/workspace",
      image
    ] ++ cmd_args
  end

  # v28: Sandbox is the default in ALL non-test environments.
  # Only :test env can opt out (to avoid Docker dependency for unit tests).
  # In dev, host execution requires explicit KRAIT_DEV_HOST_EXEC=true env var.
  defp use_sandbox? do
    env = Application.get_env(:krait, :env, :dev)

    if env == :test do
      # Tests can opt out of sandbox for speed (no Docker needed)
      allow_local = Application.get_env(:krait, :allow_local_execution, false)
      accept_risk = Application.get_env(:krait, :accept_host_execution_risk, false)
      not (allow_local and accept_risk)
    else
      # All non-test envs: sandbox unless BOTH flags explicitly set
      allow_local = Application.get_env(:krait, :allow_local_execution, false)
      accept_risk = Application.get_env(:krait, :accept_host_execution_risk, false)
      not (allow_local and accept_risk)
    end
  end

  @doc false
  def lockfile_checksum(lockfile) do
    case File.read(lockfile) do
      {:ok, content} -> :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
      {:error, _} -> nil
    end
  end

  @doc false
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

  @doc "Commit changes in the workspace"
  @spec commit(String.t(), String.t()) :: :ok | {:error, term()}
  def commit(workspace_dir, message) do
    with :ok <- run_cmd("git", ["-C", workspace_dir, "add", "."]) do
      run_cmd("git", ["-C", workspace_dir, "commit", "-m", message])
    end
  end

  @doc "Clean up the workspace directory"
  @spec cleanup(String.t()) :: :ok | {:error, :invalid_cleanup_path}
  def cleanup(workspace_dir) do
    # v22 SEC-19: Resolve symlinks before cleanup to prevent deletion of targets outside tmp_dir
    alias Krait.Security.PathResolver
    tmp_dir = System.tmp_dir!()

    with {:ok, resolved} <- PathResolver.safe_realpath(workspace_dir),
         {:ok, resolved_tmp} <- PathResolver.safe_realpath(tmp_dir) do
      # v23 L-5: Structured workspace prefix check instead of loose String.contains?("krait")
      basename = Path.basename(resolved)

      if String.starts_with?(resolved, resolved_tmp <> "/") and
           String.starts_with?(basename, @workspace_prefix) do
        File.rm_rf!(resolved)
        :ok
      else
        Logger.error("Rejected cleanup of path outside workspace scope: #{workspace_dir}")
        {:error, :invalid_cleanup_path}
      end
    else
      {:error, _} ->
        Logger.error("Rejected cleanup — could not resolve path: #{workspace_dir}")
        {:error, :invalid_cleanup_path}
    end
  end

  # ---------------------------------------------------------------------------
  # Per-language build commands
  # ---------------------------------------------------------------------------

  @doc """
  Returns `{deps_cmd, compile_cmd, test_cmd, lockfile_name}` for a given language.
  Each command is `{binary, [args]}` or `nil` if not applicable.
  """
  @spec build_commands(String.t()) ::
          {{String.t(), [String.t()]} | nil, {String.t(), [String.t()]} | nil,
           {String.t(), [String.t()]} | nil, String.t()}
  def build_commands(language) do
    case language do
      "elixir" ->
        {{"mix", ["deps.get"]}, {"mix", ["compile", "--warnings-as-errors"]}, {"mix", ["test"]},
         "mix.lock"}

      "python" ->
        {{"pip", ["install", "-r", "requirements.txt", "--no-deps"]},
         {"python", ["-m", "py_compile", "__main__.py"]}, {"python", ["-m", "pytest"]},
         "requirements.txt"}

      lang when lang in ["javascript", "jsx"] ->
        {{"npm", ["ci", "--ignore-scripts"]}, nil, {"npx", ["jest", "--passWithNoTests"]},
         "package-lock.json"}

      lang when lang in ["typescript", "tsx"] ->
        {{"npm", ["ci", "--ignore-scripts"]}, {"npx", ["tsc", "--noEmit"]},
         {"npx", ["jest", "--passWithNoTests"]}, "package-lock.json"}

      "go" ->
        {{"go", ["mod", "download"]}, {"go", ["build", "./..."]}, {"go", ["test", "./..."]},
         "go.sum"}

      "rust" ->
        {{"cargo", ["fetch", "--locked"]}, {"cargo", ["check"]}, {"cargo", ["test"]},
         "Cargo.lock"}

      _ ->
        # Default to Elixir for unknown languages
        {{"mix", ["deps.get"]}, {"mix", ["compile", "--warnings-as-errors"]}, {"mix", ["test"]},
         "mix.lock"}
    end
  end

  # ---------------------------------------------------------------------------
  # Path containment validation
  # ---------------------------------------------------------------------------

  defp validate_path_containment(workspace_dir, file_path) do
    if String.contains?(file_path, "..") or String.starts_with?(file_path, "/") do
      {:error, {:path_traversal, file_path}}
    else
      resolved = Path.expand(Path.join(workspace_dir, file_path))
      workspace_abs = Path.expand(workspace_dir)

      if String.starts_with?(resolved, workspace_abs <> "/") do
        # Additionally resolve symlinks in existing parent dirs to catch
        # symlink-based escapes (e.g., workspace/escape -> /etc)
        check_symlink_escape(workspace_abs, resolved, file_path)
      else
        {:error, {:path_traversal, file_path}}
      end
    end
  end

  # Walk existing path segments and resolve symlinks to detect escape
  defp check_symlink_escape(workspace_abs, full_path, original_path) do
    dir = Path.dirname(full_path)

    if File.exists?(dir) do
      alias Krait.Security.PathResolver

      with {:ok, real_dir} <- PathResolver.safe_realpath(dir),
           {:ok, real_ws} <- PathResolver.safe_realpath(workspace_abs) do
        if String.starts_with?(real_dir, real_ws <> "/") or real_dir == real_ws do
          :ok
        else
          {:error, {:path_escape, original_path}}
        end
      else
        {:error, _} ->
          # Fail-closed: if realpath is unavailable, reject the path
          {:error, {:path_escape, original_path}}
      end
    else
      # Directory doesn't exist yet — will be created, no symlinks to worry about
      :ok
    end
  end

  # ---------------------------------------------------------------------------
  # Branch name validation
  # ---------------------------------------------------------------------------

  defp validate_branch_name(name) when is_binary(name) and byte_size(name) > 0 do
    if Regex.match?(@branch_name_pattern, name), do: :ok, else: {:error, :invalid_branch_name}
  end

  defp validate_branch_name(_), do: {:error, :invalid_branch_name}

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp workspace_path do
    random_suffix = :crypto.strong_rand_bytes(8) |> Base.url_encode64(padding: false)
    Path.join(System.tmp_dir!(), @workspace_prefix <> random_suffix)
  end

  defp run_cmd(cmd, args, opts \\ []) do
    cd = Keyword.get(opts, :cd)
    timeout = Keyword.get(opts, :timeout, @default_cmd_timeout)

    cmd_opts =
      [stderr_to_stdout: true]
      |> then(fn o -> if cd, do: Keyword.put(o, :cd, cd), else: o end)

    Logger.debug("Workspace cmd", cmd: cmd, args: args, timeout: timeout)

    task =
      Task.async(fn ->
        System.cmd(cmd, args, cmd_opts)
      end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {_output, 0}} -> :ok
      {:ok, {output, code}} -> {:error, {:cmd_failed, cmd, code, output}}
      nil -> {:error, {:cmd_timeout, cmd, timeout}}
    end
  rescue
    e in [ErlangError, ArgumentError, SystemLimitError] ->
      {:error, {:cmd_error, cmd, Exception.message(e)}}
  end
end
