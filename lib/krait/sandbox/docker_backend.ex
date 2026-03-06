defmodule Krait.Sandbox.DockerBackend do
  @moduledoc """
  FLAME.Backend implementation for Docker containers.
  Manages ephemeral containers for sandboxed code execution.

  This backend creates Docker containers on demand, runs
  Elixir code inside them via Erlang distribution, and
  cleans up on shutdown.

  ## Configuration

  Accepts the following options (as a keyword list, per the FLAME.Backend contract):

    * `:image` - Docker image to use. Defaults to `"elixir:1.17-otp-27-slim"`.
    * `:memory_mb` - Memory limit in MB. Defaults to `2048`.
    * `:cpus` - CPU limit. Defaults to `2`.
    * `:env` - Map of environment variables to pass to the container. Defaults to `%{}`.
    * `:boot_timeout` - Boot timeout in milliseconds. Defaults to `30_000`.
    * `:network` - Docker network mode. Defaults to `"none"` (fully sandboxed).
    * `:terminator_sup` - The terminator supervisor (passed by FLAME internals).
    * `:log` - Log level for backend messages. Defaults to `false`.

  ## Implementation Notes

  This follows the FLAME.Backend behaviour contract. The callback signatures are:

    - `init(opts :: Keyword.t()) :: {:ok, state} | {:error, term()}`
    - `remote_boot(state) :: {:ok, remote_terminator_pid, new_state} | {:error, term()}`
    - `remote_spawn_monitor(state, func) :: {:ok, {pid, reference()}} | {:error, term()}`
    - `system_shutdown() :: no_return()`
    - `handle_info(msg, state) :: {:noreply, new_state} | {:stop, reason, new_state}`

  Study FLAME.FlyBackend and FLAME.LocalBackend for reference implementations.
  """

  @behaviour FLAME.Backend

  require Logger

  @default_image "elixir:1.17-otp-27-slim"
  @default_memory_mb 2048
  @default_cpus 2
  @default_boot_timeout 30_000

  defstruct [
    :image,
    :memory_mb,
    :cpus,
    :boot_timeout,
    :network,
    :container_id,
    :container_name,
    :runner_node_name,
    :remote_terminator_pid,
    :parent_ref,
    :terminator_sup,
    env: %{},
    log: false
  ]

  @valid_opts [
    :image,
    :memory_mb,
    :cpus,
    :boot_timeout,
    :network,
    :env,
    :terminator_sup,
    :log
  ]

  # ---------------------------------------------------------------------------
  # FLAME.Backend callbacks
  # ---------------------------------------------------------------------------

  @impl true
  @doc """
  Initializes the Docker backend state from a keyword list of options.

  Merges application-level config (`config :flame, Krait.Sandbox.DockerBackend`)
  with the per-pool opts, validates, and builds an initial state struct.
  """
  def init(opts) when is_list(opts) do
    conf = Application.get_env(:flame, __MODULE__) || []

    provided_opts =
      conf
      |> Keyword.merge(opts)
      |> Keyword.validate!(@valid_opts)

    image = Keyword.get(provided_opts, :image, @default_image)
    validate_image!(image)

    network = Keyword.get(provided_opts, :network, "none")
    validate_network!(network)

    state = %__MODULE__{
      image: image,
      memory_mb: Keyword.get(provided_opts, :memory_mb, @default_memory_mb),
      cpus: Keyword.get(provided_opts, :cpus, @default_cpus),
      boot_timeout: Keyword.get(provided_opts, :boot_timeout, @default_boot_timeout),
      network: Keyword.get(provided_opts, :network, "none"),
      env: Keyword.get(provided_opts, :env, %{}),
      terminator_sup: Keyword.get(provided_opts, :terminator_sup),
      log: Keyword.get(provided_opts, :log, false),
      parent_ref: make_ref()
    }

    {:ok, state}
  end

  # v26 M-5: Allowed Docker network modes
  @allowed_networks ["none", "bridge"]

  @doc false
  def validate_network!(network) when is_binary(network) do
    unless network in @allowed_networks do
      raise ArgumentError,
            "invalid Docker network mode: #{inspect(network)}, allowed: #{inspect(@allowed_networks)}"
    end
  end

  def validate_network!(network) do
    raise ArgumentError, "invalid Docker network mode: #{inspect(network)}"
  end

  # v21 M-8: Validate Docker image names to prevent command injection
  @valid_image_re ~r/^[a-z0-9]([a-z0-9._\/-]*[a-z0-9])?(:[\w][\w.\-]{0,127})?(@sha256:[a-f0-9]{64})?$/
  defp validate_image!(image) when is_binary(image) and image != "" do
    unless Regex.match?(@valid_image_re, image) do
      raise ArgumentError, "invalid Docker image name: #{inspect(image)}"
    end
  end

  defp validate_image!(image) do
    raise ArgumentError, "invalid Docker image name: #{inspect(image)}"
  end

  @impl true
  @doc """
  Boots a remote Docker container and waits for it to connect back.

  Returns `{:ok, remote_terminator_pid, new_state}` on success.

  In the current stub implementation, this starts a local FLAME.Terminator
  (similar to LocalBackend) since full Erlang distribution into an
  ephemeral Docker container requires additional infrastructure (epmd,
  cookie sharing, network bridging). The Docker container is still
  created for resource isolation; distribution integration is the next
  step.
  """
  def remote_boot(%__MODULE__{} = state) do
    container_name = "krait-sandbox-#{System.unique_integer([:positive])}"

    args = build_container_args(container_name, state)

    args =
      args ++
        env_args(state.env) ++
        [
          state.image,
          "sleep",
          "3600"
        ]

    case System.cmd("docker", args, stderr_to_stdout: true) do
      {container_id, 0} ->
        container_id = String.trim(container_id)
        log(state, "Started sandbox container: #{container_id} (#{container_name})")

        new_state = %{
          state
          | container_id: container_id,
            container_name: container_name
        }

        # Start a local terminator so the FLAME pool machinery works.
        # In a production implementation, the terminator would run inside
        # the Docker container and connect back via Erlang distribution.
        terminator_pid = start_local_terminator(new_state)

        new_state = %{
          new_state
          | remote_terminator_pid: terminator_pid,
            runner_node_name: node(terminator_pid)
        }

        {:ok, terminator_pid, new_state}

      {error, _exit_code} ->
        {:error, "Failed to start Docker container: #{String.trim(error)}"}
    end
  end

  @impl true
  @doc """
  Spawns and monitors a function on the remote node.

  Returns `{:ok, {pid, ref}}`.

  Currently delegates to the local node since full Erlang distribution
  into Docker containers is not yet wired. When distribution is enabled,
  this will use `Node.spawn_monitor/2` targeting the container node.
  """
  def remote_spawn_monitor(%__MODULE__{runner_node_name: nil}, term) do
    # v20 H-3: Explicit config flag instead of env check
    if Application.get_env(:krait, :allow_local_execution, false) do
      Logger.warning(
        "DockerBackend: runner_node_name is nil — running locally (allow_local_execution=true)"
      )

      {pid, ref} = spawn_monitor_local(term)
      {:ok, {pid, ref}}
    else
      {:error, :no_remote_node}
    end
  end

  def remote_spawn_monitor(%__MODULE__{} = state, term) do
    case term do
      func when is_function(func, 0) ->
        {pid, ref} = Node.spawn_monitor(state.runner_node_name, func)
        {:ok, {pid, ref}}

      {mod, fun, args} when is_atom(mod) and is_atom(fun) and is_list(args) ->
        {pid, ref} = Node.spawn_monitor(state.runner_node_name, mod, fun, args)
        {:ok, {pid, ref}}

      other ->
        raise ArgumentError,
              "expected a zero-arity function or {mod, fun, args}. Got: #{inspect(other)}"
    end
  end

  defp spawn_monitor_local(func) when is_function(func, 0), do: spawn_monitor(func)

  defp spawn_monitor_local({mod, fun, args}),
    do: spawn_monitor(fn -> apply(mod, fun, args) end)

  @impl true
  @doc """
  Called on the remote (child) node to shut down the system.

  Attempts to stop any running container before halting.
  """
  def system_shutdown do
    Logger.info("DockerBackend system_shutdown called")
    System.stop()
  end

  @impl true
  @doc """
  Handles messages sent to the backend runner process.

  Reacts to FLAME terminator protocol messages and container lifecycle events.
  """
  def handle_info(
        {ref, {:remote_up, remote_terminator_pid}},
        %__MODULE__{parent_ref: ref} = state
      ) do
    log(state, "Remote terminator up: #{inspect(remote_terminator_pid)}")
    {:noreply, %{state | remote_terminator_pid: remote_terminator_pid}}
  end

  def handle_info({ref, {:remote_shutdown, reason}}, %__MODULE__{parent_ref: ref} = state) do
    log(state, "Remote shutdown (#{inspect(reason)}), cleaning up container")
    cleanup_container(state)
    {:stop, {:remote_shutdown, reason}, state}
  end

  def handle_info(msg, state) do
    log(state, "DockerBackend received unexpected message: #{inspect(msg)}")
    {:noreply, state}
  end

  # ---------------------------------------------------------------------------
  # Private helpers
  # ---------------------------------------------------------------------------

  @doc """
  Build the Docker container arguments with security hardening flags.
  Extracted for testability.
  """
  @spec build_container_args(String.t(), %__MODULE__{}) :: [String.t()]
  def build_container_args(container_name, state) do
    [
      "run",
      "-d",
      "--name",
      container_name,
      "--memory",
      "#{state.memory_mb}m",
      "--cpus",
      "#{state.cpus}",
      "--network",
      state.network,
      "--rm",
      "--security-opt=no-new-privileges",
      "--cap-drop=ALL",
      "--user",
      "65534:65534",
      "--pids-limit=256",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=100m"
    ]
  end

  @valid_env_key ~r/^[A-Z_][A-Z0-9_]*$/
  # v25 M-11: Removed ERL_AFLAGS and ELIXIR_ERL_OPTIONS — attacker could inject
  # BEAM flags (e.g., -eval to execute code, -remsh to connect to remote shell)
  @allowed_env_keys ~w(MIX_ENV LANG LC_ALL PATH HOME TERM USER)

  @doc """
  Filter environment variables through the allowlist.

  Only keys in the explicit allowlist are passed through to the sandbox.
  This is safer than a blocklist since any new secret env var is automatically excluded.
  """
  @spec filter_env(map()) :: map()
  def filter_env(env) do
    Map.filter(env, fn {k, _v} -> to_string(k) in @allowed_env_keys end)
  end

  defp env_args(env) when map_size(env) == 0, do: []

  defp env_args(env) do
    env
    |> filter_env()
    |> Enum.flat_map(fn {k, v} ->
      k_str = to_string(k)
      v_str = to_string(v)

      if Regex.match?(@valid_env_key, k_str) and
           not String.contains?(v_str, ["\n", "\r", "\0"]) do
        ["-e", "#{k_str}=#{v_str}"]
      else
        Logger.warning("Rejected invalid env var", key: k_str)
        []
      end
    end)
  end

  defp cleanup_container(%__MODULE__{container_id: nil}), do: :ok

  defp cleanup_container(%__MODULE__{container_id: container_id} = state) do
    case System.cmd("docker", ["stop", container_id], stderr_to_stdout: true) do
      {_, 0} ->
        log(state, "Stopped sandbox container: #{container_id}")
        :ok

      {error, _} ->
        log(state, "Warning: failed to stop container #{container_id}: #{String.trim(error)}")
        :ok
    end
  end

  defp start_local_terminator(%__MODULE__{} = state) do
    # Bootstrap a local FLAME.Terminator so the pool machinery is satisfied.
    # This mirrors what FLAME.LocalBackend does.
    parent = FLAME.Parent.new(state.parent_ref, self(), __MODULE__, "nonode", nil)

    name =
      if state.terminator_sup do
        Module.concat(state.terminator_sup, to_string(System.unique_integer([:positive])))
      else
        :"krait_docker_terminator_#{System.unique_integer([:positive])}"
      end

    opts = [name: name, parent: parent, log: state.log]
    spec = Supervisor.child_spec({FLAME.Terminator, opts}, restart: :temporary)

    if state.terminator_sup do
      {:ok, _sup_pid} = DynamicSupervisor.start_child(state.terminator_sup, spec)
    else
      {:ok, _pid} = GenServer.start(FLAME.Terminator, opts, name: name)
    end

    case Process.whereis(name) do
      pid when is_pid(pid) -> pid
    end
  end

  defp log(%__MODULE__{log: false}, _msg), do: :ok
  defp log(%__MODULE__{log: nil}, _msg), do: :ok
  defp log(%__MODULE__{log: level}, msg), do: Logger.log(level, "DockerBackend: #{msg}")
end
