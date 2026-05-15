defmodule Krait.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    # v22 SEC-08: ETS tables are now owned by GenServers (RateLimitCounter,
    # HealthCacheServer, EvolveCooldownServer) in the supervisor children.
    log_security_warnings()

    # Phase 2: Verify NIF binary integrity at boot in production
    if Application.get_env(:krait, :env) == :prod do
      Krait.Security.NifIntegrity.verify!()
    end

    children = children()

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Krait.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # v22 SEC-03: Changed from defp to def for testability
  @doc false
  def log_security_warnings do
    unless Application.get_env(:krait, :require_deep_scan, false) do
      Logger.warning(
        "[SECURITY] Deep scan is NOT required — set require_deep_scan: true for production"
      )
    end

    env = Application.get_env(:krait, :env, :dev)

    if env == :prod do
      validate_session_salts!()
      validate_live_view_salt!()
      validate_admin_session_salt!()
      validate_filesystem_sandbox!()
      validate_admin_token!()
      validate_token_complexity!()
      validate_sandbox_config!()
      validate_secret_key_base!()

      # v23 M-4: Warn about missing trusted_proxies config behind reverse proxy
      trusted = Application.get_env(:krait, :trusted_proxies, [])

      if Enum.empty?(trusted) do
        Logger.warning(
          "[SECURITY] :trusted_proxies is empty — rate limiting uses conn.remote_ip only. " <>
            "Configure trusted_proxies if behind a reverse proxy."
        )
      end
    else
      # v28: Warn about unsandboxed execution in non-prod environments
      if Application.get_env(:krait, :allow_local_execution, false) do
        Logger.warning(
          "[SECURITY] allow_local_execution=true — code executes on host, not in Docker sandbox. " <>
            "Sandbox is the default; set KRAIT_DEV_HOST_EXEC=true only for fast iteration."
        )
      end

      # v25 C-1: Warn about dev secret_key_base even in non-prod
      check_dev_secret_key_base()

      # v23 L-8: Warn if debug_errors is enabled on a non-loopback binding
      check_debug_binding_safety()
    end
  end

  @doc """
  Validates session salts are not using dev defaults in production.
  Raises if signing or encryption salts contain "dev_default" in prod.
  """
  def validate_session_salts! do
    endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])
    session_opts = Keyword.get(endpoint_config, :session_options, [])
    signing = Keyword.get(session_opts, :signing_salt, "")
    encryption = Keyword.get(session_opts, :encryption_salt, "")

    if String.contains?(signing, "dev_default") or String.contains?(encryption, "dev_default") do
      raise "[SECURITY] Production is using dev_default session salts! " <>
              "Set SIGNING_SALT and ENCRYPTION_SALT environment variables."
    end
  end

  @doc """
  Validates LiveView signing salt is not using dev defaults in production.
  Raises if the signing salt contains "dev_default" in prod.
  """
  def validate_live_view_salt! do
    endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])
    live_view_opts = Keyword.get(endpoint_config, :live_view, [])
    signing_salt = Keyword.get(live_view_opts, :signing_salt, "")

    if String.contains?(signing_salt, "dev_default") do
      raise "[SECURITY] Production is using dev_default LiveView signing salt! " <>
              "Set LIVE_VIEW_SALT environment variable."
    end
  end

  @doc """
  Validates admin session salt is configured in production.
  Raises if the salt is nil (v20 M-1: no hardcoded fallback).
  """
  def validate_admin_session_salt! do
    salt = Application.get_env(:krait, :admin_session_salt)

    if is_nil(salt) do
      raise "[SECURITY] ADMIN_SESSION_SALT environment variable is missing. " <>
              "Set a unique random value for production."
    end

    :ok
  end

  @doc """
  Validates filesystem sandbox root is explicitly configured in production.
  """
  def validate_filesystem_sandbox! do
    unless Application.get_env(:krait, :filesystem_sandbox_root) do
      raise "[SECURITY] Production requires explicit :filesystem_sandbox_root configuration"
    end
  end

  # Dev secret_key_base values that must not appear in production.
  @dev_secret_key_bases [
    "MoCO2EgSPBi+j+Kqq1PBQof5lhiJIpr5i9YB+mw/9dqJmatGIrQRA/g/mtujgDEF",
    "2SYuF2iHOYKH5sJMMt10aXwwID2W+E6Q7bGa0r340jmuxBHgCnAUoxH7s4IGl0nu"
  ]

  @doc """
  Validates that secret_key_base is not using dev/test defaults in production.
  Raises if the configured secret matches a known dev value.
  """
  def validate_secret_key_base! do
    endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])
    skb = Keyword.get(endpoint_config, :secret_key_base, "")

    if skb in @dev_secret_key_bases do
      raise "[SECURITY] Production is using a dev/test secret_key_base! " <>
              "Set SECRET_KEY_BASE to a unique random value (mix phx.gen.secret)."
    end

    :ok
  end

  @doc """
  Validates that a dedicated admin token is configured in production.
  Raises if `:admin_auth_token` is nil — sharing API token for admin access
  violates least privilege.
  """
  def validate_admin_token! do
    if is_nil(Application.get_env(:krait, :admin_auth_token)) do
      raise "[SECURITY] KRAIT_ADMIN_TOKEN must be set in production. " <>
              "Sharing KRAIT_API_TOKEN for admin access violates least privilege."
    end

    :ok
  end

  @doc """
  Validates that API and admin tokens meet minimum complexity requirements.
  Raises if either token is shorter than 32 characters in production.
  """
  def validate_token_complexity! do
    api_token = Application.get_env(:krait, :api_auth_token)
    admin_token = Application.get_env(:krait, :admin_auth_token)

    if api_token && String.length(api_token) < 32 do
      raise "[SECURITY] KRAIT_API_TOKEN must be at least 32 characters in production."
    end

    if admin_token && String.length(admin_token) < 32 do
      raise "[SECURITY] KRAIT_ADMIN_TOKEN must be at least 32 characters in production."
    end

    :ok
  end

  @doc """
  Validates that allow_local_execution is false in production.
  Raises if sandbox bypass is enabled in prod.
  """
  def validate_sandbox_config! do
    if Application.get_env(:krait, :allow_local_execution, false) do
      raise "[SECURITY] allow_local_execution must be false in production. " <>
              "Code must execute in Docker sandbox, not on the host."
    end

    :ok
  end

  # v25 C-1: Warn when using a known dev secret_key_base in non-prod
  defp check_dev_secret_key_base do
    endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])
    skb = Keyword.get(endpoint_config, :secret_key_base, "")

    if skb in @dev_secret_key_bases do
      Logger.warning(
        "[SECURITY] Using known dev secret_key_base — set SECRET_KEY_BASE env var for deployment"
      )
    end
  end

  # v27 M-6: Raise (not just warn) when debug_errors is enabled on non-loopback address.
  # debug_errors exposes full stack traces and source code in error pages.
  defp check_debug_binding_safety do
    endpoint_config = Application.get_env(:krait, KraitWeb.Endpoint, [])
    http_config = Keyword.get(endpoint_config, :http, [])
    ip = Keyword.get(http_config, :ip, {127, 0, 0, 1})
    debug = Keyword.get(endpoint_config, :debug_errors, false)

    if debug and ip not in [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}] do
      raise "[SECURITY] debug_errors=true with non-loopback binding #{inspect(ip)} — " <>
              "source code and stack traces visible to the network. " <>
              "Either set debug_errors: false or bind to 127.0.0.1."
    end
  end

  defp children do
    base = [
      KraitWeb.Telemetry,
      Krait.Repo,
      {DNSCluster, query: Application.get_env(:krait, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Krait.PubSub},
      # Phase 0: Kill switch in base list — must be available regardless of :start_workers
      # Placed after Repo (needs DB) and PubSub (needs broadcasts)
      # In test env, skip DB restoration (tests use start_supervised! with sandbox)
      {Krait.KillSwitch,
       name: Krait.KillSwitch, skip_db: Application.get_env(:krait, :env) == :test},
      {Task.Supervisor, name: Krait.TaskSupervisor}
    ]

    workers =
      if Application.get_env(:krait, :start_workers, true) do
        [
          Krait.LLM.QualityGate,
          {Krait.Memory.Hot, name: Krait.Memory.Hot},
          {Krait.Skills.Registry,
           skills: [
             Krait.Skills.Core.WebFetch,
             Krait.Skills.Core.Filesystem,
             Krait.Skills.Core.MemorySkill,
             Krait.Skills.Core.Evolve,
             Krait.Skills.Community.TextTransform,
             Krait.Skills.Community.JsonTools,
             Krait.Skills.Community.MathUtils,
             Krait.Skills.Community.DateHelper,
             Krait.Skills.Community.CodeMetrics
           ]}
        ]
      else
        []
      end

    # v22 SEC-08: All ETS-owning GenServers must start before Endpoint
    # Endpoint must be the last entry
    base ++
      [KraitWeb.RateLimitCounter, Krait.HealthCacheServer, Krait.EvolveCooldownServer] ++
      workers ++ maybe_deep_analyzer() ++ [KraitWeb.Endpoint]
  end

  defp maybe_deep_analyzer do
    narsil_binary =
      (Application.get_env(:krait, Krait.Analyzer.Deep) || [])
      |> Keyword.get(:narsil_binary, "narsil-mcp")

    if System.find_executable(narsil_binary) do
      Logger.info("Narsil MCP found at #{narsil_binary} — deep analysis enabled")

      [
        {Krait.Analyzer.Deep, repo_path: File.cwd!(), name: Krait.Analyzer.Deep}
      ]
    else
      Logger.info("Narsil MCP not found — deep analysis disabled")
      []
    end
  end

  # Phase 3: Graceful shutdown — drain in-flight evolutions before stopping.
  @impl true
  def prep_stop(_state) do
    Logger.info("[SHUTDOWN] Draining in-flight evolutions...")
    Krait.KillSwitch.halt_transient!("graceful_shutdown")
    drain_evolutions(30_000)
    :ok
  rescue
    # KillSwitch may already be stopped during shutdown
    e in [ArgumentError, RuntimeError, ErlangError] ->
      Logger.debug("[SHUTDOWN] KillSwitch unavailable: #{Exception.message(e)}")
      :ok
  end

  defp drain_evolutions(timeout) do
    deadline = System.monotonic_time(:millisecond) + timeout
    drain_loop(deadline)
  end

  defp drain_loop(deadline) do
    active =
      case Krait.EvolveCooldownServer.lookup(:active_evolutions) do
        [{_, count}] -> count
        [] -> 0
      end

    cond do
      active == 0 ->
        Logger.info("[SHUTDOWN] All evolutions drained")
        :ok

      System.monotonic_time(:millisecond) > deadline ->
        Logger.warning("[SHUTDOWN] Timeout waiting for #{active} evolutions to drain")

        :timeout

      true ->
        Process.sleep(500)
        drain_loop(deadline)
    end
  rescue
    # EvolveCooldownServer may already be stopped during shutdown
    e in [ArgumentError, RuntimeError, ErlangError] ->
      Logger.info("[SHUTDOWN] CooldownServer unavailable: #{Exception.message(e)}")
      :ok
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    KraitWeb.Endpoint.config_change(changed, removed)
    # v22 SEC-07: Invalidate cached session opts when config changes
    KraitWeb.Plugs.RuntimeSession.invalidate_cache()
    :ok
  end
end
