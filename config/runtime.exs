import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/krait start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :krait, KraitWeb.Endpoint, server: true
end

# OpenRouter API key (primary); falls back to ANTHROPIC_API_KEY for migration
openrouter_key = System.get_env("OPENROUTER_API_KEY") || System.get_env("ANTHROPIC_API_KEY")
if openrouter_key, do: config(:krait, :openrouter_api_key, openrouter_key)
# Deprecated: kept for backward compat with claude.ex during transition
config :krait, :anthropic_api_key, System.get_env("ANTHROPIC_API_KEY")
config :krait, :api_auth_token, System.get_env("KRAIT_API_TOKEN")

# Dry-run mode: use DryRunClient for GitHub (no GitHub App needed)
if System.get_env("KRAIT_DRY_RUN") == "true" do
  config :krait, github_client: Krait.GitHub.DryRunClient
end

# Filesystem sandbox root from environment
if sandbox_root = System.get_env("FILESYSTEM_SANDBOX_ROOT") do
  config :krait, :filesystem_sandbox_root, sandbox_root
end

# v26 L-11: Separate admin token — no fallback, nil disables admin login
config :krait, :admin_auth_token, System.get_env("KRAIT_ADMIN_TOKEN")

# Ollama local LLM configuration
if ollama_url = System.get_env("OLLAMA_BASE_URL") do
  config :krait, Krait.LLM.Ollama,
    base_url: ollama_url,
    model: System.get_env("OLLAMA_MODEL", "qwen2.5-coder:14b")
end

port =
  case Integer.parse(System.get_env("PORT", "4000")) do
    {p, ""} when p > 0 and p < 65536 -> p
    _ -> raise "PORT must be a valid port number (1-65535)"
  end

config :krait, KraitWeb.Endpoint, http: [port: port]

# Trusted proxies configuration — parsed from comma-separated TRUSTED_PROXIES env var.
# Empty or unset = don't trust X-Forwarded-For (fail-closed: use conn.remote_ip only).
trusted_proxies =
  case System.get_env("TRUSTED_PROXIES") do
    nil ->
      []

    "" ->
      []

    proxies ->
      proxies |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
  end

config :krait, :trusted_proxies, trusted_proxies

if config_env() == :prod do
  # v21 M-7: Require DATABASE_URL in production
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  config :krait, Krait.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10")

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  config :krait, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  live_view_salt =
    System.get_env("LIVE_VIEW_SALT") ||
      raise """
      environment variable LIVE_VIEW_SALT is missing.
      You can generate one by calling: mix phx.gen.secret 32
      """

  session_signing_salt =
    System.get_env("SESSION_SIGNING_SALT") ||
      raise """
      environment variable SESSION_SIGNING_SALT is missing.
      You can generate one by calling: mix phx.gen.secret 32
      """

  session_encryption_salt =
    System.get_env("SESSION_ENCRYPTION_SALT") ||
      raise """
      environment variable SESSION_ENCRYPTION_SALT is missing.
      You can generate one by calling: mix phx.gen.secret 32
      """

  admin_session_salt =
    System.get_env("ADMIN_SESSION_SALT") ||
      raise """
      environment variable ADMIN_SESSION_SALT is missing.
      You can generate one by calling: mix phx.gen.secret 32
      """

  config :krait, :admin_session_salt, admin_session_salt

  config :krait, KraitWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    # v22 SEC-06: Restrict WebSocket origins to configured host
    check_origin: ["//#{host}"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base,
    live_view: [signing_salt: live_view_salt],
    session_options: [
      signing_salt: session_signing_salt,
      encryption_salt: session_encryption_salt,
      secure: true
    ]

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :krait, KraitWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :krait, KraitWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.

  # Phase 3: Structured JSON logging in production (via runtime.exs to avoid
  # compile-time dependency on logger_json which is only: :prod)
  config :logger, :default_handler, formatter: {LoggerJSON.Formatters.Basic, []}

  # -------------------------------------------------------------------------
  # KRAIT Production Security Notes
  # -------------------------------------------------------------------------
  # 1. TLS: Terminate TLS at your load balancer or configure :https above.
  #    The force_ssl config in prod.exs enables HSTS and redirects HTTP->HTTPS.
  # 2. Auth: KRAIT_API_TOKEN must be set — API rejects all requests without it.
  # 3. Secrets: SECRET_KEY_BASE and LIVE_VIEW_SALT must be unique per deployment.
  # 4. Deep scan: require_deep_scan=true in prod.exs — Narsil must be available.
  # 5. Rate limiting: /api/evolve is rate-limited to 10 req/min per IP.
  # -------------------------------------------------------------------------
end
