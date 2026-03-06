import Config

# We don't run a server during test. If one is required,
# you can enable the server option below.
config :krait, KraitWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "2SYuF2iHOYKH5sJMMt10aXwwID2W+E6Q7bGa0r340jmuxBHgCnAUoxH7s4IGl0nu",
  server: false

# Swap real modules for mocks in test
config :krait,
  env: :test,
  llm_module: Krait.LLM.Mock,
  github_client: Krait.GitHub.ClientMock,
  analyzer_quick: Krait.Analyzer.QuickMock,
  analyzer_deep: Krait.Analyzer.DeepMock,
  allow_local_network: true,
  sandbox_enabled: false,
  allow_local_execution: true,
  # v26 H-3: Both flags needed for local execution in tests
  accept_host_execution_risk: true,
  disable_auth: true,
  disable_webhook_auth: true

# Router tests override this via Application.put_env in setup
config :krait, Krait.LLM.Router,
  cloud_module: Krait.LLM.CloudMock,
  local_module: Krait.LLM.LocalMock,
  force_cloud: [:planning, :reflection, :retry_guide],
  force_local: [:code_gen, :test_gen, :chat],
  escalation_threshold: 2

config :krait, KraitWeb.Endpoint, live_view: [signing_salt: "test_only_salt"]

# v20 M-1: Admin session salt for test
config :krait, :admin_session_salt, "test_admin_salt"

# v25 H-5: Don't require deep scan in test (narsil-mcp not always available)
config :krait, require_deep_scan: false

# Don't start workers globally in test — tests use start_supervised! instead
config :krait, start_workers: false

# Print only warnings and errors during test
config :logger, level: :warning

# Initialize plugs at runtime for faster test compilation
config :phoenix, :plug_init_mode, :runtime

# Sort query params output of verified routes for robust url comparisons
config :phoenix,
  sort_verified_routes_query_params: true

config :krait, Krait.Repo,
  username: "postgres",
  password: "postgres",
  hostname: "localhost",
  database: "krait_test#{System.get_env("MIX_TEST_PARTITION")}",
  pool: Ecto.Adapters.SQL.Sandbox,
  pool_size: 10
