# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :krait,
  env: config_env(),
  generators: [timestamp_type: :utc_datetime],
  llm_module: Krait.LLM.Router,
  github_client: Krait.GitHub.Client,
  analyzer_quick: Krait.Analyzer.Quick,
  analyzer_deep: Krait.Analyzer.Deep,
  repo_url: System.get_env("KRAIT_REPO_URL", "https://github.com/postrv/krait"),
  repo_name: System.get_env("KRAIT_REPO_NAME", "postrv/krait"),
  max_evolution_retries: 3,
  max_complexity_budget: 1500,
  max_complexity_delta: 100,
  immutable_manifest_path: ".krait-immutable",
  network_allowlist: ["openrouter.ai", "api.github.com", "api.coingecko.com"],
  # v25 H-5: Default to true — deep scan required everywhere (overridden in test.exs)
  require_deep_scan: true,
  # v20 H-3: Local execution guard — false by default, overridden in dev/test
  allow_local_execution: false

config :krait, Krait.LLM.Router,
  local_module: Krait.LLM.Ollama,
  cloud_module: Krait.LLM.OpenRouter,
  force_cloud: [:planning, :reflection, :retry_guide],
  force_local: [:code_gen, :test_gen, :chat],
  escalation_threshold: 2

config :krait, Krait.LLM.OpenRouter,
  base_url: "https://openrouter.ai/api/v1",
  model: "anthropic/claude-sonnet-4.5",
  site_url: "",
  site_name: "Krait",
  request_timeout: 120_000,
  default_provider: %{data_collection: "deny"}

config :krait, Krait.LLM.Ollama,
  base_url: "http://localhost:11434",
  model: "qwen2.5-coder:14b",
  request_timeout: 120_000

config :krait, Krait.LLM.QualityGate,
  escalation_threshold: 0.60,
  window_size: 20,
  cooldown_after_escalation: 10

config :krait, Krait.Analyzer.Deep,
  narsil_binary: System.get_env("NARSIL_BINARY", "narsil-mcp"),
  preset: "security"

# Configure the endpoint
config :krait, KraitWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [json: KraitWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Krait.PubSub,
  # v26 L-2: Runtime salt override in dev.exs/prod runtime.exs — this is a placeholder
  live_view: [signing_salt: "override_in_env_config"]

# Configure Elixir's Logger
config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

config :krait, Krait.Repo, migration_primary_key: [type: :binary_id]

config :krait, ecto_repos: [Krait.Repo]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
