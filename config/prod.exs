import Config

# Force using SSL in production. This also sets the "strict-security-transport" header,
# known as HSTS. If you have a health check endpoint, you may want to exclude it below.
# Note `:force_ssl` is required to be set at compile-time.
# v21 L-1: Removed host exclusion from HSTS — all production traffic must use TLS.
# Health check paths can be excluded if needed: exclude: [paths: ["/health"]]
# v22 SEC-05: HSTS with subdomains and preload for full protection
config :krait, KraitWeb.Endpoint,
  force_ssl: [rewrite_on: [:x_forwarded_proto], hsts: true, subdomains: true, preload: true]

# Require deep scan in production — fail closed if Narsil unavailable
config :krait, require_deep_scan: true

# Do not print debug messages in production
config :logger, level: :info

# Runtime production configuration, including reading
# of environment variables, is done on config/runtime.exs.
