defmodule KraitWeb.Router do
  use KraitWeb, :router

  # v22 SEC-16: Shared secure headers — CSP + Referrer-Policy + Permissions-Policy
  # NOTE: style-src 'unsafe-inline' required by Phoenix LiveView for runtime
  # styles (phx-loading, phx-connected visibility). Accepted risk — script-src
  # 'unsafe-inline' required by LiveView for inline <script> initialization.
  # CDN domains whitelisted for Phoenix/LiveView JS bundles and Google Fonts.
  @secure_headers %{
    "content-security-policy" =>
      "default-src 'self'; " <>
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " <>
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " <>
        "font-src 'self' https://fonts.gstatic.com; " <>
        "img-src 'self' data:; connect-src 'self' wss:; frame-ancestors 'none'; " <>
        "object-src 'none'; base-uri 'self'; form-action 'self'",
    "referrer-policy" => "strict-origin-when-cross-origin",
    "permissions-policy" => "camera=(), microphone=(), geolocation=()",
    "x-frame-options" => "DENY"
  }

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    # v24 F-15: MethodOverride scoped to browser pipeline only (was global in endpoint)
    plug Plug.MethodOverride
    plug :put_root_layout, html: {KraitWeb.Layouts, :app}
    plug :protect_from_forgery
    plug :put_secure_browser_headers, @secure_headers
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug KraitWeb.Plugs.ApiAuth
  end

  pipeline :rate_limited_api do
    plug :accepts, ["json"]
    plug KraitWeb.Plugs.ApiAuth
    plug KraitWeb.Plugs.RateLimit, max_requests: 10, window_ms: 60_000
  end

  pipeline :authenticated_browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :put_root_layout, html: {KraitWeb.Layouts, :app}
    plug :protect_from_forgery
    plug :put_secure_browser_headers, @secure_headers
    plug KraitWeb.Plugs.RequireAdminAuth
  end

  pipeline :read_api do
    plug :accepts, ["json"]
    plug KraitWeb.Plugs.ApiAuth
    plug KraitWeb.Plugs.RateLimit, max_requests: 30, window_ms: 60_000
  end

  # Phase 3: Health check endpoints — unauthenticated by design.
  # Liveness/readiness probes must not require auth tokens.
  # Rate-limited to 60 req/min to prevent abuse of unauthenticated endpoints.
  pipeline :health do
    plug :accepts, ["json"]
    plug KraitWeb.Plugs.RateLimit, max_requests: 60, window_ms: 60_000
  end

  scope "/health", KraitWeb do
    pipe_through :health

    get "/", HealthController, :check
    get "/ready", HealthController, :ready
  end

  # v27 L-6: Evolution health exposes kill switch state — require API or admin token
  pipeline :authenticated_health do
    plug :accepts, ["json"]
    plug KraitWeb.Plugs.ApiAuth
  end

  scope "/health", KraitWeb do
    pipe_through :authenticated_health

    get "/evolution", HealthController, :evolution
  end

  scope "/admin", KraitWeb do
    pipe_through :browser

    get "/login", AdminSessionController, :new
    post "/login", AdminSessionController, :create
    delete "/logout", AdminSessionController, :delete
  end

  scope "/", KraitWeb do
    pipe_through :authenticated_browser

    live "/", EvolutionLive
    live "/evolution", EvolutionLive
  end

  scope "/api", KraitWeb do
    pipe_through :read_api

    get "/feed", EvolutionController, :feed
  end

  scope "/api", KraitWeb do
    pipe_through :rate_limited_api

    post "/evolve", EvolutionController, :trigger
  end

  # Phase 0: Admin kill switch API — toggle rate-limited to 2 req/min
  # v25 H-1: Uses AdminApiAuth (reads :admin_auth_token, not :api_auth_token)
  pipeline :admin_toggle_api do
    plug :accepts, ["json"]
    plug KraitWeb.Plugs.AdminApiAuth
    plug KraitWeb.Plugs.RateLimit, max_requests: 2, window_ms: 60_000
  end

  scope "/api/admin", KraitWeb do
    pipe_through :admin_toggle_api

    post "/kill-switch/halt", KillSwitchController, :halt
    post "/kill-switch/resume", KillSwitchController, :resume
  end

  # v25 H-1: Admin status also requires admin token
  pipeline :admin_read_api do
    plug :accepts, ["json"]
    plug KraitWeb.Plugs.AdminApiAuth
    plug KraitWeb.Plugs.RateLimit, max_requests: 10, window_ms: 60_000
  end

  scope "/api/admin", KraitWeb do
    pipe_through :admin_read_api

    get "/kill-switch/status", KillSwitchController, :status
  end
end
