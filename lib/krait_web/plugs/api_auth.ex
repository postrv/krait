defmodule KraitWeb.Plugs.ApiAuth do
  @moduledoc """
  Bearer token authentication for API routes.

  Reads the expected token from config at runtime:

      config :krait, :api_auth_token, "your-secret-token"

  Requests must include: `Authorization: Bearer <token>`

  ## Security Model

  - **Production**: Token MUST be configured via `KRAIT_API_TOKEN` env var.
    If no token is set, all API requests are rejected with 503 to prevent
    accidental open access. Use a cryptographically random token (>= 32 chars).

  - **Dev**: If no token is configured, requests are rejected with 503
    (same as prod). Set `KRAIT_API_TOKEN` in your environment for dev access.

  - **Test**: Auth is bypassed only when `config :krait, disable_auth: true`
    is set (default in test.exs). This allows test requests without tokens.

  ## Production Deployment Checklist

  1. Set `KRAIT_API_TOKEN` to a strong random value
  2. Set `SECRET_KEY_BASE` via `mix phx.gen.secret`
  3. Set `LIVE_VIEW_SALT` via `mix phx.gen.secret 32`
  4. Enable TLS termination (nginx/load balancer or `force_ssl` config)
  5. Enable HSTS headers (already configured in prod.exs)
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case expected_token() do
      nil ->
        cond do
          Application.get_env(:krait, :env, :dev) == :test and
              Application.get_env(:krait, :disable_auth, false) ->
            Logger.warning("[SECURITY] API auth disabled (test env only)")
            conn

          true ->
            Logger.warning("API auth rejected: token not configured",
              env: Application.get_env(:krait, :env, :dev)
            )

            conn
            |> put_status(503)
            |> Phoenix.Controller.json(%{error: "Service unavailable"})
            |> halt()
        end

      expected ->
        case get_req_header(conn, "authorization") do
          ["Bearer " <> token] ->
            if Plug.Crypto.secure_compare(token, expected) do
              conn
            else
              conn
              |> put_status(401)
              |> Phoenix.Controller.json(%{error: "unauthorized"})
              |> halt()
            end

          _ ->
            conn
            |> put_status(401)
            |> Phoenix.Controller.json(%{error: "unauthorized"})
            |> halt()
        end
    end
  end

  defp expected_token do
    Application.get_env(:krait, :api_auth_token)
  end
end
