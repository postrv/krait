defmodule KraitWeb.Plugs.RequireAdminAuth do
  @moduledoc """
  Plug-level authentication for LiveView and browser routes.

  Checks the session for a valid admin token hash (set by AdminSessionController
  on login). Redirects unauthenticated users to /admin/login.

  Bypass: only in :test env when `disable_auth: true` is configured, matching
  the existing ApiAuth pattern.
  """

  import Plug.Conn
  require Logger

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    if bypass?() do
      conn
    else
      verify_session(conn)
    end
  end

  defp bypass? do
    Application.get_env(:krait, :env, :dev) == :test and
      Application.get_env(:krait, :disable_auth, false)
  end

  # v22 SEC-12: Use KraitWeb.Auth.verify_admin_session (nonce-based Phoenix.Token)
  defp verify_session(conn) do
    session_signed = get_session(conn, :krait_admin_token)

    case KraitWeb.Auth.verify_admin_session(session_signed) do
      :ok ->
        conn

      :error ->
        conn
        |> Phoenix.Controller.redirect(to: "/admin/login")
        |> halt()
    end
  end
end
