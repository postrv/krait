defmodule KraitWeb.AdminSessionController do
  @moduledoc """
  Token-based admin login for the LiveView dashboard.

  Validates the submitted token against the configured `:api_auth_token`
  using timing-safe comparison. Sets `krait_admin_token` in the session
  on success.
  """

  use KraitWeb, :controller

  require Logger

  plug :fetch_session
  plug :put_root_layout, false

  # v22 SEC-10: Rate limit login page (30/min) separately from login attempts (3/min)
  plug KraitWeb.Plugs.RateLimit,
       [max_requests: 30, window_ms: 60_000, response_format: :html]
       when action in [:new]

  plug KraitWeb.Plugs.RateLimit,
       [max_requests: 3, window_ms: 60_000, response_format: :html]
       when action in [:create]

  def new(conn, _params) do
    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, login_html(nil, Plug.CSRFProtection.get_csrf_token()))
  end

  def create(conn, %{"token" => token}) when is_binary(token) and token != "" do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()

    # v24 F-03: Time-bucketed lockout key — entries expire after @lockout_window_seconds
    lockout_key = lockout_key(ip)

    # v24 F-03: Probabilistic sweep of old lockout entries (~1% of login attempts)
    maybe_sweep_old_lockouts()

    case check_lockout(lockout_key) do
      :locked ->
        conn
        |> put_resp_content_type("text/html")
        |> send_resp(
          429,
          login_html(
            "Too many failed attempts. Try again later.",
            Plug.CSRFProtection.get_csrf_token()
          )
        )

      :ok ->
        expected = admin_token()

        if expected && Plug.Crypto.secure_compare(token, expected) do
          # Reset failure counter on success
          reset_lockout(lockout_key)

          conn
          |> fetch_session()
          |> configure_session(renew: true)
          |> put_session(:krait_admin_token, sign_session_token(token))
          |> redirect(to: "/evolution")
        else
          # v21 H-5: Log failed login attempt with client IP
          Logger.warning("Failed admin login attempt", ip: ip)

          # v23 L-4: Increment failure counter
          increment_lockout(lockout_key)

          conn
          |> put_resp_content_type("text/html")
          |> send_resp(401, login_html("Invalid token", Plug.CSRFProtection.get_csrf_token()))
        end
    end
  end

  def create(conn, _params) do
    # v20 L-3: Return 401 on missing/empty token
    conn
    |> put_resp_content_type("text/html")
    |> send_resp(401, login_html("Token is required", Plug.CSRFProtection.get_csrf_token()))
  end

  def delete(conn, _params) do
    # v23 M-6: Broadcast session invalidation so LiveView sockets disconnect
    Phoenix.PubSub.broadcast(Krait.PubSub, "admin:session_invalidated", :session_invalidated)

    conn
    |> fetch_session()
    |> clear_session()
    |> redirect(to: "/")
  end

  @doc """
  Sign a SHA-256 hash of the token for session storage using Phoenix.Token.

  v23 H-2: Signs a hash of the token instead of the raw token, so even if
  secret_key_base leaks, the raw admin token is not recoverable from the session.
  Includes nonce + timestamp for replay attack prevention.
  """
  def sign_session_token(token) when is_binary(token) do
    salt = session_salt!()
    hash = :crypto.hash(:sha256, token) |> Base.encode64()
    Phoenix.Token.sign(KraitWeb.Endpoint, salt, hash)
  end

  @doc """
  Verify a signed session token. Returns `{:ok, token_hash}` or `{:error, reason}`.

  v23 H-6: Max age defaults to 3600 (1 hour) to align with cookie max_age in endpoint.ex.
  """
  def verify_session_token(signed) when is_binary(signed) do
    salt = session_salt!()
    max_age = Application.get_env(:krait, :admin_session_max_age, 3600)
    Phoenix.Token.verify(KraitWeb.Endpoint, salt, signed, max_age: max_age)
  end

  def verify_session_token(_), do: {:error, :invalid}

  @max_login_failures 10
  @lockout_window_seconds 900

  # v24 F-02: Direct ETS lookup (bypasses EvolveCooldownServer.lookup/1's rescue)
  # so we can detect table absence and fail-closed.
  defp check_lockout(lockout_key) do
    case :ets.lookup(:krait_evolve_cooldown, lockout_key) do
      [{_, count}] when count >= @max_login_failures -> :locked
      _ -> :ok
    end
  rescue
    error ->
      Logger.critical("[SECURITY] Lockout check failed — failing closed",
        error: Exception.format(:error, error)
      )

      :locked
  end

  defp increment_lockout(lockout_key) do
    Krait.EvolveCooldownServer.update_counter(
      lockout_key,
      {2, 1},
      {lockout_key, 0}
    )
  rescue
    _ -> :ok
  end

  defp reset_lockout(lockout_key) do
    Krait.EvolveCooldownServer.insert({lockout_key, 0})
  rescue
    _ -> :ok
  end

  defp session_salt! do
    Application.get_env(:krait, :admin_session_salt) ||
      raise "Missing :admin_session_salt config — set ADMIN_SESSION_SALT env var in prod"
  end

  defp admin_token, do: KraitWeb.Auth.admin_token()

  # v24 F-03: Time-bucketed lockout key — old buckets are naturally stale
  defp lockout_key(ip) do
    bucket = div(System.system_time(:second), @lockout_window_seconds)
    {:admin_login_failures, ip, bucket}
  end

  # v24 F-03: Probabilistic sweep of old lockout entries (~1% of login attempts)
  defp maybe_sweep_old_lockouts do
    if :rand.uniform(100) == 1 do
      Krait.EvolveCooldownServer.sweep_old_lockouts(@lockout_window_seconds)
    end
  rescue
    _ -> :ok
  end

  defp login_html(error, csrf_token) do
    error_html =
      if error do
        escaped = error |> Plug.HTML.html_escape() |> IO.iodata_to_binary()
        ~s(<p style="color:red;margin-bottom:1rem">#{escaped}</p>)
      else
        ""
      end

    # v23 M-10: Escape CSRF token for defense-in-depth
    escaped_csrf = csrf_token |> Plug.HTML.html_escape() |> IO.iodata_to_binary()

    """
    <!DOCTYPE html>
    <html><head><title>Admin Login</title></head>
    <body style="display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif">
    <div style="max-width:400px;width:100%">
    <h1>Admin Login</h1>
    #{error_html}
    <form method="post" action="/admin/login">
    <input type="hidden" name="_csrf_token" value="#{escaped_csrf}">
    <label for="token">Admin Token</label><br>
    <input type="password" name="token" id="token" style="width:100%;padding:0.5rem;margin:0.5rem 0"><br>
    <button type="submit" style="padding:0.5rem 1rem">Login</button>
    </form>
    </div>
    </body></html>
    """
  end
end
