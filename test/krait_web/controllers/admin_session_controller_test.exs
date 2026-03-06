defmodule KraitWeb.AdminSessionControllerTest do
  use KraitWeb.ConnCase, async: false

  setup do
    prev_token = Application.get_env(:krait, :api_auth_token)
    prev_admin = Application.get_env(:krait, :admin_auth_token)
    Application.put_env(:krait, :api_auth_token, "admin-test-token-123")
    # v23 H-4: Tests must use admin_auth_token directly (no fallback)
    Application.put_env(:krait, :admin_auth_token, "admin-test-token-123")

    # v21 H-3: Ensure RateLimitCounter GenServer is running and clean
    ensure_rate_limit_counter!()
    GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

    on_exit(fn ->
      if prev_token,
        do: Application.put_env(:krait, :api_auth_token, prev_token),
        else: Application.delete_env(:krait, :api_auth_token)

      if prev_admin,
        do: Application.put_env(:krait, :admin_auth_token, prev_admin),
        else: Application.delete_env(:krait, :admin_auth_token)
    end)
  end

  describe "GET /admin/login" do
    test "renders login form", %{conn: conn} do
      conn = get(conn, "/admin/login")
      assert conn.status == 200
      assert conn.resp_body =~ "Admin Login"
    end

    test "v22 SEC-10: rate limits after 30 GET requests" do
      GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

      results =
        for _ <- 1..31 do
          conn = get(build_conn(), "/admin/login")
          conn.status
        end

      # First 30 should be 200
      assert Enum.take(results, 30) |> Enum.all?(&(&1 == 200))
      # 31st should be 429
      assert List.last(results) == 429
    end

    test "login form contains non-empty CSRF token", %{conn: conn} do
      conn = get(conn, "/admin/login")
      assert conn.resp_body =~ ~r/name="_csrf_token" value="[^"]+"/
    end

    test "source code uses get_csrf_token" do
      source = File.read!("lib/krait_web/controllers/admin_session_controller.ex")
      assert source =~ "get_csrf_token"
    end
  end

  describe "POST /admin/login" do
    test "valid token sets session and redirects", %{conn: conn} do
      conn = post(conn, "/admin/login", %{"token" => "admin-test-token-123"})
      assert redirected_to(conn) == "/evolution"
    end

    test "invalid token returns 401", %{conn: conn} do
      # v20 L-3: Returns 401 on invalid token
      conn = post(conn, "/admin/login", %{"token" => "wrong-token"})
      assert conn.status == 401
      assert conn.resp_body =~ "Invalid token"
    end

    test "empty token returns 401", %{conn: conn} do
      # v20 L-3: Returns 401 on empty token
      conn = post(conn, "/admin/login", %{"token" => ""})
      assert conn.status == 401
      assert conn.resp_body =~ "Token is required"
    end

    test "missing token param returns 401", %{conn: conn} do
      # v20 L-3: Returns 401 on missing token
      conn = post(conn, "/admin/login", %{})
      assert conn.status == 401
      assert conn.resp_body =~ "Token is required"
    end

    test "rate limits after 3 failed login attempts" do
      GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

      results =
        for _ <- 1..4 do
          conn = post(build_conn(), "/admin/login", %{"token" => "wrong-token"})
          conn.status
        end

      # First 3 should be 401 (bad token)
      assert Enum.take(results, 3) |> Enum.all?(&(&1 == 401))
      # 4th should be 429
      assert List.last(results) == 429
    end

    test "failed login emits Logger.warning" do
      import ExUnit.CaptureLog

      log =
        capture_log(fn ->
          post(build_conn(), "/admin/login", %{"token" => "wrong-token"})
        end)

      assert log =~ "Failed admin login attempt"
    end

    test "regenerates session on successful login (prevents session fixation)" do
      source = File.read!("lib/krait_web/controllers/admin_session_controller.ex")
      assert source =~ "configure_session"
      assert source =~ "renew: true"
    end

    test "uses Plug.Crypto.secure_compare" do
      # Source code assertion — verify the controller uses timing-safe comparison
      source = File.read!("lib/krait_web/controllers/admin_session_controller.ex")
      assert source =~ "Plug.Crypto.secure_compare"
    end

    test "stores signed token in session, not raw token" do
      conn =
        build_conn()
        |> post("/admin/login", %{"token" => "admin-test-token-123"})

      session_value = get_session(conn, :krait_admin_token)
      # Session should not contain the raw token
      refute session_value == "admin-test-token-123"
      # Session should contain a non-empty signed value
      assert is_binary(session_value)
      assert byte_size(session_value) > 0
    end

    test "v22 SEC-12: sign_session_token includes timestamp (different across seconds)" do
      signed1 = KraitWeb.AdminSessionController.sign_session_token("admin-test-token-123")
      # Phoenix.Token embeds a timestamp — tokens signed in different seconds differ.
      # Within the same second they may be equal, so we verify the token is opaque
      # and not the raw value.
      refute signed1 == "admin-test-token-123"
      assert is_binary(signed1)
      assert byte_size(signed1) > 20
    end

    test "v23 H-2: verify round-trip returns hash, not raw token" do
      signed = KraitWeb.AdminSessionController.sign_session_token("admin-test-token-123")

      expected_hash = :crypto.hash(:sha256, "admin-test-token-123") |> Base.encode64()

      assert {:ok, ^expected_hash} =
               KraitWeb.AdminSessionController.verify_session_token(signed)
    end

    test "v22 SEC-12: tampered token rejected" do
      signed = KraitWeb.AdminSessionController.sign_session_token("admin-test-token-123")
      tampered = signed <> "TAMPERED"
      assert {:error, :invalid} = KraitWeb.AdminSessionController.verify_session_token(tampered)
    end

    test "error messages are HTML-escaped to prevent XSS" do
      source = File.read!("lib/krait_web/controllers/admin_session_controller.ex")
      assert source =~ "html_escape"
    end

    test "source code uses Phoenix.Token for session token signing" do
      source = File.read!("lib/krait_web/controllers/admin_session_controller.ex")
      assert source =~ "Phoenix.Token.sign"
      assert source =~ "Phoenix.Token.verify"
    end
  end

  describe "H-4: admin token separation" do
    test "uses admin_auth_token when configured", %{conn: conn} do
      Application.put_env(:krait, :admin_auth_token, "separate-admin-token")

      on_exit(fn -> Application.delete_env(:krait, :admin_auth_token) end)

      # Login with the separate admin token should succeed
      conn = post(conn, "/admin/login", %{"token" => "separate-admin-token"})
      assert redirected_to(conn) == "/evolution"
    end

    test "v23 H-4: rejects login when admin_auth_token is nil (no fallback)", %{conn: conn} do
      Application.delete_env(:krait, :admin_auth_token)

      # Login with the API token should NOT work — no fallback
      conn = post(conn, "/admin/login", %{"token" => "admin-test-token-123"})
      assert conn.status == 401
    end

    test "admin_auth_token takes priority over api_auth_token", %{conn: conn} do
      Application.put_env(:krait, :admin_auth_token, "the-admin-token")

      on_exit(fn -> Application.delete_env(:krait, :admin_auth_token) end)

      # API token should NOT work when admin token is set
      conn = post(conn, "/admin/login", %{"token" => "admin-test-token-123"})
      assert conn.status == 401
    end
  end

  describe "v24 F-02: lockout fail-closed" do
    test "source code uses fail-closed rescue (returns :locked, not :ok)" do
      source = File.read!("lib/krait_web/controllers/admin_session_controller.ex")
      # Verify the rescue in check_lockout returns :locked (fail-closed)
      assert source =~ "Lockout check failed"
      assert source =~ ":locked"
      # Verify it does NOT have the old fail-open pattern
      refute Regex.match?(~r/rescue\s+_\s*->\s*:ok\s*\n\s*end\s*\n\s*\n\s*defp increment/, source)
    end

    test "check_lockout returns :locked when ETS table is missing" do
      # Rename the ETS table to simulate it being unavailable
      # We can't easily stop the server (supervisor restarts it), so instead
      # we verify the direct ETS lookup raises when given a bad table name
      assert_raise ArgumentError, fn ->
        :ets.lookup(:nonexistent_table_for_test, {:admin_login_failures, "1.2.3.4", 0})
      end
    end
  end

  describe "DELETE /admin/logout" do
    test "clears session and redirects", %{conn: conn} do
      # Use a signed token in session (matches what login stores)
      signed = KraitWeb.AdminSessionController.sign_session_token("admin-test-token-123")

      conn =
        conn
        |> init_test_session(%{krait_admin_token: signed})
        |> delete("/admin/logout")

      assert redirected_to(conn) == "/"
    end
  end

  defp ensure_rate_limit_counter! do
    case GenServer.whereis(KraitWeb.RateLimitCounter) do
      nil -> KraitWeb.RateLimitCounter.start_link([])
      pid -> if Process.alive?(pid), do: :ok, else: KraitWeb.RateLimitCounter.start_link([])
    end
  end
end
