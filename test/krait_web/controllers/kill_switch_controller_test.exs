defmodule KraitWeb.KillSwitchControllerTest do
  use KraitWeb.ConnCase, async: false

  setup do
    # Reset kill switch state (uses supervisor-started instance, skip_db: true)
    GenServer.call(Krait.KillSwitch, :reset_for_test)

    # v25 H-1: Admin routes require admin_auth_token (not api_auth_token)
    Application.delete_env(:krait, :api_auth_token)
    Application.delete_env(:krait, :admin_auth_token)

    # Clear rate limit state
    GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

    :ok
  end

  describe "POST /api/admin/kill-switch/halt" do
    test "engages kill switch with 200", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer test-token-for-api")
        |> post("/api/admin/kill-switch/halt", %{"reason" => "test halt"})

      assert json_response(conn, 200)["status"] == "halted"
      assert json_response(conn, 200)["reason"] == "test halt"
      assert Krait.KillSwitch.halted?()
    end

    test "requires admin authentication", %{conn: conn} do
      # v25 H-1: Re-enable admin auth for this test
      Application.put_env(:krait, :admin_auth_token, "admin-secret")

      conn = post(conn, "/api/admin/kill-switch/halt", %{"reason" => "no auth"})
      assert json_response(conn, 401)

      Application.delete_env(:krait, :admin_auth_token)
    end

    test "rejects regular API token on admin routes", %{conn: conn} do
      # v25 H-1: Regular API token must NOT work on admin routes
      Application.put_env(:krait, :admin_auth_token, "admin-secret")
      Application.put_env(:krait, :api_auth_token, "api-secret")

      conn =
        conn
        |> put_req_header("authorization", "Bearer api-secret")
        |> post("/api/admin/kill-switch/halt", %{"reason" => "wrong token"})

      assert json_response(conn, 401)

      Application.delete_env(:krait, :admin_auth_token)
      Application.delete_env(:krait, :api_auth_token)
    end
  end

  describe "POST /api/admin/kill-switch/resume" do
    test "disengages kill switch with 200", %{conn: conn} do
      Krait.KillSwitch.halt!("to resume")

      conn =
        conn
        |> put_req_header("authorization", "Bearer test-token-for-api")
        |> post("/api/admin/kill-switch/resume")

      assert json_response(conn, 200)["status"] == "resumed"
      refute Krait.KillSwitch.halted?()
    end

    test "returns 429 if called within cooldown period", %{conn: conn} do
      Application.put_env(:krait, :kill_switch_resume_cooldown, 30)
      Krait.KillSwitch.halt!("cooldown test")

      # First resume succeeds
      conn1 =
        build_conn()
        |> put_req_header("authorization", "Bearer test-token-for-api")
        |> post("/api/admin/kill-switch/resume")

      assert json_response(conn1, 200)["status"] == "resumed"

      # Second resume within cooldown should return 429
      conn2 =
        conn
        |> put_req_header("authorization", "Bearer test-token-for-api")
        |> post("/api/admin/kill-switch/resume")

      assert json_response(conn2, 429)["error"] == "resume_cooldown"
    end
  end

  describe "GET /api/admin/kill-switch/status" do
    test "returns current kill switch state", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer test-token-for-api")
        |> get("/api/admin/kill-switch/status")

      body = json_response(conn, 200)
      assert body["halted"] == false
      assert body["consecutive_failures"] == 0
    end

    test "reflects halted state", %{conn: conn} do
      Krait.KillSwitch.halt!("status check")

      conn =
        conn
        |> put_req_header("authorization", "Bearer test-token-for-api")
        |> get("/api/admin/kill-switch/status")

      body = json_response(conn, 200)
      assert body["halted"] == true
      assert body["halted_by"] == "status check"
    end

    test "requires admin authentication", %{conn: conn} do
      # v25 H-1: Admin routes require admin_auth_token
      Application.put_env(:krait, :admin_auth_token, "admin-secret")

      conn = get(conn, "/api/admin/kill-switch/status")
      assert json_response(conn, 401)

      Application.delete_env(:krait, :admin_auth_token)
    end
  end
end
