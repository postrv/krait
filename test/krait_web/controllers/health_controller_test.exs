defmodule KraitWeb.HealthControllerTest do
  use KraitWeb.ConnCase, async: false

  setup do
    # Reset kill switch state before each test
    GenServer.call(Krait.KillSwitch, :reset_for_test)

    # Ensure EvolveCooldownServer is running
    case GenServer.whereis(Krait.EvolveCooldownServer) do
      nil -> Krait.EvolveCooldownServer.start_link([])
      pid -> if Process.alive?(pid), do: :ok, else: Krait.EvolveCooldownServer.start_link([])
    end

    on_exit(fn ->
      GenServer.call(Krait.KillSwitch, :reset_for_test)
    end)

    :ok
  end

  describe "GET /health" do
    test "returns 200 with alive status", %{conn: conn} do
      conn = get(conn, "/health")
      assert json_response(conn, 200)["status"] == "alive"
    end
  end

  describe "GET /health/ready" do
    test "returns 200 when all services up", %{conn: conn} do
      conn = get(conn, "/health/ready")
      body = json_response(conn, 200)
      assert body["status"] == "ready"
      assert is_map(body["checks"])
    end

    test "returns 200 even when kill switch engaged", %{conn: conn} do
      Krait.KillSwitch.halt!("health test")
      conn = get(conn, "/health/ready")
      # Must still return 200 -- kill switch MUST NOT affect readiness
      assert json_response(conn, 200)["status"] == "ready"
    end

    test "includes database check in response", %{conn: conn} do
      conn = get(conn, "/health/ready")
      body = json_response(conn, 200)
      assert body["checks"]["database"] == "ok"
    end

    test "includes cooldown_server check in response", %{conn: conn} do
      conn = get(conn, "/health/ready")
      body = json_response(conn, 200)
      assert body["checks"]["cooldown_server"] == "ok"
    end

    test "includes nif check in response", %{conn: conn} do
      conn = get(conn, "/health/ready")
      body = json_response(conn, 200)
      # NIF may or may not be loaded in test, but key must exist
      assert body["checks"]["nif"] in ["ok", "unavailable"]
    end
  end

  describe "GET /health/evolution" do
    test "reflects kill switch state when not halted", %{conn: conn} do
      conn = get(conn, "/health/evolution")
      body = json_response(conn, 200)
      assert body["evolution_enabled"] == true
      assert is_map(body["kill_switch"])
      assert body["kill_switch"]["halted"] == false
    end

    test "reflects halted kill switch", %{conn: conn} do
      Krait.KillSwitch.halt!("evolution health test")
      conn = get(conn, "/health/evolution")
      body = json_response(conn, 200)
      assert body["evolution_enabled"] == false
      assert body["kill_switch"]["halted"] == true
      # v25 L-1: halted_by no longer exposed on unauthenticated endpoint
      refute Map.has_key?(body["kill_switch"], "halted_by")
    end
  end

  describe "health endpoints security" do
    test "liveness and readiness do not require authentication", %{conn: conn} do
      # Set auth token to ensure auth is enforced on protected endpoints
      Application.put_env(:krait, :api_auth_token, "real-secret")

      # Liveness and readiness endpoints should still work without auth
      conn1 = get(conn, "/health")
      assert json_response(conn1, 200)

      conn2 = build_conn() |> get("/health/ready")
      assert json_response(conn2, 200)

      Application.delete_env(:krait, :api_auth_token)
    end

    # v27 L-6: Evolution health now requires API token auth
    test "evolution endpoint requires authentication" do
      Application.put_env(:krait, :api_auth_token, "real-secret")

      # Without auth — should get 401
      conn1 = build_conn() |> get("/health/evolution")
      assert json_response(conn1, 401)

      # With auth — should get 200
      conn2 =
        build_conn()
        |> put_req_header("authorization", "Bearer real-secret")
        |> get("/health/evolution")

      assert json_response(conn2, 200)

      Application.delete_env(:krait, :api_auth_token)
    end
  end
end
