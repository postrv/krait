defmodule KraitWeb.V27HealthControllerTest do
  @moduledoc "v27 L-6: Health endpoint authentication tests"
  use KraitWeb.ConnCase, async: false

  setup do
    prev_token = Application.get_env(:krait, :api_auth_token)
    Application.put_env(:krait, :api_auth_token, "test-api-token-for-health-check!")

    on_exit(fn ->
      if prev_token do
        Application.put_env(:krait, :api_auth_token, prev_token)
      else
        Application.delete_env(:krait, :api_auth_token)
      end
    end)

    :ok
  end

  describe "GET /health" do
    test "liveness probe is unauthenticated", %{conn: conn} do
      conn = get(conn, "/health")
      assert json_response(conn, 200)["status"] == "alive"
    end
  end

  describe "GET /health/ready" do
    test "readiness probe is unauthenticated", %{conn: conn} do
      conn = get(conn, "/health/ready")
      # May be 200 or 503 depending on DB state, but should not be 401
      assert conn.status in [200, 503]
    end
  end

  describe "GET /health/evolution" do
    test "requires authentication", %{conn: conn} do
      conn = get(conn, "/health/evolution")
      assert json_response(conn, 401)["error"] == "unauthorized"
    end

    test "returns evolution status with valid API token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer test-api-token-for-health-check!")
        |> get("/health/evolution")

      assert json_response(conn, 200)["evolution_enabled"] != nil
    end

    test "rejects invalid token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer wrong-token")
        |> get("/health/evolution")

      assert json_response(conn, 401)
    end
  end
end
