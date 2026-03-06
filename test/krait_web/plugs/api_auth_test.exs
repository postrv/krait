defmodule KraitWeb.Plugs.ApiAuthTest do
  use KraitWeb.ConnCase, async: false

  setup do
    # v21 H-3: Ensure RateLimitCounter GenServer is running and clean
    ensure_rate_limit_counter!()
    GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

    # v22 SEC-08: Clear evolution cooldown via GenServer API (table is :protected)
    ensure_evolve_cooldown_server!()
    Krait.EvolveCooldownServer.delete_all()

    # Reset kill switch to ensure evolution endpoint returns 200 not 503
    if GenServer.whereis(Krait.KillSwitch) do
      GenServer.call(Krait.KillSwitch, :reset_for_test)
    end

    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Krait.Repo, shared: true)
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end

  describe "when token is configured" do
    setup do
      prev = Application.get_env(:krait, :api_auth_token)
      Application.put_env(:krait, :api_auth_token, "test-secret-token")

      on_exit(fn ->
        if prev,
          do: Application.put_env(:krait, :api_auth_token, prev),
          else: Application.delete_env(:krait, :api_auth_token)
      end)
    end

    test "rejects requests without Authorization header", %{conn: conn} do
      conn = get(conn, "/api/feed")
      assert json_response(conn, 401)["error"] == "unauthorized"
    end

    test "rejects requests with wrong token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer wrong-token")
        |> get("/api/feed")

      assert json_response(conn, 401)["error"] == "unauthorized"
    end

    test "rejects near-miss token (timing-safe)", %{conn: conn} do
      # Differs by only last character — must still reject
      conn =
        conn
        |> put_req_header("authorization", "Bearer test-secret-tokeN")
        |> get("/api/feed")

      assert json_response(conn, 401)["error"] == "unauthorized"
    end

    test "rejects requests with malformed auth header", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Basic dXNlcjpwYXNz")
        |> get("/api/feed")

      assert json_response(conn, 401)["error"] == "unauthorized"
    end

    test "allows requests with correct token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer test-secret-token")
        |> get("/api/feed")

      assert json_response(conn, 200)
    end

    test "allows POST with correct token", %{conn: conn} do
      conn =
        conn
        |> put_req_header("authorization", "Bearer test-secret-token")
        |> post("/api/evolve", %{
          "skill_name" => "test_skill",
          "description" => "A test skill"
        })

      assert json_response(conn, 200)["status"] == "evolution_started"
    end
  end

  describe "when no token is configured" do
    setup do
      prev_token = Application.get_env(:krait, :api_auth_token)
      prev_env = Application.get_env(:krait, :env)
      prev_disable = Application.get_env(:krait, :disable_auth)
      Application.delete_env(:krait, :api_auth_token)

      on_exit(fn ->
        if prev_token,
          do: Application.put_env(:krait, :api_auth_token, prev_token),
          else: Application.delete_env(:krait, :api_auth_token)

        if prev_env,
          do: Application.put_env(:krait, :env, prev_env),
          else: Application.delete_env(:krait, :env)

        if prev_disable,
          do: Application.put_env(:krait, :disable_auth, prev_disable),
          else: Application.delete_env(:krait, :disable_auth)
      end)
    end

    test "allows bypass when env is :test and disable_auth is true", %{conn: conn} do
      Application.put_env(:krait, :env, :test)
      Application.put_env(:krait, :disable_auth, true)

      conn = get(conn, "/api/feed")
      assert json_response(conn, 200)
    end

    test "rejects when env is :dev even if disable_auth is true", %{conn: conn} do
      Application.put_env(:krait, :env, :dev)
      Application.put_env(:krait, :disable_auth, true)

      conn = get(conn, "/api/feed")
      assert json_response(conn, 503)["error"] == "Service unavailable"
    end

    test "rejects when env is :prod even if disable_auth is true", %{conn: conn} do
      Application.put_env(:krait, :env, :prod)
      Application.put_env(:krait, :disable_auth, true)

      conn = get(conn, "/api/feed")
      assert json_response(conn, 503)["error"] == "Service unavailable"
    end

    test "rejects when env is :test but disable_auth is false", %{conn: conn} do
      Application.put_env(:krait, :env, :test)
      Application.put_env(:krait, :disable_auth, false)

      conn = get(conn, "/api/feed")
      assert json_response(conn, 503)["error"] == "Service unavailable"
    end

    test "error response does not leak config details", %{conn: conn} do
      Application.put_env(:krait, :env, :dev)

      conn = get(conn, "/api/feed")
      body = json_response(conn, 503)
      refute body["error"] =~ "KRAIT_API_TOKEN"
      refute body["error"] =~ "disable_auth"
    end
  end

  defp ensure_rate_limit_counter! do
    case GenServer.whereis(KraitWeb.RateLimitCounter) do
      nil -> KraitWeb.RateLimitCounter.start_link([])
      pid -> if Process.alive?(pid), do: :ok, else: KraitWeb.RateLimitCounter.start_link([])
    end
  end

  defp ensure_evolve_cooldown_server! do
    case GenServer.whereis(Krait.EvolveCooldownServer) do
      nil -> Krait.EvolveCooldownServer.start_link([])
      pid -> if Process.alive?(pid), do: :ok, else: Krait.EvolveCooldownServer.start_link([])
    end
  end
end
