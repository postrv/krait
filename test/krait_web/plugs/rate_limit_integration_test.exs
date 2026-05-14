defmodule KraitWeb.Plugs.RateLimitIntegrationTest do
  @moduledoc "Integration test: rate limiter through the full Phoenix router"
  use KraitWeb.ConnCase, async: false

  setup do
    # v21 H-3: Ensure RateLimitCounter GenServer is running and clean
    ensure_rate_limit_counter!()
    GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

    # v22 SEC-08: Clear evolution cooldown via GenServer API (table is :protected)
    ensure_evolve_cooldown_server!()
    Krait.EvolveCooldownServer.delete_all()

    # Keep this test scoped to rate limiting, not kill-switch state leaked by
    # earlier evolution tests.
    GenServer.call(Krait.KillSwitch, :reset_for_test)

    # Set high concurrency limit to avoid evolution throttling during rate limit test
    prev_max = Application.get_env(:krait, :max_concurrent_evolutions)
    Application.put_env(:krait, :max_concurrent_evolutions, 100)

    on_exit(fn ->
      if prev_max,
        do: Application.put_env(:krait, :max_concurrent_evolutions, prev_max),
        else: Application.delete_env(:krait, :max_concurrent_evolutions)
    end)

    # Configure auth token for API access
    prev_token = Application.get_env(:krait, :api_auth_token)
    Application.put_env(:krait, :api_auth_token, "integration-test-token")

    on_exit(fn ->
      GenServer.call(Krait.KillSwitch, :reset_for_test)

      if prev_token,
        do: Application.put_env(:krait, :api_auth_token, prev_token),
        else: Application.delete_env(:krait, :api_auth_token)
    end)
  end

  test "rate limits POST /api/evolve after 10 requests" do
    results =
      for _ <- 1..11 do
        conn =
          build_conn()
          |> put_req_header("authorization", "Bearer integration-test-token")
          |> put_req_header("content-type", "application/json")
          |> post("/api/evolve", %{
            "skill_name" => "test_skill",
            "description" => "A test skill"
          })

        conn.status
      end

    # First 10 should succeed (200 or 422 — not rate limited)
    first_10 = Enum.take(results, 10)
    assert Enum.all?(first_10, &(&1 in [200, 422]))

    # 11th should be rate limited
    assert List.last(results) == 429
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
