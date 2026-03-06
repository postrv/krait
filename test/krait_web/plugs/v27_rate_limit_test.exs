defmodule KraitWeb.Plugs.V27RateLimitTest do
  @moduledoc "v27 M-4: Rate limit circuit breaker admin bypass tests"
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias KraitWeb.Plugs.RateLimit

  @table :krait_rate_limit

  setup do
    # Ensure rate limit table exists
    case :ets.whereis(@table) do
      :undefined ->
        case KraitWeb.RateLimitCounter.start_link([]) do
          {:ok, _} -> :ok
          {:error, {:already_started, _}} -> :ok
        end

      _ ->
        :ok
    end

    # Clear table
    GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

    prev_admin = Application.get_env(:krait, :admin_auth_token)
    Application.put_env(:krait, :admin_auth_token, "test-admin-token-32chars-minimum!!")

    on_exit(fn ->
      GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})

      if prev_admin do
        Application.put_env(:krait, :admin_auth_token, prev_admin)
      else
        Application.delete_env(:krait, :admin_auth_token)
      end
    end)

    :ok
  end

  describe "circuit breaker admin bypass" do
    test "normal requests get 503 when circuit breaker trips" do
      opts = RateLimit.init(max_requests: 10, window_ms: 60_000)

      # Fill ETS above threshold
      fill_ets_above_threshold()

      conn =
        :get
        |> conn("/api/test")
        |> put_req_header("content-type", "application/json")
        |> RateLimit.call(opts)

      assert conn.status == 503
    end

    test "admin token bypasses circuit breaker" do
      opts = RateLimit.init(max_requests: 1000, window_ms: 60_000)

      # Fill ETS above threshold
      fill_ets_above_threshold()

      conn =
        :get
        |> conn("/api/test")
        |> put_req_header("content-type", "application/json")
        |> put_req_header("authorization", "Bearer test-admin-token-32chars-minimum!!")
        |> RateLimit.call(opts)

      # Admin should NOT get 503 — they bypass the circuit breaker
      # They may still be rate-limited normally (429) but not circuit-broken (503)
      assert conn.status != 503
    end

    test "wrong admin token does not bypass circuit breaker" do
      opts = RateLimit.init(max_requests: 10, window_ms: 60_000)

      fill_ets_above_threshold()

      conn =
        :get
        |> conn("/api/test")
        |> put_req_header("content-type", "application/json")
        |> put_req_header("authorization", "Bearer wrong-token")
        |> RateLimit.call(opts)

      assert conn.status == 503
    end
  end

  # Helper to fill ETS above the 100K threshold
  defp fill_ets_above_threshold do
    # Insert enough entries to exceed threshold via GenServer handle_call
    for i <- 1..100_001 do
      GenServer.call(KraitWeb.RateLimitCounter, {:insert_raw, {{:flood, i, 999_999}, 1}})
    end
  end
end
