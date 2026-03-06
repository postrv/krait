defmodule KraitWeb.Plugs.RateLimitTest do
  use ExUnit.Case, async: false
  import Plug.Test
  import Plug.Conn

  alias KraitWeb.Plugs.RateLimit

  setup do
    # v21 H-3: Ensure RateLimitCounter GenServer is running (owns :protected table)
    ensure_counter!()
    GenServer.call(KraitWeb.RateLimitCounter, {:sweep_all})
    :ok
  end

  defp ensure_counter! do
    case GenServer.whereis(KraitWeb.RateLimitCounter) do
      nil ->
        {:ok, _} = KraitWeb.RateLimitCounter.start_link([])

      pid ->
        if Process.alive?(pid), do: :ok, else: KraitWeb.RateLimitCounter.start_link([])
    end
  end

  test "allows requests under the limit" do
    opts = RateLimit.init(max_requests: 3, window_ms: 60_000)

    for _ <- 1..3 do
      conn =
        conn(:post, "/api/evolve", %{})
        |> RateLimit.call(opts)

      refute conn.halted
    end
  end

  test "blocks requests over the limit" do
    opts = RateLimit.init(max_requests: 2, window_ms: 60_000)

    # First 2 allowed
    for _ <- 1..2 do
      conn =
        conn(:post, "/api/evolve", %{})
        |> RateLimit.call(opts)

      refute conn.halted
    end

    # 3rd blocked
    conn =
      conn(:post, "/api/evolve", %{})
      |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
      |> Plug.Conn.put_private(:phoenix_format, "json")
      |> RateLimit.call(opts)

    assert conn.halted
    assert conn.status == 429
  end

  test "resets after window expires" do
    opts = RateLimit.init(max_requests: 1, window_ms: 1)

    conn =
      conn(:post, "/api/evolve", %{})
      |> RateLimit.call(opts)

    refute conn.halted

    # Wait for window to expire
    Process.sleep(5)

    conn =
      conn(:post, "/api/evolve", %{})
      |> RateLimit.call(opts)

    refute conn.halted
  end

  test "sets retry-after header on 429" do
    opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

    conn(:post, "/api/evolve", %{})
    |> RateLimit.call(opts)

    conn =
      conn(:post, "/api/evolve", %{})
      |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
      |> Plug.Conn.put_private(:phoenix_format, "json")
      |> RateLimit.call(opts)

    assert conn.halted
    assert get_resp_header(conn, "retry-after") == ["60"]
  end

  describe "X-Forwarded-For extraction" do
    setup do
      original = Application.get_env(:krait, :trusted_proxies)

      on_exit(fn ->
        if original do
          Application.put_env(:krait, :trusted_proxies, original)
        else
          Application.delete_env(:krait, :trusted_proxies)
        end
      end)

      :ok
    end

    test "uses X-Forwarded-For when behind trusted proxy" do
      Application.put_env(:krait, :trusted_proxies, ["127.0.0.1"])

      opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

      # First request from 10.0.0.1 via trusted proxy — allowed
      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "10.0.0.1")
        |> RateLimit.call(opts)

      refute conn.halted

      # Second request from 10.0.0.1 — blocked (same forwarded IP)
      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "10.0.0.1")
        |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
        |> Plug.Conn.put_private(:phoenix_format, "json")
        |> RateLimit.call(opts)

      assert conn.halted

      # Third request from 10.0.0.2 — allowed (different forwarded IP)
      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "10.0.0.2")
        |> RateLimit.call(opts)

      refute conn.halted
    end
  end

  describe "atomic concurrency" do
    test "concurrent tasks count correctly" do
      opts = RateLimit.init(max_requests: 5, window_ms: 60_000)

      tasks =
        for _ <- 1..10 do
          Task.async(fn ->
            conn =
              conn(:post, "/api/evolve", %{})
              |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
              |> Plug.Conn.put_private(:phoenix_format, "json")
              |> RateLimit.call(opts)

            conn.halted
          end)
        end

      results = Task.await_many(tasks)
      allowed = Enum.count(results, &(!&1))
      blocked = Enum.count(results, & &1)

      # With atomic counter, exactly 5 should pass, 5 should be blocked
      assert allowed == 5
      assert blocked == 5
    end
  end

  describe "rightmost untrusted IP from XFF" do
    setup do
      original = Application.get_env(:krait, :trusted_proxies)
      Application.put_env(:krait, :trusted_proxies, ["10.0.0.100", "10.0.0.200"])

      on_exit(fn ->
        if original do
          Application.put_env(:krait, :trusted_proxies, original)
        else
          Application.delete_env(:krait, :trusted_proxies)
        end
      end)

      :ok
    end

    test "uses rightmost untrusted IP from XFF chain" do
      opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

      # XFF: "spoofed, real_client, trusted_proxy"
      # Should use real_client (192.168.1.1), not spoofed
      conn =
        conn(:post, "/api/evolve", %{})
        |> Map.put(:remote_ip, {10, 0, 0, 100})
        |> put_req_header("x-forwarded-for", "1.2.3.4, 192.168.1.1, 10.0.0.200")
        |> RateLimit.call(opts)

      refute conn.halted

      # Second request from same real_client via different spoofed IP — blocked
      conn =
        conn(:post, "/api/evolve", %{})
        |> Map.put(:remote_ip, {10, 0, 0, 100})
        |> put_req_header("x-forwarded-for", "5.6.7.8, 192.168.1.1, 10.0.0.200")
        |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
        |> Plug.Conn.put_private(:phoenix_format, "json")
        |> RateLimit.call(opts)

      assert conn.halted
    end

    test "falls back to remote_ip when all XFF IPs are trusted" do
      opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

      conn =
        conn(:post, "/api/evolve", %{})
        |> Map.put(:remote_ip, {10, 0, 0, 100})
        |> put_req_header("x-forwarded-for", "10.0.0.100, 10.0.0.200")
        |> RateLimit.call(opts)

      refute conn.halted

      # Second request with same remote_ip — blocked
      conn =
        conn(:post, "/api/evolve", %{})
        |> Map.put(:remote_ip, {10, 0, 0, 100})
        |> put_req_header("x-forwarded-for", "10.0.0.100, 10.0.0.200")
        |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
        |> Plug.Conn.put_private(:phoenix_format, "json")
        |> RateLimit.call(opts)

      assert conn.halted
    end

    test "ignores XFF when trusted_proxies not configured" do
      Application.delete_env(:krait, :trusted_proxies)
      opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

      # Even with XFF header, should use remote_ip since no trusted proxies configured
      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "1.2.3.4")
        |> RateLimit.call(opts)

      refute conn.halted

      # Second request — should be rate limited on remote_ip (127.0.0.1)
      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "5.6.7.8")
        |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
        |> Plug.Conn.put_private(:phoenix_format, "json")
        |> RateLimit.call(opts)

      assert conn.halted
    end
  end

  describe "XFF IP validation" do
    setup do
      original = Application.get_env(:krait, :trusted_proxies)
      Application.put_env(:krait, :trusted_proxies, ["127.0.0.1"])

      on_exit(fn ->
        if original do
          Application.put_env(:krait, :trusted_proxies, original)
        else
          Application.delete_env(:krait, :trusted_proxies)
        end
      end)

      :ok
    end

    test "garbage XFF falls back to remote_ip" do
      opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

      # First request with garbage XFF — should use remote_ip (127.0.0.1)
      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "not-an-ip-address!!!")
        |> RateLimit.call(opts)

      refute conn.halted

      # Second request with same garbage XFF — should be blocked (same remote_ip)
      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "different-garbage")
        |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
        |> Plug.Conn.put_private(:phoenix_format, "json")
        |> RateLimit.call(opts)

      assert conn.halted
    end

    test "valid IPv4 XFF used" do
      opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

      conn =
        conn(:post, "/api/evolve", %{})
        |> put_req_header("x-forwarded-for", "203.0.113.50")
        |> RateLimit.call(opts)

      refute conn.halted
    end
  end

  describe "HTML response format" do
    test "returns HTML 429 when response_format is :html" do
      opts = RateLimit.init(max_requests: 1, window_ms: 60_000, response_format: :html)

      conn(:post, "/admin/login", %{})
      |> RateLimit.call(opts)

      conn =
        conn(:post, "/admin/login", %{})
        |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
        |> Plug.Conn.put_private(:phoenix_format, "json")
        |> RateLimit.call(opts)

      assert conn.halted
      assert conn.status == 429
      assert get_resp_header(conn, "content-type") |> List.first() =~ "text/html"
      assert conn.resp_body =~ "Rate limit exceeded"
    end

    test "returns JSON 429 by default" do
      opts = RateLimit.init(max_requests: 1, window_ms: 60_000)

      conn(:post, "/api/evolve", %{})
      |> RateLimit.call(opts)

      conn =
        conn(:post, "/api/evolve", %{})
        |> put_private(:phoenix_endpoint, KraitWeb.Endpoint)
        |> Plug.Conn.put_private(:phoenix_format, "json")
        |> RateLimit.call(opts)

      assert conn.halted
      assert conn.status == 429
      # Default format is JSON
      refute conn.resp_body =~ "<html>"
    end
  end

  describe "stale entry cleanup" do
    test "sweeps stale bucket entries from ETS" do
      now = System.monotonic_time(:millisecond)
      window = 60_000
      # Insert a bucket from two epochs ago (stale) via GenServer
      stale_epoch = div(now, window) - 2

      GenServer.call(
        KraitWeb.RateLimitCounter,
        {:insert_raw, {{"stale_ip", stale_epoch}, 5}}
      )

      # Verify it exists (direct read allowed on :protected)
      assert [{_, _}] = :ets.lookup(:krait_rate_limit, {"stale_ip", stale_epoch})

      # Trigger sweep
      RateLimit.sweep_stale(window)

      # Verify it was removed
      assert [] = :ets.lookup(:krait_rate_limit, {"stale_ip", stale_epoch})
    end

    test "does not remove current bucket entries" do
      now = System.monotonic_time(:millisecond)
      window = 60_000
      current_epoch = div(now, window)

      GenServer.call(
        KraitWeb.RateLimitCounter,
        {:insert_raw, {{"fresh_ip", current_epoch}, 3}}
      )

      RateLimit.sweep_stale(window)

      assert [{_, _}] = :ets.lookup(:krait_rate_limit, {"fresh_ip", current_epoch})
    end
  end
end
