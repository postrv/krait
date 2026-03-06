defmodule KraitWeb.RateLimitCounterTest do
  use ExUnit.Case, async: false

  alias KraitWeb.RateLimitCounter

  setup do
    # Ensure counter is running; clear between tests
    case GenServer.whereis(RateLimitCounter) do
      nil ->
        {:ok, pid} = RateLimitCounter.start_link([])
        {:ok, pid: pid}

      pid ->
        if Process.alive?(pid) do
          GenServer.call(pid, {:sweep_all})
          {:ok, pid: pid}
        else
          {:ok, pid} = RateLimitCounter.start_link([])
          {:ok, pid: pid}
        end
    end
  end

  test "table is :protected" do
    assert :ets.info(:krait_rate_limit, :protection) == :protected
  end

  test "increment/1 atomically increments counter" do
    key = {"test_ip", 12_345}
    assert RateLimitCounter.increment(key) == 1
    assert RateLimitCounter.increment(key) == 2
    assert RateLimitCounter.increment(key) == 3
  end

  test "get_count/1 returns 0 for unknown key" do
    assert RateLimitCounter.get_count({"unknown", 0}) == 0
  end

  test "get_count/1 reads from non-owner process (protected allows reads)" do
    key = {"read_test", 99}
    RateLimitCounter.increment(key)

    # Read from a different process
    count =
      Task.async(fn -> RateLimitCounter.get_count(key) end)
      |> Task.await()

    assert count == 1
  end

  test "direct ETS write fails from non-owner process (protected enforces)" do
    result =
      Task.async(fn ->
        try do
          :ets.update_counter(:krait_rate_limit, {"hack", 1}, {2, 1}, {{"hack", 1}, 0})
          :unexpected_success
        rescue
          ArgumentError -> :write_rejected
        end
      end)
      |> Task.await()

    assert result == :write_rejected
  end

  test "concurrent increments are correct" do
    key = {"concurrent", 42}

    tasks =
      for _ <- 1..10 do
        Task.async(fn -> RateLimitCounter.increment(key) end)
      end

    Task.await_many(tasks)
    assert RateLimitCounter.get_count(key) == 10
  end

  test "sweep_stale/1 removes old entries" do
    now = System.monotonic_time(:millisecond)
    window = 60_000
    stale_epoch = div(now, window) - 2

    # Insert via increment
    RateLimitCounter.increment({"fresh", div(now, window)})

    # Insert stale entry directly through GenServer
    GenServer.call(RateLimitCounter, {:insert_raw, {{"stale", stale_epoch}, 5}})

    assert RateLimitCounter.get_count({"stale", stale_epoch}) == 5

    RateLimitCounter.sweep_stale(window)

    assert RateLimitCounter.get_count({"stale", stale_epoch}) == 0
    assert RateLimitCounter.get_count({"fresh", div(now, window)}) > 0
  end
end
