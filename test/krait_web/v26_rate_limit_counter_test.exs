defmodule KraitWeb.V26RateLimitCounterTest do
  # Must be async: false — shared ETS table via global GenServer name
  use ExUnit.Case, async: false

  alias KraitWeb.RateLimitCounter

  setup do
    # Start the counter if not already running
    case start_supervised(RateLimitCounter) do
      {:ok, _pid} -> :ok
      {:error, {:already_started, _}} -> :ok
    end

    # Clear all entries before each test
    GenServer.call(RateLimitCounter, {:sweep_all})
    :ok
  end

  # Helper: compute a definitely-stale epoch for the given window_ms
  defp stale_epoch(window_ms) do
    now = System.monotonic_time(:millisecond)
    div(now, window_ms) - 2
  end

  defp current_epoch(window_ms) do
    now = System.monotonic_time(:millisecond)
    div(now, window_ms)
  end

  describe "sweep_stale/1 token key support (L-5)" do
    @window_ms 60_000

    test "sweeps stale 2-tuple IP keys" do
      stale = stale_epoch(@window_ms)
      GenServer.call(RateLimitCounter, {:insert_raw, {{"127.0.0.1", stale}, 5}})
      assert RateLimitCounter.table_size() == 1

      RateLimitCounter.sweep_stale(@window_ms)

      assert RateLimitCounter.table_size() == 0
    end

    test "sweeps stale 3-tuple token keys" do
      stale = stale_epoch(@window_ms)
      GenServer.call(RateLimitCounter, {:insert_raw, {{:token, "abc123", stale}, 3}})
      assert RateLimitCounter.table_size() == 1

      RateLimitCounter.sweep_stale(@window_ms)

      assert RateLimitCounter.table_size() == 0
    end

    test "preserves current-epoch entries during sweep" do
      current = current_epoch(@window_ms)
      stale = stale_epoch(@window_ms)

      # Insert current IP key and current token key
      GenServer.call(RateLimitCounter, {:insert_raw, {{"10.0.0.1", current}, 2}})
      GenServer.call(RateLimitCounter, {:insert_raw, {{:token, "xyz", current}, 1}})
      # Insert a stale token key
      GenServer.call(RateLimitCounter, {:insert_raw, {{:token, "old", stale}, 5}})

      assert RateLimitCounter.table_size() == 3

      RateLimitCounter.sweep_stale(@window_ms)

      # Only the stale entry should be swept
      assert RateLimitCounter.table_size() == 2
    end

    test "sweeps mixed stale IP and token keys together" do
      stale = stale_epoch(@window_ms)

      GenServer.call(RateLimitCounter, {:insert_raw, {{"192.168.1.1", stale}, 10}})
      GenServer.call(RateLimitCounter, {:insert_raw, {{:token, "stale_tok", stale}, 7}})

      assert RateLimitCounter.table_size() == 2

      RateLimitCounter.sweep_stale(@window_ms)

      assert RateLimitCounter.table_size() == 0
    end
  end
end
