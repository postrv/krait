defmodule Krait.EvolveCooldownServerTest do
  use ExUnit.Case, async: false

  setup do
    # Ensure the server is running
    case GenServer.whereis(Krait.EvolveCooldownServer) do
      nil -> Krait.EvolveCooldownServer.start_link([])
      pid -> if Process.alive?(pid), do: :ok, else: Krait.EvolveCooldownServer.start_link([])
    end

    Krait.EvolveCooldownServer.delete_all()
    :ok
  end

  describe "v22 SEC-08: EvolveCooldownServer" do
    test "insert + lookup round-trip" do
      Krait.EvolveCooldownServer.insert({:last_evolution, 12_345})
      assert [{:last_evolution, 12_345}] = Krait.EvolveCooldownServer.lookup(:last_evolution)
    end

    test "lookup returns empty list for unknown key" do
      assert [] = Krait.EvolveCooldownServer.lookup(:nonexistent)
    end

    test "update_counter increments atomically" do
      count = Krait.EvolveCooldownServer.update_counter(:active, {2, 1}, {:active, 0})
      assert count == 1

      count = Krait.EvolveCooldownServer.update_counter(:active, {2, 1}, {:active, 0})
      assert count == 2
    end

    test "delete_all clears all entries" do
      Krait.EvolveCooldownServer.insert({:key1, "val1"})
      Krait.EvolveCooldownServer.insert({:key2, "val2"})

      Krait.EvolveCooldownServer.delete_all()

      assert [] = Krait.EvolveCooldownServer.lookup(:key1)
      assert [] = Krait.EvolveCooldownServer.lookup(:key2)
    end

    test "table is :protected — direct ETS read succeeds from non-owner" do
      Krait.EvolveCooldownServer.insert({:readable, "value"})

      result = :ets.lookup(:krait_evolve_cooldown, :readable)
      assert [{:readable, "value"}] = result
    end

    test "table is :protected — direct ETS write from non-owner raises" do
      assert_raise ArgumentError, fn ->
        :ets.insert(:krait_evolve_cooldown, {:unauthorized, "bad"})
      end
    end
  end

  describe "v24 F-05: atomic slot acquisition" do
    test "try_acquire_slot returns :ok under capacity" do
      assert :ok = Krait.EvolveCooldownServer.try_acquire_slot(:test_slots, 2)
    end

    test "try_acquire_slot returns {:error, :at_capacity} at max" do
      :ok = Krait.EvolveCooldownServer.try_acquire_slot(:cap_slots, 2)
      :ok = Krait.EvolveCooldownServer.try_acquire_slot(:cap_slots, 2)
      assert {:error, :at_capacity} = Krait.EvolveCooldownServer.try_acquire_slot(:cap_slots, 2)
    end

    test "10 concurrent tasks with max=2 yields exactly 2 successes" do
      results =
        1..10
        |> Enum.map(fn _ ->
          Task.async(fn ->
            Krait.EvolveCooldownServer.try_acquire_slot(:race_slots, 2)
          end)
        end)
        |> Enum.map(&Task.await/1)

      successes = Enum.count(results, &(&1 == :ok))
      assert successes == 2
    end

    test "release_slot decrements with floor at 0" do
      :ok = Krait.EvolveCooldownServer.try_acquire_slot(:release_slots, 5)
      :ok = Krait.EvolveCooldownServer.try_acquire_slot(:release_slots, 5)
      assert [{:release_slots, 2}] = Krait.EvolveCooldownServer.lookup(:release_slots)

      :ok = Krait.EvolveCooldownServer.release_slot(:release_slots)
      assert [{:release_slots, 1}] = Krait.EvolveCooldownServer.lookup(:release_slots)

      :ok = Krait.EvolveCooldownServer.release_slot(:release_slots)
      assert [{:release_slots, 0}] = Krait.EvolveCooldownServer.lookup(:release_slots)

      # Floor at 0
      :ok = Krait.EvolveCooldownServer.release_slot(:release_slots)
      assert [{:release_slots, 0}] = Krait.EvolveCooldownServer.lookup(:release_slots)
    end
  end

  describe "v24 F-24: slot crash cleanup" do
    test "slot counter decrements when monitored process dies" do
      :ok = Krait.EvolveCooldownServer.try_acquire_slot(:crash_slots, 5)
      assert [{:crash_slots, 1}] = Krait.EvolveCooldownServer.lookup(:crash_slots)

      # Start a process that will die
      pid =
        spawn(fn ->
          receive do
            :die -> :ok
          end
        end)

      Krait.EvolveCooldownServer.register_slot_owner(:crash_slots, pid)
      send(pid, :die)

      # Allow DOWN message to be processed
      Process.sleep(50)

      assert [{:crash_slots, 0}] = Krait.EvolveCooldownServer.lookup(:crash_slots)
    end
  end

  describe "v24 F-03: lockout TTL expiry" do
    test "sweep removes old lockout entries" do
      # Insert an entry with an old bucket (bucket 0)
      Krait.EvolveCooldownServer.insert({{:admin_login_failures, "1.2.3.4", 0}, 5})
      # Insert an entry with a current bucket
      current_bucket = div(System.system_time(:second), 900)
      Krait.EvolveCooldownServer.insert({{:admin_login_failures, "1.2.3.4", current_bucket}, 3})

      # Sweep should remove the old one
      Krait.EvolveCooldownServer.sweep_old_lockouts(900)
      Process.sleep(50)

      assert [] = Krait.EvolveCooldownServer.lookup({:admin_login_failures, "1.2.3.4", 0})

      assert [{{:admin_login_failures, "1.2.3.4", ^current_bucket}, 3}] =
               Krait.EvolveCooldownServer.lookup(
                 {:admin_login_failures, "1.2.3.4", current_bucket}
               )
    end
  end
end
