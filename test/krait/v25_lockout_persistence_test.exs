defmodule Krait.V25LockoutPersistenceTest do
  use ExUnit.Case, async: false

  alias Krait.EvolveCooldownServer

  @dets_table :krait_lockout_persist

  setup do
    # Ensure server is running
    case GenServer.whereis(EvolveCooldownServer) do
      nil ->
        case EvolveCooldownServer.start_link([]) do
          {:ok, _} -> :ok
          {:error, {:already_started, _}} -> :ok
        end

      _ ->
        :ok
    end

    # Clean ETS and DETS for this test
    EvolveCooldownServer.delete_all()

    if :dets.info(@dets_table) != :undefined do
      :dets.delete_all_objects(@dets_table)
    end

    on_exit(fn ->
      if GenServer.whereis(EvolveCooldownServer) do
        EvolveCooldownServer.delete_all()
      end

      if :dets.info(@dets_table) != :undefined do
        :dets.delete_all_objects(@dets_table)
      end
    end)

    :ok
  end

  describe "v25 L-4: lockout persistence via DETS" do
    test "lockout counter writes are persisted to DETS" do
      lockout_key = {:admin_login_failures, "192.168.1.100", 999_999}
      EvolveCooldownServer.update_counter(lockout_key, {2, 1}, {lockout_key, 0})
      EvolveCooldownServer.update_counter(lockout_key, {2, 1}, {lockout_key, 0})

      # Verify ETS has the data
      assert [{^lockout_key, 2}] = EvolveCooldownServer.lookup(lockout_key)

      # Verify DETS also has the data (direct check, no restart needed)
      :dets.sync(@dets_table)
      assert [{^lockout_key, 2}] = :dets.lookup(@dets_table, lockout_key)
    end

    test "non-lockout entries are NOT persisted to DETS" do
      slot_key = {:evolve_slot, "test"}
      EvolveCooldownServer.insert({slot_key, 1})

      # In ETS
      assert [{^slot_key, 1}] = EvolveCooldownServer.lookup(slot_key)

      # NOT in DETS (only lockout keys are persisted)
      :dets.sync(@dets_table)
      assert [] = :dets.lookup(@dets_table, slot_key)
    end

    test "lockout reset is persisted to DETS" do
      lockout_key = {:admin_login_failures, "10.0.0.1", 999_998}
      EvolveCooldownServer.update_counter(lockout_key, {2, 1}, {lockout_key, 0})
      EvolveCooldownServer.update_counter(lockout_key, {2, 1}, {lockout_key, 0})
      EvolveCooldownServer.update_counter(lockout_key, {2, 1}, {lockout_key, 0})

      # Reset
      EvolveCooldownServer.insert({lockout_key, 0})

      # DETS should have the reset value
      :dets.sync(@dets_table)
      assert [{^lockout_key, 0}] = :dets.lookup(@dets_table, lockout_key)
    end

    test "DETS lockout_key? filter only accepts admin_login_failures tuples" do
      # This tests the core logic: only lockout keys are persisted
      lockout_key = {:admin_login_failures, "1.2.3.4", 100}
      EvolveCooldownServer.update_counter(lockout_key, {2, 1}, {lockout_key, 0})

      cooldown_key = {:evolve_cooldown, "test"}
      EvolveCooldownServer.insert({cooldown_key, 123})

      :dets.sync(@dets_table)
      assert [{^lockout_key, 1}] = :dets.lookup(@dets_table, lockout_key)
      assert [] = :dets.lookup(@dets_table, cooldown_key)
    end
  end
end
