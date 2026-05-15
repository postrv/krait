defmodule Krait.KillSwitchPersistenceTest do
  use Krait.DataCase, async: false

  alias Krait.KillSwitch

  describe "persistence" do
    test "init/1 restores halted state from database on restart" do
      # Insert halted state directly into DB
      Krait.Repo.insert!(%Krait.KillSwitchState{
        halted: true,
        halted_at: DateTime.utc_now(),
        halted_by: "persist test",
        consecutive_failures: 0
      })

      # Start a separate KillSwitch instance with different name/table and DB access
      {:ok, pid} =
        KillSwitch.start_link(
          name: :test_kill_switch_persist,
          table_name: :test_ks_persist,
          skip_db: false
        )

      status = GenServer.call(pid, :status)
      assert status.halted == true
      assert status.halted_by == "persist test"

      GenServer.stop(pid)
    end

    test "consecutive_failures counter survives GenServer restart" do
      Krait.Repo.insert!(%Krait.KillSwitchState{
        halted: false,
        consecutive_failures: 3
      })

      {:ok, pid} =
        KillSwitch.start_link(
          name: :test_kill_switch_failures,
          table_name: :test_ks_failures,
          skip_db: false
        )

      status = GenServer.call(pid, :status)
      assert status.consecutive_failures == 3

      GenServer.stop(pid)
    end

    test "transient halt does not persist graceful shutdown as a global halt" do
      persisted =
        Krait.Repo.insert!(%Krait.KillSwitchState{
          halted: false,
          halted_at: nil,
          halted_by: nil,
          consecutive_failures: 0
        })

      {:ok, pid} =
        KillSwitch.start_link(
          name: :test_kill_switch_transient,
          table_name: :test_ks_transient,
          skip_db: false
        )

      assert :ok = GenServer.call(pid, {:halt_transient, "graceful_shutdown"})

      status = GenServer.call(pid, :status)
      assert status.halted == true
      assert status.halted_by == "graceful_shutdown"

      reloaded = Krait.Repo.get!(Krait.KillSwitchState, persisted.id)
      assert reloaded.halted == false
      assert reloaded.halted_by == nil

      GenServer.stop(pid)
    end
  end
end
