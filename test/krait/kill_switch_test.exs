defmodule Krait.KillSwitchTest do
  use ExUnit.Case, async: false

  alias Krait.KillSwitch

  setup do
    # Use the supervisor-started KillSwitch (skip_db: true in test)
    # Reset its state between tests by sending a direct GenServer call
    GenServer.call(KillSwitch, :reset_for_test)
    :ok
  end

  describe "halted?/0" do
    test "returns false by default" do
      refute KillSwitch.halted?()
    end

    test "returns true after halt!/1" do
      KillSwitch.halt!("test halt")
      assert KillSwitch.halted?()
    end
  end

  describe "halt!/1" do
    test "sets halted state with reason and timestamp" do
      assert :ok = KillSwitch.halt!("security concern")

      status = KillSwitch.status()
      assert status.halted == true
      assert status.halted_by == "security concern"
      assert %DateTime{} = status.halted_at
    end

    test "is idempotent — calling halt! twice doesn't crash or change timestamp" do
      assert :ok = KillSwitch.halt!("first halt")
      status1 = KillSwitch.status()

      # Small delay to ensure timestamps would differ if regenerated
      Process.sleep(10)

      assert :ok = KillSwitch.halt!("second halt")
      status2 = KillSwitch.status()

      # Timestamp should not change (idempotent)
      assert status1.halted_at == status2.halted_at
      # But reason is updated
      assert status2.halted_by == "second halt"
    end

    test "broadcasts :kill_switch_engaged on PubSub" do
      Phoenix.PubSub.subscribe(Krait.PubSub, "kill_switch")

      KillSwitch.halt!("pubsub test")

      assert_receive {:kill_switch_engaged, "pubsub test"}, 1000
    end
  end

  describe "resume!/0" do
    test "clears halted state" do
      KillSwitch.halt!("to be resumed")
      assert KillSwitch.halted?()

      assert :ok = KillSwitch.resume!()
      refute KillSwitch.halted?()
    end

    test "broadcasts :kill_switch_disengaged on PubSub" do
      KillSwitch.halt!("for resume")
      Phoenix.PubSub.subscribe(Krait.PubSub, "kill_switch")

      KillSwitch.resume!()

      assert_receive :kill_switch_disengaged, 1000
    end

    test "returns error if called within cooldown period" do
      Application.put_env(:krait, :kill_switch_resume_cooldown, 30)
      KillSwitch.halt!("cooldown test")

      assert :ok = KillSwitch.resume!()

      # Second resume within 30s should fail
      result = KillSwitch.resume!()
      assert {:error, :resume_cooldown, remaining} = result
      assert remaining > 0
    end
  end

  describe "record_failure/0" do
    test "increments consecutive failure counter" do
      KillSwitch.record_failure()
      status = KillSwitch.status()
      assert status.consecutive_failures == 1

      KillSwitch.record_failure()
      status = KillSwitch.status()
      assert status.consecutive_failures == 2
    end

    test "auto-trips after threshold consecutive failures (default 5)" do
      Application.put_env(:krait, :kill_switch_failure_threshold, 5)

      for i <- 1..4 do
        assert :ok = KillSwitch.record_failure(),
               "Failure #{i} should not trip kill switch"
      end

      refute KillSwitch.halted?()

      # 5th failure should auto-trip
      assert {:halted, reason} = KillSwitch.record_failure()
      assert reason =~ "5 consecutive validation failures"
      assert KillSwitch.halted?()
    end
  end

  describe "record_success/0" do
    test "resets consecutive failure counter" do
      KillSwitch.record_failure()
      KillSwitch.record_failure()
      assert KillSwitch.status().consecutive_failures == 2

      KillSwitch.record_success()
      assert KillSwitch.status().consecutive_failures == 0
    end
  end

  describe "status/0" do
    test "returns full state map" do
      status = KillSwitch.status()

      assert Map.has_key?(status, :halted)
      assert Map.has_key?(status, :halted_at)
      assert Map.has_key?(status, :halted_by)
      assert Map.has_key?(status, :consecutive_failures)
    end
  end

  # Persistence tests removed from this module — see KillSwitchPersistenceTest

  describe "integration" do
    test "5 consecutive policy violations auto-halt evolution" do
      Application.put_env(:krait, :kill_switch_failure_threshold, 5)
      Phoenix.PubSub.subscribe(Krait.PubSub, "kill_switch")

      for _ <- 1..5, do: KillSwitch.record_failure()

      assert KillSwitch.halted?()
      assert_receive {:kill_switch_engaged, _reason}, 1000
    end
  end
end
