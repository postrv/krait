defmodule Krait.LLM.QualityGateTest do
  use ExUnit.Case, async: true

  alias Krait.LLM.QualityGate

  setup do
    # Start a fresh QualityGate for each test with a unique name
    name = :"quality_gate_#{System.unique_integer([:positive])}"

    {:ok, pid} =
      QualityGate.start_link(
        name: name,
        escalation_threshold: 0.60,
        window_size: 10,
        cooldown_after_escalation: 3
      )

    {:ok, name: name, pid: pid}
  end

  describe "record/4 and stats/1" do
    test "tracks successes and failures", %{name: name} do
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :code_gen, :failure, name)

      stats = QualityGate.stats(name)
      local_code = stats[{:local, :code_gen}]

      assert local_code.success == 2
      assert local_code.failure == 1
      assert local_code.total == 3
      assert_in_delta local_code.rate, 0.667, 0.01
    end

    test "maintains rolling window", %{name: name} do
      # Fill window with 10 successes
      for _ <- 1..10, do: QualityGate.record(:local, :code_gen, :success, name)

      stats = QualityGate.stats(name)
      assert stats[{:local, :code_gen}].total == 10
      assert stats[{:local, :code_gen}].rate == 1.0

      # Add 5 more failures — should push out 5 successes from window
      for _ <- 1..5, do: QualityGate.record(:local, :code_gen, :failure, name)

      stats = QualityGate.stats(name)
      assert stats[{:local, :code_gen}].total == 10
      assert stats[{:local, :code_gen}].success == 5
      assert stats[{:local, :code_gen}].failure == 5
    end

    test "tracks different backends independently", %{name: name} do
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:cloud, :code_gen, :failure, name)

      stats = QualityGate.stats(name)
      assert stats[{:local, :code_gen}].success == 1
      assert stats[{:cloud, :code_gen}].failure == 1
    end

    test "tracks different task types independently", %{name: name} do
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :test_gen, :failure, name)

      stats = QualityGate.stats(name)
      assert stats[{:local, :code_gen}].rate == 1.0
      assert stats[{:local, :test_gen}].rate == 0.0
    end
  end

  describe "should_escalate?/2" do
    test "does not escalate with insufficient data", %{name: name} do
      QualityGate.record(:local, :code_gen, :failure, name)
      QualityGate.record(:local, :code_gen, :failure, name)

      # Only 2 data points — needs at least 3
      refute QualityGate.should_escalate?(:code_gen, name)
    end

    test "escalates when success rate drops below threshold", %{name: name} do
      # 1 success, 2 failures = 33% success rate (below 60% threshold)
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :code_gen, :failure, name)
      QualityGate.record(:local, :code_gen, :failure, name)

      assert QualityGate.should_escalate?(:code_gen, name)
    end

    test "does not escalate when success rate is above threshold", %{name: name} do
      # 3 successes, 1 failure = 75% success rate (above 60%)
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :code_gen, :failure, name)

      refute QualityGate.should_escalate?(:code_gen, name)
    end

    test "de-escalates after enough cloud successes (cooldown)", %{name: name} do
      # Trigger escalation
      QualityGate.record(:local, :code_gen, :failure, name)
      QualityGate.record(:local, :code_gen, :failure, name)
      QualityGate.record(:local, :code_gen, :failure, name)
      assert QualityGate.should_escalate?(:code_gen, name)

      # Record cloud successes (cooldown is 3)
      QualityGate.record(:cloud, :code_gen, :success, name)
      QualityGate.record(:cloud, :code_gen, :success, name)
      assert QualityGate.should_escalate?(:code_gen, name)

      QualityGate.record(:cloud, :code_gen, :success, name)
      # After 3 cloud successes, should de-escalate
      refute QualityGate.should_escalate?(:code_gen, name)
    end

    test "different task types escalate independently", %{name: name} do
      # code_gen is failing
      for _ <- 1..3, do: QualityGate.record(:local, :code_gen, :failure, name)

      # test_gen is succeeding
      for _ <- 1..3, do: QualityGate.record(:local, :test_gen, :success, name)

      assert QualityGate.should_escalate?(:code_gen, name)
      refute QualityGate.should_escalate?(:test_gen, name)
    end
  end

  describe "reset/1" do
    test "clears all tracked data", %{name: name} do
      QualityGate.record(:local, :code_gen, :success, name)
      QualityGate.record(:local, :code_gen, :failure, name)
      QualityGate.record(:local, :code_gen, :failure, name)
      QualityGate.record(:local, :code_gen, :failure, name)

      assert QualityGate.should_escalate?(:code_gen, name)

      :ok = QualityGate.reset(name)

      stats = QualityGate.stats(name)
      assert stats == %{escalated: %{}}
      refute QualityGate.should_escalate?(:code_gen, name)
    end
  end
end
