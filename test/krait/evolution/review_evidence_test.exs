defmodule Krait.Evolution.ReviewEvidenceTest do
  use ExUnit.Case, async: true

  alias Krait.Evolution.ReviewEvidence

  describe "new/1" do
    test "normalizes a valid provider result" do
      started_at = ~U[2026-05-14 12:00:00Z]
      completed_at = ~U[2026-05-14 12:00:03Z]

      assert {:ok, evidence} =
               ReviewEvidence.new(%{
                 provider: :llm_review,
                 provider_version: "claude-sonnet-4.5",
                 status: "passed",
                 findings: [
                   %{"severity" => "low", "rule" => "style"},
                   %{severity: :medium, rule: "bounds"}
                 ],
                 confidence: 0.94,
                 artifacts: [%{type: "sarif", path: "reports/review.sarif"}],
                 started_at: started_at,
                 completed_at: completed_at
               })

      assert evidence.provider == "llm-review"
      assert evidence.provider_version == "claude-sonnet-4.5"
      assert evidence.status == :passed
      assert evidence.max_severity == :medium
      assert evidence.confidence == 0.94
      assert evidence.artifacts == [%{type: "sarif", path: "reports/review.sarif"}]
      assert evidence.started_at == started_at
      assert evidence.completed_at == completed_at
    end

    test "uses explicit max severity when it is higher than findings" do
      assert {:ok, evidence} =
               ReviewEvidence.new(%{
                 provider: "narsil",
                 status: :passed,
                 findings: [%{severity: :low}],
                 max_severity: "high",
                 confidence: 0.91
               })

      assert evidence.max_severity == :high
      assert ReviewEvidence.blocking?(evidence)
    end

    test "rejects invalid statuses" do
      assert {:error, {:invalid_status, :running}} =
               ReviewEvidence.new(%{provider: "narsil", status: :running})
    end

    test "rejects invalid severity values" do
      assert {:error, {:invalid_severity, "loud"}} =
               ReviewEvidence.new(%{
                 provider: "narsil",
                 status: :passed,
                 findings: [%{"severity" => "loud"}]
               })
    end

    test "rejects confidence outside zero to one" do
      assert {:error, {:invalid_confidence, 1.01}} =
               ReviewEvidence.new(%{
                 provider: "narsil",
                 status: :passed,
                 confidence: 1.01
               })
    end

    test "requires a provider" do
      assert {:error, :provider_required} = ReviewEvidence.new(%{status: :passed})
    end
  end

  describe "blocking?/1" do
    test "critical and high findings are blocking by default" do
      assert {:ok, critical} =
               ReviewEvidence.new(%{
                 provider: "narsil",
                 status: :passed,
                 max_severity: :critical
               })

      assert {:ok, high} =
               ReviewEvidence.new(%{provider: "narsil", status: :passed, max_severity: :high})

      assert {:ok, medium} =
               ReviewEvidence.new(%{
                 provider: "narsil",
                 status: :passed,
                 max_severity: :medium
               })

      assert ReviewEvidence.blocking?(critical)
      assert ReviewEvidence.blocking?(high)
      refute ReviewEvidence.blocking?(medium)
    end
  end

  describe "to_map/1" do
    test "serializes to a stable map" do
      assert {:ok, evidence} =
               ReviewEvidence.new(%{
                 provider: "sandbox",
                 status: :passed,
                 confidence: 1.0
               })

      assert %{
               provider: "sandbox",
               status: :passed,
               max_severity: :none,
               confidence: 1.0
             } = ReviewEvidence.to_map(evidence)
    end
  end
end
