defmodule Krait.Evolution.PromotionDecisionTest do
  use ExUnit.Case, async: true

  alias Krait.Evolution.{PromotionDecision, ReviewEvidence}

  @provenance %{
    model: "qwen2.5-coder:14b",
    prompt_hash: String.duplicate("a", 64),
    source_hash: String.duplicate("b", 64),
    test_hash: String.duplicate("c", 64)
  }

  describe "decide/1" do
    test "approves a pure compute candidate with required passing evidence" do
      evidence = [
        evidence!("narsil", :passed, 0.96),
        evidence!("sandbox", :passed, 1.0)
      ]

      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :pure_compute,
                 requested_capabilities: [],
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: evidence
               })

      assert decision.status == :approved
      assert decision.score == 96
      assert decision.threshold == 90
      assert decision.reasons == []
    end

    test "rejects a candidate missing a required provider" do
      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :pure_compute,
                 requested_capabilities: [],
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [evidence!("narsil", :passed, 0.96)]
               })

      assert decision.status == :rejected
      assert decision.score == 0
      assert "required provider unavailable: sandbox" in decision.reasons
    end

    test "rejects candidates without an explicit risk class" do
      assert {:error, {:unknown_risk_class, nil}} =
               PromotionDecision.decide(%{
                 requested_capabilities: [],
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [
                   evidence!("narsil", :passed, 0.99),
                   evidence!("sandbox", :passed, 1.0)
                 ]
               })
    end

    test "rejects high severity findings even when the provider status is passed" do
      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :pure_compute,
                 requested_capabilities: [],
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [
                   evidence!("narsil", :passed, 0.98, max_severity: :high),
                   evidence!("sandbox", :passed, 1.0)
                 ]
               })

      assert decision.status == :rejected
      assert "blocking severity from narsil: high" in decision.reasons
    end

    test "rejects capability mismatch" do
      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :local_read,
                 requested_capabilities: [:filesystem],
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [
                   evidence!("narsil", :passed, 0.98),
                   evidence!("llm-review", :passed, 0.96),
                   evidence!("sandbox", :passed, 1.0)
                 ]
               })

      assert decision.status == :rejected
      assert "declared capabilities do not match requested capabilities" in decision.reasons
    end

    test "requires explicit capability declarations" do
      assert {:error, {:missing_capabilities, :requested_capabilities}} =
               PromotionDecision.decide(%{
                 risk_class: :pure_compute,
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [
                   evidence!("narsil", :passed, 0.98),
                   evidence!("sandbox", :passed, 1.0)
                 ]
               })
    end

    test "rejects unsupported or non-string capability values" do
      base = %{
        risk_class: :pure_compute,
        declared_capabilities: [],
        dependency_delta: [],
        provenance: @provenance,
        evidence: [
          evidence!("narsil", :passed, 0.98),
          evidence!("sandbox", :passed, 1.0)
        ]
      }

      assert {:error, {:unsupported_capability, "shell"}} =
               PromotionDecision.decide(Map.put(base, :requested_capabilities, ["shell"]))

      assert {:error, {:invalid_capability, %{name: "filesystem"}}} =
               PromotionDecision.decide(
                 base
                 |> Map.put(:requested_capabilities, [%{name: "filesystem"}])
                 |> Map.put(:declared_capabilities, [%{name: "filesystem"}])
               )
    end

    test "normalizes string capability names before comparing" do
      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :network,
                 requested_capabilities: ["NETWORK"],
                 declared_capabilities: [:network],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [
                   evidence!("narsil", :passed, 0.98),
                   evidence!("llm-review", :passed, 0.96),
                   evidence!("sandbox", :passed, 1.0),
                   evidence!("ssrf", :passed, 0.99)
                 ]
               })

      assert decision.status == :approved
    end

    test "rejects dependency changes unless explicitly approved" do
      candidate = %{
        risk_class: :pure_compute,
        requested_capabilities: [],
        declared_capabilities: [],
        dependency_delta: [%{package: "new_dep"}],
        provenance: @provenance,
        evidence: [
          evidence!("narsil", :passed, 0.98),
          evidence!("sandbox", :passed, 1.0)
        ]
      }

      assert {:ok, rejected} = PromotionDecision.decide(candidate)
      assert rejected.status == :rejected
      assert "dependency changes require human approval" in rejected.reasons

      assert {:ok, approved} =
               PromotionDecision.decide(candidate, dependency_approved?: true)

      assert approved.status == :approved
    end

    test "requires network-specific review evidence for network risk" do
      base = %{
        risk_class: :network,
        requested_capabilities: [:network],
        declared_capabilities: [:network],
        dependency_delta: [],
        provenance: @provenance
      }

      assert {:ok, missing_ssrf} =
               PromotionDecision.decide(
                 Map.put(base, :evidence, [
                   evidence!("narsil", :passed, 0.98),
                   evidence!("llm-review", :passed, 0.96),
                   evidence!("sandbox", :passed, 1.0)
                 ])
               )

      assert missing_ssrf.status == :rejected
      assert "required provider unavailable: ssrf" in missing_ssrf.reasons

      assert {:ok, approved} =
               PromotionDecision.decide(
                 Map.put(base, :evidence, [
                   evidence!("narsil", :passed, 0.98),
                   evidence!("llm-review", :passed, 0.96),
                   evidence!("sandbox", :passed, 1.0),
                   evidence!("ssrf", :passed, 0.99)
                 ])
               )

      assert approved.status == :approved
      assert approved.threshold == 95
    end

    test "routes privileged candidates to manual review" do
      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :privileged,
                 requested_capabilities: [],
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [
                   evidence!("narsil", :passed, 0.99),
                   evidence!("sandbox", :passed, 1.0)
                 ]
               })

      assert decision.status == :manual_review
      assert "privileged risk class requires human security approval" in decision.reasons
    end

    test "rejects missing provenance" do
      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :pure_compute,
                 requested_capabilities: [],
                 declared_capabilities: [],
                 dependency_delta: [],
                 provenance: Map.delete(@provenance, :test_hash),
                 evidence: [
                   evidence!("narsil", :passed, 0.99),
                   evidence!("sandbox", :passed, 1.0)
                 ]
               })

      assert decision.status == :rejected
      assert "missing provenance: test_hash" in decision.reasons
    end

    test "rejects passing evidence below the risk threshold" do
      assert {:ok, decision} =
               PromotionDecision.decide(%{
                 risk_class: :network,
                 requested_capabilities: [:network],
                 declared_capabilities: [:network],
                 dependency_delta: [],
                 provenance: @provenance,
                 evidence: [
                   evidence!("narsil", :passed, 0.98),
                   evidence!("llm-review", :passed, 0.94),
                   evidence!("sandbox", :passed, 1.0),
                   evidence!("ssrf", :passed, 0.99)
                 ]
               })

      assert decision.status == :rejected
      assert "score 94 is below threshold 95" in decision.reasons
    end
  end

  defp evidence!(provider, status, confidence, opts \\ []) do
    attrs =
      opts
      |> Map.new()
      |> Map.merge(%{provider: provider, status: status, confidence: confidence})

    {:ok, evidence} = ReviewEvidence.new(attrs)
    evidence
  end
end
