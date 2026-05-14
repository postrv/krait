# ADR-008: Promotion-Gated Capability Evolution

## Status

Proposed

## Context

KRAIT currently treats the default-deny allowlist as the primary security gate.
That design is still valuable: it gives the system a small, reviewable local
execution surface and blocks unknown dangerous primitives by default.

The release model we want, however, is broader than a single static gate:

1. A user asks KRAIT for a new capability.
2. An LLM builds the candidate implementation and tests.
3. Independent review systems evaluate the candidate.
4. Once the evidence clears a configured threshold, the change is merged.
5. The BEAM activates the reviewed capability without a full manual redeploy.

This shifts the system from "the allowlist is the whole security model" to
"the allowlist is the first local gate inside a promotion pipeline." The
important distinction is that generated code still cannot alter or invoke the
security boundary. The trusted KRAIT runtime may promote and activate reviewed
artifacts, but generated capabilities may not hot-load arbitrary code or modify
the analyzers, policy, deployment, or configuration.

As of 2026-05-14, Arbiter Security describes Arbiter and Aletheia as Rust MCP
servers for web and binary security automation: <https://arbitersec.com/>. Any
integration with a paid external service should be represented as a review
provider behind a stable KRAIT behaviour, not embedded as a policy dependency
until an API contract and data-handling agreement are confirmed.

## Decision

Adopt a promotion-gated capability evolution model for the mutable periphery.

The immutable core remains unchanged:

- Analyzer allowlists, KRAIT rules, sandbox policy, deployment policy, config,
  and core evolution orchestration remain human-owned.
- Generated capabilities can target only approved mutable paths.
- KRAIT-005 continues to forbid generated code from calling hot-code-loading
  APIs. Runtime activation is performed only by trusted KRAIT code after merge.
- The allowlist remains a hard local gate, not a soft signal.

The proposed promotion pipeline is:

```text
CapabilityRequest
  -> CandidateBuild
  -> StaticGate
  -> SandboxGate
  -> ReviewEvidence
  -> PromotionDecision
  -> Merge
  -> RuntimeActivation
```

### CapabilityRequest

A request records:

- User intent and acceptance criteria.
- Requested capabilities, such as `:filesystem`, `:network`, or `:memory`.
- Risk class: pure compute, local read, memory, network, or privileged.
- Target paths and language.
- Generated test expectations.

The request should be stored before generation so the final review can compare
the produced behavior against the original scope.

### CandidateBuild

The LLM builds source and tests in an isolated workspace. Candidate provenance
must include:

- Model and provider.
- Prompt hash.
- Source hash and test hash.
- Requested capabilities.
- Dependency delta.

The current code already starts this provenance chain in
`Krait.Evolution.Proposer`; the release path should preserve it through
validation, PR creation, attestation, and feed recording.

### StaticGate

Static gates remain hard blockers:

- Elixir AST analyzer.
- Rust NIF analyzer.
- KRAIT-003, KRAIT-006, and KRAIT-007 intent checks.
- Complexity and immutable-manifest policy.

Any static violation rejects the candidate before paid or slower review runs.

### SandboxGate

The sandbox compiles and tests the candidate through FLAME/Docker. Networkless
compile and test should remain the default after dependency resolution. The
sandbox result is review evidence, not just a build step.

### ReviewEvidence

All review providers should normalize to a single evidence shape:

```elixir
%{
  provider: "narsil" | "llm-review" | "arbitersec" | String.t(),
  provider_version: String.t() | nil,
  status: :passed | :failed | :inconclusive | :unavailable,
  findings: [map()],
  max_severity: :none | :low | :medium | :high | :critical,
  confidence: float(),
  artifacts: [map()],
  started_at: DateTime.t(),
  completed_at: DateTime.t()
}
```

Initial providers:

- Narsil quick/deep/full-project scans.
- Independent LLM security reviewer using a different model or prompt family
  than the builder.
- Optional ArbiterSec provider once the service contract is known.
- Dependency/SBOM review.
- Sandbox compile/test evidence.

### PromotionDecision

Promotion is threshold-based but still fail-closed. Hard blockers always reject:

- Static gate failure.
- Failing tests or compilation.
- Critical or high severity finding from any required provider.
- Required provider unavailable or inconclusive.
- New dependency without explicit human approval.
- Missing provenance, attestation, or source hash mismatch.
- Immutable path targeting.
- Requested capability mismatch.

Suggested thresholds:

- `pure_compute`: no hard blockers, Narsil complete, sandbox pass, score >= 90.
- `local_read` or `memory`: no hard blockers, Narsil complete, LLM reviewer
  pass, sandbox pass, score >= 92.
- `network`: no hard blockers, Narsil complete, LLM reviewer pass, SSRF/domain
  policy evidence, sandbox pass, score >= 95.
- `privileged`: no automatic promotion. Human security approval required.

For the first release, KRAIT should keep human merge approval. Later, bot
auto-merge can be an opt-in mode guarded by branch protection and required
status checks.

### Merge

Merge should happen only through a protected branch policy. The promotion
decision should become a required status check with an attached evidence bundle.
The PR body should include the evidence summary, source hashes, test hashes,
attestation data, and reviewer versions.

### RuntimeActivation

Runtime activation is allowed only for reviewed, merged, signed artifacts from
mutable capability paths.

Activation requirements:

- The source commit is on a protected branch or signed release channel.
- The artifact hash matches the attestation.
- The module implements the expected skill behaviour.
- The declared capabilities match the promotion decision.
- Activation updates the registry atomically.
- The previous active version remains available for rollback.

Runtime activation must not load analyzer, sandbox, config, web, LLM, gateway,
GitHub, or other immutable-core modules.

## Consequences

### Positive

- Security decisions become evidence-based rather than a single pass/fail scan.
- KRAIT can add useful capabilities without relaxing the immutable core.
- Paid or specialized review systems can be added without hardwiring one vendor
  into the security model.
- Hot activation becomes possible while keeping generated code away from
  `Code`, `:code`, and other hot-loading primitives.
- PRs become more auditable because the full review bundle is attached.

### Negative

- The pipeline is more complex and needs careful failure semantics.
- Review provider drift can create noisy or inconsistent decisions.
- Runtime activation introduces a new trusted subsystem that must be small,
  test-heavy, and human-owned.
- Automated merge must be delayed until branch protection, status checks, and
  rollback are proven in production-like environments.

## Implementation Notes

This ADR requires human-owned changes in immutable paths:

- `lib/krait/evolution/validator.ex` to preserve and return review evidence.
- `lib/krait/evolution/deployer.ex` to publish evidence as PR status/checks.
- `lib/krait/evolution/evolution.ex` to thread provenance and promotion state.
- `lib/krait/skills/registry.ex` or a new human-owned activation module to
  support atomic runtime activation.
- `config/` to declare required providers and thresholds per environment.
- Production Docker packaging to guarantee required review tools are present.

Non-immutable helper modules can be introduced for evidence normalization and
provider adapters, but the enforcement hook must remain human-owned.

## Open Questions

- Should the first public release expose hot activation, or should it ship with
  promotion evidence plus human merge only?
- Should network-capable skills require an external review provider by default?
- Should medium-severity findings be allowed with warning evidence, or require
  an explicit human override?
- What is the rollback contract for a hot-activated skill that passes review but
  misbehaves operationally?
