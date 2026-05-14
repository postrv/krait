# KRAIT Release Readiness Review

**Date:** 2026-05-14  
**Scope:** Local source review, existing security model, proposed promotion
pipeline, and release gates.

## Current Baseline

Verified locally after this implementation pass:

| Gate | Result |
|------|--------|
| `mix test` | Passed: 1916 tests, 0 failures, 39 excluded |
| `mix format --check-formatted` | Passed |
| `mix credo --strict` | Passed: no issues |
| `mix hex.audit` | Passed: no retired packages |
| `cargo test` in `native/krait_analyzer` | Passed: 199 tests, 0 failures |
| `cargo clippy -- -D warnings` in `native/krait_analyzer` | Passed |
| `cargo audit` in `native/krait_analyzer` | Passed: no reported vulnerabilities |
| `mix precommit` | Passed: compile, format, Credo strict, tests |

Not yet verified in this pass:

- Docker sandbox tests tagged `:docker_required`
- Narsil-required tests tagged `:narsil_required`
- pgvector-required tests tagged `:pgvector_required`
- Production image build and smoke test with real `NARSIL_SHA256`
- `docker-compose.prod.yml` end-to-end boot
- Full external security review

## Architectural Assessment

The current architecture is strong as a static safety model:

- Default-deny allowlist in Elixir and Rust.
- Immutable security core.
- Capability injection for least privilege.
- Narsil deep analysis support.
- Docker/FLAME sandbox execution.
- GitHub PR review and attestation primitives.

The proposed release model should be framed differently:

> The allowlist is the first hard gate. Release readiness is decided by a
> promotion pipeline that combines static analysis, sandbox evidence,
> independent review providers, signed provenance, merge policy, and controlled
> runtime activation.

That framing keeps the best part of the existing model while making room for
Narsil, an independent LLM reviewer, optional ArbiterSec review, FLAME sandbox
evidence, and BEAM activation after merge.

## Release Blockers And Current Status

### 1. Promotion Pipeline Is Not Implemented

Current flow:

```text
LLM proposal -> quick/deep validation -> sandbox compile/test -> PR
```

Target flow:

```text
Capability request -> candidate -> static gate -> sandbox gate
  -> review evidence -> promotion decision -> merge -> activation
```

Missing pieces:

- Immutable-core wiring for review evidence and promotion decisions.
- Promotion decision persisted with the proposal.
- Required PR status/check for promotion.
- External provider adapters for Narsil, independent LLM review, and optional
  ArbiterSec review.

Implemented in this pass:

- `Krait.Evolution.ReviewEvidence` normalizes provider output.
- `Krait.Evolution.PromotionDecision` implements deterministic provider quorum,
  threshold, provenance, capability, dependency, and severity policy.
- `Krait.Evolution.PromotionDecision` now fails closed for missing risk class,
  missing capability declarations, unsupported capability values, and missing
  required review providers. Scores are `0` whenever required evidence is absent.
- Unit tests cover approval, rejection, manual-review, provider, provenance,
  capability, dependency, and threshold cases.

### 2. Provenance Is Started But Not Fully Enforced

`Krait.Evolution.Proposer` attaches `llm_model` and `prompt_hash` to generated
proposals, and `Krait.Evolution.Attestation` knows how to include those fields.
The orchestrator path should be reviewed because provenance must survive through
validation, PR rendering, commit/attestation, and feed recording.

Current review also found that the attestation module is tested and the
verification mix task exists, but attestation signing is not visibly wired into
`Krait.Evolution.Deployer.propose_evolution/1`. That means the release docs
should not claim end-to-end signed promotion until the deploy path produces and
publishes the attestation evidence.

Release condition:

- Every promoted capability has model, prompt hash, source hash, test hash,
  analyzer versions, review provider versions, and attestation hash.
- PR rendering and `mix krait.verify` expose enough data for a third party to
  replay the decision.

### 3. Narsil Is Required In Production But Was Not Packaged In The App Image

Production config sets `require_deep_scan: true`, so the app image must have a
reliable `narsil-mcp` binary path if deep scan is a release requirement.

Implemented in this pass:

- `docker/Dockerfile.prod` now downloads `narsil-mcp` by version and requires a
  build-time SHA-256 checksum.
- The production build rejects any Narsil version other than `1.7.0` until the
  pinned release is intentionally upgraded.
- The runtime image sets `NARSIL_BINARY=/usr/local/bin/narsil-mcp`.
- `docker-compose.prod.yml` passes the required image build args and exposes the
  same absolute binary path.
- The deploy workflow passes `NARSIL_VERSION` and `NARSIL_SHA256` build args.
- The deploy workflow validates required release build variables before Docker
  build starts, so missing Narsil inputs fail with explicit errors.

Remaining release condition:

- CI or release operators must set `NARSIL_VERSION=1.7.0` and the real Narsil
  checksum.
- Boot health or setup validation must run against the built image.
- CI runs at least one Narsil-required smoke test on the release image.

### 4. Hot Reload Needs A Trusted Activation Boundary

Current policy rightly forbids generated code from hot loading code. The new
model can still support BEAM activation if activation is performed by trusted
KRAIT runtime code after a reviewed merge.

Release condition:

- Hot activation is limited to mutable capability paths.
- Activation loads compiled, hash-checked artifacts, not arbitrary source
  strings.
- Activation verifies behaviour implementation and declared capabilities.
- Skill registry updates are atomic.
- Rollback to the previous active version is tested.
- Immutable core modules cannot be activated through this path.

### 5. CI Treats Some Release-Critical Jobs As Advisory

The integration job is `continue-on-error: true`. That can be useful while the
project is early, but a release candidate needs a smaller required gate set that
cannot fail silently.

Release condition:

- A release workflow requires unit tests, Rust tests, clippy, formatting, Credo,
  dependency audit, immutable guard, production image build, and image smoke.
- Integration, Docker, Narsil, and pgvector gates are either required for tags or
  explicitly documented as non-release-blocking with rationale.

### 6. Setup Validation Was Mostly Implicit

Production boot validates many secrets and safety settings, but operators need
a single validation surface for release readiness.

Implemented in this pass:

- `Krait.SetupValidation` reports database, NIF, Narsil, sandbox image, GitHub
  auth, attestation key, OpenRouter/Ollama configuration, filesystem sandbox,
  admin token, and kill switch state.
- LLM validation mirrors router behavior by accepting OpenRouter or Anthropic
  cloud API keys, with Ollama allowed as local configuration.
- Kill-switch validation probes the ETS table and treats missing state as an
  error instead of relying on `halted?/0` fallback behavior.
- `mix krait.setup_validate` provides human and JSON output.
- Production checks fail closed for missing Narsil, missing sandbox image,
  incomplete GitHub auth, missing attestation key, missing LLM config, missing
  filesystem sandbox, weak admin token, or absent kill switch.

### 7. The Prescribed Precommit Alias Has A Lockfile Side Effect

The project guidelines require `mix precommit`. Credo strict issues in test
files have been resolved and the alias now exits successfully. During this
review, `deps.unlock --unused` still attempted to remove stale lockfile entries;
those lockfile changes were reverted because dependency locks are
immutable-core material.

Release condition:

- Ensure `mix precommit` does not produce lockfile churn during ordinary release
  verification, or document the expected dependency cleanup as a human-owned
  immutable-path change.

### 8. New Policy Files Must Stay Out Of The Mutable Periphery

Implemented in this pass:

- `.krait-immutable` now lists `lib/krait/evolution/promotion_decision.ex`,
  `lib/krait/evolution/review_evidence.ex`, `lib/krait/setup_validation.ex`,
  `lib/mix/tasks/`, and `docs/adr/`.
- README immutable-core copy has been updated to match the manifest.

## Suggested Release Tracks

### Track A: Conservative v0.1 Release

Ship the current human-gated PR model, but do not advertise automatic merge or
hot activation yet.

Required:

- All local gates pass.
- Production image includes or mounts Narsil.
- Release CI has required image smoke.
- Attestation/provenance path is complete.
- Setup validation exists.
- Documentation says generated code cannot merge or hot reload itself.

### Track B: Promotion-Gated Beta

Ship the proposed security model behind an explicit feature flag.

Required:

- ADR-008 accepted.
- Review evidence schema and provider adapters.
- Narsil and independent LLM review required for network-capable skills.
- Promotion decision status check on PRs.
- Human merge remains required.
- No hot activation in production unless explicitly enabled.

### Track C: Controlled Hot Activation

Enable runtime activation after reviewed merge.

Required:

- Atomic registry activation.
- Artifact hash verification.
- Signed attestation verification.
- Rollback tests.
- Operational telemetry and alerting for activation failures.
- Manual kill switch tested against active evolutions and active skills.

### Track D: Opt-In Auto-Merge

Only after Track C is boring in practice.

Required:

- Protected branch required checks.
- Bot merge identity with minimal permissions.
- Provider quorum and high thresholds.
- External review required for higher-risk classes.
- Human approval still required for privileged or dependency-changing skills.

## Immediate Next Work

1. Accept or revise ADR-008.
2. Ship v0.1 as Track A: human-gated PRs, no auto-merge, no hot activation.
3. Preserve provenance through the full evolution/deploy path.
4. Add provider adapters and immutable-core wiring for promotion evidence.
5. Add a required PR status/check for promotion decisions before Track B.
6. Add hot activation only after promotion evidence is stable.

## Release Command Checklist

Run before cutting a release candidate:

```bash
mix precommit
cd native/krait_analyzer && cargo test
cd native/krait_analyzer && cargo clippy -- -D warnings
mix test --include narsil_required
mix test --include docker_required
mix test --include pgvector_required
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up --wait
```

Some commands require external services or Docker. If a gate is skipped, the
release notes should say exactly why and what risk remains.
