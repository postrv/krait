# ADR-003: No Shadow/Parallel Validation Mode

## Status

Accepted

## Context

When migrating from a denylist to an allowlist security model, a common
practice is to run the new system in "shadow mode" -- logging what the allowlist
would reject without actually blocking, while the denylist remains the primary
enforcement mechanism. This allows teams to measure false-positive rates and
build confidence before cutting over.

The argument for shadow mode in KRAIT would be:

1. Run the allowlist check alongside the existing KRAIT-001 through KRAIT-007
   denylist rules.
2. Log discrepancies where the allowlist would reject code that the denylist
   permits.
3. After a confidence period, promote the allowlist to primary enforcement.

## Decision

We skipped shadow mode and went directly to allowlist-primary enforcement.

The denylist was provably broken. Across 24 security hardening versions, each
adversarial audit found new bypass vectors at an ~82% discovery rate. The
denylist was not a trustworthy baseline to validate against -- shadow mode would
have been comparing a new system against a known-broken one.

Shadow mode adds implementation complexity:

- Dual validation paths that must be maintained in parallel.
- Log analysis infrastructure to review discrepancies at scale.
- A transition period where the security posture is ambiguous -- neither the old
  system nor the new system is authoritative.
- Risk of the shadow period extending indefinitely due to inertia.

The allowlist approach is structurally simpler to reason about: if a module is
not on the list of ~50 entries, it is rejected. False positives manifest as
compilation or test failures, which are immediately visible.

The existing denylist rules (KRAIT-001 through KRAIT-007) are retained as a
defense-in-depth layer in `Krait.Analyzer.Quick` and the Rust NIF. They still
run after the allowlist check passes. This provides a safety net without the
complexity of a formal shadow mode.

## Consequences

**Positive:**

- No ambiguous transition period. The security boundary is clearly defined from
  the moment the allowlist is deployed.
- No shadow-mode infrastructure to build, maintain, or decommission.
- Faster time to a trustworthy security posture.
- The denylist remains as defense-in-depth, not as a competing authority.

**Negative:**

- Any false positives in the allowlist block legitimate code immediately rather
  than being logged for later review. This was mitigated by testing the allowlist
  against all existing community skills before deployment.
- If the allowlist is too restrictive, it requires a code change and redeployment
  to expand (see ADR-002). This is accepted as intentional friction.
