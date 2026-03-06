# ADR-001: Allowlist Over Denylist for Code Validation

## Status

Accepted

## Context

KRAIT's evolution system generates Elixir code via LLM and deploys it as new
skills. The validator pipeline (`Krait.Evolution.Validator`) must ensure that
generated code cannot access dangerous modules, functions, or system primitives.

From v1 through v24 of security hardening, the project used a denylist approach:
explicitly enumerating forbidden calls (KRAIT-001 through KRAIT-007 rules) in
`Krait.Analyzer.Quick` and the Rust NIF (`native/krait_analyzer/src/rules.rs`).
Each audit cycle discovered new bypass vectors:

- v1: `Code.eval_string`, `System.cmd`, `:erlang.open_port`
- v5: `&System.cmd/2` capture shorthand, integer list construction
- v7: `Module.concat`, runtime string construction, integer sequence encoding
- v8: `apply(:os, :cmd, ...)`, `defdelegate to: :os`, `:"Elixir.System"` quoted atoms
- v17: `Kernel.spawn`, `@before_compile`, `receive`, `quote`, `defprotocol`, variable dispatch

The pattern was clear: every hardening round added 5-15 new bypass detections.
Across 24 versions, the denylist grew from ~20 entries to 100+ forbidden patterns
while new evasion techniques were discovered at an ~82% bypass rate per audit
cycle. The denylist was fundamentally unbounded -- an attacker only needs to find
one pattern not yet enumerated.

## Decision

We inverted the security model from denylist to allowlist. Rather than
enumerating what is forbidden, we enumerate what is permitted. Everything not
explicitly on the allowlist is denied by default.

The allowlist is implemented in two parallel modules that must stay in sync:

- `lib/krait/analyzer/allowlist.ex` -- Elixir module with compile-time MapSets
- `native/krait_analyzer/src/allowlist.rs` -- Rust NIF with HashSets

Both are protected by `.krait-immutable` and cannot be modified by the agent.

The allowlist is organized in five tiers:

1. Pure computation (Enum, Map, String, Jason, etc.)
2. Restricted Kernel (arithmetic, guards, control flow -- no spawn/send/apply)
3. Safe Erlang (:math, :lists, :maps, :binary, :rand, etc.)
4. Approved external dependencies (initially empty)
5. Krait framework interfaces (Skill behaviour, capability modules)

The existing denylist rules (KRAIT-001 through KRAIT-007) remain as a defense-
in-depth layer. The allowlist check (`KRAIT-ALW`) runs first and rejects any
module not on the list before the denylist rules even execute.

## Consequences

**Positive:**

- Unknown bypass vectors are blocked by default -- new evasion techniques cannot
  reference modules not on the allowlist regardless of encoding or indirection.
- Audit scope is finite and reviewable: the allowlist is ~50 modules total.
- Adding a new allowed module is an explicit, auditable decision.
- Security hardening cycles shift from reactive (finding bypasses) to proactive
  (reviewing allowlist additions).

**Negative:**

- Generated skills are constrained to the allowlisted surface. Skills that need
  HTTP, file I/O, or process management must use Krait capability interfaces
  (`FilesystemCap`, `NetworkCap`, `MemoryCap`) rather than direct stdlib calls.
- The allowlist must be maintained in two languages (Elixir and Rust). Drift
  between the two implementations is detected by `Attestation.compute_allowlist_version/0`
  which hashes both source files.
- Existing community-contributed skills may need refactoring if they used modules
  outside the allowlist.
