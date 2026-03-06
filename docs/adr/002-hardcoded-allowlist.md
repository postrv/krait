# ADR-002: Hardcoded Allowlist in Module Attributes, Not YAML

## Status

Accepted

## Context

With the decision to adopt an allowlist model (ADR-001), the question arose of
where to define the allowlist. Three options were considered:

1. **External YAML/JSON file** loaded at runtime (e.g., `rules/allowlist.yaml`)
2. **Database table** with admin UI for live editing
3. **Hardcoded module attributes** compiled into the analyzer binary

External configuration files introduce deserialization as an attack surface.
YAML parsing in particular has a history of deserialization vulnerabilities
(arbitrary object instantiation, anchor/alias bombs). A YAML allowlist would
need to be parsed by `yaml_elixir`/`yamerl` at runtime, adding a dependency
in the critical security path. An attacker who could write to the YAML file
could add `System` or `Code` to the allowlist and bypass all protection.

A database-backed allowlist adds latency to every validation check and creates
a new privilege escalation vector: anyone with database write access can modify
the security boundary.

## Decision

The allowlist is defined as compile-time module attributes in two source files:

- `lib/krait/analyzer/allowlist.ex` -- `@tier_1_modules`, `@tier_3_erlang_modules`,
  `@tier_5_krait_modules`, `@denied_kernel_functions`, `@allowed_macros`,
  `@allowed_attrs`, etc. as `MapSet.new([...])` literals.
- `native/krait_analyzer/src/allowlist.rs` -- `ALLOWED_ELIXIR_MODULES`,
  `ALLOWED_ERLANG_MODULES`, `ALLOWED_KRAIT_MODULES`, `DENIED_KERNEL_FUNCTIONS`
  as `&[&str]` constants, lazy-initialized into `HashSet<String>` via `OnceLock`.

Both files are listed in `.krait-immutable`, which means the agent's evolution
system structurally cannot propose changes to them. Modifications require human
review through the "Constitutional Convention" process (documented in
`.krait-immutable` header).

Lookups are O(1) via `MapSet.member?/2` (Elixir) and `HashSet::contains`
(Rust), with zero runtime I/O or deserialization.

## Consequences

**Positive:**

- No deserialization attack surface. The allowlist is parsed by the Elixir/Rust
  compiler, not a runtime YAML parser.
- O(1) lookup with zero allocation per check. Module attributes are compiled
  into the BEAM bytecode; Rust constants are initialized once via `OnceLock`.
- Changes to the allowlist require a code change, a compilation, and deployment.
  This creates an auditable trail in git history.
- `.krait-immutable` enforcement prevents the agent from self-modifying its own
  security boundary.
- `Krait.Evolution.Attestation.compute_allowlist_version/0` hashes both source
  files (`lib/krait/analyzer/allowlist.ex` + `native/krait_analyzer/src/allowlist.rs`)
  to produce a deterministic version string embedded in every attestation.

**Negative:**

- Adding a new module to the allowlist requires a code change and redeployment.
  This is intentional friction, not a bug.
- The allowlist cannot be updated without restarting the application. Hot-patching
  the security boundary is explicitly not supported.
- Operators who need project-specific extensions must fork or configure Tier 4
  (`@tier_4_deps` / `ALLOWED_KRAIT_MODULES`) before deployment.
