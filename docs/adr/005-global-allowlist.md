# ADR-005: Global Allowlist, Not Per-Skill

## Status

Accepted

## Context

When designing the allowlist system (ADR-001), we considered whether the
allowlist should be global (one list for all generated skills) or per-skill
(each skill declares its own permitted modules).

A per-skill model would look like:

```elixir
defmodule Krait.Skills.Community.WeatherFetcher do
  @allowlist [:Enum, :Map, :Jason, :"Krait.Skills.Core.WebFetch"]
  # ...
end
```

This mirrors capability-based security where each component declares its
minimum required permissions. The per-skill approach has theoretical appeal:
a string-processing skill should not need network access, and a network skill
should not need filesystem access.

## Decision

The allowlist is global -- a single set of permitted modules defined in
`lib/krait/analyzer/allowlist.ex` and `native/krait_analyzer/src/allowlist.rs`,
applied uniformly to all agent-generated code.

Three factors drove this decision:

**1. Audit simplicity.** A single allowlist is one document to review. Per-skill
allowlists scatter the security boundary across potentially dozens of files,
each of which must be individually audited. The `.krait-immutable` manifest
protects one file path (`lib/krait/analyzer/allowlist.ex`), not N skill-specific
declarations.

**2. Privilege escalation prevention.** In a per-skill model, the agent
generates both the skill code and its allowlist declaration. A compromised LLM
output could request `@allowlist [:System, :Code, :File]` alongside benign-
looking code. The validator would need a meta-allowlist defining which modules
each skill is permitted to request -- recursing the problem.

With a global allowlist, the agent cannot influence what modules are permitted.
The allowlist is in `.krait-immutable` and the agent structurally cannot propose
changes to it.

**3. Capability system handles granular access.** Fine-grained access control
is handled by the capability system (`Krait.Skills.CapableSkill`,
`Krait.Skills.Capabilities.FilesystemCap`, `NetworkCap`, `MemoryCap`), not by
the allowlist. A skill that needs filesystem access uses `FilesystemCap` which
provides sandboxed, audited file operations. The allowlist's job is to prevent
direct access to dangerous primitives, not to implement per-skill least
privilege.

## Consequences

**Positive:**

- Single security boundary. One file to audit, one file to protect, one version
  hash in attestations (`Attestation.compute_allowlist_version/0`).
- No privilege escalation between skills. All skills operate within the same
  permitted surface.
- Simpler validator implementation. `Allowlist.allowed_module?/1` checks one
  set, not a skill-specific configuration.
- The `.krait-immutable` protection is straightforward: one path covers the
  entire allowlist.

**Negative:**

- A skill that only needs `Enum` and `Map` has access to all Tier 1 modules
  (including `Jason`, `URI`, `Regex`, etc.). Broader surface than strictly needed.
- The capability system must be trusted to enforce access boundaries for I/O
  and network. The allowlist prevents direct calls; capability enforcement is
  a separate layer.
- Adding a module to the global allowlist exposes it to all skills. Each
  addition requires careful review.
