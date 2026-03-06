# ADR-004: Metaprogramming Banned in Generated Skills

## Status

Accepted

## Context

Elixir's metaprogramming system (`defmacro`, `defmacrop`, `quote`, `unquote`,
`defprotocol`, `defimpl`, `defoverridable`, compile hook attributes) allows
code to generate code at compile time. This creates a fundamental conflict
with KRAIT's static analysis model.

`Krait.Evolution.Validator` analyzes the AST of proposed code before
compilation via `Macro.prewalk/3` (Elixir) and tree-sitter queries (Rust NIF).
This analysis is inherently pre-compilation.

Macros execute during compilation and can generate arbitrary code that is not
visible in the source AST. A macro like:

```elixir
defmacro safe_looking_helper(x) do
  quote do: System.cmd(unquote(x), [])
end
```

would pass AST analysis (the `quote` block is opaque to the walker) but produce
a `System.cmd` call at compile time, bypassing both the allowlist and denylist.
Similarly, `@before_compile` and `@on_load` hooks execute code outside the
validation window.

## Decision

The following constructs are banned in all agent-generated code:

- `defmacro` and `defmacrop` -- compile-time code generation
- `quote` blocks -- AST construction
- `defprotocol` and `defimpl` -- protocol dispatch (can introduce arbitrary
  module references at runtime)
- `defoverridable` -- callback override mechanism (can mask function behavior)
- `@before_compile`, `@after_compile`, `@on_load`, `@on_definition` -- compile
  hooks that execute code outside the validation window

Enforcement is implemented in three layers:

1. **Allowlist** (`lib/krait/analyzer/allowlist.ex`): `@denied_macros` MapSet
   contains `:defmacro` and `:defmacrop`. `@banned_compile_attrs` MapSet
   contains `:before_compile`, `:after_compile`, `:on_load`, `:on_definition`.
2. **Elixir analyzer** (`Krait.Analyzer.Quick`): AST walk detects macro
   definitions and compile hook attributes.
3. **Rust NIF** (`native/krait_analyzer/src/allowlist.rs`): `check_defmacro`
   uses string-based line scanning for `defmacro`, `defmacrop`, `defprotocol`,
   `defimpl`, `defoverridable`, and compile hook attributes. `check_quote_blocks`
   and `check_receive_blocks` detect `quote do` and `receive do` patterns.

The allowed structural macros are limited to: `def`, `defp`, `defmodule`,
`defstruct`, `defguard`, `defguardp`, `defexception` (defined in
`@allowed_macros` in `lib/krait/analyzer/allowlist.ex`).

## Consequences

**Positive:**

- Static analysis results are trustworthy. What the validator sees in the AST
  is what will execute at runtime.
- No compile-time code injection vectors. The agent cannot generate code that
  produces different behavior when compiled than what was analyzed.
- The banned list is small and well-understood. Legitimate skills do not need
  metaprogramming -- they implement the `Krait.Skills.Skill` behaviour with
  `def`/`defp` functions.

**Negative:**

- Skills cannot define domain-specific macros, custom protocols, or use
  `defoverridable`. All behavior must be expressed through regular functions.
- Some Elixir idioms (e.g., `use` with `__using__` macros) are restricted.
  Skills can only `use` allowlisted modules like `Krait.Skills.CapableSkill`.
- Protocol-based polymorphism is unavailable. Skills must use pattern matching
  or behaviour callbacks instead.
