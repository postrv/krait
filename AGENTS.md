This is a web application written using the Phoenix web framework.

## Security Architecture

KRAIT uses a **default-deny allowlist** as its primary security gate. Agent-generated code is validated by both an Elixir AST analyzer (`lib/krait/analyzer/quick.ex`) and a Rust NIF analyzer (`native/krait_analyzer/src/allowlist.rs`). Both must pass for code to be accepted.

### How Validation Works

1. **Allowlist gate (KRAIT-ALW)** — Every module, function, macro, and directive must be on the allowlist. Unknown modules are rejected immediately. This is the primary enforcement layer.
2. **KRAIT-003** — Credential path access (file operations targeting `~/.ssh`, `.env`, etc.)
3. **KRAIT-006** — Immutable path targeting (`native/`, `config/`, `.krait-immutable`, etc.)
4. **KRAIT-007** — Self-modification (references to `Krait.Evolution`, `Krait.Analyzer`, `KraitWeb`, etc.)

### Allowlist Definition

The allowlist is defined as **compile-time MapSets** in `lib/krait/analyzer/allowlist.ex` (Elixir) and **lazy-initialized HashSets** in `native/krait_analyzer/src/allowlist.rs` (Rust). There is no YAML configuration file — this was a deliberate architectural decision:

- **Compile-time guarantees**: Typos in module names are caught at compile time
- **No parsing dependency**: No YAML library needed, no runtime file access
- **Immutability**: Both files are in `.krait-immutable` — the agent cannot modify them

### What the Agent CAN Use

The allowlist permits 40 modules across 5 tiers:

- **Tier 1** (24 modules): Pure computation — `Enum`, `Map`, `List`, `String`, `Jason`, `Regex`, `Integer`, etc.
- **Tier 3** (8 modules): Safe Erlang — `:math`, `:lists`, `:maps`, `:binary`, `:rand`, `:calendar`, etc.
- **Tier 5** (8 modules): Krait framework — `Skill`, `WebFetch`, `Filesystem`, `MemorySkill`, `CapableSkill`, capability modules

Some functions on allowed modules are still denied (e.g., `String.to_atom/1`, `Stream.resource/3`).

### What the Agent CANNOT Use

Everything not on the allowlist is denied by default. This includes:

- `System`, `File`, `Process`, `Code`, `Node`, `Port`, `Task`, `Agent`, `GenServer`, `Supervisor`, `Application`
- All raw HTTP clients (`Req`, `HTTPoison`, `Finch`, `:httpc`, `:hackney`)
- All Erlang modules not in Tier 3 (`:os`, `:file`, `:code`, `:ets`, `:gen_tcp`, `:erlang`)
- Dangerous macros: `defmacro`, `defprotocol`, `defimpl`, `defoverridable`
- Compile hooks: `@before_compile`, `@after_compile`, `@on_load`
- Constructs: `receive` blocks, `quote` blocks

### Capability System

Skills declare required capabilities via `@behaviour Krait.Skills.CapableSkill`:

```elixir
@impl true
def required_capabilities, do: [:network, :memory]  # Only these two injected

@impl true
def execute(params, capabilities) do
  # capabilities.network and capabilities.memory available
  # capabilities.filesystem NOT available
end
```

Three capabilities exist: `:filesystem` (read/list), `:network` (fetch with SSRF protection), `:memory` (key-value store).

### Contributor Guidelines for Security Changes

- **Adding a module to the allowlist**: Edit both `lib/krait/analyzer/allowlist.ex` AND `native/krait_analyzer/src/allowlist.rs`. Add tests in both `test/krait/analyzer/allowlist_test.exs` and the Rust test suite. Both files are in `.krait-immutable` — requires human-only push.
- **Adding a new capability**: Create module in `lib/krait/skills/capabilities/`, register in `capability_injector.ex`, add tests. All paths are immutable.
- **Modifying KRAIT-003/006/007**: Edit both `quick.ex` and `rules.rs`. These are content-based checks that run after the allowlist.
- **Non-Elixir code**: Falls back to string-based pattern matching (`check_forbidden_patterns_string`). Deep analysis via Narsil MCP provides cross-language coverage.

### Testing Security Changes

```bash
# Allowlist-specific tests (194 tests)
mix test test/krait/analyzer/allowlist_test.exs test/krait/analyzer/allowlist_enforcement_test.exs test/krait/analyzer/allowlist_primary_test.exs test/krait/analyzer/allowlist_mode_test.exs

# Rust NIF allowlist tests (59 tests)
cd native/krait_analyzer && cargo test allowlist

# Full security test suite
mix test && cd native/krait_analyzer && cargo test && cargo clippy -- -D warnings
```

## Project guidelines

- Use `mix precommit` alias when you are done with all changes and fix any pending issues
- Use the already included and available `:req` (`Req`) library for HTTP requests, **avoid** `:httpoison`, `:tesla`, and `:httpc`. Req is included by default and is the preferred HTTP client for Phoenix apps

### Phoenix v1.8 guidelines

- **Always** begin your LiveView templates with `<Layouts.app flash={@flash} ...>` which wraps all inner content
- The `MyAppWeb.Layouts` module is aliased in the `my_app_web.ex` file, so you can use it without needing to alias it again
- Anytime you run into errors with no `current_scope` assign:
  - You failed to follow the Authenticated Routes guidelines, or you failed to pass `current_scope` to `<Layouts.app>`
  - **Always** fix the `current_scope` error by moving your routes to the proper `live_session` and ensure you pass `current_scope` as needed
- Phoenix v1.8 moved the `<.flash_group>` component to the `Layouts` module. You are **forbidden** from calling `<.flash_group>` outside of the `layouts.ex` module
- Out of the box, `core_components.ex` imports an `<.icon name="hero-x-mark" class="w-5 h-5"/>` component for for hero icons. **Always** use the `<.icon>` component for icons, **never** use `Heroicons` modules or similar
- **Always** use the imported `<.input>` component for form inputs from `core_components.ex` when available. `<.input>` is imported and using it will save steps and prevent errors
- If you override the default input classes (`<.input class="myclass px-2 py-1 rounded-lg">)`) class with your own values, no default classes are inherited, so your
custom classes must fully style the input


<!-- usage-rules-start -->

<!-- phoenix:elixir-start -->
## Elixir guidelines

- Elixir lists **do not support index based access via the access syntax**

  **Never do this (invalid)**:

      i = 0
      mylist = ["blue", "green"]
      mylist[i]

  Instead, **always** use `Enum.at`, pattern matching, or `List` for index based list access, ie:

      i = 0
      mylist = ["blue", "green"]
      Enum.at(mylist, i)

- Elixir variables are immutable, but can be rebound, so for block expressions like `if`, `case`, `cond`, etc
  you *must* bind the result of the expression to a variable if you want to use it and you CANNOT rebind the result inside the expression, ie:

      # INVALID: we are rebinding inside the `if` and the result never gets assigned
      if connected?(socket) do
        socket = assign(socket, :val, val)
      end

      # VALID: we rebind the result of the `if` to a new variable
      socket =
        if connected?(socket) do
          assign(socket, :val, val)
        end

- **Never** nest multiple modules in the same file as it can cause cyclic dependencies and compilation errors
- **Never** use map access syntax (`changeset[:field]`) on structs as they do not implement the Access behaviour by default. For regular structs, you **must** access the fields directly, such as `my_struct.field` or use higher level APIs that are available on the struct if they exist, `Ecto.Changeset.get_field/2` for changesets
- Elixir's standard library has everything necessary for date and time manipulation. Familiarize yourself with the common `Time`, `Date`, `DateTime`, and `Calendar` interfaces by accessing their documentation as necessary. **Never** install additional dependencies unless asked or for date/time parsing (which you can use the `date_time_parser` package)
- Don't use `String.to_atom/1` on user input (memory leak risk)
- Predicate function names should not start with `is_` and should end in a question mark. Names like `is_thing` should be reserved for guards
- Elixir's builtin OTP primitives like `DynamicSupervisor` and `Registry`, require names in the child spec, such as `{DynamicSupervisor, name: MyApp.MyDynamicSup}`, then you can use `DynamicSupervisor.start_child(MyApp.MyDynamicSup, child_spec)`
- Use `Task.async_stream(collection, callback, options)` for concurrent enumeration with back-pressure. The majority of times you will want to pass `timeout: :infinity` as option

## Mix guidelines

- Read the docs and options before using tasks (by using `mix help task_name`)
- To debug test failures, run tests in a specific file with `mix test test/my_test.exs` or run all previously failed tests with `mix test --failed`
- `mix deps.clean --all` is **almost never needed**. **Avoid** using it unless you have good reason

## Test guidelines

- **Always use `start_supervised!/1`** to start processes in tests as it guarantees cleanup between tests
- **Avoid** `Process.sleep/1` and `Process.alive?/1` in tests
  - Instead of sleeping to wait for a process to finish, **always** use `Process.monitor/1` and assert on the DOWN message:

      ref = Process.monitor(pid)
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}

   - Instead of sleeping to synchronize before the next call, **always** use `_ = :sys.get_state/1` to ensure the process has handled prior messages
<!-- phoenix:elixir-end -->

<!-- phoenix:phoenix-start -->
## Phoenix guidelines

- Remember Phoenix router `scope` blocks include an optional alias which is prefixed for all routes within the scope. **Always** be mindful of this when creating routes within a scope to avoid duplicate module prefixes.

- You **never** need to create your own `alias` for route definitions! The `scope` provides the alias, ie:

      scope "/admin", AppWeb.Admin do
        pipe_through :browser

        live "/users", UserLive, :index
      end

  the UserLive route would point to the `AppWeb.Admin.UserLive` module

- `Phoenix.View` no longer is needed or included with Phoenix, don't use it
<!-- phoenix:phoenix-end -->

<!-- usage-rules-end -->