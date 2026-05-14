# KRAIT

**Kill-switched, Reproducible, Auditable, Intelligent Taskrunner**

A self-evolving **polyglot** AI agent built with Elixir/OTP + Rust NIF + Narsil-MCP. KRAIT proposes, validates, and deploys new capabilities in **6 languages** (Elixir, Python, JavaScript, TypeScript, Go, Rust) through a human-gated evolution loop. The agent is a **contributor with no merge rights** — every self-modification is a signed Git commit with a full AST diff, verifiable by anyone.

> *"Immutable Core, Mutable Periphery."*

## Architecture

```
                    +-------------------+
                    |    Gateway        |
                    |  Telegram/Webhook |
                    +--------+----------+
                             |
                    +--------v----------+
                    |    Brain (ReAct)   |
                    |  LLM + Skills     |
                    +--------+----------+
                             |
              +--------------+--------------+
              |              |              |
     +--------v---+  +------v------+  +----v-------+
     | Skills     |  | Memory      |  | Evolution  |
     | Core +     |  | Hot (ETS)   |  | Propose -> |
     | Community  |  | Cold (PG)   |  | Validate ->|
     +------------+  +-------------+  | Deploy     |
                                      +-----+------+
                                            |
                          +-----------------+---------+
                          |                           |
                 +--------v--------+         +--------v--------+
                 | Narsil Analyzer |         | GitHub API      |
                 | NIF / MCP /     |         | Branch -> PR    |
                 | Sandbox         |         +-----------------+
                 +-----------------+
```

### Three Planes of Operation

| Plane | Technology | Purpose |
|-------|-----------|---------|
| **Control** | Elixir/OTP | Brain, Gateway, Memory, Skills, Evolution, Kill Switch |
| **Analysis** | Rust NIF + Narsil-MCP | AST security scanning in 3 modes |
| **Sandbox** | Docker + FLAME | Ephemeral containers for code testing |

### Analysis Modes

| Mode | Latency | Use Case |
|------|---------|----------|
| **NIF** (Rust tree-sitter) | <5ms | Every code generation — syntax + allowlist + KRAIT rules + BLAKE3 hash. 6 languages: Elixir, Python, JS/TS, Go, Rust |
| **MCP Sidecar** (Narsil) | 100ms-5s | Deep scan — OWASP/CWE rules, taint analysis, call graphs |
| **Sandbox Scan** (Narsil in Docker) | 5-30s | Full-project cross-file analysis after code applied |

### LLM Backend

KRAIT uses **OpenRouter** as its cloud LLM backend, providing access to multiple AI providers through a single OpenAI-compatible API. The LLM Router (`Krait.LLM.Router`) dispatches requests to either a local Ollama instance or the OpenRouter cloud, with automatic escalation when local quality scores fall below threshold.

| Feature | Description |
|---------|-------------|
| **Multi-model selection** | Pass `models: ["anthropic/claude-sonnet-4.5", "openai/gpt-4o"]` for automatic fallback |
| **Provider preferences** | Control provider priority, cost caps, and data collection opt-out |
| **Cost tracking** | Every response includes `usage.cost` from OpenRouter's billing API |
| **Credit monitoring** | `check_credits/1` queries account balance via `GET /api/v1/key` |
| **Local/cloud routing** | Ollama handles simple tasks; OpenRouter handles complex ones via quality gate escalation |

**Default model:** `anthropic/claude-sonnet-4.5` via OpenRouter

**Message format:** KRAIT uses Anthropic-native content blocks internally (text, tool_use, tool_result). The OpenRouter module translates to/from OpenAI format at the API boundary. This keeps the internal message pipeline consistent regardless of which provider serves the request.

**Migration note:** `ANTHROPIC_API_KEY` is accepted as a fallback if `OPENROUTER_API_KEY` is not set. The deprecated `Krait.LLM.Claude` module is retained for backward compatibility.

## Quick Start

### Quickstart (Docker — 5 minutes)

```bash
git clone https://github.com/postrv/krait.git && cd krait
echo "OPENROUTER_API_KEY=sk-or-your-key" > .env
docker compose -f docker-compose.quickstart.yml up
# → KRAIT running at localhost:4000 with PostgreSQL, seed skills, dry-run mode
# → Auto-generates all secrets, runs migrations, seeds demo data
```

### Development Setup

```bash
# Prerequisites: Elixir 1.15+, Rust, PostgreSQL, Docker (optional)
git clone https://github.com/postrv/krait.git && cd krait

# Install dependencies
mix deps.get
mix compile

# Set up database
mix ecto.create && mix ecto.migrate

# Configure (see .env.example for all options)
export OPENROUTER_API_KEY=your-openrouter-key

# Run
mix phx.server
```

### Production Deployment

```bash
# Generate all production secrets
scripts/setup-prod-secrets.sh

# Start production stack (PostgreSQL + DinD sidecar + KRAIT)
docker compose -f docker-compose.prod.yml up -d
```

See [docs/tutorial-first-evolution.md](docs/tutorial-first-evolution.md) for a complete walkthrough from clone to first approved evolution.

## Configuration

See `.env.example` for all options.

```bash
# Required
OPENROUTER_API_KEY=sk-or-...        # OpenRouter API key for brain + evolution (multi-model)

# Authentication (required in production)
KRAIT_API_TOKEN=your-secure-token   # Bearer token for /api endpoints (min 32 chars in prod)
KRAIT_ADMIN_TOKEN=your-admin-token  # Separate admin token for /admin + LiveView (min 32 chars)

# GitHub App (enables real PRs — omit for dry-run mode)
GITHUB_APP_ID=12345
GITHUB_APP_PRIVATE_KEY_PATH=/path/to/key.pem
KRAIT_REPO_NAME=your-org/krait

# Narsil (deep security analysis — optional, graceful degradation)
NARSIL_BINARY=/path/to/narsil-mcp

# Production Narsil image pin
NARSIL_VERSION=1.7.0
NARSIL_SHA256=<sha256 for narsil-mcp-x86_64-unknown-linux-gnu v1.7.0>

# Ollama (local LLM — optional, falls back to OpenRouter cloud)
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5-coder:14b

# Production (all required)
SECRET_KEY_BASE=...                 # mix phx.gen.secret
LIVE_VIEW_SALT=...                  # mix phx.gen.secret 32
SESSION_SIGNING_SALT=...            # mix phx.gen.secret 32
SESSION_ENCRYPTION_SALT=...         # mix phx.gen.secret 32
ADMIN_SESSION_SALT=...              # mix phx.gen.secret 32
DATABASE_URL=ecto://USER:PASS@HOST/DATABASE

# Security
ERL_CRASH_DUMP=/dev/null            # Prevent sensitive state in crash dumps
```

## Security Model

KRAIT uses a **default-deny allowlist architecture** for code validation. Every module, function, macro, and directive in agent-generated code must be explicitly allowed. This inverts the traditional denylist approach — instead of trying to block every dangerous API (an impossible task), KRAIT permits only a curated set of safe operations.

The allowlist runs as the **primary gate** in both analyzers (Elixir AST + Rust tree-sitter NIF). Three defense-in-depth rules (KRAIT-003, KRAIT-006, KRAIT-007) run after the allowlist to check content and intent that module-level allowlisting cannot catch.

### Allowlist Architecture (KRAIT-ALW)

The allowlist is defined as compile-time MapSets in Elixir (`lib/krait/analyzer/allowlist.ex`) and lazy-initialized HashSets in Rust (`native/krait_analyzer/src/allowlist.rs`). Both are byte-for-byte synchronized. This design was chosen over a YAML configuration file for three reasons: compile-time guarantees, no YAML parsing dependency, and no runtime file access.

**5-Tier Module Allowlist:**

| Tier | Count | Contents | Examples |
|------|-------|----------|----------|
| 1. Pure Computation | 26 | Safe Elixir stdlib | `Enum`, `Map`, `List`, `String`, `Jason`, `Regex`, `URI`, `Kernel` |
| 2. Restricted Kernel | 29 denied | Kernel functions denied by name | `spawn`, `send`, `apply`, `exit`, `node`, `dbg`, `struct!`, `tap` |
| 3. Safe Erlang | 9 | Side-effect-free Erlang modules | `:math`, `:lists`, `:maps`, `:binary`, `:rand`, `:calendar`, `:base64` |
| 4. Approved Deps | 0 | External packages (empty, future use) | -- |
| 5. Krait Framework | 8 | Agent-accessible Krait modules | `Skill`, `WebFetch`, `Filesystem`, `MemorySkill`, caps |

**Denied-on-Allowed Patterns:** Some functions on otherwise-allowed modules are denied:
- `String.to_atom/1`, `String.to_existing_atom/1` (atom table exhaustion)
- `Stream.resource/3`, `Stream.run/1`, `Stream.repeatedly/1`, `Stream.iterate/2`, `Stream.unfold/2` (arbitrary side effects)

**Structural Controls:**
- **Allowed macros:** `def`, `defp`, `defmodule`, `defstruct`, `defguard`, `defguardp`, `defexception`
- **Banned macros:** `defmacro`, `defmacrop`, `defprotocol`, `defimpl`, `defoverridable`
- **Banned compile hooks:** `@before_compile`, `@after_compile`, `@on_load`, `@on_definition`
- **Banned constructs:** `receive` blocks, `quote` blocks

### Capability System

Skills declare their required capabilities via the `CapableSkill` behaviour. The `CapabilityInjector` maps capability names to sandboxed implementation modules at runtime, enforcing principle of least privilege:

| Capability | Module | Operations | Guardrails |
|-----------|--------|------------|------------|
| `:filesystem` | `FilesystemCap` | `read/1`, `list/1` | Blocks `~/` paths, `/proc`, `/sys`, `/dev`; delegates to sandboxed `Filesystem` skill |
| `:network` | `NetworkCap` | `fetch/1` | Domain allowlist, SSRF protection (DNS pinning, IPv6 blocking, redirect disabled) |
| `:memory` | `MemoryCap` | `read/1`, `write/2`, `list/0` | Key-value only, ETS hot + PostgreSQL cold storage |

A skill requesting only `[:network]` physically cannot access the filesystem.

### Defense-in-Depth Rules

These rules run **after** the allowlist passes, catching intent that module-level checking cannot:

| Rule | ID | What It Catches |
|------|----|-----------------|
| No Credential Access | KRAIT-003 | File operations targeting `~/.ssh`, `~/.aws`, `/etc/shadow`, `.env`, etc. (compound check: file op + credential path) |
| No Immutable Paths | KRAIT-006 | Code targeting `native/`, `.krait-immutable`, `config/`, `mix.exs`. Detects `Path.join`, `<>`, integer sequence encoding, charlist/sigil evasion |
| No Self-Modification | KRAIT-007 | References to `Krait.Evolution`, `Krait.Analyzer`, `Krait.Sandbox`, `KraitWeb`, etc. Detects `:"Elixir.Krait.*"` quoted atom bypass |

### Evasion Detection

The allowlist detects 10+ indirection patterns that attempt to bypass module-level checks:

- **Import/alias/use bypass**: `import System, only: [cmd: 2]`
- **Bare atom indirection**: `apply(:os, :cmd, [~c"whoami"])`
- **Variable indirection**: `mod = System; mod.cmd("ls", [])`
- **Quoted atoms**: `:"Elixir.System".cmd("ls", [])`
- **Module attribute indirection**: `@target :os; @target.cmd("ls")`
- **Integer list encoding**: `[83,121,115,116,101,109]` decoding to forbidden modules
- **`defdelegate` bypass**: `defdelegate my_cmd(c), to: :os`
- **Capture shorthand**: `&System.cmd/2`, `&apply/3`
- **`Function.capture/3`**: `Function.capture(:os, :cmd, 1)`
- **String construction**: `Path.join`, `Enum.join`, `Enum.map_join`, `<>` building forbidden paths
- **Tuple/list destructuring**: `{m, f} = {System, :cmd}; m.f()`

### Polyglot Security Analysis

The Rust NIF includes **per-language tree-sitter parsers** for 6 languages, each with adapted KRAIT rule implementations:

| Language | Parser | Rules Enforced | Allowlist |
|----------|--------|----------------|-----------|
| **Elixir** | tree-sitter-elixir | Full AST: ALW + KRAIT-001..007 + evasion detection | 5-tier module allowlist |
| **Python** | tree-sitter-python | KRAIT-001..007 + ALW (forbidden imports: `ctypes`, `socket`, etc.) | Import-based |
| **JavaScript** | tree-sitter-javascript | KRAIT-001..007 + ALW (forbidden requires: `fs`, `net`, etc.) | Require/import-based |
| **TypeScript** | tree-sitter-typescript | Same as JS (separate grammar for correct query dispatch) | Require/import-based |
| **Go** | tree-sitter-go | KRAIT-001..007 + ALW (forbidden imports: `os`, `unsafe`, etc.) | Import-based |
| **Rust** | tree-sitter-rust | KRAIT-002..007 + ALW (forbidden uses: `std::fs`, `std::net`, etc.) | Use-based |

Each language module checks all 7 KRAIT rules using language-appropriate AST patterns (e.g., Python's `eval()`/`exec()` for KRAIT-001, Go's `os/exec` import for KRAIT-002). The `LanguageRules` trait in `native/krait_analyzer/src/lang/mod.rs` defines the common interface.

A string-based fallback (`check_forbidden_patterns_string`) provides defense-in-depth for edge cases. Deep analysis via Narsil MCP provides cross-language coverage.

### Kill Switch

KRAIT includes a production kill switch (`Krait.KillSwitch`) that can halt all evolution activity:

- **Circuit breaker**: Auto-trips after configurable consecutive failures (default: 5)
- **Manual control**: `POST /api/admin/kill-switch/halt` and `/resume` endpoints
- **Persistence**: State persisted to PostgreSQL, survives restarts
- **Graceful shutdown**: `application.ex` halts the kill switch and drains in-flight evolutions (30s timeout) on SIGTERM
- **Fail-closed**: All evolution requests return `{:error, :system_halted}` when engaged

### Cryptographic Attestation

Every evolution PR includes an Ed25519-signed attestation capturing:
- AST hash (BLAKE3), cyclomatic complexity, security findings count, taint flow count
- LLM model used, prompt hash (SHA256), allowlist version hash
- Verifiable via `mix krait.verify <commit_sha>` — extracts attestation from commit message and verifies signature

### Immutable Core

Files listed in `.krait-immutable` (30 path prefixes) cannot be targeted by agent-generated code. Updates require a **"Constitutional Convention"** — human-only, manual push:

```
native/                              # Rust NIF source
rules/                               # Narsil rule definitions
.krait-immutable                     # This manifest
AGENTS.md                            # Contributor security guidance
lib/krait/analyzer/                  # Allowlist + analyzers
lib/krait/analyzer/allowlist.ex      # 5-tier module/function allowlist
lib/krait/evolution/validator.ex     # Validation pipeline
lib/krait/evolution/deployer.ex      # Deployment pipeline
lib/krait/evolution/promotion_decision.ex
lib/krait/evolution/review_evidence.ex
lib/krait/evolution/evolution.ex     # Evolution orchestrator
lib/krait/evolution/naming.ex        # Skill name validation
lib/krait/sandbox/                   # Docker sandboxing
lib/krait/setup_validation.ex        # Operator release validation
lib/mix/tasks/                       # Release/security mix tasks
docs/adr/                            # Architecture decision records
lib/krait/brain/                     # ReAct cognitive loop
lib/krait/gateway/                   # Channel routing
lib/krait/llm/                       # LLM abstraction
lib/krait/skills/core/               # Core skills
lib/krait/skills/capable_skill.ex    # Capability behaviour
lib/krait/skills/capability_injector.ex
lib/krait/skills/capabilities/       # Cap implementations
lib/krait/github/                    # GitHub integration
lib/krait/security/                  # Security utilities
lib/krait/application.ex             # Supervisor tree
lib/krait_web/                       # Web layer
config/                              # All configuration
mix.exs                              # Project definition
mix.lock                             # Dependency lockfile
```

## Production Readiness

**Current status (May 14, 2026): conservative v0.1 release candidate**

KRAIT's shippable release model is human-gated PR evolution: the agent proposes
reviewable changes, humans merge them, and new capabilities take effect on the
next deploy. Promotion-gated auto-merge and BEAM hot activation are tracked as
forward-looking work in ADR-008; they are not part of the current release
contract.

| Area | Status | Detail |
|------|--------|--------|
| **Code Quality** | 9.5/10 | 1,916 Elixir tests + 199 Rust NIF tests, Credo strict clean, Clippy clean |
| **Security** | 9/10 | 27 hardening rounds, dual-engine allowlist, Ed25519 attestation, 10+ evasion detection patterns |
| **Polyglot** | Complete | 6-language NIF (Elixir, Python, JS/TS, Go, Rust), per-language tree-sitter parsers, language-aware evolution pipeline |
| **Seed Content** | Complete | 5 community skills (text_transform, math_utils, json_tools, date_helper, code_metrics) — 91 tests |
| **Documentation** | 9/10 | README, AGENTS.md, CONTRIBUTING.md, SECURITY.md, 8 ADRs, release-readiness review, secret management guide, first evolution tutorial, issue/PR templates |
| **Deployment** | 92% | Production + quickstart Docker Compose, CD pipeline (GHCR), secret provisioning, release module |
| **Observability** | 25% | Evolution telemetry only. Missing: validation/kill-switch/LLM telemetry, Prometheus, alerting docs |
| **CI/CD** | 60% | 7 CI jobs + CD pipeline. Missing: prod smoke test, pre-release script |

## Testing

```bash
# Unit tests (1916 tests, 39 excluded for integration/docker/narsil/pgvector)
mix test

# Include integration tests (requires running services)
mix test --include integration

# Include Narsil deep scan tests
mix test --include narsil_required

# Include Docker sandbox tests
mix test --include docker_required

# Rust NIF tests (199 tests — rules + allowlist + polyglot)
cd native/krait_analyzer && cargo test

# Rust linting
cd native/krait_analyzer && cargo clippy -- -D warnings

# Full precommit check
mix precommit
```

## Supervisor Tree

The OTP supervisor tree (`lib/krait/application.ex`) starts 14 children:

**Base children (always started):**
1. `KraitWeb.Telemetry` — Telemetry event handlers
2. `Krait.Repo` — Ecto database connection pool
3. `DNSCluster` — DNS-based cluster discovery
4. `Phoenix.PubSub` — PubSub for LiveView and channels
5. `Krait.KillSwitch` — Kill switch GenServer (skip_db in test)
6. `Krait.TaskSupervisor` — Task.Supervisor for evolution workers

**Conditional workers (when `start_workers: true`, default in non-test):**
7. `Krait.LLM.QualityGate` — LLM response quality scoring
8. `Krait.Memory.Hot` — ETS-backed hot memory (protected table)
9. `Krait.Skills.Registry` — Skill registry with Evolve skill

**ETS-owning GenServers (must start before Endpoint):**
10. `KraitWeb.RateLimitCounter` — Rate limit counters
11. `Krait.HealthCacheServer` — Ollama health cache
12. `Krait.EvolveCooldownServer` — Evolution slot management

**Optional:**
13. `Krait.Analyzer.Deep` — Narsil MCP sidecar (only if binary found)

**Last:**
14. `KraitWeb.Endpoint` — Phoenix web server

**Production boot validations (10 checks):**
- Session signing/encryption salts not using dev defaults
- LiveView signing salt not using dev default
- Admin session salt configured
- Filesystem sandbox root explicitly configured
- Secret key base not using known dev values
- Dedicated admin token configured (separate from API token)
- API and admin tokens minimum 32 characters
- `allow_local_execution` must be false (double-confirmation with `accept_host_execution_risk`)
- Trusted proxies configured (warning if empty)
- NIF binary integrity verification (SHA256)

**Graceful shutdown:** `prep_stop/1` halts the kill switch and polls `EvolveCooldownServer` every 500ms until all in-flight evolutions drain (30s timeout).

## API Endpoints

| Method | Path | Auth | Rate Limit | Description |
|--------|------|------|------------|-------------|
| `GET` | `/health` | - | - | Liveness probe |
| `GET` | `/health/ready` | - | - | Readiness probe (DB + kill switch) |
| `GET` | `/health/evolution` | Bearer token | - | Evolution subsystem status |
| `POST` | `/api/evolve` | Bearer token | 10 req/min | Trigger evolution cycle |
| `GET` | `/api/feed` | Bearer token | 30 req/min | Get evolution event feed |
| `POST` | `/api/admin/kill-switch/halt` | Bearer token | 2 req/min | Halt all evolutions |
| `POST` | `/api/admin/kill-switch/resume` | Bearer token | 2 req/min | Resume evolutions |
| `GET` | `/api/admin/kill-switch/status` | Bearer token | 10 req/min | Kill switch status |
| `GET` | `/admin/login` | - | - | Admin login page |
| `POST` | `/admin/login` | - | Lockout (5 attempts) | Admin login submit |
| `DELETE` | `/logout` | Admin session | - | Admin logout |
| `GET` | `/` | Admin session | - | LiveView evolution dashboard |
| `GET` | `/evolution` | Admin session | - | LiveView evolution dashboard |

## Project Structure

```
lib/
  krait/
    analyzer/              # Security analysis engine
      allowlist.ex         # 5-tier module/function allowlist (compile-time MapSets)
      quick.ex             # Elixir AST analyzer (Macro.prewalk, allowlist + KRAIT-003/006/007)
      quick_behaviour.ex   # Behaviour for mock injection
      nif.ex               # Rust NIF bridge (falls back to Quick if not loaded)
      deep.ex              # Narsil MCP sidecar client (OWASP/CWE scanning)
      deep_behaviour.ex    # Behaviour for mock injection
      deep_stub.ex         # Dev stub (when Narsil unavailable)
      policy.ex            # Policy engine (combines Quick + Deep results)
    brain/                 # ReAct cognitive loop
      brain.ex             # Core agent loop (observe -> think -> act)
      planner.ex           # Multi-step task decomposition
      reflector.ex         # Post-action learning / memory storage
      prompt_builder.ex    # Prompt template construction
    evolution/             # Self-modification lifecycle
      attestation.ex       # Ed25519 signed attestation (AST hash, complexity, model, prompt hash)
      proposer.ex          # LLM-driven code generation with prompt injection defense
      validator.ex         # NIF quick -> MCP deep validation pipeline
      deployer.ex          # Git branch -> PR creation
      workspace.ex         # Workspace management with symlink validation + Docker hardening
      naming.ex            # Skill name validation (path traversal prevention)
      feed.ex              # Ecto-backed evolution event log
      spec.ex              # Evolution specification struct
      result.ex            # Evolution result struct
      event_schema.ex      # Ecto schema for events
      evolution.ex         # Orchestrator (propose -> validate -> deploy)
    gateway/               # Multi-channel message routing
      router.ex            # Channel -> Brain message routing (max 100 concurrent)
      channel.ex           # Channel behaviour
      channels/
        telegram.ex        # Telegram bot adapter (token wrapped in closure)
        webhook.ex         # Generic webhook with HMAC verification + payload sanitization
        console.ex         # Dev console adapter
    github/                # GitHub App integration
      auth.ex              # JWT generation + installation token rotation (Joken)
      client.ex            # Req-based GitHub REST API (redirect-disabled)
      client_behaviour.ex
      dry_run_client.ex    # Dev stub (logs instead of calling GitHub)
      pr_renderer.ex       # PR body Markdown generation
    kill_switch.ex         # Kill switch GenServer (circuit breaker + manual halt + DB persistence)
    kill_switch_state.ex   # Kill switch Ecto schema
    llm/                   # LLM abstraction with failover
      router.ex            # Local/cloud routing with escalation + SSRF validation
      openrouter.ex        # OpenRouter cloud backend (OpenAI-compatible, multi-model, cost tracking)
      claude.ex            # Claude API client (deprecated — kept for backward compat)
      ollama.ex            # Ollama local LLM client with health caching
      quality_gate.ex      # Response quality scoring + escalation trigger (GenServer)
      behaviour.ex         # LLM behaviour for mock injection
    memory/                # Dual-layer memory
      hot.ex               # ETS-backed hot memory (protected table, GenServer writes)
      cold.ex              # PostgreSQL + pgvector cold storage
      guard.ex             # Memory access control (credential filtering)
      memory_schema.ex     # Ecto schema
    sandbox/               # Docker/FLAME sandboxing
      workspace.ex         # Sandbox workspace with path containment + symlink validation
      full_scan.ex         # Narsil full-project scan inside container
      docker_backend.ex    # FLAME backend for Docker (DinD sidecar, network mode allowlist)
    security/              # Security utilities
      atomic_write.ex      # Atomic file writes (temp + rename)
      nif_integrity.ex     # NIF binary SHA256 verification at boot
      path_resolver.ex     # Symlink resolution + path containment
      prompt_sanitizer.ex  # Prompt injection defense (XML delimiters, pattern stripping, bidi char removal)
    skills/                # Capability system
      capable_skill.ex     # CapableSkill behaviour (declare required capabilities)
      capability_injector.ex # Maps capability names -> sandboxed modules
      registry.ex          # Skill registry (core + community)
      skill.ex             # Skill behaviour
      capabilities/
        filesystem_cap.ex  # Sandboxed filesystem (read, list)
        network_cap.ex     # Sandboxed network (fetch with SSRF protection)
        memory_cap.ex      # Sandboxed memory (read, write, list)
      community/
        text_transform.ex  # String manipulation (reverse, ROT13, case conversion, etc.)
        math_utils.ex      # Statistical functions (mean, median, std_dev, percentile)
        json_tools.ex      # JSON path extraction, validation, flattening
        date_helper.ex     # Relative date parsing, format validation
        code_metrics.ex    # LoC/function count via :filesystem capability
      core/
        evolve.ex          # Self-evolution skill
        web_fetch.ex       # HTTP fetch with domain allowlist + SSRF protection
        filesystem.ex      # Sandboxed filesystem operations
        memory_skill.ex    # Memory read/write skill
    application.ex         # Supervisor tree (14 children) + production validations + graceful shutdown
    evolve_cooldown_server.ex  # ETS-owning GenServer for evolution slot management
    health_cache_server.ex     # ETS-owning GenServer for Ollama health caching
    release.ex             # Release task helpers (migrate, rollback, health_check, seed)
    repo.ex                # Ecto Repo
  krait_web/
    auth.ex              # Admin authentication (token-based session management)
    endpoint.ex          # Phoenix endpoint with RuntimeSession plug
    router.ex            # API + admin + browser routes with rate limiting
    telemetry.ex         # Telemetry events
    rate_limit_counter.ex # ETS-owning GenServer for rate limit counters
    plugs/
      api_auth.ex        # Bearer token auth (timing-safe comparison)
      rate_limit.ex      # ETS-based rate limiter with probabilistic cleanup
      require_admin_auth.ex  # Admin session verification plug
      runtime_session.ex # Runtime session salt injection (prevents compile-time secrets)
    controllers/
      evolution_controller.ex      # POST /api/evolve, GET /api/feed
      health_controller.ex         # GET /health, /health/ready, /health/evolution
      kill_switch_controller.ex    # POST halt/resume, GET status
      admin_session_controller.ex  # Admin login/logout with lockout protection
      error_json.ex                # JSON error renderer
    live/
      evolution_live.ex  # LiveView evolution dashboard (periodic session re-verify)
    components/
      layouts.ex         # LiveView layouts
  mix/
    tasks/
      krait.seed_feed.ex              # Mix task: seed evolution feed with sample data
      krait.verify.ex                 # Mix task: verify Ed25519 attestation on commits
      krait.rotate_attestation_key.ex # Mix task: rotate attestation keypair

native/
  krait_analyzer/        # Rust NIF (tree-sitter + BLAKE3)
    src/
      lib.rs             # NIF entry points (quick_validate, validate_code)
      allowlist.rs       # Module/function allowlist (mirrors allowlist.ex, 59 tests)
      rules.rs           # Elixir KRAIT-003/006/007 + 85 tests, tree-sitter queries
      complexity.rs      # Cyclomatic complexity estimation
      hash.rs            # BLAKE3 content hashing
      parser.rs          # Multi-language parser management (6 languages)
      lang/              # Per-language KRAIT rule implementations
        mod.rs           # LanguageRules trait + shared constants
        python.rs        # Python security rules (eval, subprocess, requests, etc.)
        javascript.rs    # JS/TS security rules (eval, child_process, fetch, etc.)
        go.rs            # Go security rules (reflect, os/exec, net/http, etc.)
        rust_lang.rs     # Rust security rules (process::Command, std::net, etc.)

rules/
  krait-agent.yaml       # KRAIT-001..007 rule definitions (Narsil-compatible)

docker/
  Dockerfile.sandbox     # Ephemeral sandbox (pinned base image + Rust + Narsil)
  Dockerfile.prod        # Production release image (multi-stage build)
  Dockerfile.dev         # Development container
  docker-compose.yml     # Full stack (app + Postgres + DinD sidecar)
  docker-compose.test.yml
  quickstart-entrypoint.sh  # Auto-secret generation + migration + seeding

docker-compose.prod.yml      # Production compose (restart policies, resource limits, Docker secrets, DinD TLS)
docker-compose.quickstart.yml # Batteries-included mode (only OPENROUTER_API_KEY required)

docs/
  adr/                   # Architecture Decision Records
    001-allowlist-over-denylist.md
    002-hardcoded-allowlist.md
    003-no-shadow-mode.md
    004-defmacro-banned.md
    005-global-allowlist.md
    006-ed25519-attestation.md
    007-kill-switch-persistence.md
  secret-management.md            # Secret management guide (19 secrets inventory, rotation, emergency response)
  tutorial-first-evolution.md     # Step-by-step guide: git clone to first evolution (quickstart + production paths)

scripts/
  setup-prod-secrets.sh  # Generate all production secrets (.env.prod, chmod 600)

SECURITY.md              # Vulnerability reporting, response timelines, 7 KRAIT rules, known limitations

test/                    # 117 test files, 1916 tests
  integration/           # End-to-end tests (evolution lifecycle, prompt injection, self-modification)
  krait/                 # Unit tests mirroring lib/ structure
  krait_web/             # Controller, LiveView, plug, admin auth tests
  support/               # Test helpers, mocks, fixtures
```

## Security Hardening History

KRAIT has undergone 27 rounds of security hardening plus a 10-phase pre-deployment hardening cycle, based on adversarial red-team assessments:

| Version | Focus | Key Changes |
|---------|-------|-------------|
| **v1** | Foundation | API auth, path traversal prevention, task supervisor, accumulator fixes |
| **v2** | Red-team | Timing-safe auth, SSRF fail-closed, IPv6 blocking, DNS pinning, symlink resolution |
| **v3** | Post-audit | Redirect-disabled HTTP, Teredo/6to4 blocking, Docker env allowlist, DinD sidecar |
| **v4** | Re-audit | Runtime session salts, prompt injection defense, ETS :protected, branch validation |
| **v5** | Adversarial | Capture shorthand detection, integer list bypass, variable indirection, XML escape |
| **v7** | Broad detection | Accumulator bug fix, broad forbidden module detection, integer sequence decoder |
| **v8** | Broad bypass | Bare atom apply, defdelegate, EEx/SSH/FTP/RPC modules, map_join evasion, Ollama SSRF |
| **v9** | NIF parity | Rust NIF: import/alias/use, bare atoms, sigils, Function.capture, hex/octal integers |
| **v10** | Comprehensive retest | 15 findings remediated from full retest cycle |
| **v12** | Consolidated assessment | 12 P0/P1 findings from consolidated security assessment |
| **v14** | Assessment followup | 19 findings remediated from v13 consolidated assessment |
| **v16** | Assessment followup | 26 findings remediated from v15 consolidated assessment |
| **v17** | Allowlist + CI/CD | Kernel.spawn/send/exit denied, @before_compile blocked, receive/quote blocked, denied-on-allowed-modules, module attribute indirection, variable dispatch, defprotocol/defimpl banned |
| **v18** | Adversarial assessment | 21 remediations from adversarial security assessment |
| **v19** | Allowlist migration | 5-tier allowlist as primary gate (Elixir + Rust NIF), CapableSkill behaviour, capability injection, 194 allowlist-specific tests |
| **v20** | Production readiness | 21 remediations: force sweep on ETS overflow, sandbox path canonicalization, env-var validation |
| **v21** | Deep audit | 2C/5H/14M/7L: ETS :protected tables, rate limit GenServer serialization, lockfile integrity |
| **v22** | Targeted hardening | 16 findings: supply chain lockfile check, workspace path containment, NIF binary SHA256 |
| **v23** | Full-spectrum | 1C/6H/10M/8L: fail-closed lockout, time-bucketed rate keys, atomic slot acquisition |
| **v24** | Consolidated | 6H/12M/1L: TOCTOU-safe cleanup, full prompt sanitization, LiveView session re-verify, max conversations, per-token rate limit, Telegram token closure |
| **v25** | 5-agent pentest | 1C/6H/11M/5L: slot crash cleanup, env-var gated local execution, fail-closed lockout, time-bucketed lockout keys, atomic slot acquisition, post-deploy kill switch advisory |
| **v26** | Second-round pentest | 3H/9M/14L: Docker sandbox hardening (6 flags), lockfile integrity, host execution double-confirm, bidi char stripping, network mode allowlist, webhook sanitization, code size limit, module attr chain resolution |
| **v27** | Third-round pentest | 3H/5M/4L: SSRF IP pinning fail-closed, filesystem TOCTOU symlink fix, webhook IP pinning, sanitize_strict everywhere, recursive payload sanitization, rate limit admin bypass, health auth, Shannon entropy credential detection, session cookie secure flag, supply chain hardening |
| **OpenRouter** | LLM migration | OpenRouter replaces direct Anthropic API as cloud backend; multi-model fallback, provider preferences, cost tracking, credit monitoring; quality remediation (1C/3H/7M) |
| **Pre-deploy** | 10-phase hardening | Kill switch + DB persistence, Ed25519 attestation, NIF integrity verification, health endpoints, graceful shutdown, production Dockerfile, CI pipeline (7 jobs), ADRs, secret management |

## Dependencies

### Elixir (mix.exs)

| Category | Package | Version |
|----------|---------|---------|
| Web | phoenix | ~> 1.8 |
| Web | phoenix_pubsub | ~> 2.1 |
| Web | phoenix_live_view | ~> 1.0 |
| Web | bandit | ~> 1.5 |
| Web | jason | ~> 1.4 |
| Web | gettext | ~> 1.0 |
| Web | dns_cluster | ~> 0.2.0 |
| Rust FFI | rustler | ~> 0.37 |
| LLM | langchain | ~> 0.3 |
| HTTP | req | ~> 0.5 |
| Database | ecto_sql | ~> 3.12 |
| Database | postgrex | ~> 0.19 |
| Database | pgvector | ~> 0.3 |
| Infrastructure | flame | ~> 0.5 |
| Security | joken | ~> 2.6 |
| Security | cloak / cloak_ecto | ~> 1.1 / ~> 1.3 |
| Observability | telemetry | ~> 1.0 |
| Observability | telemetry_metrics | ~> 1.0 |
| Observability | telemetry_poller | ~> 1.0 |
| Logging | logger_json | ~> 6.0 (prod) |
| Audit | mix_audit | ~> 2.1 (dev/test) |
| Analysis | credo | ~> 1.7 (dev/test) |
| Analysis | dialyxir | ~> 1.4 (dev/test) |
| Test | mox | ~> 1.0 |
| Test | bypass | ~> 2.1 |
| Test | ex_machina | ~> 2.8 |
| Test | stream_data | ~> 1.0 |

### Rust (Cargo.toml)

| Crate | Version | Purpose |
|-------|---------|---------|
| rustler | 0.37 | Erlang NIF bridge |
| tree-sitter | 0.24 | AST parsing |
| tree-sitter-elixir | 0.3 | Elixir grammar |
| tree-sitter-python | 0.23 | Python grammar |
| tree-sitter-javascript | 0.23 | JavaScript grammar |
| tree-sitter-typescript | 0.23 | TypeScript grammar |
| tree-sitter-go | 0.23 | Go grammar |
| tree-sitter-rust | 0.23 | Rust grammar |
| blake3 | 1 | Content hashing |
| regex | 1 | Pattern matching |
| streaming-iterator | 0.1 | tree-sitter query iteration |

## Design Principles

1. **Immutable Core, Mutable Periphery** -- Core security modules are read-only. Only community skills can evolve.
2. **Human-Gated Evolution** -- All changes go through PR review. The agent cannot merge or deploy.
3. **Fail-Closed Security** -- Unknown errors reject code, never pass it through.
4. **Defence in Depth** -- Elixir AST + Rust NIF + Narsil MCP + Docker sandbox + Git audit trail.
5. **Config-Driven Testing** -- All external dependencies behind behaviours + Mox mocks.
6. **TDD Methodology** -- Tests first, implement to green, refactor.
7. **Default Deny** -- No module, function, or macro is permitted unless explicitly allowlisted. The allowlist is the primary security gate; denylists serve only as defense-in-depth for content/path checks.

## Architecture Decision Records

Key design decisions are documented in [docs/adr/](docs/adr/):

| ADR | Decision |
|-----|----------|
| [001](docs/adr/001-allowlist-over-denylist.md) | Allowlist over denylist as primary security gate |
| [002](docs/adr/002-hardcoded-allowlist.md) | Compile-time MapSets over YAML configuration |
| [003](docs/adr/003-no-shadow-mode.md) | Agent cannot run code in main process |
| [004](docs/adr/004-defmacro-banned.md) | Agent cannot define macros |
| [005](docs/adr/005-global-allowlist.md) | Single global allowlist (no per-skill allowlists) |
| [006](docs/adr/006-ed25519-attestation.md) | Ed25519 signing for evolution attestations |
| [007](docs/adr/007-kill-switch-persistence.md) | Kill switch state persists to PostgreSQL |
| [008](docs/adr/008-promotion-gated-capability-evolution.md) | Proposed promotion-gated capability evolution |

For the current release gate checklist, see [docs/release-readiness.md](docs/release-readiness.md).

## License

Apache License 2.0. See [LICENSE](LICENSE) for the full text.
