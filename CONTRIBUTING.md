# Contributing to KRAIT

Thank you for your interest in contributing to KRAIT! This document explains how to contribute code, report issues, and work with the project's security architecture.

## Code of Conduct

Be respectful, constructive, and patient. We are building safety-critical infrastructure — precision and thoroughness matter more than speed.

## Getting Started

### Prerequisites

- Elixir 1.15+ and Erlang/OTP 27+
- Rust (stable toolchain)
- PostgreSQL 15+
- Docker (for sandbox tests)

### Development Setup

```bash
git clone https://github.com/postrv/krait.git && cd krait
mix deps.get && mix compile
mix ecto.create && mix ecto.migrate
cd native/krait_analyzer && cargo build && cd ../..
```

### Running Tests

```bash
# Elixir tests (1883 tests, 39 excluded for integration/docker/narsil/pgvector)
mix test

# Rust NIF tests (199 tests)
cd native/krait_analyzer && cargo test

# Full precommit check (compile, format, credo, test)
mix precommit
```

## How to Contribute

### Reporting Bugs

Open a [GitHub issue](https://github.com/postrv/krait/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- Elixir/OTP version, OS, Docker version

**Security vulnerabilities**: Do NOT open a public issue. Email `security@krait.dev` instead. See [SECURITY.md](SECURITY.md) for details.

### Proposing Changes

1. **Fork** the repository and create a feature branch from `main`
2. **Write tests first** (TDD methodology)
3. **Implement** to make tests green
4. **Run quality gates**: `mix precommit` and `cd native/krait_analyzer && cargo clippy -- -D warnings && cargo test`
5. **Open a pull request** against `main`

### Pull Request Guidelines

- Keep PRs focused — one logical change per PR
- Include tests for new functionality
- Ensure all CI checks pass (7 jobs: quality, rust, integration, security, immutable, dialyzer, dockerfile-check)
- Update documentation if behavior changes
- Follow existing code style (enforced by `mix format` and `cargo clippy`)

## Security Architecture

KRAIT uses a **default-deny allowlist** as its primary security gate. Understanding this is essential before making security-related changes.

See [AGENTS.md](AGENTS.md) for the full security architecture reference, including:
- How the 5-tier allowlist works
- What the agent can and cannot use
- How to add modules to the allowlist
- How to modify KRAIT-003/006/007 rules
- Testing security changes

### Immutable Core

Files listed in `.krait-immutable` cannot be modified by the agent. Changes to these files require human-only commits. This includes:
- `lib/krait/analyzer/` — Allowlist and analyzers
- `native/krait_analyzer/` — Rust NIF source
- `lib/krait/evolution/validator.ex` — Validation pipeline
- `config/` — All configuration

If your change touches immutable paths, the CI `immutable-check` job verifies the change comes from a human commit.

### Dual-Analyzer Parity

Both the Elixir analyzer (`lib/krait/analyzer/quick.ex`) and the Rust NIF analyzer (`native/krait_analyzer/src/`) must agree. If you add a rule or pattern to one, add it to the other and include tests in both:

```bash
# Elixir allowlist tests
mix test test/krait/analyzer/allowlist_test.exs

# Rust NIF tests
cd native/krait_analyzer && cargo test
```

### Polyglot Rules

The NIF enforces KRAIT rules for 6 languages: Elixir, Python, JavaScript, TypeScript, Go, and Rust. Language-specific rules live in `native/krait_analyzer/src/lang/`. When adding patterns, consider whether they apply cross-language.

## Code Style

- **Elixir**: `mix format` enforces formatting. `mix credo --strict` for static analysis.
- **Rust**: `cargo clippy -- -D warnings` must pass. `deny(clippy::unwrap_used)` and `deny(clippy::expect_used)` are enabled.
- Prefer `Req` for HTTP requests (not HTTPoison, Tesla, or :httpc)
- External dependencies behind behaviours + Mox mocks
- No `inspect()` in Logger calls (use structured fields instead)

## Architecture Decision Records

Design decisions are documented in `docs/adr/`. If your change involves an architectural decision (new security rule, new capability, structural change), consider adding an ADR.

## License

By contributing to KRAIT, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
