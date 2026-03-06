# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-21

Initial open-source release of KRAIT.

### Core Features
- Self-evolving AI agent with kill-switch architecture
- Elixir/OTP control plane with Rust NIF analysis engine
- 7 KRAIT security rules (001-007) enforced at AST level
- 5-tier default-deny module allowlist (primary security gate)
- Immutable core / mutable periphery design
- Evolution pipeline: spec -> propose -> validate -> sandbox -> deploy
- Docker sandbox with network isolation for code execution
- OpenRouter LLM backend with model fallback and cost tracking
- Kill switch with auto-trip on consecutive validation failures
- Ed25519 cryptographic attestation on every evolution
- LiveView dashboard for evolution monitoring
- **Polyglot NIF**: tree-sitter parsers for Python, JavaScript, TypeScript, Go, and Rust
  - Per-language `LanguageRules` trait with adapted KRAIT-001..007 checks
  - Language-specific allowlists (forbidden imports/requires/uses per language)
  - Credential path, immutable path, and self-modification detection across all languages
- Polyglot evolution pipeline: language detection from file extension, language-appropriate build/test commands
- Trusted proxies configuration via `TRUSTED_PROXIES` env var (fail-closed)
- Health endpoint rate limiting (60 req/min)
- X-Frame-Options: DENY header on all browser responses

### Security (27 rounds of hardening)
- KRAIT-001: No code eval (Code.eval_string, exec, compile, EEx, quote blocks)
- KRAIT-002: No raw shell (System.cmd, subprocess, child_process, os/exec, spawn)
- KRAIT-003: No credential path access (~/.ssh, ~/.aws, /etc/shadow)
- KRAIT-004: No network exfil (raw HTTP clients forbidden, domain allowlist)
- KRAIT-005: No hot code loading (importlib.reload, dynamic require, plugin.Open)
- KRAIT-006: No immutable path targeting (native/, .krait-immutable, rules/)
- KRAIT-007: No recursive self-modification (Krait.Evolution, Krait.Analyzer)
- Bearer token auth on API routes (timing-safe comparison)
- Rate limiting with sliding window (per-IP and per-token)
- SSRF protection: redirect blocking, DNS pinning, IPv6 blocking
- Docker sandbox: network=none, read-only rootfs, no capabilities, PID limits
- Symlink resolution with max-hop limits
- Prompt injection defense with XML delimiters and pattern stripping
- Lockfile integrity verification (pre/post checksum)
- Session salt rotation per boot in dev
- Compile-time and runtime path guards
- AST evasion detection: variable indirection, integer lists, module attrs, defdelegate, bare atom apply, charlist/sigil construction, quoted atoms, Function.capture, defprotocol/defimpl, receive/quote blocks

### Infrastructure
- CI pipeline: 7 jobs (quality, rust, integration, security, immutable, dialyzer, dockerfile-check)
- CD pipeline: tag-based deployment to GHCR via `deploy.yml` with smoke test
- Dockerfile.prod: multi-stage release build with pinned base images
- Dockerfile.sandbox: isolated execution environment
- Docker-in-Docker sidecar (no socket mount)
- Narsil-MCP integration for deep security analysis
- PostgreSQL with pgvector for memory storage
- Apache 2.0 LICENSE
- CONTRIBUTING.md with development setup, PR guidelines, security architecture reference
- GitHub issue/PR templates
- Sandbox is default in dev; host execution requires explicit `KRAIT_DEV_HOST_EXEC=true`

### Test Coverage
- 1,883 Elixir tests across all modules
- 199 Rust NIF tests (rules + allowlist + polyglot)
- Bypass scenario coverage: capture shorthand, integer lists, variable indirection, XML breakout, quoted atoms, defdelegate, module attrs, polyglot rule enforcement
