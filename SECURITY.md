# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Please report vulnerabilities via email to: **security@krait.dev**

### What to Include

- Description of the vulnerability
- Steps to reproduce (or proof-of-concept code)
- Affected component (e.g., analyzer, sandbox, web interface)
- Potential impact assessment
- Any suggested fixes (optional)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Assessment | Within 7 days |
| Fix (Critical/High) | Within 14 days |
| Fix (Medium/Low) | Within 30 days |

You will receive updates at each stage. If we determine the report is not a vulnerability, we will explain why.

## Security Model

KRAIT enforces a strict allowlist architecture for all agent-generated code. The system operates on the principle of "deny by default" — only explicitly permitted operations are allowed.

### Seven Security Rules

Every piece of agent-generated code is validated against these rules by dual analyzers (Elixir AST + Rust NIF tree-sitter):

| Rule | Description |
|------|-------------|
| KRAIT-001 | No code evaluation (`Code.eval_string`, `EEx.eval_string`, etc.) |
| KRAIT-002 | No raw shell access (`System.cmd`, `:os.cmd`, `Port.open`, etc.) |
| KRAIT-003 | No credential path access (`~/.ssh`, `~/.aws`, etc.) |
| KRAIT-004 | No network exfiltration (raw HTTP clients forbidden, domain allowlist enforced) |
| KRAIT-005 | No hot code loading (`Code.load_file`, `:code.purge`, etc.) |
| KRAIT-006 | No immutable path targeting (`native/`, `.krait-immutable`, etc.) |
| KRAIT-007 | No recursive self-modification (evolution/analyzer modules protected) |

### Dual-Engine Validation

All agent-generated code passes through two independent analyzers:
- **Quick Analyzer** (Elixir): Macro.prewalk AST analysis with evasion detection
- **NIF Analyzer** (Rust): tree-sitter parsing with independent rule implementation

Both must agree the code is safe before it can proceed. The Rust NIF runs in `DirtyCpu` scheduler to avoid blocking the BEAM.

### Polyglot Security

The Rust NIF includes dedicated tree-sitter parsers for 6 languages (Elixir, Python, JavaScript, TypeScript, Go, Rust). All 7 KRAIT rules are enforced per-language with adapted AST patterns. Language detection is automatic based on file extension.

### Kill Switch

The global kill switch (the "K" in KRAIT) provides immediate halt of all evolution activity. It auto-trips after consecutive failures and persists state across restarts via PostgreSQL.

### Sandbox Execution

Agent-generated code executes in ephemeral Docker containers via a DinD (Docker-in-Docker) sidecar. The sandbox network is internal-only (no internet access from containers). Resource limits (CPU, memory) are enforced at the container level.

## Hardening History

KRAIT has undergone 27 rounds of security hardening including:
- Multiple independent security assessments
- Adversarial red-team exercises
- Automated vulnerability scanning (OWASP Top 10, CWE Top 25)
- Evasion detection for bypass techniques (variable indirection, integer list construction, module concatenation, charlist encoding, quoted atoms, defdelegate, module attribute indirection, and more)

## Known Limitations

- **DinD Requirement**: The Docker sandbox requires Docker-in-Docker, which needs privileged mode. Compensating controls include userns-remap, seccomp profiles, internal-only networking, and resource limits.
- **Narsil Optional**: The deep analyzer (Narsil-MCP) is optional. Without it, the system operates with quick analysis only, which has lower fidelity for complex code patterns.
- **String Fallback**: Unsupported languages (e.g., shell scripts) fall back to string-based pattern matching rather than AST analysis. Python, JS/TS, Go, and Rust have full tree-sitter AST analysis. The string fallback is intentionally retained for defense-in-depth.

## Security-Related Configuration

See the project README for required environment variables and production deployment guidance. Key points:

- All secrets must be configured via environment variables (never hardcoded)
- Session salts, API tokens, and admin tokens are validated at boot
- Rate limiting is enabled on all API endpoints
- CSRF protection is enabled for all form submissions
- Content Security Policy headers are configured
