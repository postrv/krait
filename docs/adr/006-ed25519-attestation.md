# ADR-006: Ed25519 for Attestation Signing

## Status

Accepted

## Context

KRAIT's evolution system produces cryptographic attestations
(`Krait.Evolution.Attestation`) that capture the full validation provenance for
each evolved skill: AST hash, complexity score, security findings count, taint
flow count, allowlist version, validator version, LLM model, and prompt hash.
These attestations are signed and embedded in git commits as trailer lines.

The signing algorithm must satisfy:

1. **Compact signatures** -- attestations are embedded in commit messages and
   JSON payloads. Large signatures add noise.
2. **Fast signing/verification** -- attestations are created on every successful
   evolution and verified during audit.
3. **Dedicated key** -- the attestation key must be separate from the GitHub App
   key used for API authentication to maintain key separation.

Three algorithms were considered:

- **RS256 (RSA-PKCS1-v1_5 with SHA-256)**: Industry standard, ~256-byte
  signatures for 2048-bit keys. Already used by the GitHub App JWT flow
  (`Krait.GitHub.Auth`) with the app's private key.
- **ES256 (ECDSA with P-256)**: ~72-byte signatures, widely supported. Requires
  careful nonce generation to avoid key leakage.
- **Ed25519 (EdDSA with Curve25519)**: 64-byte signatures, deterministic (no
  nonce), fast, constant-time.

## Decision

Attestations are signed with Ed25519 using OTP's `:crypto` module. The
implementation is in `lib/krait/evolution/attestation.ex`:

```elixir
signature = :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
```

Verification uses the corresponding public key:

```elixir
:crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
```

The attestation private key is configured via `:attestation_key_path` in
application config and is separate from the GitHub App private key used in
`Krait.GitHub.Auth` for JWT generation.

Key properties: 64-byte signatures (vs ~256 for RSA, ~72 for ECDSA),
deterministic signing (no nonce leakage risk), no algorithm negotiation field
to downgrade, and native OTP support via `:crypto.sign(:eddsa, ...)` with no
external dependencies. PEM decoding handles both OTP 27+ (`ECPrivateKey`) and
older versions (`PrivateKeyInfo` wrapper).

## Consequences

**Positive:**

- Compact attestations. The 64-byte signature keeps commit trailers readable
  and JSON payloads small.
- No nonce-related vulnerabilities. Deterministic signing eliminates an entire
  class of cryptographic implementation errors.
- Key separation. The attestation key is independent of the GitHub App key,
  limiting blast radius if either is compromised.
- Native OTP support with no additional dependencies.

**Negative:**

- Ed25519 keys cannot be used with systems that require RSA (e.g., some older
  HSMs). The attestation key is purpose-built and not shared with those systems.
- If the private key is compromised, attestations can be forged. Mitigation:
  key file at 0600 permissions, path outside agent-accessible workspace.
- Requires OTP 22+. KRAIT's minimum is OTP 25+, so this is not a constraint.
