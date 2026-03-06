# KRAIT Secret Management

## Secret Inventory

| Secret | Environment Variable | Purpose | Required In | Rotation Cadence |
|--------|---------------------|---------|-------------|------------------|
| API Token | `KRAIT_API_TOKEN` | Bearer auth for `/api/*` endpoints | All (prod required, dev optional) | 90 days |
| Admin Token | `KRAIT_ADMIN_TOKEN` | Auth for `/api/admin/*` (kill switch, etc.) | Prod | 90 days |
| Anthropic API Key | `ANTHROPIC_API_KEY` | LLM access for evolution proposals | Prod | Per provider policy |
| GitHub App Private Key | `GITHUB_APP_PRIVATE_KEY_PATH` | File path to PEM for GitHub App JWT signing | Prod | Annually or on compromise |
| Attestation Signing Key | `KRAIT_ATTESTATION_KEY_PATH` | File path to Ed25519 PEM for evolution attestation | Prod | Annually or on compromise |
| Secret Key Base | `SECRET_KEY_BASE` | Phoenix session encryption/signing | Prod | On compromise only |
| LiveView Salt | `LIVE_VIEW_SALT` | LiveView WebSocket token signing | Prod | On compromise only |
| Session Signing Salt | `SESSION_SIGNING_SALT` | Cookie session signing | Prod | On compromise only |
| Session Encryption Salt | `SESSION_ENCRYPTION_SALT` | Cookie session encryption | Prod | On compromise only |
| Admin Session Salt | `ADMIN_SESSION_SALT` | Admin session isolation | Prod | On compromise only |
| Database URL | `DATABASE_URL` | PostgreSQL connection string | Prod | On credential rotation |
| Ollama Base URL | `OLLAMA_BASE_URL` | Local LLM endpoint (optional) | Dev/staging | N/A (not a secret) |

## Key Generation

### API and Admin Tokens

```bash
# Generate a cryptographically secure token (64 hex chars)
mix phx.gen.secret 32
```

### Phoenix Session Secrets

```bash
# SECRET_KEY_BASE (64+ chars)
mix phx.gen.secret

# Salts (32 chars each)
mix phx.gen.secret 32
```

### Attestation Key (Ed25519)

```bash
# Generate a new Ed25519 keypair for attestation signing
mix krait.rotate_attestation_key

# Or manually:
openssl genpkey -algorithm Ed25519 -out krait-attestation-ed25519.pem
openssl pkey -in krait-attestation-ed25519.pem -pubout -out krait-attestation-ed25519.pub
```

The public key (`krait-attestation-ed25519.pub`) should be distributed to anyone who needs to verify evolution attestations. The private key must never leave the production environment.

### GitHub App Private Key

Generated and downloaded from the GitHub App settings page. Store the PEM file securely and reference it via `GITHUB_APP_PRIVATE_KEY_PATH`.

## Storage

- **Production**: Use your platform's secret manager (e.g., AWS Secrets Manager, Vault, GCP Secret Manager, fly.io secrets)
- **Development**: `.env` file with mode `600` (owner read/write only). Never commit `.env` to version control
- **CI**: GitHub Actions secrets (repository or environment level)

## Access Control

| Role | Secrets Accessible | Notes |
|------|-------------------|-------|
| Production deployment | All | Injected via secret manager |
| CI pipeline | `DATABASE_URL`, test tokens | Test-only values, not production |
| Developer (local) | `ANTHROPIC_API_KEY`, `OLLAMA_BASE_URL` | Dev tokens only; no prod access |
| KRAIT agent (runtime) | None directly | Agent code cannot access env vars (KRAIT-002/003 rules) |

## Rotation Procedures

### Rotating API/Admin Tokens

1. Generate new token: `mix phx.gen.secret 32`
2. Update in secret manager
3. Deploy with new token
4. Update any external clients (webhooks, monitoring)
5. Previous token becomes invalid immediately on deploy

### Rotating Attestation Key

1. Run `mix krait.rotate_attestation_key` to generate new keypair
2. Distribute new public key to verifiers
3. Update `KRAIT_ATTESTATION_KEY_PATH` in secret manager
4. Deploy — new evolutions signed with new key
5. Old attestations remain verifiable with the old public key (keep old pubkeys archived)

### Emergency Key Compromise

1. **Engage kill switch**: `POST /api/admin/kill-switch/halt` with reason "key_compromise"
2. **Rotate compromised key** using procedures above
3. **Audit**: Review evolution feed for unauthorized activity since estimated compromise time
4. **Resume**: `POST /api/admin/kill-switch/resume` after rotation complete

## Audit Logging

- Every `Attestation.sign/1` invocation is logged with timestamp and skill name (never key material)
- Kill switch state changes are logged and persisted to database
- API authentication failures are logged with source IP
- Rate limit violations are logged

## What Must NEVER Appear in Logs

- Private key material (PEM contents)
- `SECRET_KEY_BASE` or session salts
- Full `DATABASE_URL` (mask password portion)
- `KRAIT_API_TOKEN` or `KRAIT_ADMIN_TOKEN` values
- `ANTHROPIC_API_KEY` value

The Telegram token is wrapped in a closure (opaque in crash dumps) per F-17. Logger calls use safe alternatives instead of `inspect()` for sensitive structures per M-2/M-3.
