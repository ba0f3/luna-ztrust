# Luna Z-Trust

Ephemeral SSH authentication for AI agents, DevOps runners, and automation. A self-hosted **luna-proxy** holds encrypted signing keys (manual unseal), issues short-lived SSH **certificates** (`local-ca`) or **hosted-key signatures** (`local-key`), and gates access with out-of-band approval (Telegram v1; mobile enroll/approve API on the server).

## Components

| Component | Role |
|-----------|------|
| **luna-sdk** | Publishable Go library: ephemeral keys, PoP, mTLS + HMAC to proxy, cert/signature lifecycle |
| **luna-proxy** | Central gateway: auth pipeline, keystore unseal, signing, Telegram OOB, session leases |
| **luna-agent** | OS daemon: `SSH_AUTH_SOCK` interceptor; blocking `Sign` for unmodified `ssh` |

**Out of scope in this repository:** [lunacli](https://github.com/ba0f3/lunacli) (separate project; imports `luna-sdk`), target `sshd` provisioning.

## Architecture

```mermaid
graph TD
    subgraph CENTRAL["Central host"]
        LP["luna-proxy :8443 mTLS"]
        KS["encrypted key + admin unseal"]
        KS --> LP
        LP --> TG["Telegram API"]
    end

    subgraph CLIENT["Client host"]
        LA["luna-agent"]
        SDK["luna-sdk"]
        SSH["ssh / automation"]
        SSH -->|"SSH_AUTH_SOCK"| LA
        LA --> SDK
        SDK -->|"HTTPS mTLS"| LP
    end

    SDK --> Target["Target sshd"]
    LA --> Target
```

**Sign flow (transaction + wait):**

1. Client generates an ephemeral Ed25519 keypair (memory only).
2. `POST /api/v1/ssh/sign` with JSON body, `pop_signature`, mTLS, `X-Luna-Body-Mac`.
3. Proxy validates the auth pipeline; if the keystore is sealed → `503`. Otherwise lease fast-path or new `tx_id` + Telegram (or auto-approve in dev).
4. `GET /api/v1/ssh/sign/{tx_id}/wait` blocks until approved, denied, or timeout.
5. Proxy signs via `local-ca` (SSH user cert + `source-address`) or `local-key` (`agent_sign_data` → `ssh_signature`).
6. SDK returns cert + private key, or signature; agent returns `ssh.Signature` to OpenSSH.

## Repository layout

```
luna-ztrust/
  go.work
  sdk/          # github.com/ba0f3/luna-ztrust/sdk
  proxy/        # github.com/ba0f3/luna-ztrust/proxy
  agent/        # github.com/ba0f3/luna-ztrust/agent
  docs/
    superpowers/specs/2026-05-30-self-hosted-central-design.md
    superpowers/plans/2026-05-30-self-hosted-central.md
```

**Module dependency rules:**

- `agent` → `sdk`
- `proxy` does not import `sdk`
- `sdk` does not import `agent` or `proxy`

## Requirements

- Go 1.25+ (see `go.work`)
- Linux recommended (keystore `mlock` on unseal)
- Internal mTLS CA (client certs for SDK/agent; admin OU for unseal API)
- Encrypted signing key at `LUNA_KEY_PATH`
- Telegram bot (production approval path)

## Build and test

```bash
go work sync
make test
make testdata   # mTLS + encrypted SSH keys for CI
```

## E2E

Docker Compose runs `luna-proxy` with test mTLS and an encrypted CA key. Tests call `POST /api/v1/admin/unseal` before signing.

```bash
make testdata
make e2e-up
make e2e-test
make e2e-down
```

```bash
LUNA_PROXY_URL=https://localhost:8443 go test -tags=e2e ./sdk/sign/... -v
```

## Configuration (overview)

### luna-proxy

| Variable | Purpose |
|----------|---------|
| `LUNA_KEY_PATH` | Encrypted SSH signing key (PEM, passphrase at unseal) |
| `LUNA_SIGNER_MODE` | `local-ca` (default) or `local-key` |
| `LUNA_ADMIN_CLIENT_OU` | Client cert OU for `/api/v1/admin/*` (default `luna-admin`) |
| `LUNA_ENV=dev` | Auto-approve (proxy env only) |
| `TELEGRAM_BOT_TOKEN` | Outbound Telegram API |
| `TELEGRAM_WEBHOOK_SECRET` | Webhook validation |
| `TELEGRAM_CHAT_ID` | Admin chat for approval prompts |
| `FCM_CREDENTIALS` | P5 hook for mobile push (stub until implemented) |

Vault / `LUNA_VAULT_*` are removed from the runtime path; see [docs/legacy-vault-migration.md](docs/legacy-vault-migration.md).

### luna-agent

| Variable | Purpose |
|----------|---------|
| `LUNA_PROXY_URL` | Proxy base URL |
| `LUNA_SIGNER_MODE` | `local-ca` or `local-key` (must match proxy) |
| `LUNA_MTLS_CERT` / `LUNA_MTLS_KEY` / `LUNA_MTLS_CA` | Client mTLS material |
| `LUNA_TARGET_USER` | Default SSH principal |
| `LUNA_TARGET_HOST` | Target IP/hostname for PoP / cert binding |

Agent socket: `/run/luna/agent.sock` (mode `0600`).

## HTTP API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/admin/unseal` | Admin mTLS: load signing key |
| `GET` | `/api/v1/admin/seal-status` | Admin mTLS: sealed state |
| `GET` | `/api/v1/capabilities` | mTLS: signer mode, TTLs, sealed |
| `POST` | `/api/v1/ssh/sign` | Create transaction; `202` + `tx_id` |
| `GET` | `/api/v1/ssh/sign/{tx_id}/wait` | Block until cert/signature or error |
| `POST` | `/api/v1/telegram/webhook` | Telegram approval callback |
| `POST` | `/api/v1/mobile/enroll` | Admin mTLS: register device |
| `POST` | `/api/v1/mobile/approve` | mTLS + device signature |
| `DELETE` | `/api/v1/mobile/devices/{device_id}` | Admin mTLS: revoke device |
| `GET` | `/healthz` | Health check (no client cert required) |

Auth order on sign requests: mTLS → HMAC → timestamp → replay LRU → PoP → tx/lease/sign.

## Security principles

- **Fail-closed:** Auth and unseal failures never create transactions or Telegram prompts.
- **Sealed by default:** Sign returns `503` until admin unseal.
- **Zero disk keys on clients:** Ephemeral private keys stay in memory.
- **IP binding:** `source-address` on user certs from mTLS `RemoteAddr`.
- **Session leases:** Re-approval skipped for same client + target + approver within TTL.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/setup.md](docs/setup.md) | Target `sshd` trust, unseal runbook, legacy Vault notes |
| [docs/legacy-vault-migration.md](docs/legacy-vault-migration.md) | Vault → self-hosted mapping |
| [docs/superpowers/specs/2026-05-30-self-hosted-central-design.md](docs/superpowers/specs/2026-05-30-self-hosted-central-design.md) | Self-hosted central server design |
| [docs/superpowers/plans/2026-05-30-self-hosted-central.md](docs/superpowers/plans/2026-05-30-self-hosted-central.md) | Implementation plan |
| [AGENTS.md](AGENTS.md) | Guidance for AI coding agents |

## License

See repository license file when published.
