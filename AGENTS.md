# Luna Z-Trust — Agent Guide

Guidance for AI coding agents working in this repository.

## What is this?

**Luna Z-Trust** provides ephemeral SSH certificate authentication for AI agents, DevOps runners, and automation. Three in-repo Go modules implement the client and control plane:

| Module | Path | Role |
|--------|------|------|
| `luna-sdk` | `sdk/` | Publishable library: ephemeral keys, PoP, mTLS + HMAC, cert HTTP client |
| `luna-proxy` | `proxy/` | Central gateway: auth pipeline, Telegram OOB, Vault SSH CA signing |
| `luna-agent` | `agent/` | `SSH_AUTH_SOCK` daemon; blocking `Sign` via SDK |

**Not in this repo:** `lunacli` (separate repo), `vault-agent`, Vault server, target `sshd` provisioning.

## Canonical specs

Before implementing or changing behavior, read:

1. **Component design (authoritative for sdk/proxy/agent):** [`docs/superpowers/specs/2026-05-21-luna-core-design.md`](docs/superpowers/specs/2026-05-21-luna-core-design.md)
2. **Implementation plan (phased tasks, file map):** [`docs/superpowers/plans/2026-05-21-luna-core.md`](docs/superpowers/plans/2026-05-21-luna-core.md)
3. **System north-star (Vault, zero-disk, lunacli):** [`docs/design-specification.md`](docs/design-specification.md)

When behavior, flags, or APIs change, update **README.md**, this file, and any affected spec sections.

## Architecture constraints

### Dependency rules (strict)

```
agent  →  sdk
proxy  ✗  sdk
sdk    ✗  agent, proxy
```

- **Single protocol implementation:** HTTP, PoP, HMAC, and mTLS live in `sdk` only. The agent must not duplicate them.
- **Proxy isolation:** `proxy` talks to Vault and Telegram; it never imports `sdk`.

### Sign flow (Approach 2)

`POST /api/v1/ssh/sign` → `202` + `tx_id` → `GET /api/v1/ssh/sign/{tx_id}/wait` → cert or terminal error. Optional `?wait=1` on POST for one round-trip; server still uses internal `tx_id`.

### Auth pipeline order (proxy)

1. mTLS — reject missing/invalid client cert  
2. HMAC — constant-time `X-Luna-Body-Mac` (TLS exporter label `luna-request-hmac`, 32 bytes)  
3. Timestamp — ±30s  
4. Replay LRU — `SHA256(raw_body)`, 60s TTL → `409` on duplicate  
5. PoP — verify `pop_signature` against `public_key`  
6. Create `tx_id` (ULID), enqueue approval  

Auth failure → **no** `tx_id`, **no** Telegram.

### Security (non-negotiable)

- **Fail-closed** on all auth and vault-agent errors.
- **`LUNA_ENV=dev` auto-approve** only from proxy process env — never from client headers.
- **Never log:** private keys, TLS exporter keys, Vault tokens, raw signatures.
- **`source-address`:** from mTLS listener `RemoteAddr`; do not trust `X-Forwarded-For` on that listener unless a separate ingress is documented.
- **vault-agent token:** Linux `SO_PEERCRED` on Unix socket; UID/PID check (build tag `linux`).
- **Agent v1:** `Sign` blocks until cert ready; mutex around in-flight sign; `LUNA_TARGET_HOST` required (OpenSSH does not pass remote host in `Sign`).

## Build and test

```bash
go work sync
make test          # go test ./sdk/... ./proxy/... ./agent/...
make testdata      # when scripts/gen-test-ca.sh exists
```

Go version: **1.23+** (see `go.work`).

## Project layout (target)

```
luna-ztrust/
  go.work
  Makefile
  sdk/                    # github.com/ba0f3/luna-ztrust/sdk
    sign/                 # HTTP: create tx + wait
    client.go pop.go mtls.go signer.go
  proxy/                  # github.com/ba0f3/luna-ztrust/proxy
    cmd/luna-proxy/
    internal/{api,auth,approval,vault,config}/
  agent/                  # github.com/ba0f3/luna-ztrust/agent
    cmd/luna-agent/
    agent.go config.go
  docs/
  deploy/                 # docker-compose E2E (per plan)
  testdata/ca/            # generated test mTLS certs
```

## Implementation phases

Follow the plan; do not skip exit criteria.

| Phase | Focus | Exit |
|-------|--------|------|
| P0 | Workspace + mTLS skeleton | Handshake OK |
| P1 | Auth pipeline | Bad requests rejected in tests |
| P2 | tx + wait + dev bypass + Vault mock | SDK gets cert in CI |
| P3 | SO_PEERCRED + real Vault SSH | Cert login to test sshd |
| P4 | Telegram path | Staging manual approve |
| P5 | luna-agent blocking Sign | `ssh` via agent sock works |

**Test layers:** unit (PoP, HMAC, LRU, tx FSM) → integration (mock vault-agent, Vault, Telegram) → E2E (docker-compose).

## Coding conventions

- **Go:** Match standard library and `golang.org/x/crypto/ssh` patterns; exhaustive handling for status/enum unions where applicable.
- **Imports:** Top of file only; no inline imports.
- **Linux-only code:** Use `//go:build linux` for SO_PEERCRED and platform-specific vault token paths.
- **Minimal scope:** Touch only files required by the current task; match existing naming and package layout in the plan.
- **English** for all code and comments.

## SDK public API (minimum)

```go
type Config struct {
    ProxyURL   string
    TLSCert    tls.Certificate
    TLSRootCAs *x509.CertPool
    Timeout    time.Duration // default ~90s for wait
}

func NewClient(cfg Config) (*Client, error)
func (c *Client) RequestCertificate(ctx context.Context, req CertRequest) (cert *ssh.Certificate, priv ed25519.PrivateKey, err error)
func NewCertSigner(cert *ssh.Certificate, priv ed25519.PrivateKey) (ssh.Signer, error)
```

PoP payload: `fmt.Sprintf("%s:%s:%d", targetUser, targetIP, timestamp)` signed with ephemeral key; hex-encode signature in JSON.

## Proxy packages

| Package | Role |
|---------|------|
| `internal/auth` | mTLS, HMAC, timestamp, replay LRU, PoP |
| `internal/approval` | `tx_id` store, Telegram, dev bypass |
| `internal/vault` | SO_PEERCRED socket, SSH CA sign |
| `internal/api` | HTTP routing, handlers |

## Deferred (do not implement in v1 unless spec changes)

- Kubernetes manifests  
- FCM push (Telegram is v1)  
- `memfd_create` subprocess key FD passing  
- Global API keys (use mTLS + PoP + HMAC)  
- Disk-persisted SSH private keys or Vault tokens on proxy  

## Documentation checklist

| Change type | Update |
|-------------|--------|
| User-facing behavior, env vars, API | `README.md` |
| Agent architecture, security, build | `AGENTS.md` |
| Approved component design | `docs/superpowers/specs/2026-05-21-luna-core-design.md` |
| Task breakdown / file map | `docs/superpowers/plans/2026-05-21-luna-core.md` |
| Cross-cutting system design | `docs/design-specification.md` |

## Related projects

- **lunacli** — end-user CLI; separate repository; consumes `luna-sdk`
- **luna** (OpenCode agent) — different project under `github.com/ba0f3/luna`; do not confuse with this repo
