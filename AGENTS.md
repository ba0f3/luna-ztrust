# Luna Z-Trust — Agent Guide

Guidance for AI coding agents working in this repository.

## What is this?

**Luna Z-Trust** provides ephemeral SSH certificate authentication for AI agents, DevOps runners, and automation. Three in-repo Go modules implement the client and control plane:

| Module | Path | Role |
|--------|------|------|
| `luna-sdk` | `sdk/` | Publishable library: ephemeral keys, PoP, mTLS + HMAC, cert/signature HTTP client |
| `luna-proxy` | `proxy/` | Central gateway: auth pipeline, Unix control socket, in-memory key pool, Telegram OOB, local CA/key signing |
| `luna-agent` | `agent/` | `SSH_AUTH_SOCK` daemon; blocking `Sign` via SDK for certs or hosted-key signatures |

**Not in this repo:** `lunacli` (separate repo), target `sshd` provisioning. Vault / `vault-agent` are legacy; see [`docs/legacy-vault-migration.md`](docs/legacy-vault-migration.md).

## Canonical specs

Before implementing or changing behavior, read:

1. **Proxy CLI, control socket, key pool:** [`docs/superpowers/specs/2026-05-31-proxy-cli-keystore-design.md`](docs/superpowers/specs/2026-05-31-proxy-cli-keystore-design.md)
2. **CLI remote key load:** [`docs/superpowers/specs/2026-05-31-cli-remote-key-load-design.md`](docs/superpowers/specs/2026-05-31-cli-remote-key-load-design.md)
3. **Self-hosted central (signing, key load, leases):** [`docs/superpowers/specs/2026-05-30-self-hosted-central-design.md`](docs/superpowers/specs/2026-05-30-self-hosted-central-design.md) (HTTP admin unseal sections superseded by 2026-05-31 specs)
4. **Self-hosted implementation plan:** [`docs/superpowers/plans/2026-05-30-self-hosted-central.md`](docs/superpowers/plans/2026-05-30-self-hosted-central.md)
5. **Core protocol (mTLS, HMAC, PoP, tx/wait, agent):** [`docs/superpowers/specs/2026-05-21-luna-core-design.md`](docs/superpowers/specs/2026-05-21-luna-core-design.md) (Vault and HTTP unseal sections superseded)
6. **System north-star (zero-disk, lunacli):** [`docs/design-specification.md`](docs/design-specification.md)

When behavior, flags, or APIs change, update **README.md**, this file, and any affected spec sections.

## Architecture constraints

### Dependency rules (strict)

```
agent  →  sdk
proxy  ✗  sdk
sdk    ✗  agent, proxy
```

- **Single protocol implementation:** HTTP, PoP, HMAC, and mTLS live in `sdk` only. The agent must not duplicate them.
- **Proxy isolation:** `proxy` talks to Telegram and local signing; it never imports `sdk`.

### Sign flow (Approach 2)

`POST /api/v1/ssh/sign` → `202` + `tx_id` → `GET /api/v1/ssh/sign/{tx_id}/wait` → cert/signature or terminal error. Optional `?wait=1` on POST for one round-trip; server still uses internal `tx_id`.

### Auth pipeline order (proxy)

1. mTLS — reject missing/invalid client cert  
2. HMAC — constant-time `X-Luna-Body-Mac` (TLS exporter label `luna-request-hmac`, 32 bytes)  
3. Timestamp — ±30s  
4. Replay LRU — `SHA256(raw_body)`, 60s TTL → `409` on duplicate  
5. PoP — verify `pop_signature` against `public_key`  
6. Create `tx_id` (ULID), enqueue approval  

Auth failure → **no** `tx_id`, **no** Telegram.

### Security (non-negotiable)

- **Fail-closed** on all auth, key-load, and signing errors.
- **Sealed keystore:** `POST /api/v1/ssh/sign` returns `503` until a signer is loaded with `luna-proxy key load` or `key confirm`.
- **HTTP admin unseal is gone:** `POST /api/v1/admin/unseal` and `GET /api/v1/admin/seal-status` return `410 Gone`; use the Unix control socket commands.
- **`LUNA_ENV=dev` auto-approve** only from proxy process env — never from client headers.
- **Never log:** private keys, TLS exporter keys, passphrases, encrypted PEM request bodies, Vault tokens, raw signatures.
- **`source-address`:** from mTLS listener `RemoteAddr`; do not trust `X-Forwarded-For` on that listener unless a separate ingress is documented.
- **Signing keys:** encrypted PEM is decrypted only in proxy RAM (`internal/keystore`); `local-ca` has one active signer, `local-key` has a fingerprint-keyed pool.
- **Control plane:** `luna-proxy serve` starts the mTLS API and Linux Unix control socket; socket ops use `SO_PEERCRED` and the configured admin group.
- **Remote CLI key load:** only enrolled `OU=luna-cli` devices may call `POST /api/v1/cli/keys/load`; admin and automation certs must be rejected.
- **Agent v1:** `Sign` blocks until cert/signature ready; mutex around in-flight sign; local-key requires a non-forwarded OpenSSH `session-bind@openssh.com` extension.
- **Local-key destination:** the verified SSH server host-key fingerprint is authoritative; `target_ip` is display/audit metadata only.
- **Direct SDK local-key:** in-process `x/crypto/ssh` callers pass the host key accepted by `HostKeyCallback` as `DestinationHostPublicKey`; this client-reported path never uses approval leases.
- **Bootstrap:** insecure first-contact CA download requires an out-of-band SHA-256 CA certificate fingerprint; enrollment must not refresh trust automatically.

## Build and test

```bash
go work sync
make test          # go test ./sdk/... ./proxy/... ./agent/...
make testdata      # mTLS and encrypted SSH test keys
make build         # bin/luna-proxy, bin/luna-agent
make ci            # fmt-check, lint, test, build
```

Go version: **1.25+** (see `go.work`).

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
    internal/{api,auth,approval,keystore,signing,lease,mobile,cli,control,config}/
  agent/                  # github.com/ba0f3/luna-ztrust/agent
    cmd/luna-agent/
    agent.go config.go
  docs/
  deploy/                 # docker-compose E2E (per plan)
  testdata/ca/            # generated test mTLS certs
```

## Current implementation map

| Area | Current shape |
|------|---------------|
| Process model | `luna-proxy serve` runs the mTLS API and Unix control socket; root command prints help |
| Keystore | `local-ca`: one active signer; `local-key`: fingerprint-keyed in-memory signer pool |
| Operator socket | `status`, `key.load`, `key.list`, `key.remove`, `key.confirm`, `key.reject`, `key.pending.list`, `mobile.*`, `cli.*` |
| HTTP admin | `/api/v1/admin/unseal` and `/api/v1/admin/seal-status` return `410 Gone` |
| CLI devices | CSR enrollment via control socket or admin mTLS; registry is in-memory in v1 |
| Remote key load | `POST /api/v1/cli/keys/load`, enrolled `luna-cli` mTLS only, `local-key` only |
| Mobile key upload | `POST /api/v1/mobile/keys/pending` stores encrypted blob; local `key confirm` decrypts and loads |

**Test layers:** unit (PoP, HMAC, LRU, tx FSM, keystore, control ops) → integration (mTLS API, CLI enroll/load, Telegram/mobile) → E2E (docker-compose).

## Coding conventions

- **Go:** Match standard library and `golang.org/x/crypto/ssh` patterns; exhaustive handling for status/enum unions where applicable.
- **Imports:** Top of file only; no inline imports.
- **Linux-only code:** Use `//go:build linux` for SO_PEERCRED and platform-specific control socket behavior.
- **Minimal scope:** Touch only files required by the current task; match existing naming and package layout in the plan.
- **English** for all code and comments.

## SDK public API (minimum)

```go
type ClientInfo struct {
    SourceUser    string // optional OS/login user on the client host
    ClientName    string // optional, e.g. luna-agent, lunacli
    ClientVersion string // optional release version
}

type CertRequest struct {
    TargetUser string
    TargetIP   string
    Client     ClientInfo
}

type Config struct {
    ProxyURL   string
    TLSCert    tls.Certificate
    TLSRootCAs *x509.CertPool
    Timeout    time.Duration // default ~90s for wait
    SignerMode string
}

func NewClient(cfg Config) (*Client, error)
func (c *Client) RequestCertificate(ctx context.Context, req CertRequest) (cert *ssh.Certificate, priv ed25519.PrivateKey, err error)
func (c *Client) RequestSignature(ctx context.Context, req SignatureRequest, signData []byte) (*ssh.Signature, error)
func (c *Client) FetchCapabilities(ctx context.Context) (Capabilities, error)
func NewCertSigner(cert *ssh.Certificate, priv ed25519.PrivateKey) (ssh.Signer, error)
```

PoP payload: `fmt.Sprintf("%s:%s:%d", targetUser, targetIP, timestamp)` signed with ephemeral key; hex-encode signature in JSON. Optional sign JSON fields `source_user`, `client_name`, `client_version` are for approval display and audit logs only (not in PoP). Authoritative **source IP** is always from mTLS `RemoteAddr` on the proxy. `local-key` sign requests include `agent_sign_data`, `host_key_fingerprint`, and verified session-binding fields; capabilities expose loaded signer fingerprints and public keys when available.

## Proxy packages

| Package | Role |
|---------|------|
| `internal/auth` | mTLS, HMAC, timestamp, replay LRU, PoP |
| `internal/approval` | `tx_id` store, Telegram, dev bypass |
| `internal/keystore` | In-memory signer pool, encrypted PEM load/confirm, pending uploads, mlock |
| `internal/signing` | `local-ca`, `local-key` |
| `internal/lease` | Session lease store |
| `internal/mobile` | Device registry, push stub |
| `internal/cli` | CLI device registry, CSR signing, remote key-load HTTP client |
| `internal/control` | Unix control socket, peer credential auth, local operator ops |
| `internal/api` | HTTP routing, handlers (`/api/v1/cli/*` enroll/list/delete + `keys/load`) |

## Deferred (do not implement in v1 unless spec changes)

- Kubernetes manifests  
- FCM push (Telegram is v1)  
- `memfd_create` subprocess key FD passing  
- Global API keys (use mTLS + PoP + HMAC)  
- Disk-persisted SSH private keys or Vault tokens on proxy  
- Persistent CLI/mobile registries and keystore pools (v1 is in-memory)

## Documentation checklist

| Change type | Update |
|-------------|--------|
| User-facing behavior, env vars, API | `README.md` |
| Install, systemd, Docker/GHCR deploy | `docs/deploy.md`, `deploy/*.example*` |
| First-time mTLS PKI | `luna-proxy setup mtls`, `proxy/internal/setup` |
| Agent client setup | `luna-agent setup`, `agent/internal/setup` |
| Vault / vault-agent / target `sshd` setup | `docs/setup.md` |
| Agent architecture, security, build | `AGENTS.md` |
| Approved component design | `docs/superpowers/specs/2026-05-31-proxy-cli-keystore-design.md` or affected spec |
| Task breakdown / file map | affected `docs/superpowers/plans/*.md` |
| Cross-cutting system design | `docs/design-specification.md` |

## Related projects

- **lunacli** — end-user CLI; separate repository; consumes `luna-sdk`
- **luna** (OpenCode agent) — different project under `github.com/ba0f3/luna`; do not confuse with this repo
