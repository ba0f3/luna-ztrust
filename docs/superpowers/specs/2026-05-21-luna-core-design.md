# Luna Core Design: luna-proxy, luna-sdk, luna-agent

**Status:** Approved via brainstorming (2026-05-21)  
**Supersedes:** Partial sketches in `docs/design-specification.md` for these three components  
**Out of scope:** `lunacli` (separate repository; consumes `luna-sdk`), `vault-agent`, HashiCorp Vault server, target `sshd` provisioning

---

## 1. Summary

Luna Z-Trust provides ephemeral SSH certificate authentication for AI agents, DevOps runners, and automation. This design covers three in-repo components:

| Component | Role |
|-----------|------|
| **luna-sdk** | Publishable Go library: ephemeral keys, PoP, mTLS + HMAC to proxy, cert lifecycle |
| **luna-proxy** | Central gateway: authZ, Telegram OOB approval, Vault SSH CA signing |
| **luna-agent** | OS daemon: `SSH_AUTH_SOCK` interceptor; blocking `Sign` for unmodified `ssh` |

**Deployment:** Classic split — central proxy host; SDK and agent on client hosts over HTTPS with mTLS.

**Sign flow:** Approach 2 — transaction + wait endpoints (LB-safe, idempotent Telegram).

---

## 2. Decisions log

| Topic | Decision |
|-------|----------|
| Scope | `luna-proxy`, `luna-sdk`, `luna-agent` only |
| lunacli | Separate project; imports `luna-sdk` |
| Approval | Full Telegram in v1; `LUNA_ENV=dev` auto-approve on proxy only |
| Deployment | Classic split (not K8s-first) |
| Repository | Go workspace; `sdk` publishable module |
| Agent ↔ SDK | Agent imports SDK (single protocol implementation) |
| Transport | mTLS required (internal CA client certs) |
| Body auth | Ed25519 PoP + HMAC over raw JSON body |
| HMAC key | TLS exporter label `luna-request-hmac` (no static client secret file) |
| Replay | 30s timestamp window; SHA256(body) LRU 60s |
| IP binding | Vault `source-address` from client `RemoteAddr` |
| Vault token | SO_PEERCRED Unix socket from vault-agent (v1) |
| Agent Sign | Blocking until cert ready (v1) |
| Sign API | POST create `tx_id` + GET wait (Approach 2) |

---

## 3. Architecture

### 3.1 System boundary

**In scope:** proxy, sdk, agent modules and their HTTP/agent protocols.

**External dependencies:**

- **vault-agent** — AppRole auth, delivers Vault token to proxy via Unix socket
- **Vault** — SSH secrets engine / CA signing
- **Telegram** — OOB human approval
- **sshd** on targets — validates signed certificates

### 3.2 Deployment topology

```
┌──────────────────────── CENTRAL HOST ────────────────────────┐
│  vault-agent ──SO_PEERCRED──► luna-proxy :443 (mTLS)       │
│       │                              │                      │
│       └── Vault token                ├──► Telegram API     │
│                                      └──► Vault SSH sign    │
└────────────────────────────────────────────────────────────┘
              ▲ mTLS
              │
┌─────────────┴──────── CLIENT HOST ─────────────────────────┐
│  SSH_AUTH_SOCK ──► luna-agent ──imports──► luna-sdk        │
│  (automation)  ─────────────────────────────► luna-sdk      │
└────────────────────────────────────────────────────────────┘
```

### 3.3 Repository layout

```
luna-ztrust/
  go.work
  sdk/                    # github.com/ba0f3/luna-ztrust/luna-sdk
    sign/                 # HTTP: create tx + wait
    pop.go
    mtls.go
    client.go
  proxy/                  # github.com/ba0f3/luna-ztrust/luna-proxy
    cmd/luna-proxy/
    internal/api/
    internal/approval/
    internal/auth/
    internal/vault/
  agent/                  # github.com/ba0f3/luna-ztrust/luna-agent
    cmd/luna-agent/
    agent.go
```

**Dependency rules:**

- `agent` → `sdk`
- `proxy` does not import `sdk`
- `sdk` does not import `agent` or `proxy`

### 3.4 Sign sequence (Approach 2)

1. Client generates ephemeral Ed25519 keypair (memory only).
2. `POST /api/v1/ssh/sign` with JSON body, `pop_signature`, mTLS, `X-Luna-Body-Mac`.
3. Proxy validates auth pipeline → creates `tx_id` → Telegram (or dev auto-approve).
4. `GET /api/v1/ssh/sign/{tx_id}/wait` blocks until approved/denied/timeout.
5. Proxy obtains Vault token via vault-agent socket, signs cert with `source-address`.
6. SDK returns `*ssh.Certificate` + private key; agent returns `ssh.Signature` to OpenSSH.

---

## 4. Component specifications

### 4.1 luna-sdk

**Public API (minimum):**

```go
type Config struct {
    ProxyURL    string        // https://luna-proxy.internal
    TLSCert     tls.Certificate
    TLSRootCAs  *x509.CertPool
    Timeout     time.Duration // default 90s for wait
}

type CertRequest struct {
    TargetUser string
    TargetIP   string
}

func NewClient(cfg Config) (*Client, error)
func (c *Client) RequestCertificate(ctx context.Context, req CertRequest) (cert *ssh.Certificate, priv ed25519.PrivateKey, err error)
func NewCertSigner(cert *ssh.Certificate, priv ed25519.PrivateKey) (ssh.Signer, error)
```

**Responsibilities:**

- Ephemeral Ed25519 generation
- PoP: sign `fmt.Sprintf("%s:%s:%d", targetUser, targetIP, timestamp)` with ephemeral key
- mTLS HTTP transport
- HMAC: `HMAC-SHA256(raw_body, tls_exporter("luna-request-hmac", 32))` after handshake
- `RequestCertificate`: POST sign → GET wait → parse cert

**Non-goals:** Telegram, Vault, transaction store.

### 4.2 luna-proxy

**Subsystems:**

| Package | Role |
|---------|------|
| `internal/auth` | mTLS, HMAC verify, timestamp, nonce LRU, PoP verify |
| `internal/approval` | `tx_id` store, Telegram, dev bypass |
| `internal/vault` | SO_PEERCRED socket read, SSH CA sign API |
| `internal/api` | HTTP routing |

**Environment:**

| Variable | Purpose |
|----------|---------|
| `LUNA_ENV=dev` | Auto-approve (proxy process only; not client-settable) |
| `VAULT_AGENT_SOCKET` | Unix path for token handoff |
| `TELEGRAM_BOT_TOKEN` | Outbound API |
| `TELEGRAM_WEBHOOK_SECRET` | Webhook validation |

**Non-goals:** Persist SSH private keys; disk-backed Vault tokens; run on client hosts.

### 4.3 luna-agent

**Socket:** `/run/luna/agent.sock`, mode `0600`, owned by service user.

**Config:**

| Variable | Purpose |
|----------|---------|
| `LUNA_PROXY_URL` | Proxy base URL |
| `LUNA_MTLS_CERT` / `LUNA_MTLS_KEY` / `LUNA_MTLS_CA` | Client mTLS material |
| `LUNA_TARGET_USER` | Default SSH principal (override from sign request when possible) |
| `LUNA_TARGET_HOST` | Target IP/hostname for cert principal binding |

**`Sign` behavior (v1):** Block calling `sdk.RequestCertificate` until cert available; build cert signer; return signature for requested blob.

**Non-goals:** Duplicate HTTP/PoP logic; direct Vault/Telegram access.

---

## 5. HTTP API

### 5.1 Endpoints

| Method | Path | Response |
|--------|------|----------|
| `POST` | `/api/v1/ssh/sign` | `202` + `{"tx_id":"tx_01H..."}` |
| `GET` | `/api/v1/ssh/sign/{tx_id}/wait` | `200` cert or terminal error |
| `POST` | `/api/v1/telegram/webhook` | `200` (Telegram ack) |
| `GET` | `/healthz` | `200` (no auth) |

Optional: `POST /api/v1/ssh/sign?wait=1` returns `200` with cert in one round-trip (server still uses internal `tx_id`).

### 5.2 Request body

```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "target_user": "deploy",
  "target_ip": "10.0.1.50",
  "timestamp": 1716300000,
  "pop_signature": "<hex>"
}
```

### 5.3 Headers

| Header | Required | Description |
|--------|----------|-------------|
| (TLS) | Yes | Client certificate from internal CA |
| `X-Luna-Body-Mac` | Yes | HMAC-SHA256 of raw body using TLS exporter key |
| `Content-Type` | Yes | `application/json` |

### 5.4 Auth pipeline (strict order)

1. mTLS — reject missing/invalid client cert
2. HMAC — constant-time compare `X-Luna-Body-Mac`
3. Timestamp — ±30 seconds
4. Replay LRU — `SHA256(raw_body)`, 60s TTL, reject duplicate with `409`
5. PoP — verify `pop_signature` against `public_key`
6. Create `tx_id` (ULID), enqueue approval

### 5.5 Wait response

Success `200`:

```json
{
  "ssh_certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "expires_at": "2026-05-21T12:05:00Z"
}
```

| Status | Meaning |
|--------|---------|
| `403` | Denied |
| `408` / `504` | Approval timeout (60s default) |
| `404` | Unknown `tx_id` |
| `410` | `tx_id` consumed |
| `409` | Duplicate body (replay) |
| `503` | Vault / vault-agent unavailable |

### 5.6 Telegram approval

- **Production:** One message per `tx_id`; inline Approve/Deny; webhook resolves transaction.
- **Idempotent:** Re-notify and duplicate webhooks must not create duplicate user prompts or double-sign.
- **`LUNA_ENV=dev`:** Skip Telegram; approve immediately after validation.

### 5.7 Vault signing

After approval:

1. Read token from vault-agent via SO_PEERCRED Unix socket (UID/PID check).
2. Call Vault SSH sign endpoint with `valid_principals=target_user`, `critical_options.source-address=<client public IP>`.
3. Return `signed_key` to waiter; mark `tx_id` consumed.

**IP extraction:** Use `RemoteAddr` on the mTLS listener. Do not trust `X-Forwarded-For` on this listener unless a separate documented ingress is added later.

### 5.8 Implementation notes

- **TLS exporter:** Use `crypto/tls.Conn.ExportKeyingMaterial` with label `luna-request-hmac`, length 32, context empty. Requires TLS 1.2+. SDK and proxy must use the same label and hash the **exact** HTTP body bytes received.
- **PoP signature format:** Use SSH-layer verification (`ssh.Signature` + `ssh.PublicKey.Verify`) so non-Ed25519 ephemeral keys remain extensible; hex-encode the signature blob in `pop_signature`.
- **Agent target host:** OpenSSH `Sign` does not pass remote host; v1 requires `LUNA_TARGET_HOST` (or parsed ssh config path documented in agent README).

---

## 6. Error handling

### 6.1 Fail-closed

- Auth failure → no `tx_id`, no Telegram.
- Dev bypass only from proxy `LUNA_ENV`, never from client headers.
- vault-agent failure → `503`, no partial certificate.

### 6.2 Client disconnect

If `wait` client disconnects, cancel waiter and expire `tx_id` after TTL to prevent goroutine leaks.

### 6.3 Agent concurrency

Mutex around in-flight `Sign` → one active `tx_id` per agent instance unless OpenSSH serializes (still use mutex for safety).

### 6.4 Logging

Structured JSON: `tx_id`, `client_cert_fp`, `target_user`, `target_ip`, `outcome`, `latency_ms`. Never log private keys, exporter keys, Vault tokens, or raw signatures.

---

## 7. Testing & delivery

### 7.1 Test layers

- **Unit:** PoP, HMAC exporter vectors, LRU, tx state machine
- **Integration:** Mock vault-agent socket, mock Vault HTTP, mock Telegram webhook
- **E2E:** docker-compose with Vault dev + dev auto-approve + test sshd

### 7.2 Implementation phases

| Phase | Deliverable | Exit criterion |
|-------|-------------|----------------|
| P0 | Workspace + mTLS skeleton | Handshake OK |
| P1 | Auth pipeline | Bad requests rejected in tests |
| P2 | tx + wait + dev bypass + Vault mock | SDK gets cert in CI |
| P3 | SO_PEERCRED + real Vault SSH | Cert login to test sshd |
| P4 | Telegram path | Staging manual approve |
| P5 | luna-agent blocking Sign | `ssh` via agent sock works |

### 7.3 Deferred (not v1)

- Kubernetes manifests
- FCM push (Telegram is v1 channel)
- `memfd_create` for subprocess key FD passing
- Global API keys (replaced by mTLS + PoP + HMAC)

---

## 8. Relationship to master spec

`docs/design-specification.md` remains the north-star for Vault phases, zero-disk keys, and lunacli. This document narrows and updates:

- Client auth: mTLS + TLS-exporter HMAC + PoP (not `X-API-Key` alone)
- Sign API: transaction + wait (not single blocking handler)
- HMAC: no static `SharedSecret` on SDK hosts
- lunacli: explicitly external

---

## 9. References

- Master specification: `docs/design-specification.md`
- Brainstorming session: 2026-05-21
