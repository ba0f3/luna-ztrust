# Self-Hosted Central Server Design (luna-proxy evolution)

**Status:** Approved via brainstorming (2026-05-30)  
**Supersedes:** Vault signing and `proxy/internal/vault` in [`2026-05-21-luna-core-design.md`](2026-05-21-luna-core-design.md) (sections 3.2 external Vault, 4.2 vault package, 5.7, P2–P3 Vault phases)  
**Inspiration:** [`docs/new-plan.md`](../../new-plan.md) (OOB approval, unseal); aligned with existing mTLS + tx/wait + Telegram patterns  
**Out of scope:** HashiCorp Vault, vault-agent, lunacli (separate repo), target `sshd` provisioning

---

## 1. Summary

Evolve **luna-ztrust** so **luna-proxy** is a self-hosted central control plane that:

1. Holds **encrypted signing keys** on disk; **manual unseal** loads decrypted material into **RAM-only** storage (`mlock`).
2. Signs SSH access via **`local-ca`** (ephemeral client keys + short-lived certificates) or **`local-key`** (server signs OpenSSH agent challenges with a hosted private key).
3. Enforces **Out-of-Band approval** via **Telegram** in v1, with **session leases** and **per-credential TTL** chosen at approve time (e.g. 3m, 5m).
4. Documents and phases **mobile secure approve** (device-bound signatures, push later) without shipping the app in v1.

**Unchanged from core design:** `luna-sdk` / `luna-agent` dependency rule, mTLS + TLS-exporter HMAC + PoP auth pipeline, Approach 2 sign API (`POST` + `GET` wait), `LUNA_ENV=dev` auto-approve on proxy only, fail-closed auth.

**Removed:** Vault SSH engine, vault-agent SO_PEERCRED token path, `503` for Vault unavailable.

---

## 2. Decisions log

| Topic | Decision |
|-------|----------|
| Repository | Evolve **luna-ztrust** (not greenfield repo) |
| Vault | **Out of scope**; migration notes only in `docs/legacy-vault-migration.md` |
| Signing modes | **`local-ca`** and **`local-key`**; config selects one per deployment |
| Lease | **Session lease** (skip re-approval) **and** **credential TTL** per sign; `credential_ttl ≤ lease_ttl` |
| Lease binding | mTLS client cert fingerprint + `target_user` + `target_ip` + client `RemoteAddr` IP + **approver** (`telegram_chat_id`; later `device_id`) |
| Approval v1 | **Telegram** with inline TTL choices |
| Approval later | **Mobile** — enrolled device pubkey, signed approve API; FCM/APNs in later phase |
| Key unlock | **Manual unseal** (Vault-style); restart clears RAM until unseal |
| Admin unseal auth | **Separate admin mTLS client certificate** (automation certs cannot unseal) |
| Implementation shape | **Approach 1:** extend `luna-proxy` + `luna-sdk` + `luna-agent`; `internal/signing` plugin |

---

## 3. Architecture

### 3.1 System boundary

**In scope:** `luna-proxy`, `luna-sdk`, `luna-agent` and protocols between them.

**External:**

- **Telegram** — OOB human approval (v1)
- **Mobile app** — phased; v1 spec only
- **sshd** on targets — certificate or pubkey trust per signing mode

### 3.2 Deployment topology

```
┌──────────────────────── CENTRAL HOST ─────────────────────────┐
│  luna-proxy :443 (mTLS)                                        │
│    ├── keystore (sealed → unsealed RAM, mlock)                 │
│    ├── lease store (in-memory)                                 │
│    ├── signing: local-ca | local-key                         │
│    └── Telegram webhook / outbound API                       │
└────────────────────────────────────────────────────────────────┘
              ▲ mTLS (automation cert + admin cert for unseal)
              │
┌─────────────┴──────── CLIENT HOST ────────────────────────────┐
│  SSH_AUTH_SOCK ──► luna-agent ──imports──► luna-sdk           │
└───────────────────────────────────────────────────────────────┘
```

### 3.3 Repository layout (delta)

```
proxy/
  internal/
    keystore/      # encrypt-at-rest, unseal, mlock, sealed gate
    signing/       # Signer interface: LocalCA, LocalKey
    lease/         # lease key, TTL, approver binding
    approval/      # tx store + Telegram (extended callbacks)
    auth/          # unchanged pipeline
    api/           # + admin unseal, capabilities
  # DELETE: internal/vault/
```

**Dependency rules:** unchanged (`agent` → `sdk`; `proxy` ✗ `sdk`).

### 3.4 Sign sequence (Approach 2, extended)

1. Client generates ephemeral key (CA mode) or presents agent sign request (key mode).
2. `POST /api/v1/ssh/sign` with JSON body, PoP, mTLS, `X-Luna-Body-Mac`.
3. Proxy: auth pipeline → **if sealed, `503` (no tx, no Telegram)**.
4. Proxy: compute **lease lookup key** from request (+ approver when reusing lease).
5. **Active lease?** → sign immediately with remaining credential TTL cap → return via wait or sync response.
6. **No lease?** → create `tx_id` → Telegram message with Approve/Deny and **TTL buttons** (e.g. 3m, 5m, 15m).
7. `GET /api/v1/ssh/sign/{tx_id}/wait` blocks until approved/denied/timeout.
8. On approve: record **lease** + sign with **credential TTL** = admin-selected duration.
9. Response: `ssh_certificate` (CA mode) or `ssh_signature` + metadata (key mode).

---

## 4. Key custody and unseal

### 4.1 At rest

- Signing material stored as **encrypted PEM** (or documented age-wrapped blob) at `LUNA_KEY_PATH` (and optional separate `LUNA_CA_KEY_PATH` if CA ≠ host key).
- File mode `0400`, owned by proxy service user.
- Process starts **sealed** (cannot sign).

### 4.2 Unseal

| Method | Path | Auth |
|--------|------|------|
| HTTP | `POST /api/v1/admin/unseal` | **Admin mTLS** client cert (distinct CA profile or EKU) |
| Status | `GET /api/v1/admin/seal-status` | Same admin mTLS |

Request body:

```json
{ "passphrase": "..." }
```

- Passphrase used only to decrypt; **zeroized** after load.
- Decrypted `ssh.Signer`(s) held in memory with **`unix.Mlock`** on backing buffers where feasible.
- **Fail-closed:** wrong passphrase → `403`; no partial unseal.

### 4.3 Seal / restart

- Process restart or explicit future `POST /admin/seal` clears signers from memory; proxy returns **`503`** with body hint `sealed` on sign paths until unseal.

### 4.4 Non-goals

- Auto-unseal on boot via plaintext env (dev-only documented exception: `LUNA_DEV_UNSEAL_PASSPHRASE` forbidden in production configs).
- Persisting passphrases or decrypted keys to disk.

---

## 5. Signing modes

Configured via `LUNA_SIGNER_MODE=local-ca|local-key`.

### 5.1 `local-ca`

- Central holds **SSH CA private key** (unsealed).
- Client sends ephemeral `public_key` in sign request (unchanged).
- After approval/lease, proxy signs **SSH certificate** with:
  - `valid_principals` = `target_user`
  - `critical_options.source-address` = client IP from mTLS listener **`RemoteAddr`** (not `X-Forwarded-For` on this listener)
  - `ValidBefore` = `min(lease_expires_at, now + credential_ttl)`
- Targets trust CA via `TrustedUserCAKeys`.

### 5.2 `local-key`

- Central holds **user/host SSH private key** used for login (same trust as traditional pubkey auth).
- Client `POST` includes agent **sign payload** (public key + challenge bytes) per extended request schema.
- After approval/lease, proxy signs challenge with hosted key; returns signature blob for agent to return to OpenSSH.
- **SDK:** `RequestSignature` (or mode branch in client) when `GET /api/v1/capabilities` reports `signer_mode: local-key`.
- **Agent:** uses cert path or signature path based on capabilities / `LUNA_SIGNER_MODE` env mirror.

### 5.3 Mode selection guidance

| Use case | Mode |
|----------|------|
| Zero-trust cert, principal + IP binding | `local-ca` |
| Legacy `authorized_keys` / single shared admin key | `local-key` |

---

## 6. Session leases and credential TTL

### 6.1 Definitions

- **Session lease:** Authorization for the proxy to **skip Telegram** for subsequent sign requests matching the lease key until `lease_expires_at`.
- **Credential TTL:** Validity of **one issued** certificate or signature (chosen at approve time; e.g. 3m, 5m).

Invariant: **`credential_ttl ≤ lease_remaining`** at issue time.

### 6.2 Lease key (all required to match)

| Field | Source |
|-------|--------|
| Client identity | SHA-256 fingerprint of mTLS client cert (SPKI) |
| Target user | Request `target_user` |
| Target host | Request `target_ip` (canonical IP; no hostname in lease key) |
| Workstation | TCP `RemoteAddr` host IP on mTLS listener |
| Approver | `telegram_chat_id` from webhook (v1); `device_id` when mobile added |

Different approver → **new lease** (does not extend another admin’s lease).

### 6.3 Telegram approve UX (v1)

- One notification per `tx_id` (idempotent webhook handling unchanged).
- Inline buttons: **Deny** | **Approve 3m** | **Approve 5m** | **Approve 15m** (durations configurable).
- Callback data: `deny:{tx_id}` or `approve:{tx_id}:{ttl_seconds}`.
- Whitelist: only configured `TELEGRAM_CHAT_ID`(s).

### 6.4 Lease store

- In-memory map + background expiry (v1).
- Optional later: admin revoke API, persistence.

### 6.5 Dev bypass

- `LUNA_ENV=dev` on proxy: auto-approve with default TTL (e.g. 5m) after auth pipeline; **no Telegram**; still respects sealed gate unless `LUNA_DEV_ALLOW_UNSEALED` documented for CI only.

---

## 7. HTTP API

### 7.1 Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/api/v1/admin/unseal` | Admin mTLS | Load signers into RAM |
| `GET` | `/api/v1/admin/seal-status` | Admin mTLS | `{ "sealed": true\|false }` |
| `GET` | `/api/v1/capabilities` | mTLS | `{ "signer_mode", "lease_supported", ... }` |
| `POST` | `/api/v1/ssh/sign` | mTLS + HMAC + PoP | Create tx or lease fast-path |
| `GET` | `/api/v1/ssh/sign/{tx_id}/wait` | mTLS | Cert or signature |
| `POST` | `/api/v1/telegram/webhook` | Webhook secret | Approvals |
| `GET` | `/healthz` | None | Liveness |

Optional: `POST /api/v1/ssh/sign?wait=1` unchanged.

### 7.2 Sign request (CA mode — unchanged core fields)

```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "target_user": "deploy",
  "target_ip": "10.0.1.50",
  "timestamp": 1716300000,
  "pop_signature": "<hex>"
}
```

### 7.3 Sign request (key mode — extension)

```json
{
  "public_key": "ssh-ed25519 AAAA...",
  "target_user": "deploy",
  "target_ip": "10.0.1.50",
  "timestamp": 1716300000,
  "pop_signature": "<hex>",
  "agent_sign_data": "<base64>"
}
```

### 7.4 Wait response — CA mode

```json
{
  "ssh_certificate": "ssh-ed25519-cert-v01@openssh.com AAAA...",
  "expires_at": "2026-05-30T12:05:00Z",
  "lease_expires_at": "2026-05-30T12:08:00Z"
}
```

### 7.5 Wait response — key mode

```json
{
  "ssh_signature": "<base64>",
  "expires_at": "2026-05-30T12:05:00Z",
  "lease_expires_at": "2026-05-30T12:08:00Z"
}
```

### 7.6 Status codes (delta)

| Status | Meaning |
|--------|---------|
| `503` | Sealed, or signer not loaded |
| `403` | Denied / bad unseal |
| Others | Same as core design (`409` replay, `410` consumed tx, etc.) |

Remove: `503` Vault / vault-agent unavailable.

### 7.7 Auth pipeline

Unchanged strict order: mTLS → HMAC → timestamp → replay LRU → PoP → tx/lease/sign.

Auth failure → **no** `tx_id`, **no** Telegram.

---

## 8. Mobile approval (specified, not v1)

### 8.1 Goals

- Approve/reject with **cryptographic proof** from device hardware-backed key (Secure Enclave / Keystore).
- Same lease + TTL semantics as Telegram; lease key includes `device_id`.

### 8.2 Enrollment (phase M1)

- `POST /api/v1/mobile/enroll` — admin-authenticated; body includes device label + `device_pubkey`; server returns `device_id`.
- Revocation: `DELETE /api/v1/mobile/devices/{device_id}` (admin).

### 8.3 Secure approve (phase M2)

Canonical payload signed by device:

```json
{
  "tx_id": "tx_01H...",
  "action": "approve",
  "ttl_seconds": 300,
  "device_id": "dev_01H...",
  "timestamp": 1716300000
}
```

- `POST /api/v1/mobile/approve` — verify Ed25519 signature with enrolled pubkey; constant-time compare.
- **v1 product:** Telegram only; mobile endpoints may return `501` until implemented.

### 8.4 Push (phase M3)

- FCM (Android) + APNs (iOS) for pending `tx_id` notifications.
- Idempotency: same rules as Telegram (no duplicate effective approvals).

---

## 9. Component notes

### 9.1 luna-proxy packages

| Package | Role |
|---------|------|
| `internal/keystore` | Sealed gate, decrypt, mlock, expose `Signer(s)` |
| `internal/signing` | `Signer` interface; `LocalCA`, `LocalKey` |
| `internal/lease` | Lease CRUD, key derivation, expiry |
| `internal/approval` | Tx FSM + Telegram + lease creation on approve |
| `internal/auth` | Unchanged |
| `internal/api` | Routes, admin auth middleware |

### 9.2 luna-sdk

- Keep `RequestCertificate` for `local-ca`.
- Add `RequestSignature` (or unified `RequestAccess`) for `local-key`.
- Query capabilities at client init or via config.

### 9.3 luna-agent

- Blocking `Sign` unchanged.
- Branch: cert signer vs returned signature for key mode.
- `LUNA_TARGET_HOST` still required for PoP binding in v1.

---

## 10. Security

### 10.1 Fail-closed

- Sealed → no sign, no Telegram.
- Auth failure → no tx.
- Unseal failure → no key material loaded.
- Signing error after approve → terminal tx error; no retry with duplicate cert for same tx without new request.

### 10.2 Logging

Structured: `tx_id`, `client_cert_fp`, `target_user`, `target_ip`, `lease_hit`, `ttl_seconds`, `approver_chat_id`, `outcome`.  
**Never log:** passphrases, private keys, decrypted blobs, HMAC exporter material, raw signatures.

### 10.3 Telegram

- Webhook secret validation unchanged.
- Callback TTL must match allowed set (reject crafted oversized TTL).

---

## 11. Testing and delivery

### 11.1 Test layers

- **Unit:** lease key derivation, TTL cap, sealed gate, signing mocks, Telegram callback parse
- **Integration:** unseal with test encrypted key, lease hit skips notifier, both signer modes
- **E2E:** docker-compose — gen test CA/key, unseal step, Telegram mock or dev bypass, sshd login

### 11.2 Implementation phases

| Phase | Deliverable | Exit criterion |
|-------|-------------|----------------|
| P0 | `keystore` + admin unseal + seal-status | Sealed proxy rejects sign; unseal enables mock signer |
| P1 | `local-ca` + remove Vault code | SDK receives cert in CI; E2E sshd cert login |
| P2 | Leases + Telegram TTL buttons | Second sign within lease skips Telegram; TTL enforced on cert |
| P3 | `local-key` + agent/SDK signature path | `ssh` via agent with hosted key mode |
| P4 | Mobile enroll + signed approve API | Integration test with test device key; no push |
| P5 | Mobile push (FCM/APNs) | Staging manual approve on device |

### 11.3 Documentation deliverables

| Artifact | Path |
|----------|------|
| This spec | `docs/superpowers/specs/2026-05-30-self-hosted-central-design.md` |
| Implementation plan | `docs/superpowers/plans/2026-05-30-self-hosted-central.md` (via writing-plans) |
| Vault migration | `docs/legacy-vault-migration.md` |
| Update | `README.md`, `AGENTS.md`, `docs/setup.md` when implementing |

---

## 12. Relationship to prior specs

- [`2026-05-21-luna-core-design.md`](2026-05-21-luna-core-design.md) remains valid for **auth pipeline**, **tx/wait**, **agent/sdk split**, and **Telegram idempotency** unless this document explicitly overrides.
- [`docs/design-specification.md`](../../design-specification.md) Vault-centric deployment is **historical**; new deployments follow this self-hosted model.
- [`docs/new-plan.md`](../../new-plan.md) raw agent-byte and mobile ECDSA ideas are incorporated here in structured form.

---

## 13. References

- Brainstorming session: 2026-05-30
- Prior core spec: 2026-05-21
- Agent guide: `AGENTS.md`
