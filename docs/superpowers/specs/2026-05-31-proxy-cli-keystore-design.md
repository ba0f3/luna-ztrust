# Proxy CLI, Unix Control Plane, and Multi-Key Keystore

**Status:** Approved (brainstorming 2026-05-31)  
**Builds on:** [`2026-05-30-self-hosted-central-design.md`](2026-05-30-self-hosted-central-design.md)  
**Out of scope (v1):** Multi-CA selection for `local-ca`; lunacli as separate repo (admin UX lives in `luna-proxy`); persisting decrypted keys to disk

---

## 1. Summary

Evolve **luna-proxy** into a **Cobra-based** binary with `serve` as the long-running server, an **ssh-add-style signing key pool** for `local-key` mode, a **local Unix control socket** for all operator CLI actions, and **HTTP mTLS** retained for automation sign flows and mobile (enroll, approve, encrypted key upload). Operators load keys via CLI; mobile may upload **passphrase-encrypted PEM blobs** that enter the pool only after **local confirmation** on the control socket.

**Unchanged from self-hosted design:** mTLS + HMAC + PoP auth pipeline, tx/wait sign API, Telegram OOB, leases, `LUNA_ENV=dev` auto-approve on proxy only, fail-closed auth, module boundaries (`proxy` ✗ `sdk`).

---

## 2. Decisions log

| Topic | Decision |
|-------|----------|
| Multi-key model | **ssh-add style** in-memory pool; v1 multi-key **only** for `local-key` |
| `local-ca` | **Single** active CA signer at a time (`key load` replaces) |
| Signer selection (`local-key`) | Request includes **host signing public key** (or fingerprint); proxy matches loaded pool |
| CLI packaging | **Single binary** `luna-proxy` with Cobra subcommands |
| Operator transport | **Unix control socket only** (no remote admin over HTTPS) |
| HTTP admin unseal | **Deprecated/removed** in v1; replaced by socket ops |
| HTTP retained | Sign/wait, capabilities, Telegram, mobile enroll/approve, mobile **pending key upload** |
| Mobile key ingest | **Encrypted blob upload** (B); operator **`key confirm`** on socket with passphrase |
| Architecture | **Approach 1:** one process, two listeners (mTLS + Unix), shared keystore |

---

## 3. CLI and process model

### 3.1 Cobra root

- **Binary:** `luna-proxy` (module `proxy/cmd/luna-proxy`).
- **Default (no subcommand):** print help and exit non-zero (breaking change from implicit server start).
- **Long-running server:** `luna-proxy serve`.

### 3.2 Subcommands (v1)

| Command | Transport | Purpose |
|---------|-----------|---------|
| `serve` | — | Load config; start mTLS API + Unix control listener |
| `status` | Unix socket | Seal state, `signer_mode`, loaded key fingerprints, pending key count |
| `key load <path>` | Unix socket | Decrypt PEM (passphrase stdin/TTY) → pool or sole CA |
| `key list` | Unix socket | List loaded signers (fingerprint, optional comment) |
| `key remove <fingerprint>` | Unix socket | Remove one signer from pool (`local-key`) or clear CA |
| `key confirm <pending-id>` | Unix socket | Decrypt mobile-uploaded pending blob → add to pool |
| `key reject <pending-id>` | Unix socket | Drop pending upload |
| `mobile enroll` | Unix socket | Register device (label + device pubkey) |
| `mobile list` | Unix socket | List enrolled devices |
| `mobile delete <device_id>` | Unix socket | Remove device |

**Optional v1 (nice-to-have):** `tx list` — pending sign transactions for operator visibility.

### 3.3 Flags

- Global: `--socket <path>` — override control socket (default from config or `/run/luna/control.sock`).
- `key load`: `--passphrase-stdin` (non-interactive).

### 3.4 Deployment

- systemd: `ExecStart=/usr/bin/luna-proxy serve`.
- Document migration: replace bare `luna-proxy` invocations with `luna-proxy serve`.

---

## 4. Keystore and signing

### 4.1 Pool semantics

Refactor `internal/keystore` from a single `ssh.Signer` to:

- **`local-ca` mode:** one slot `caSigner`; `key load` replaces; `Available()` iff CA loaded.
- **`local-key` mode:** `map[string]ssh.Signer` keyed by **fingerprint** (see §4.2); zero or more entries.

**Seal:** process restart clears all signers. Optional `key clear` (socket) wipes pool without restart.

**Security:** retain `mlock` + zeroing on PEM/passphrase buffers; unseal lockout (5 fails / 15m) applies per **load/confirm** attempt on a given path or pending id.

### 4.2 Fingerprint algorithm

- Compute **SHA-256** over `ssh.MarshalPublicKey(pub)` (OpenSSH wire format).
- Encode fingerprint as **hex** (document in API/SDK).
- Sign requests accept either full `host_public_key` (base64 SSH wire) or `host_key_fingerprint` (hex); proxy prefers wire key when both present and must match.

### 4.3 Sign path changes

**`local-ca`:** unchanged — ephemeral client `public_key` in JSON is certified by the sole loaded CA.

**`local-key`:** extend sign JSON schema:

```json
{
  "host_public_key": "<base64 ssh public key wire>",
  "host_key_fingerprint": "<hex, optional if wire present>",
  "... existing agent sign fields ..."
}
```

Proxy selects signer from pool; errors:

| Condition | HTTP |
|-----------|------|
| No matching loaded key | `503` + `no_matching_signer` |
| Pool empty / sealed | `503` + `sealed` |
| Ambiguous fingerprint | `400` |

### 4.4 Config delta

- **`signer_mode`:** `local-ca` | `local-key` (unchanged).
- **`ca_key_path`:** optional default path for one-shot `serve` bootstrap (document only; prefer `key load`).
- **Deprecate `key_path` as auto-unseal target** for `local-key`; keys come from CLI/mobile confirm only.
- For **`local-ca`**, optional `ca_key_path` may still seed a path hint for operators; loading always via `key load` or documented bootstrap.

---

## 5. Unix control socket

### 5.1 Listener

- **Config key:** `control_socket` (YAML) / env `LUNA_CONTROL_SOCKET`.
- **Default:** `/run/luna/control.sock`.
- **Permissions:** create with `0660`, owning user `luna`, group `luna-admin` (configurable `control_socket_group`).
- Started only under `luna-proxy serve`.

### 5.2 Authorization

- Linux **`SO_PEERCRED`** on each connection (`//go:build linux`).
- Allow if peer **UID == 0** OR peer primary/supplementary GID matches configured admin group.
- Non-Linux: compile stub returns error for control socket (document Linux-only control plane) OR allow only UID 0 — pick **Linux-only** to match existing `mlock` posture.

### 5.3 Protocol

**Newline-delimited JSON** (one request per line, one response per line). Simple to debug with `nc -U`.

**Request envelope:**

```json
{ "op": "status", "id": "optional-correlation" }
```

**Response envelope:**

```json
{ "ok": true, "id": "...", "data": { } }
```

```json
{ "ok": false, "id": "...", "error": "message", "code": "SEALED" }
```

**Operations (v1):** `status`, `key.load`, `key.list`, `key.remove`, `key.confirm`, `key.reject`, `key.pending.list`, `mobile.enroll`, `mobile.list`, `mobile.delete`.

- `key.load`: `{ "path": "...", "passphrase": "..." }` — passphrase only on socket (local); never logged.
- `key.confirm`: `{ "pending_id": "...", "passphrase": "..." }`.

Internal package `internal/control` implements handlers; Cobra client in `internal/control/client` (or `cmd` shared package).

### 5.4 HTTP admin deprecation

Remove or return **`410 Gone`** for:

- `POST /api/v1/admin/unseal`
- `GET /api/v1/admin/seal-status`

Capabilities and sign paths report `sealed` from pool state as today.

---

## 6. HTTP API (retained and extended)

### 6.1 Unchanged

- `POST /api/v1/ssh/sign`, `GET /api/v1/ssh/sign/{tx_id}/wait`
- `GET /api/v1/capabilities`
- `POST /api/v1/telegram/webhook`
- `POST /api/v1/mobile/approve` (device mTLS + signed payload)

### 6.2 Mobile enroll

- **Keep** `POST /api/v1/mobile/enroll` on **admin mTLS** (OU `luna-admin`) for apps/scripts that cannot use Unix socket.
- **Mirror** same logic on socket op `mobile.enroll` for operators on the host.

### 6.3 Mobile encrypted key upload (pending queue)

**`POST /api/v1/mobile/keys/pending`** (enrolled device mTLS only; automation certs rejected)

| Field | Description |
|-------|-------------|
| `encrypted_pem` | base64 ciphertext (passphrase-protected OpenSSH PEM as stored on device) |
| `label` | operator-visible label |
| `comment` | optional |

**Auth:** enrolled **device mTLS** (automation certs rejected). Rate-limit per device; **max body 64 KiB**.

**Behavior:** store in-memory pending record `{ id, device_id, label, blob, expires_at }` (default TTL **15 minutes**). Do **not** decrypt on upload.

**Operator confirm:** only via Unix socket `key.confirm` with passphrase — decrypt, validate parses as private key, insert into **`local-key` pool only**. Wrong passphrase counts toward lockout for that pending id.

**Reject:** socket `key.reject` or expiry.

### 6.4 Capabilities extension

When `signer_mode=local-key` and not sealed:

```json
{
  "signer_mode": "local-key",
  "sealed": false,
  "lease_supported": true,
  "allowed_ttl_seconds": [180, 300, 900],
  "loaded_signers": [
    { "fingerprint": "<hex>", "comment": "deploy-prod" }
  ]
}
```

`local-ca` omits `loaded_signers` or returns at most one CA entry with fingerprint only (no private material).

---

## 7. SDK and agent impact

### 7.1 SDK

- **`local-ca`:** no request schema change.
- **`local-key`:** add `HostPublicKey` / `HostKeyFingerprint` to `CertRequest` (or dedicated sign request struct); set from env/config.
- Parse extended **capabilities** for `loaded_signers` when choosing host key.

### 7.2 Agent

- New env: `LUNA_HOST_PUBLIC_KEY` or `LUNA_HOST_KEY_FINGERPRINT` (required in `local-key` when multiple signers possible).
- If exactly one signer in capabilities, agent may default to that fingerprint.

### 7.3 lunacli (external repo)

- Document that **server admin** moves to `luna-proxy` subcommands; lunacli remains SDK-facing automation client if desired.

---

## 8. Repository layout (delta)

```
proxy/
  cmd/luna-proxy/
    main.go           # Cobra root
    serve.go
    status.go
    key.go
    mobile.go
  internal/
    control/          # Unix listener, SO_PEERCRED, op dispatch
    control/client/   # CLI dial + call helpers
    keystore/         # pool, pending queue, fingerprints
    api/              # HTTP; remove admin unseal handlers
    config/           # + control_socket, control_socket_group
```

**Dependency:** `github.com/spf13/cobra` in `proxy/go.mod`.

---

## 9. Error handling and security

- **Fail-closed:** invalid peer on socket → close connection; no partial pool state on failed decrypt.
- **Never log:** passphrases, PEM plaintext, decrypted keys, mobile blobs.
- **Audit (info level):** `key_loaded fp=...`, `key_removed fp=...`, `pending_created id=...`, `pending_confirmed fp=...`, `mobile_enroll device_id=...`.
- **Pending queue:** cap count (e.g. 32 global, 4 per device); reject when full.
- **Sign + sealed:** unchanged `503` before tx/Telegram.

---

## 10. Testing

| Layer | Cases |
|-------|--------|
| Unit | Fingerprint stability; pool add/remove; pending TTL; confirm wrong passphrase lockout |
| Unit (linux) | SO_PEERCRED allow/deny |
| Integration | `serve` + socket `key load` + `status`; confirm pending |
| Integration | `local-key` sign with two keys → correct matcher |
| HTTP | mobile pending upload → confirm via socket → sign succeeds |
| Regression | `local-ca` single CA; capabilities sealed flag |

---

## 11. Migration

1. Replace systemd `luna-proxy` → `luna-proxy serve`.
2. Replace `curl .../admin/unseal` with `luna-proxy key load` (or `key confirm` for mobile queue).
3. Set `control_socket` and create `luna-admin` group for operators.
4. For `local-key` deployments: configure agent/SDK with host key fingerprint; load all host keys via CLI.
5. Update README, AGENTS.md, `.env.example`, YAML examples.

---

## 12. Phasing (implementation hint)

| Phase | Deliverable |
|-------|-------------|
| P1 | Cobra + `serve`; control socket + `status`; keystore pool refactor |
| P2 | `key load/list/remove`; deprecate HTTP unseal |
| P3 | `local-key` request field + capabilities `loaded_signers`; SDK/agent |
| P4 | Mobile pending upload HTTP + `key confirm/reject` |
| P5 | CLI `mobile *`; docs + E2E |

---

## 13. Non-goals (v1)

- Multiple simultaneous CAs with client-side CA picker (`local-ca` multi-key).
- Auto-unseal from env on boot (except existing dev patterns — still forbidden in prod).
- Persisting pending blobs or decrypted keys across restart.
- Remote Unix socket forwarding / SSH tunnel as supported workflow.
- Replacing Telegram with mobile-only approval.

---

## 14. Remote key load (CLI mTLS)

Socket `key.load` with a server-local path remains the on-host operator path. For **`local-key`** deployments, operators on a laptop upload encrypted PEM over **`POST /api/v1/cli/keys/load`** using an enrolled CLI client cert (`OU=luna-cli`).

CSR enrollment, HTTP API, Cobra `luna-proxy cli …`, and `key load` HTTP branch are specified in [`2026-05-31-cli-remote-key-load-design.md`](2026-05-31-cli-remote-key-load-design.md). Mobile pending upload (§6.3) is unchanged.
