# CLI Remote Key Load Design

**Status:** Approved (2026-05-31)  
**Builds on:** [`2026-05-31-proxy-cli-keystore-design.md`](2026-05-31-proxy-cli-keystore-design.md), [`2026-05-30-self-hosted-central-design.md`](2026-05-30-self-hosted-central-design.md)  
**Out of scope:** `local-ca` over HTTP, CLI pending queue, non-admin enrollment, SDK/agent sign protocol changes, lunacli (separate repo)

---

## 1. Summary

Operators running **`luna-proxy key load`** from a **laptop** can upload a **passphrase-protected PEM** over **enrolled CLI mTLS** in one request. The proxy decrypts into the **`local-key` pool** in RAM (`mlock`). The encrypted key file does not need to exist on the central host.

**Enrollment:** Admin-only, **CSR-based** — TLS client private key never leaves the workstation.

**On-host operators:** Unix socket `key.load` with server-local `path` remains unchanged (including future `local-ca` load on the central host).

---

## 2. Decisions log

| Topic | Decision |
|-------|----------|
| Custody over the wire | Encrypted PEM (base64) + passphrase in same HTTPS request inside mTLS |
| Plaintext key | Only in proxy RAM after decrypt (same as socket load today) |
| CLI enrollment | Admin-only (`luna-admin` mTLS or control socket) |
| Load flow | One-shot HTTP (no CLI pending queue) |
| HTTP signer mode | **`local-key` only** |
| mTLS identity | CSR signed by existing mTLS CA; `OU=luna-cli` |
| Socket `key.load` | **Retained** for on-host path-based load |
| Mobile key upload | **Unchanged** (pending + socket confirm) |
| Request signing | mTLS + device registry + TLS-exporter HMAC, timestamp, replay LRU (no PoP) |

---

## 3. Goals and boundaries

### 3.1 Goals

1. Remote operators load host signing keys without copying encrypted PEM to the central filesystem.
2. Per-workstation **CLI device** identity distinct from automation and admin certs.
3. Fail-closed auth: only enrolled `luna-cli` certs may call key load.

### 3.2 In scope

- `internal/cli` device store and CSR signing helper.
- HTTP: `POST /api/v1/cli/enroll`, `GET /api/v1/cli/devices`, `DELETE /api/v1/cli/devices/{id}`, `POST /api/v1/cli/keys/load`.
- Control socket ops: `cli.enroll`, `cli.list`, `cli.delete`.
- Cobra: `luna-proxy cli …`; `key load` branches to HTTP when CLI profile configured.
- Config: `cli_client_ou` (default `luna-cli`).
- Tests and `gen-test-ca.sh` / integration coverage for enroll + load.

### 3.3 Out of scope (v1)

- HTTP load for `local-ca`.
- CLI two-step pending / second-person confirm.
- Delegated (non-admin) CLI enrollment.
- Cert renewal API (re-enroll via admin).
- PoP on CLI key-load body (HMAC + timestamp + replay required; same TLS exporter as sign API).

---

## 4. Architecture

### 4.1 Component diagram

```
┌── OPERATOR LAPTOP ──────────────────────────────────────────┐
│  luna-proxy cli init / csr                                 │
│  ~/.config/luna/cli.key + cli.crt (after admin enroll)     │
│  luna-proxy key load ./encrypted.pem  →  HTTPS + mTLS      │
└────────────────────────────┬──────────────────────────────┘
                             │ POST /api/v1/cli/keys/load
                             ▼
┌── CENTRAL HOST ─────────────────────────────────────────────┐
│  luna-proxy :443                                             │
│    api/          cli enroll (admin) + keys/load (cli)       │
│    cli/store     device_id ↔ cert fingerprint               │
│    keystore/     LoadPEMBytes → local-key pool              │
│    control/      socket key.load (on-host path) + cli.*   │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Approach

**Dedicated `internal/cli` subsystem** (not merged into `mobile`):

- Mobile devices: ed25519 approve + optional encrypted upload pending.
- CLI devices: TLS client identity for **key custody** only.

Rejected alternative: reuse automation `client.crt` + fingerprint allowlist (excessive blast radius, weak workstation identity).

---

## 5. Enrollment and mTLS binding

### 5.1 CLI device record

| Field | Description |
|-------|-------------|
| `device_id` | `cli_<ulid>` |
| `label` | Operator-visible name |
| `cert_fingerprint` | SHA256 fingerprint of issued client certificate (hex) |
| `enrolled_at` | UTC timestamp |

In-memory store v1 (restart loses enrollments — document; persistence deferred).

### 5.2 CSR flow

**Laptop**

1. `luna-proxy cli init [--dir]` — generate TLS key pair locally (never transmitted).
2. `luna-proxy cli csr [--dir]` — write/display PEM CSR with `OU=luna-cli`.

**Admin**

3. `luna-proxy cli enroll --label <name> --csr-file <path>`  
   - HTTP: `POST /api/v1/cli/enroll` (admin mTLS)  
   - Socket: `cli.enroll` (admin peer via SO_PEERCRED / group)

4. Server validates CSR (signature, public key size/type, requested `OU=luna-cli`), signs with **existing mTLS issuing CA**, stores fingerprint, returns `{ device_id, certificate_pem }`.

5. Operator installs `certificate_pem` beside local key.

**Revocation:** `cli delete <device_id>` or `DELETE /api/v1/cli/devices/{device_id}`. Requests with revoked fingerprint → `403`.

### 5.3 Key-load request auth

1. mTLS with peer certificate.
2. Reject `OU=luna-admin` and automation clients without `luna-cli` OU (mirror `keys_pending_handler` admin rejection).
3. Require peer `OU` == configured `cli_client_ou` (default `luna-cli`).
4. Resolve peer cert fingerprint → enrolled device; missing → `403`.

### 5.4 Configuration

| Key | Default | Purpose |
|-----|---------|---------|
| `cli_client_ou` | `luna-cli` | Required OU on CLI client certs |
| `admin_client_ou` | `luna-admin` | Unchanged for enroll/list/delete |

Environment: `LUNA_CLI_CLIENT_OU` maps to `cli_client_ou`.

### 5.5 mTLS CA signing material

CSR enrollment requires the proxy (or enroll handler) to sign client certificates with the **same mTLS CA** that issued the server certificate. Add config paths (names illustrative):

| Key | Purpose |
|-----|---------|
| `mtls_ca_cert_path` | Issuing CA certificate (for chain validation if needed) |
| `mtls_ca_key_path` | Issuing CA private key (0400, proxy user only) |

If CA key is not configured, `cli.enroll` / `POST /cli/enroll` return **`503`** with a clear error (fail-closed). Production may later substitute PKCS#11; v1 is file-based PEM, consistent with signing key custody patterns.

---

## 6. HTTP API

### 6.1 `POST /api/v1/cli/enroll`

**Auth:** Admin mTLS.

**Request:**

```json
{
  "label": "alice-macbook",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..."
}
```

**Response `201`:**

```json
{
  "device_id": "cli_01H...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

**Errors:** `400` invalid CSR/label; `403` non-admin cert.

### 6.2 `GET /api/v1/cli/devices`

**Auth:** Admin mTLS.

**Response `200`:**

```json
{
  "devices": [
    {
      "device_id": "cli_01H...",
      "label": "alice-macbook",
      "cert_fingerprint": "ab12...",
      "enrolled_at": "2026-05-31T12:00:00Z"
    }
  ]
}
```

### 6.3 `DELETE /api/v1/cli/devices/{device_id}`

**Auth:** Admin mTLS. **Response:** `204` or `404`.

### 6.4 `POST /api/v1/cli/keys/load`

**Auth:** Enrolled CLI mTLS (`luna-cli`). Body includes `timestamp`; `X-Luna-Body-Mac` (TLS exporter HMAC) and replay LRU required.

**Precondition:** `signer_mode == local-key`; else `400`.

**Request** (max body **64 KiB**):

```json
{
  "encrypted_pem": "<base64 OpenSSH encrypted private key>",
  "passphrase": "<string>",
  "label": "deploy-prod",
  "comment": "optional",
  "timestamp": 1717132800
}
```

**Response `200`:**

```json
{ "fingerprint": "<sha256 hex>" }
```

| Status | Meaning |
|--------|---------|
| `400` | Invalid JSON, missing fields, invalid base64, wrong signer mode |
| `403` | Unknown/revoked CLI cert, wrong OU, bad passphrase |
| `403` + code `LOCKED` | Keystore unseal lockout (`ErrUnsealLocked`) |
| `429` | Per-device rate limit exceeded |

**Implementation:** `Keystore.LoadPEMBytes` with existing mlock/zeroing and lockout. Audit log: `cli_key_loaded fp=... device_id=...` (no passphrase, no PEM).

**Rate limits (v1):** 10 successful loads / hour / `device_id`; failed passphrase attempts use existing 5-fail / 15m lockout per load operation.

---

## 7. Control socket

| Op | Peer | Purpose |
|----|------|---------|
| `cli.enroll` | Admin | Same as HTTP enroll |
| `cli.list` | Admin | List devices |
| `cli.delete` | Admin | Revoke device |
| `key.load` | Operator | Unchanged: `{ path, passphrase }` on **server** path |
| `key.list` / `key.remove` | Operator | Unchanged |

CLI devices do not use the Unix socket for key load.

---

## 8. CLI UX

### 8.1 `luna-proxy cli`

| Command | Description |
|---------|-------------|
| `cli init [--dir]` | Generate local TLS key |
| `cli csr [--dir]` | Emit CSR PEM |
| `cli enroll --label --csr-file` | Admin: sign CSR, register device |
| `cli list` | Admin: list devices |
| `cli delete <device_id>` | Admin: revoke |

### 8.2 `luna-proxy key load <path>`

1. Read encrypted PEM from **local** `<path>`.
2. Prompt passphrase (`--passphrase-stdin` supported); zero after use on client.
3. **If** CLI profile set (`--proxy-url`, `--cli-cert`, `--cli-key`, `--ca`, or `~/.config/luna/cli.yaml`):  
   POST `/api/v1/cli/keys/load` with mTLS.
4. **Else if** control socket available: existing socket `key.load` with server `path`.
5. **Else:** error instructing to configure CLI profile or use control socket on central host.

### 8.3 Operator config file (example)

```yaml
proxy_url: https://luna.example:443
cli_cert: ~/.config/luna/cli.crt
cli_key: ~/.config/luna/cli.key
ca: ~/.config/luna/ca.crt
```

---

## 9. Repository layout (delta)

```
proxy/
  cmd/luna-proxy/
    cli.go              # cli subcommands
    key.go              # HTTP branch in key load
  internal/
    cli/
      store.go          # device registry
      csr.go            # validate + sign CSR
    api/
      cli_handler.go    # HTTP handlers
    control/
      ops.go            # + cli.* ops
```

**Docs:** Update `README.md`, `AGENTS.md` (operator key load), cross-link from `2026-05-31-proxy-cli-keystore-design.md`.

---

## 10. Security

- **Fail-closed** on all auth and decrypt errors.
- **Never log:** passphrases, decrypted PEM, `encrypted_pem` bodies at debug.
- **Reject** admin and automation certs on `cli/keys/load`.
- **TLS** protects passphrase in transit (operator choice A).
- **At rest on laptop:** operator controls encrypted PEM; no requirement to `scp` to central.
- **In proxy RAM:** decrypted signers follow existing `mlock` / pool rules.
- Restart clears CLI enrollments (v1) and keystore pool — document re-enroll + re-load.

---

## 11. Testing

| Layer | Cases |
|-------|--------|
| Unit | CSR validation; fingerprint extraction; OU checks; store enroll/delete |
| Integration | Admin enroll → CLI mTLS load → `key.list` fingerprint; bad passphrase lockout; revoked device `403` |
| HTTP | Reject admin on `keys/load`; reject `local-ca` mode |
| CLI | `key load` HTTP path with httptest TLS |

---

## 12. Migration / operator notes

1. Admin enrolls each operator laptop (CSR flow).
2. Operator configures CLI TLS profile.
3. `luna-proxy key load ./host-key.enc` from laptop (no file on central disk).
4. On central host, continue using socket `key load /path/on/server` when preferred.
5. Mobile pending upload + `key confirm` unchanged.

---

## 13. Implementation phases (suggested)

| Phase | Deliverable |
|-------|-------------|
| P1 | `internal/cli` store + CSR sign + admin enroll HTTP/socket |
| P2 | `POST /cli/keys/load` + handler tests |
| P3 | Cobra `cli` + `key load` HTTP branch + docs |
| P4 | Integration test in CI with test CA |

---

## 14. Related specs

- Socket keystore CLI: [`2026-05-31-proxy-cli-keystore-design.md`](2026-05-31-proxy-cli-keystore-design.md) §6.3 mobile pending (unchanged)
- Self-hosted central: [`2026-05-30-self-hosted-central-design.md`](2026-05-30-self-hosted-central-design.md)
