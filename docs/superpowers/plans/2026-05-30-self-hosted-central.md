# Self-Hosted Central Server Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Vault SSH signing with a self-hosted `luna-proxy` that unseals encrypted keys in RAM, signs via `local-ca` or `local-key`, and supports Telegram OOB approval with session leases and TTL buttons; mobile APIs phased per spec.

**Architecture:** Add `internal/keystore`, `internal/signing`, `internal/lease`; wire into existing auth pipeline and `approval.Store`; remove `internal/vault`. Admin unseal uses a separate admin mTLS cert. SDK/agent gain capabilities + optional signature path.

**Tech Stack:** Go 1.23+ (`go.work`), `golang.org/x/crypto/ssh`, `golang.org/x/sys/unix` (mlock), `github.com/oklog/ulid/v2`, OpenSSL test scripts, existing docker-compose E2E.

**Spec:** [`docs/superpowers/specs/2026-05-30-self-hosted-central-design.md`](../specs/2026-05-30-self-hosted-central-design.md)

**Prerequisite:** Core luna stack from [`2026-05-21-luna-core.md`](2026-05-21-luna-core.md) is implemented (mTLS, tx/wait, Telegram, agent).

---

## File map (delta)

```
proxy/
  internal/
    keystore/
      keystore.go          # Sealed/Unsealed, Unseal(pass), Signer access
      keystore_test.go
      encrypt_testutil.go  # test-only PEM encrypt helpers
    signing/
      signer.go            # IssueInput, IssueResult, Backend interface
      local_ca.go          # Sign SSH cert from CA key
      local_ca_test.go
      local_key.go         # Sign agent challenge bytes
      local_key_test.go
    lease/
      key.go               # LeaseKey, Derive(client fp, target, remote IP, approver)
      store.go             # Get/Put/Expire
      store_test.go
    approval/
      store.go             # MODIFY: remove vault; Approve(tx, ttl, approver, sign fn)
      telegram.go          # MODIFY: TTL inline keyboard
      telegram_test.go
    api/
      admin_handler.go     # unseal, seal-status
      admin_handler_test.go
      capabilities_handler.go
      sign_handler.go      # MODIFY: sealed gate, lease fast-path
      webhook_handler.go   # MODIFY: approve:tx:ttl, chat_id → approver
      server.go            # MODIFY: routes, admin mTLS middleware
      mobile_handler.go    # P4: enroll/approve stubs or full
    config/config.go       # MODIFY: SignerMode, KeyPath, AllowedTTLs, AdminCertOUID
  cmd/luna-proxy/main.go   # MODIFY: keystore + signing + lease wiring; drop vault
  # DELETE:
  internal/vault/

sdk/
  capabilities.go          # GET /capabilities client
  sign/signature.go        # RequestSignature for local-key
  client.go                # MODIFY: optional mode branch
  sign/client.go           # MODIFY: wait response fields

agent/
  agent.go                 # MODIFY: cert vs signature branch

scripts/
  gen-test-ca.sh           # MODIFY: SSH CA key, encrypted PEM, admin client cert
  gen-test-ssh-ca.sh       # NEW: user CA + encrypted host key for CI

docs/
  legacy-vault-migration.md
  setup.md                 # MODIFY: drop Vault runtime; add unseal + TrustedUserCAKeys
  AGENTS.md                # MODIFY: phases, no vault-agent
  README.md                # MODIFY: env vars

deploy/
  docker-compose.e2e.yml   # MODIFY: no vault service; unseal init container or test hook
```

---

## Task 1: Keystore package (P0)

**Files:**
- Create: `proxy/internal/keystore/keystore.go`
- Create: `proxy/internal/keystore/keystore_test.go`
- Create: `proxy/internal/keystore/encrypt_testutil.go`

- [ ] **Step 1: Write failing test for sealed gate**

```go
// proxy/internal/keystore/keystore_test.go
func TestKeystore_SealedBlocksSigner(t *testing.T) {
	ks := keystore.New()
	if ks.Available() {
		t.Fatal("new keystore should be sealed")
	}
	_, err := ks.SSHSigner()
	if !errors.Is(err, keystore.ErrSealed) {
		t.Fatalf("got %v", err)
	}
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cd /home/tui/repos/luna-ztrust/proxy && go test ./internal/keystore/... -run TestKeystore_SealedBlocksSigner -v`  
Expected: build fail or undefined `keystore.New`

- [ ] **Step 3: Implement minimal keystore**

```go
// proxy/internal/keystore/keystore.go
package keystore

import (
	"errors"
	"sync"

	"golang.org/x/crypto/ssh"
)

var ErrSealed = errors.New("keystore sealed")

type Keystore struct {
	mu     sync.RWMutex
	signer ssh.Signer
}

func New() *Keystore { return &Keystore{} }

func (k *Keystore) Available() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.signer != nil
}

func (k *Keystore) SSHSigner() (ssh.Signer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.signer == nil {
		return nil, ErrSealed
	}
	return k.signer, nil
}

func (k *Keystore) setSigner(s ssh.Signer) {
	k.mu.Lock()
	k.signer = s
	k.mu.Unlock()
}
```

- [ ] **Step 4: Run test — expect PASS**

Run: `go test ./internal/keystore/... -run TestKeystore_SealedBlocksSigner -v`

- [ ] **Step 5: Write failing unseal test with encrypted test PEM**

In `encrypt_testutil.go`, add `EncryptPEMForTest(t, privPEM, passphrase)` using `openssl` or `x509.EncryptPEMBlock`.

Test `TestKeystore_UnsealLoadsSigner` reads `../../testdata/ssh/encrypted_ca.key` (created in Task 8 script) and calls `Unseal(passphrase)`.

- [ ] **Step 6: Implement `Unseal(path, passphrase)`**

- Parse encrypted PEM with `ssh.ParseRawPrivateKey` after decrypt
- Call `setSigner`
- Best-effort: extract signer private struct and `unix.Mlock` on underlying slice (linux build tag file `mlock_linux.go`)

- [ ] **Step 7: Run keystore package tests**

Run: `go test ./internal/keystore/... -v`  
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add proxy/internal/keystore/
git commit -m "feat(proxy): add sealed keystore with passphrase unseal"
```

---

## Task 2: Admin API + sealed gate on sign (P0 exit)

**Files:**
- Create: `proxy/internal/api/admin_handler.go`
- Create: `proxy/internal/api/admin_handler_test.go`
- Modify: `proxy/internal/api/server.go`
- Modify: `proxy/internal/api/sign_handler.go`
- Modify: `proxy/internal/config/config.go`
- Modify: `proxy/cmd/luna-proxy/main.go`

- [ ] **Step 1: Extend config**

```go
// proxy/internal/config/config.go additions
AdminClientOU    string   // e.g. "luna-admin" — client cert Subject OU must match
KeyPath          string   // LUNA_KEY_PATH
SignerMode       string   // local-ca | local-key
AllowedTTLSeconds []int   // default []int{180,300,900}
```

- [ ] **Step 2: Write failing admin unseal test**

Use `httptest` + test server TLS with admin client cert (generate in test from same CA with OU=luna-admin).

POST `{"passphrase":"test-pass"}` → 200 and `seal-status` returns `sealed:false`.

Automation client cert (no admin OU) → 403 on `/api/v1/admin/unseal`.

- [ ] **Step 3: Implement `withAdminMTLS` middleware**

Check `PeerCertificates[0]` Subject OU equals `cfg.AdminClientOU`.

- [ ] **Step 4: Implement handlers**

```go
func (s *server) handleUnseal(w http.ResponseWriter, r *http.Request) {
	var body struct{ Passphrase string `json:"passphrase"` }
	// decode; ks.Unseal(s.cfg.KeyPath, body.Passphrase)
}
func (s *server) handleSealStatus(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]bool{"sealed": !s.keystore.Available()})
}
```

Register in `NewServer`:

```go
mux.HandleFunc("POST /api/v1/admin/unseal", s.withAdminMTLS(s.handleUnseal))
mux.HandleFunc("GET /api/v1/admin/seal-status", s.withAdminMTLS(s.handleSealStatus))
```

- [ ] **Step 5: Sealed gate in `handleSign`**

After auth pipeline, before `store.Create`:

```go
if !s.keystore.Available() {
	s.logSignRequest(r, start, "", req.TargetUser, req.TargetIP, "sealed")
	http.Error(w, "sealed", http.StatusServiceUnavailable)
	return
}
```

- [ ] **Step 6: Wire keystore in `main.go`**

```go
ks := keystore.New()
handler := api.NewServer(cfg, ks, store, replay, telegram)
```

Update `NewServer` signature; remove vault params (done fully in Task 3).

- [ ] **Step 7: Run proxy tests**

Run: `cd /home/tui/repos/luna-ztrust && make test`  
Expected: PASS (fix compile breaks from signature change)

- [ ] **Step 8: Commit**

```bash
git add proxy/internal/api/admin_handler.go proxy/internal/api/admin_handler_test.go \
  proxy/internal/api/server.go proxy/internal/api/sign_handler.go \
  proxy/internal/config/config.go proxy/cmd/luna-proxy/main.go
git commit -m "feat(proxy): admin unseal API and sealed sign gate"
```

---

## Task 3: Local CA signing + remove Vault (P1)

**Files:**
- Create: `proxy/internal/signing/signer.go`, `local_ca.go`, `local_ca_test.go`
- Modify: `proxy/internal/approval/store.go` (remove vault import and `approveViaVault`)
- Delete: `proxy/internal/vault/*.go`
- Modify: `proxy/internal/api/server.go`, `sign_handler.go`, `webhook_handler.go`
- Modify: `proxy/cmd/luna-proxy/main.go`
- Create: `docs/legacy-vault-migration.md`

- [ ] **Step 1: Define signing backend interface**

```go
// proxy/internal/signing/signer.go
package signing

import (
	"time"
	"golang.org/x/crypto/ssh"
)

type IssueRequest struct {
	ClientPubKey string
	TargetUser   string
	TargetIP     string
	SourceIP     string
	ValidUntil   time.Time
}

type IssueResult struct {
	Certificate string
	ExpiresAt   time.Time
}

type CertIssuer interface {
	IssueCert(ctx context.Context, req IssueRequest) (IssueResult, error)
}
```

- [ ] **Step 2: Write failing `LocalCA` test**

Generate CA + client ed25519 in test; `IssueCert` returns cert containing principal `deploy` and `source-address` extension.

Run: `go test ./internal/signing/... -run TestLocalCA -v` → FAIL

- [ ] **Step 3: Implement `LocalCA` using `ssh.Certificate`**

Use `keystore.SSHSigner()` as CA; set `CertType: ssh.UserCert`, `ValidPrincipals`, `CriticalOptions: map[string]string{"source-address": sourceIP+CIDR}`.

- [ ] **Step 4: Refactor `approval.Store`**

Replace vault fields with:

```go
type Store struct {
	// ...
	issuer signing.CertIssuer
	keystore *keystore.Keystore
}
func (s *Store) SetIssuer(issuer signing.CertIssuer)
```

`Approve(txID, ttl time.Duration, approver string)` → load tx → `issuer.IssueCert` → `finish` with cert PEM.

Dev bypass: if `cfg.Env == "dev"`, auto-`Approve` with `cfg.DevDefaultTTL` (5m) after Create when keystore available.

- [ ] **Step 5: Delete vault package and fix imports**

Run: `rm proxy/internal/vault/*.go`  
Update all references; `make test` until green.

- [ ] **Step 6: Update dev placeholder**

Remove `"dev-cert"` string; dev path must use real `LocalCA` with test unsealed keystore in tests.

- [ ] **Step 7: Write `docs/legacy-vault-migration.md`**

Document: export CA from Vault or rotate; configure `TrustedUserCAKeys` on sshd; env var mapping old → new.

- [ ] **Step 8: Commit**

```bash
git commit -m "feat(proxy): local CA signing; remove Vault integration"
```

---

## Task 4: Lease store + Telegram TTL buttons (P2)

**Files:**
- Create: `proxy/internal/lease/key.go`, `store.go`, `store_test.go`
- Modify: `proxy/internal/approval/telegram.go`, `telegram_test.go`
- Modify: `proxy/internal/api/webhook_handler.go`, `webhook_handler_test.go`
- Modify: `proxy/internal/api/sign_handler.go`
- Modify: `proxy/internal/approval/store.go`

- [ ] **Step 1: Write failing lease key test**

```go
func TestLeaseKey_Deterministic(t *testing.T) {
	k1 := lease.NewKey("fp1", "deploy", "10.0.1.5", "203.0.113.10", "chat42")
	k2 := lease.NewKey("fp1", "deploy", "10.0.1.5", "203.0.113.10", "chat99")
	if k1 == k2 {
		t.Fatal("different approver must not match")
	}
}
```

- [ ] **Step 2: Implement lease store `Get(key) (Lease, bool)` and `Put(key, expiresAt, approver)`**

Background goroutine or lazy expiry on Get.

- [ ] **Step 3: Extend `ParseCallbackData`**

Support `approve:tx_01H...:300` and `deny:tx_01H...`.

Validate `300` ∈ `cfg.AllowedTTLSeconds`; else ignore callback.

Extract `chat_id` from webhook payload (`callback_query.message.chat.id`) and pass to `store.Approve(txID, ttl, chatID)`.

- [ ] **Step 4: Update Telegram keyboard**

```go
{"text": "Approve 3m", "callback_data": fmt.Sprintf("approve:%s:180", tx.ID)},
{"text": "Approve 5m", "callback_data": fmt.Sprintf("approve:%s:300", tx.ID)},
{"text": "Approve 15m", "callback_data": fmt.Sprintf("approve:%s:900", tx.ID)},
```

- [ ] **Step 5: Lease fast-path in `handleSign`**

After auth, derive:

- `clientFP` from `tlsConn.PeerCertificates[0]` (SHA-256 SPKI fingerprint helper in `auth` or `api`)
- `sourceIP` from `r.RemoteAddr` host

If lease hit for any active lease matching first four tuple components (scan or index by prefix — use map keyed by `LeaseKey` without approver for lookup, then verify approver matches stored lease):

- Create synthetic instant result: call issuer with `ValidUntil = min(lease.Remaining(), ttlCap)` without Telegram.

Implementation note: store approver on lease at approve time; lookup key for sign is `(fp, user, ip, remoteIP)` → returns lease record including `approver_chat_id`.

- [ ] **Step 6: On Approve, `lease.Put` with `expiresAt = now + ttl`**

Credential TTL for cert = `ttl` (same as lease duration for v1 simplicity per spec invariant).

- [ ] **Step 7: Extend wait JSON**

```go
type waitResponse struct {
	SSHCertificate string `json:"ssh_certificate"`
	ExpiresAt      string `json:"expires_at"`
	LeaseExpiresAt string `json:"lease_expires_at,omitempty"`
}
```

- [ ] **Step 8: Integration test `TestSign_SecondRequestSkipsTelegram`**

First sign → webhook approve 300s → wait cert.  
Second sign same client/target within lease → no Telegram HTTP (use `httptest` mock notifier counting calls).

Run: `go test ./proxy/internal/api/... -run TestSign_SecondRequestSkipsTelegram -v`

- [ ] **Step 9: Commit**

```bash
git commit -m "feat(proxy): session leases and Telegram TTL approval"
```

---

## Task 5: Capabilities endpoint (P2)

**Files:**
- Create: `proxy/internal/api/capabilities_handler.go`
- Create: `sdk/capabilities.go`
- Modify: `sdk/sign/client.go`

- [ ] **Step 1: Handler returns**

```json
{"signer_mode":"local-ca","lease_supported":true,"allowed_ttl_seconds":[180,300,900]}
```

- [ ] **Step 2: SDK `FetchCapabilities(ctx)` cached on `Client`**

- [ ] **Step 3: Test round-trip in `sdk/sign/client_test.go`**

- [ ] **Step 4: Commit**

```bash
git commit -m "feat: capabilities API and SDK client"
```

---

## Task 6: Local-key mode (P3)

**Files:**
- Create: `proxy/internal/signing/local_key.go`, `local_key_test.go`
- Modify: `proxy/internal/auth` sign request struct (optional `agent_sign_data`)
- Modify: `proxy/internal/approval/store.go` — `Result` adds `Signature string`
- Modify: `proxy/internal/api/sign_handler.go`, wait response
- Create: `sdk/sign/signature.go`
- Modify: `agent/agent.go`

- [ ] **Step 1: Write failing `LocalKey` test**

Host ed25519 signer signs challenge bytes; result verifies with public key.

- [ ] **Step 2: Implement `KeySigner.SignAgent(req)`**

Decode base64 `agent_sign_data`; use `ssh.Signer.Sign(rand, challenge)`.

- [ ] **Step 3: Branch in `Store.Approve` / issuer selection by `cfg.SignerMode`**

- [ ] **Step 4: SDK `RequestSignature(ctx, req)`** — same POST/wait; parse `ssh_signature` field.

- [ ] **Step 5: Agent `Sign` — if `LUNA_SIGNER_MODE=local-key` or capabilities say so, return precomputed signature bytes to OpenSSH**

Study `agent/agent.go` current cert path; add minimal branch.

- [ ] **Step 6: E2E or integration with mock sshd using pubkey auth**

- [ ] **Step 7: Commit**

```bash
git commit -m "feat: local-key signing mode for agent and SDK"
```

---

## Task 7: Test data scripts + E2E (P1–P2 hardening)

**Files:**
- Create: `scripts/gen-test-ssh-ca.sh`
- Modify: `scripts/gen-test-ca.sh` (admin client cert with OU=luna-admin)
- Modify: `deploy/docker-compose.e2e.yml`
- Modify: `Makefile` target `testdata`

- [ ] **Step 1: `gen-test-ssh-ca.sh` outputs**

```
testdata/ssh/ca.pub
testdata/ssh/encrypted_ca.key   # passphrase: test-pass
testdata/ssh/encrypted_host.key # for local-key mode tests
```

- [ ] **Step 2: Extend `gen-test-ca.sh` to emit `admin-client.crt/key` with OU=luna-admin**

- [ ] **Step 3: E2E compose**

Remove Vault service; add entrypoint script on proxy:

1. Start sealed
2. CI calls admin unseal with test passphrase
3. `LUNA_ENV=dev` optional for SDK test; staging uses Telegram mock

- [ ] **Step 4: Update `make e2e-test`**

Pre-step: curl/admin unseal or Go test helper.

- [ ] **Step 5: Run full verification**

Run: `make testdata && make e2e-up && make e2e-test && make e2e-down`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git commit -m "test: self-hosted E2E without Vault"
```

---

## Task 8: Mobile API (P4 — server only)

**Files:**
- Create: `proxy/internal/mobile/store.go` (device registry in memory)
- Create: `proxy/internal/api/mobile_handler.go`, `mobile_handler_test.go`
- Modify: `proxy/internal/api/server.go`
- Modify: `proxy/internal/api/webhook_handler.go` — optional future path

- [ ] **Step 1: Device store test — enroll returns `device_id`**

- [ ] **Step 2: `POST /api/v1/mobile/enroll`** (admin mTLS) — store `device_pubkey` ed25519

- [ ] **Step 3: `POST /api/v1/mobile/approve`** — verify canonical JSON signature; call `store.Approve` with `approver=device_id` and lease binding

- [ ] **Step 4: `DELETE /api/v1/mobile/devices/{device_id}`**

- [ ] **Step 5: Document in spec appendix is already done; add OpenAPI-style examples to `README.md` mobile section**

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(proxy): mobile enroll and signed approve API"
```

---

## Task 9: Mobile push placeholder (P5 — plan only in code comments)

**Files:**
- Create: `docs/superpowers/plans/2026-05-30-mobile-push.md` (short follow-on plan, optional)
- Or section in README “P5 deferred”

- [ ] **Step 1: Add `internal/mobile/push.go` with `type Notifier interface { NotifyPending(ctx, tx) error }` stub returning `errNotConfigured`**

- [ ] **Step 2: Hook from `store.Create` behind `FCM_CREDENTIALS` env — no external calls in CI**

- [ ] **Step 3: Commit docs stub**

```bash
git commit -m "docs: outline mobile push phase P5"
```

*Full FCM/APNs implementation is intentionally a separate plan after P4.*

---

## Task 10: Documentation sweep

**Files:**
- Modify: `README.md`, `AGENTS.md`, `docs/setup.md`
- Modify: `docs/superpowers/specs/2026-05-21-luna-core-design.md` (add deprecation banner at top)

- [ ] **Step 1: README env table**

| Variable | Purpose |
|----------|---------|
| `LUNA_KEY_PATH` | Encrypted signing key |
| `LUNA_SIGNER_MODE` | `local-ca` \| `local-key` |
| `LUNA_ADMIN_CLIENT_OU` | mTLS OU for admin routes |
| Remove | `VAULT_*`, `LUNA_VAULT_*` |

- [ ] **Step 2: AGENTS.md** — update phases P0–P5, remove vault-agent from architecture

- [ ] **Step 3: setup.md** — self-hosted CA on target sshd, unseal runbook

- [ ] **Step 4: Commit**

```bash
git commit -m "docs: self-hosted central server setup and env vars"
```

---

## Spec coverage self-review

| Spec section | Task |
|--------------|------|
| §4 Unseal / sealed | Task 1–2 |
| §5 local-ca | Task 3 |
| §5 local-key | Task 6 |
| §6 Leases + Telegram TTL | Task 4 |
| §7 Admin + capabilities API | Task 2, 5 |
| §8 Mobile | Task 8–9 |
| §10 Fail-closed sealed | Task 2 |
| §11 E2E | Task 7 |
| Vault removed | Task 3, 10 |
| Docs legacy vault | Task 3, 10 |

**Placeholder scan:** None.

**Type consistency:** `Approve(txID, ttl, approver)` used from webhook and mobile; `CertIssuer` vs `KeySigner` selected by `SignerMode`.

---

## Suggested commit order (summary)

1. keystore  
2. admin + sealed gate  
3. local-ca + vault removal  
4. leases + telegram TTL  
5. capabilities  
6. local-key + agent/sdk  
7. E2E scripts  
8. mobile API  
9. push stub/docs  
10. documentation  
