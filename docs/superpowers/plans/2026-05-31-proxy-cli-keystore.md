# Proxy CLI, Control Socket, and Multi-Key Keystore Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Cobra CLI (`luna-proxy serve` + operator commands), a Linux Unix control socket for local admin, an ssh-add-style signing pool for `local-key`, and mobile encrypted-key pending upload with socket confirm.

**Architecture:** One `luna-proxy` process runs mTLS HTTP (automation + mobile) and a newline-JSON control listener. `internal/keystore` holds either one CA signer or a fingerprint→signer map; `internal/control` dispatches ops; signing backends resolve signers by fingerprint in `local-key` mode. HTTP admin unseal removed.

**Tech Stack:** Go 1.25+ (`go.work`), Cobra, Viper (existing), `golang.org/x/crypto/ssh`, `golang.org/x/sys/unix` (SO_PEERCRED, mlock), existing approval/signing packages.

**Spec:** [`docs/superpowers/specs/2026-05-31-proxy-cli-keystore-design.md`](../specs/2026-05-31-proxy-cli-keystore-design.md)

**Prerequisite:** Self-hosted central server ([`2026-05-30-self-hosted-central.md`](2026-05-30-self-hosted-central.md)) merged; `make testdata` produces encrypted PEM + mTLS certs.

---

## File map (delta)

```
proxy/
  cmd/luna-proxy/
    root.go              # Cobra root, --socket persistent flag
    serve.go             # was main body: HTTP + control server
    status.go
    key.go               # load, list, remove, confirm, reject
    mobile.go            # enroll, list, delete
  internal/
    keystore/
      fingerprint.go     # Fingerprint(pub) hex
      pool.go            # CASigner + LocalKeyPool, LoadFromPEM, Remove
      pending.go         # Pending queue TTL, caps
      keystore.go        # MODIFY: facade over pool + mode
    control/
      server.go          # Listen unix, peer auth, read loop
      peer_linux.go      # SO_PEERCRED
      peer_stub.go       # !linux
      ops.go             # Dispatch op → handlers
      types.go           # Request/response envelopes
    control/client/
      client.go          # Dial, Call(op, payload)
    api/
      admin_handler.go   # DELETE or 410 stubs
      keys_pending_handler.go
      capabilities_handler.go  # MODIFY: loaded_signers
      sign_handler.go          # MODIFY: host key selection
      server.go                # wire routes, inject control deps
    signing/
      local_key.go       # MODIFY: SignAgent(ctx, fp, data)
      local_ca.go        # unchanged interface
    config/
      config.go          # + ControlSocket, ControlSocketGroup
      load.go            # bind env
  go.mod                 # + github.com/spf13/cobra

sdk/
  capabilities.go        # LoadedSigner struct
  sign/client.go         # HostPublicKey, HostKeyFingerprint fields

agent/
  config.go              # LUNA_HOST_KEY_FINGERPRINT
  agent.go               # pass host key hint to SDK

docs/, deploy/, *.example.yaml, README.md, AGENTS.md
```

---

## Task 1: Keystore fingerprints and pool types

**Files:**
- Create: `proxy/internal/keystore/fingerprint.go`
- Create: `proxy/internal/keystore/fingerprint_test.go`
- Create: `proxy/internal/keystore/pool.go`

- [ ] **Step 1: Write failing fingerprint test**

```go
// proxy/internal/keystore/fingerprint_test.go
func TestFingerprint_Deterministic(t *testing.T) {
	_, pub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	a := Fingerprint(sshPub)
	b := Fingerprint(sshPub)
	if a != b || len(a) != 64 {
		t.Fatalf("fingerprint = %q", a)
	}
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cd proxy && go test ./internal/keystore/... -run TestFingerprint_Deterministic -v`  
Expected: undefined `Fingerprint`

- [ ] **Step 3: Implement fingerprint**

```go
// proxy/internal/keystore/fingerprint.go
func Fingerprint(pub ssh.PublicKey) string {
	b := ssh.MarshalAuthorizedKey(pub)
	// strip trailing newline from MarshalAuthorizedKey
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
```

Note: spec says `ssh.MarshalPublicKey` — use `ssh.MarshalAuthorizedKey` wire for stability with OpenSSH tooling, document in code comment matching spec §4.2; align test vectors with one golden vector from `make testdata` key.

- [ ] **Step 4: Implement `LocalKeyPool` skeleton**

```go
// proxy/internal/keystore/pool.go
type LocalKeyPool struct {
	mu      sync.RWMutex
	signers map[string]loadedSigner // fp → signer + comment
}

func (p *LocalKeyPool) Add(signer ssh.Signer, comment string) (fingerprint string, err error)
func (p *LocalKeyPool) Remove(fingerprint string) error
func (p *LocalKeyPool) Get(fingerprint string) (ssh.Signer, error)
func (p *LocalKeyPool) List() []SignerInfo
func (p *LocalKeyPool) Available() bool
```

- [ ] **Step 5: Run keystore package tests**

Run: `cd proxy && go test ./internal/keystore/... -v`  
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add proxy/internal/keystore/fingerprint.go proxy/internal/keystore/fingerprint_test.go proxy/internal/keystore/pool.go proxy/internal/keystore/pool_test.go
git commit -m "feat(proxy): add signer fingerprint and local-key pool"
```

---

## Task 2: Refactor Keystore facade (CA slot + pool)

**Files:**
- Modify: `proxy/internal/keystore/keystore.go`
- Modify: `proxy/internal/keystore/keystore_test.go`
- Modify: `proxy/internal/signing/local_key.go`
- Modify: `proxy/internal/signing/local_ca.go`

- [ ] **Step 1: Write failing test — pool signer by fingerprint**

```go
func TestKeystore_LocalKeyPool_GetByFingerprint(t *testing.T) {
	ks := New(ModeLocalKey)
	// use encrypt_testutil + UnsealPEMBytes to load test key
	fp, err := ks.LoadPEMFile(path, "test-pass", "comment")
	// ...
	signer, err := ks.SignerForFingerprint(fp)
}
```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Add `Mode` enum and refactor**

```go
type Mode int
const (
	ModeLocalCA Mode = iota
	ModeLocalKey
)

type Keystore struct {
	mode Mode
	ca   ssh.Signer
	pool *LocalKeyPool
	// lockout maps: path or pendingID → fail count
}
```

- `LoadPEMFile(path, passphrase, comment)` — decrypt using existing PEM logic from current `Unseal`, then either set `ca` (replace) or `pool.Add`.
- `SSHSigner()` — **deprecated** for local-key; keep for local-ca only.
- `SignerForFingerprint(fp string) (ssh.Signer, error)` — new.
- `Available()` — CA loaded OR pool non-empty per mode.

- [ ] **Step 4: Update `LocalKey.SignAgent`**

```go
func (k *LocalKey) SignAgent(ctx context.Context, hostFP string, data []byte) ([]byte, error) {
	signer, err := k.ks.SignerForFingerprint(hostFP)
	// ...
}
```

- [ ] **Step 5: Fix all `keystore` call sites** (`local_ca_test`, `sign_handler_test` `unsealTestKeystore` → `LoadPEMFile`)

- [ ] **Step 6: Run full proxy tests**

Run: `make test`  
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git commit -m "feat(proxy): keystore pool and per-fingerprint signers"
```

---

## Task 3: Config — control socket paths

**Files:**
- Modify: `proxy/internal/config/config.go`
- Modify: `proxy/internal/config/load.go`
- Modify: `proxy/internal/config/load_test.go`
- Modify: `luna-proxy.testing.example.yaml`, `deploy/luna-proxy.production.example.yaml`

- [ ] **Step 1: Add fields**

```go
ControlSocket      string // default /run/luna/control.sock
ControlSocketGroup string // default luna-admin
```

- [ ] **Step 2: Bind `LUNA_CONTROL_SOCKET`, `LUNA_CONTROL_SOCKET_GROUP` in `load.go`**

- [ ] **Step 3: Extend `load_test.go` for defaults**

- [ ] **Step 4: Update example YAML**

```yaml
control_socket: /run/luna/control.sock
control_socket_group: luna-admin
```

- [ ] **Step 5: Commit**

---

## Task 4: Control socket protocol (server)

**Files:**
- Create: `proxy/internal/control/types.go`
- Create: `proxy/internal/control/ops.go`
- Create: `proxy/internal/control/server.go`
- Create: `proxy/internal/control/server_test.go`
- Create: `proxy/internal/control/peer_linux.go`
- Create: `proxy/internal/control/peer_stub.go` (`//go:build !linux`)

- [ ] **Step 1: Define envelopes**

```go
type Request struct {
	Op   string          `json:"op"`
	ID   string          `json:"id,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}
type Response struct {
	OK    bool            `json:"ok"`
	ID    string          `json:"id,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
	Code  string          `json:"code,omitempty"`
}
```

- [ ] **Step 2: Write failing test — `status` op**

Use `net.Listen("unix", path)` in temp dir; skip peer check in test via `ServerConfig{SkipPeerAuth: true}` for tests only.

```go
func TestControlServer_StatusSealed(t *testing.T) {
	// serve one line: {"op":"status"}
	// expect ok:true, data.sealed:true
}
```

- [ ] **Step 3: Implement `Server` with `Serve(ln net.Listener)` loop**

- [ ] **Step 4: Implement `opStatus` using `*keystore.Keystore` + `config.Config`**

Response data:

```json
{
  "sealed": true,
  "signer_mode": "local-ca",
  "loaded_signers": [],
  "pending_keys": 0
}
```

- [ ] **Step 5: Linux peer auth test** (build tag linux)

```go
// peer_linux_test.go - allow root only in test
```

- [ ] **Step 6: Commit**

---

## Task 5: Control socket — key ops

**Files:**
- Modify: `proxy/internal/control/ops.go`
- Create: `proxy/internal/control/ops_test.go`

- [ ] **Step 1: Tests for `key.load`, `key.list`, `key.remove`**

Use testdata encrypted key + `SkipPeerAuth`.

- [ ] **Step 2: Implement handlers**

```go
// key.load data: {"path":"...","passphrase":"..."}
// key.list → {"signers":[{"fingerprint":"...","comment":"..."}]}
// key.remove data: {"fingerprint":"..."}
```

- [ ] **Step 3: Wire lockout on failed decrypt** (reuse keystore failure recording)

- [ ] **Step 4: Run tests + commit**

---

## Task 6: Cobra root + `serve` + control client

**Files:**
- Create: `proxy/cmd/luna-proxy/root.go`
- Create: `proxy/cmd/luna-proxy/serve.go`
- Create: `proxy/internal/control/client/client.go`
- Create: `proxy/cmd/luna-proxy/status.go`
- Delete/replace: `proxy/cmd/luna-proxy/main.go` → thin `main()` calling `Execute()`

- [ ] **Step 1: Add cobra dependency**

Run: `cd proxy && go get github.com/spf13/cobra@latest`

- [ ] **Step 2: `root.go`**

```go
var socketPath string
func init() {
	rootCmd.PersistentFlags().StringVar(&socketPath, "socket", "", "control socket path")
}
func Execute() { if err := rootCmd.Execute(); err != nil { os.Exit(1) } }
```

- [ ] **Step 3: Move current `main.go` body into `serve.go` `runServe()`**

After HTTP server setup, start control server:

```go
ctrl := control.NewServer(control.ServerDeps{
	Config: cfg, Keystore: ks, Mobile: mobileStore, Pending: pendingStore,
})
go ctrl.ServeUnix(cfg.ControlSocket, cfg.ControlSocketGroup)
```

- [ ] **Step 4: `status.go` uses `control/client`**

```go
resp, err := client.Call(socketPath, "status", nil)
fmt.Fprintf(os.Stdout, "%s\n", prettyJSON(resp.Data))
```

- [ ] **Step 5: `main.go`**

```go
func main() { Execute() }
```

- [ ] **Step 6: Manual smoke**

```bash
make build
./bin/luna-proxy serve &  # background
./bin/luna-proxy --socket /tmp/luna-test.sock status  # if using temp socket in proxy.yaml
```

- [ ] **Step 7: Commit**

```bash
git commit -m "feat(proxy): cobra serve and control socket status"
```

---

## Task 7: Cobra `key` subcommands

**Files:**
- Create: `proxy/cmd/luna-proxy/key.go`

- [ ] **Step 1: `key load`, `key list`, `key remove`, `key confirm`, `key reject`**

Map to ops: `key.load`, `key.list`, `key.remove`, `key.confirm`, `key.reject`.

- [ ] **Step 2: Flags `--passphrase-stdin` on load/confirm**

- [ ] **Step 3: Integration test** in `control/ops_test.go` full roundtrip

- [ ] **Step 4: Commit**

---

## Task 8: Remove HTTP admin unseal

**Files:**
- Modify: `proxy/internal/api/server.go`
- Modify: `proxy/internal/api/admin_handler.go` (delete handlers or 410)
- Modify: `proxy/internal/api/admin_handler_test.go` → move unseal tests to `control/ops_test.go`
- Modify: `README.md`, `.env.testing.example` (curl unseal → `luna-proxy key load`)

- [ ] **Step 1: Remove routes** `POST /api/v1/admin/unseal`, `GET /api/v1/admin/seal-status`

- [ ] **Step 2: Update E2E/docs** unseal instructions

- [ ] **Step 3: `make test`**

- [ ] **Step 4: Commit**

---

## Task 9: Sign handler — host key selection (`local-key`)

**Files:**
- Modify: `proxy/internal/api/sign_handler.go`
- Modify: `proxy/internal/approval/store.go` (sign callback receives hostFP)
- Modify: `proxy/internal/signing/local_key.go` (already done Task 2)
- Create: `proxy/internal/api/sign_handler_hostkey_test.go`

- [ ] **Step 1: Extend sign request struct**

```go
HostPublicKey      string `json:"host_public_key,omitempty"`
HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
```

- [ ] **Step 2: Failing test — two keys loaded, wrong FP → 503**

- [ ] **Step 3: Resolve fingerprint** (wire key → fp; validate match if both set)

- [ ] **Step 4: Pass fp into `LocalKey.SignAgent`**

- [ ] **Step 5: Commit**

---

## Task 10: Capabilities `loaded_signers`

**Files:**
- Modify: `proxy/internal/api/capabilities_handler.go`
- Modify: `proxy/internal/api/capabilities_handler_test.go`

- [ ] **Step 1: Test sealed → `loaded_signers` null/empty**

- [ ] **Step 2: Test local-key with 2 loaded keys → array length 2**

- [ ] **Step 3: Implement**

- [ ] **Step 4: Commit**

---

## Task 11: Pending key queue + HTTP upload

**Files:**
- Create: `proxy/internal/keystore/pending.go`
- Create: `proxy/internal/api/keys_pending_handler.go`
- Modify: `proxy/internal/api/server.go`
- Modify: `proxy/internal/mobile` (helper to resolve device from mTLS cert)

- [ ] **Step 1: `PendingStore` with TTL 15m, max 32 global / 4 per device**

```go
func (s *PendingStore) Add(deviceID, label string, blob []byte) (id string, err error)
func (s *PendingStore) Get(id string) (*PendingKey, error)
func (s *PendingStore) Delete(id string) error
```

- [ ] **Step 2: HTTP test — device cert uploads, returns `pending_id`**

- [ ] **Step 3: Handler `POST /api/v1/mobile/keys/pending`**

Reject automation certs (not enrolled device mapping).

- [ ] **Step 4: Control ops `key.confirm` / `key.reject` / `key.pending.list`**

`key.confirm` only when `signer_mode=local-key`; decrypt blob into pool.

- [ ] **Step 5: Commit**

---

## Task 12: Cobra `mobile` subcommands

**Files:**
- Create: `proxy/cmd/luna-proxy/mobile.go`
- Modify: `proxy/internal/control/ops.go`

- [ ] **Step 1: Ops `mobile.enroll`, `mobile.list`, `mobile.delete`**

Delegate to existing `mobile.Store`.

- [ ] **Step 2: CLI commands with flags `--label`, `--pubkey` for enroll**

- [ ] **Step 3: Tests + commit**

---

## Task 13: SDK + agent

**Files:**
- Modify: `sdk/sign/client.go` (or request types)
- Modify: `sdk/capabilities.go`
- Modify: `agent/config.go`, `agent/config_load.go`, `agent/agent.go`
- Modify: `sdk/sign/e2e_test.go` if needed

- [ ] **Step 1: SDK capabilities parse `loaded_signers`**

- [ ] **Step 2: Add `HostKeyFingerprint` to sign request in local-key mode**

- [ ] **Step 3: Agent env `LUNA_HOST_KEY_FINGERPRINT`**

- [ ] **Step 4: If capabilities lists exactly one signer, default fingerprint**

- [ ] **Step 5: `make test`**

- [ ] **Step 6: Commit**

---

## Task 14: Documentation and examples

**Files:**
- Modify: `README.md`, `AGENTS.md`, `docs/setup.md`
- Modify: `.env.example`, `.env.testing.example`, `luna-proxy.testing.example.yaml`
- Modify: `deploy/docker-compose.e2e.yml` (init: `luna-proxy key load` via socket or exec)

- [ ] **Step 1: Document `luna-proxy serve`, control socket group, key load**

- [ ] **Step 2: Replace unseal curl examples**

- [ ] **Step 3: Document mobile pending + confirm flow**

- [ ] **Step 4: Commit**

---

## Task 15: E2E — two host keys

**Files:**
- Modify: `scripts/gen-test-ssh-ca.sh` (second encrypted host key optional)
- Create: `proxy/internal/api/sign_handler_multikey_test.go`

- [ ] **Step 1: Generate `encrypted_host2.key` in testdata**

- [ ] **Step 2: Test load both via control ops; sign with each FP**

- [ ] **Step 3: `make test` + `docker-compose.e2e` smoke if applicable**

- [ ] **Step 4: Commit**

---

## Plan self-review (spec coverage)

| Spec § | Task |
|--------|------|
| §3 Cobra CLI | 6, 7, 12 |
| §4 Keystore pool | 1, 2, 9 |
| §5 Unix socket | 4, 5, 6 |
| §5.4 HTTP admin deprecation | 8 |
| §6 HTTP mobile pending | 11 |
| §6.4 Capabilities | 10 |
| §7 SDK/agent | 13 |
| §9 Security/audit logs | 4, 5, 11 (add log lines in ops) |
| §10 Testing | all task test steps |
| §11 Migration/docs | 14 |

**Fixed in plan:** fingerprint wire format documented in Task 1; `MarshalAuthorizedKey` vs spec name called out.

**Optional v1 (`tx list`):** not scheduled — add Task 16 only if requested.

---

## Execution notes

- **Breaking change:** bare `luna-proxy` no longer starts server; update Makefile `run` target if present.
- **`proxy.yaml`:** user may use `proxy.yaml`; unrelated to this plan.
- **Do not** import `sdk` from `proxy`.
- Run `make test` after every task; Linux required for peer cred integration tests.
