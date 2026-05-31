# CLI Remote Key Load Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators run `luna-proxy key load` from a laptop by uploading passphrase-protected PEM over enrolled CLI mTLS (`OU=luna-cli`), while keeping on-host Unix socket `key.load` for server-local paths.

**Architecture:** New `internal/cli` package holds device registry (cert fingerprint → `device_id`) and CSR signing against configured mTLS CA key material. HTTP handlers mirror mobile patterns (`withAdminMTLS` / `withMTLS` + OU checks). Cobra `cli` subcommands generate CSR locally; `key load` uses HTTP when `~/.config/luna/cli.yaml` (or flags) is set.

**Tech Stack:** Go 1.25+ (`go.work`), Cobra, Viper, `crypto/x509`, existing `internal/keystore`, `internal/api` mTLS test helpers.

**Spec:** [`docs/superpowers/specs/2026-05-31-cli-remote-key-load-design.md`](../specs/2026-05-31-cli-remote-key-load-design.md)

**Prerequisite:** [`2026-05-31-proxy-cli-keystore.md`](2026-05-31-proxy-cli-keystore.md) complete (`key load` via socket, `local-key` pool, mobile pending). `make testdata` for encrypted PEM + mTLS CA under `testdata/ca/`.

---

## File map (delta)

```
proxy/
  cmd/luna-proxy/
    cli.go                    # cli init/csr/enroll/list/delete
    cli_config.go             # load ~/.config/luna/cli.yaml
    key.go                    # MODIFY: HTTP branch in runKeyLoad
  internal/
    cli/
      store.go                # Device registry
      store_test.go
      fingerprint.go          # CertFingerprint(*x509.Certificate)
      fingerprint_test.go
      csr.go                  # ValidateCSR + SignCSR
      csr_test.go
      ratelimit.go            # Per-device load rate limit
      ratelimit_test.go
    api/
      cli_handler.go          # enroll, list, delete, keys/load
      cli_handler_test.go
      auth_cli.go             # cliClientAllowed, lookup device from TLS peer
      server.go               # MODIFY: routes + cli store on server struct
    control/
      ops.go                  # MODIFY: cli.enroll/list/delete + ServerDeps.Cli
    config/
      config.go               # + CliClientOU, MTLSCACertPath, MTLSCAKeyPath
      load.go                 # bind env
  internal/control/client/    # optional: no change (socket only for admin cli ops)

scripts/gen-test-ca.sh        # optional: document; tests sign CSR with testdata ca.key

docs: README.md, AGENTS.md, luna-proxy.testing.example.yaml, spec cross-link
```

---

## Task 1: Config fields for CLI and mTLS CA

**Files:**
- Modify: `proxy/internal/config/config.go`
- Modify: `proxy/internal/config/load.go`
- Modify: `proxy/internal/config/load_test.go`
- Modify: `luna-proxy.testing.example.yaml`

- [ ] **Step 1: Write failing config test**

```go
// proxy/internal/config/load_test.go — add TestLoad_CliClientOUDefaults
func TestLoad_CliClientOUDefaults(t *testing.T) {
	t.Setenv("LUNA_CONFIG", "") // use defaults only
	// clear viper state: use isolated test like existing tests
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CliClientOU != "luna-cli" {
		t.Fatalf("CliClientOU = %q", cfg.CliClientOU)
	}
}
```

- [ ] **Step 2: Run test — expect FAIL**

Run: `cd proxy && go test ./internal/config/... -run TestLoad_CliClientOUDefaults -v`  
Expected: `cfg.CliClientOU` undefined or wrong

- [ ] **Step 3: Add fields and viper bindings**

```go
// config.go
CliClientOU    string
MTLSCACertPath string
MTLSCAKeyPath  string
```

```go
// load.go
v.SetDefault("cli_client_ou", "luna-cli")
bindEnv("cli_client_ou", "LUNA_CLI_CLIENT_OU")
bindEnv("mtls_ca_cert_path", "LUNA_MTLS_CA_CERT")
bindEnv("mtls_ca_key_path", "LUNA_MTLS_CA_KEY")
// map in configFromViper
```

- [ ] **Step 4: Run test — expect PASS**

Run: `cd proxy && go test ./internal/config/... -run TestLoad_CliClientOUDefaults -v`

- [ ] **Step 5: Commit**

```bash
git add proxy/internal/config/ luna-proxy.testing.example.yaml
git commit -m "feat(proxy): add config for CLI client OU and mTLS CA paths"
```

---

## Task 2: CLI device store and cert fingerprint

**Files:**
- Create: `proxy/internal/cli/fingerprint.go`
- Create: `proxy/internal/cli/fingerprint_test.go`
- Create: `proxy/internal/cli/store.go`
- Create: `proxy/internal/cli/store_test.go`

- [ ] **Step 1: Write failing fingerprint test**

```go
func TestCertFingerprint_Deterministic(t *testing.T) {
	// parse testdata/ca/client.crt with x509.ParseCertificate
	fp := CertFingerprint(cert)
	if len(fp) != 64 {
		t.Fatalf("len=%d", len(fp))
	}
	// golden: store first run value in test or compare double-call equality
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cd proxy && go test ./internal/cli/... -run TestCertFingerprint -v`

- [ ] **Step 3: Implement fingerprint + store**

```go
// fingerprint.go
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// store.go — mirror mobile/store.go patterns
type Device struct {
	ID, Label, CertFingerprint string
	EnrolledAt time.Time
}
func (s *Store) Enroll(label, certFingerprint string) (*Device, error)
func (s *Store) GetByFingerprint(fp string) (*Device, bool)
func (s *Store) Delete(id string) error
func (s *Store) List() []*Device
```

Device IDs: `cli_` + ULID (copy `mobile` pattern).

- [ ] **Step 4: Run store tests**

```go
func TestStore_EnrollGetDelete(t *testing.T) {
	s := NewStore()
	dev, err := s.Enroll("laptop", "abc123")
	// GetByFingerprint, Delete, GetByFingerprint miss
}
```

Run: `cd proxy && go test ./internal/cli/... -v`

- [ ] **Step 5: Commit**

```bash
git add proxy/internal/cli/
git commit -m "feat(proxy): add CLI device store and cert fingerprint helper"
```

---

## Task 3: CSR validate and sign

**Files:**
- Create: `proxy/internal/cli/csr.go`
- Create: `proxy/internal/cli/csr_test.go`

- [ ] **Step 1: Write failing CSR test**

Generate CSR in test with `x509.CreateCertificateRequest` using `OU=luna-cli`, RSA 2048 or ECDSA P-256.

```go
func TestSignCSR_IssuesClientCert(t *testing.T) {
	caCert, caKey := loadTestCA(t) // read testdata/ca/ca.crt + ca.key
	csrPEM := generateTestCSR(t, "luna-cli")
	signer := NewCSRSigner(caCert, caKey, "luna-cli", 24*time.Hour)
	certPEM, fp, err := signer.Sign(csrPEM)
	if err != nil || certPEM == "" || fp == "" {
		t.Fatalf("Sign: %v", err)
	}
}
```

- [ ] **Step 2: Run — expect FAIL**

Run: `cd proxy && go test ./internal/cli/... -run TestSignCSR -v`

- [ ] **Step 3: Implement `CSRSigner`**

```go
type CSRSigner struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
	requiredOU string
	ttl time.Duration
}

func (s *CSRSigner) Sign(csrPEM []byte) (certPEM []byte, fingerprint string, err error) {
	// ParseCertificateRequest
	// Reject if no OU match requiredOU in CSR Subject
	// Reject weak keys (< 2048 RSA)
	// x509.CreateCertificate with ClientAuth EKU
	// return PEM, CertFingerprint(issued)
}
```

Export `ErrCSRInvalid`, `ErrCANotConfigured` for handlers.

- [ ] **Step 4: Add rejection tests**

- Wrong OU → error  
- Malformed PEM → error

- [ ] **Step 5: Commit**

```bash
git add proxy/internal/cli/csr.go proxy/internal/cli/csr_test.go
git commit -m "feat(proxy): sign CLI client CSRs with mTLS CA"
```

---

## Task 4: API auth helpers for CLI mTLS

**Files:**
- Create: `proxy/internal/api/auth_cli.go`
- Create: `proxy/internal/api/auth_cli_test.go`

- [ ] **Step 1: Write failing tests**

```go
func TestCliClientAllowed_RequiresOU(t *testing.T) {
	cert := certWithOU("luna-cli")
	if !cliClientAllowed("luna-cli", cert) {
		t.Fatal("expected allowed")
	}
	if cliClientAllowed("luna-cli", certWithOU("luna-admin")) {
		t.Fatal("admin should not pass cli check")
	}
}
```

- [ ] **Step 2: Implement helpers**

```go
func cliClientAllowed(requiredOU string, cert *x509.Certificate) bool
func (s *server) cliDeviceFromPeer(cert *x509.Certificate) (*cli.Device, bool)
// uses s.cli.GetByFingerprint(CertFingerprint(cert))
```

- [ ] **Step 3: Run tests**

Run: `cd proxy && go test ./internal/api/... -run TestCliClient -v`

- [ ] **Step 4: Commit**

```bash
git add proxy/internal/api/auth_cli.go proxy/internal/api/auth_cli_test.go
git commit -m "feat(proxy): add CLI mTLS client auth helpers"
```

---

## Task 5: HTTP handlers — enroll, list, delete

**Files:**
- Create: `proxy/internal/api/cli_handler.go`
- Create: `proxy/internal/api/cli_handler_test.go`
- Modify: `proxy/internal/api/server.go`
- Modify: `proxy/internal/api/sign_handler_test.go` (`startTestServer` injects `cli.NewStore()`)

- [ ] **Step 1: Extend `NewServer` signature**

```go
func NewServer(cfg config.Config, ks *keystore.Keystore, pending *keystore.PendingStore,
	store *approval.Store, replay *auth.ReplayLRU, telegram *approval.Notifier,
	mob *mobile.Store, cliStore *cli.Store) http.Handler
```

Add to `server` struct: `cli *cli.Store`, `csrSigner *cli.CSRSigner` (build in `NewServer` when `cfg.MTLSCAKeyPath` set; nil otherwise).

Register routes:

```go
mux.HandleFunc("POST /api/v1/cli/enroll", s.withAdminMTLS(s.handleCLIEnroll))
mux.HandleFunc("GET /api/v1/cli/devices", s.withAdminMTLS(s.handleCLIListDevices))
mux.HandleFunc("DELETE /api/v1/cli/devices/{device_id}", s.withAdminMTLS(s.handleCLIDeleteDevice))
```

- [ ] **Step 2: Write failing enroll integration test**

```go
func TestCLIEnroll_IssuesCert(t *testing.T) {
	cfg := config.Config{
		AdminClientOU: "luna-admin",
		CliClientOU:   "luna-cli",
		MTLSCACertPath: "../../testdata/ca/ca.crt",
		MTLSCAKeyPath:  "../../testdata/ca/ca.key",
	}
	// start server, POST enroll with CSR PEM body
	// expect 201 + device_id + certificate_pem
}
```

Update all `api.NewServer(...)` call sites in tests and `serve.go` to pass `cli.NewStore()`.

- [ ] **Step 3: Implement handlers**

`handleCLIEnroll`: if `s.csrSigner == nil` → `503`. Parse JSON `{label, csr_pem}`, `Sign`, `cli.Enroll`, return JSON.

`handleCLIListDevices`, `handleCLIDeleteDevice`: standard admin auth.

- [ ] **Step 4: Run tests**

Run: `cd proxy && go test ./internal/api/... -run TestCLIEnroll -v`

- [ ] **Step 5: Commit**

```bash
git add proxy/internal/api/
git commit -m "feat(proxy): add HTTP CLI device enroll and list APIs"
```

---

## Task 6: HTTP `POST /api/v1/cli/keys/load`

**Files:**
- Modify: `proxy/internal/api/cli_handler.go`
- Create: `proxy/internal/cli/ratelimit.go`
- Modify: `proxy/internal/api/cli_handler_test.go`

- [ ] **Step 1: Write failing load test**

Use `startTestServerLocalKey` pattern + enroll CLI cert in test:

```go
func TestCLIKeysLoad_AddsToPool(t *testing.T) {
	// enroll CLI device, build mTLS client with issued cert
	// POST keys/load with base64 encrypted PEM from testdata + passphrase
	// assert 200 fingerprint; ks.ListSigners() contains fp
}
```

- [ ] **Step 2: Implement rate limiter**

```go
// ratelimit.go — 10 events/hour per device_id
type LoadRateLimiter struct { ... }
func (l *LoadRateLimiter) Allow(deviceID string) bool
```

- [ ] **Step 3: Implement `handleCLIKeysLoad`**

```go
func (s *server) handleCLIKeysLoad(w http.ResponseWriter, r *http.Request) {
	// Reject admin OU (mirror keys_pending_handler)
	if adminClientAllowed(...) { 403 }
	if !cliClientAllowed(s.cfg.CliClientOU, peer) { 403 }
	dev, ok := s.cliDeviceFromPeer(peer)
	if !ok { 403 }
	if s.cfg.SignerMode != approval.SignerModeLocalKey { 400 }
	if !s.loadLimiter.Allow(dev.ID) { 429 }
	// MaxBytesReader 64KiB
	// decode encrypted_pem, passphrase, label
	pass := []byte(req.Passphrase)
	defer control.ZeroBytes(pass) // import control or duplicate zero helper in keystore
	fp, err := s.keystore.LoadPEMBytes(blob, string(pass), req.Label)
	// ErrUnsealLocked → 403 + JSON code LOCKED
	log.Printf("control: cli_key_loaded fp=%s device_id=%s", fp, dev.ID)
}
```

Use `comment` field: `LoadPEMBytes(..., req.Label)` — `label` required in JSON.

- [ ] **Step 4: Negative tests**

- Admin cert on keys/load → `403`  
- `signer_mode=local-ca` → `400`  
- Unknown cert fingerprint → `403`

Run: `cd proxy && go test ./internal/api/... -run TestCLIKeys -v`

- [ ] **Step 5: Commit**

```bash
git add proxy/internal/api/cli_handler.go proxy/internal/cli/ratelimit.go
git commit -m "feat(proxy): add HTTP CLI remote key load endpoint"
```

---

## Task 7: Control socket `cli.*` ops

**Files:**
- Modify: `proxy/internal/control/ops.go`
- Modify: `proxy/internal/control/ops_test.go`
- Modify: `proxy/cmd/luna-proxy/serve.go`

- [ ] **Step 1: Add `Cli` to `ServerDeps`**

```go
type ServerDeps struct {
	...
	Cli      *cli.Store
	CSRSigner *cli.CSRSigner // or build inside ops from cfg
}
```

- [ ] **Step 2: Write failing ops test**

```go
resp := s.handle(Request{Op: "cli.enroll", Data: reqData(t, map[string]string{
	"label": "test", "csr_pem": string(csrPEM),
})})
```

- [ ] **Step 3: Implement `cli.enroll`, `cli.list`, `cli.delete`**

Mirror HTTP handler logic; return same JSON shapes in `Response.Data`.

- [ ] **Step 4: Wire `serve.go`**

```go
csrSigner, _ := cli.NewCSRSignerFromConfig(cfg) // returns nil if paths empty
ctrl := control.NewServer(control.ServerDeps{
	...
	Cli: cli.NewStore(),
	CSRSigner: csrSigner,
})
```

- [ ] **Step 5: Run tests**

Run: `cd proxy && go test ./internal/control/... -v`

- [ ] **Step 6: Commit**

```bash
git add proxy/internal/control/ proxy/cmd/luna-proxy/serve.go
git commit -m "feat(proxy): add control socket CLI device operations"
```

---

## Task 8: Cobra `luna-proxy cli` commands

**Files:**
- Create: `proxy/cmd/luna-proxy/cli.go`
- Create: `proxy/cmd/luna-proxy/cli_config.go`
- Modify: `proxy/cmd/luna-proxy/mobile.go` (pattern reference)

- [ ] **Step 1: `cli init` and `cli csr`**

```go
// cli.go
var cliDir string

func runCLIInit(cmd *cobra.Command, args []string) error {
	// openssl or crypto/tls: generate RSA 2048 key to cliDir/cli.key (0600)
}

func runCLICSR(cmd *cobra.Command, args []string) error {
	// Create CSR with Subject OU=cfg.CliClientOU default luna-cli
	// Write cli.csr.pem
}
```

- [ ] **Step 2: `cli enroll` (admin via socket)**

Reads `--csr-file`, calls `client.Call(socket, "cli.enroll", ...)`, writes `--cert-out` default `cli.crt`.

- [ ] **Step 3: `cli list` / `cli delete`**

- [ ] **Step 4: Manual smoke**

```bash
cd proxy && go build -o /tmp/luna-proxy ./cmd/luna-proxy
/tmp/luna-proxy cli init --dir /tmp/luna-cli-test
/tmp/luna-proxy cli csr --dir /tmp/luna-cli-test
```

- [ ] **Step 5: Commit**

```bash
git add proxy/cmd/luna-proxy/cli.go proxy/cmd/luna-proxy/cli_config.go
git commit -m "feat(proxy): add luna-proxy cli subcommands for device enrollment"
```

---

## Task 9: `key load` HTTP client branch

**Files:**
- Create: `proxy/internal/cli/httpclient/load.go` (or `proxy/cmd/luna-proxy/key_remote.go`)
- Modify: `proxy/cmd/luna-proxy/key.go`

- [ ] **Step 1: Config loader**

```go
// cli_config.go
type CLIProfile struct {
	ProxyURL string
	CliCert  string
	CliKey   string
	CA       string
}
func LoadCLIProfile(flags...) (*CLIProfile, error)
// ~/.config/luna/cli.yaml keys: proxy_url, cli_cert, cli_key, ca
```

- [ ] **Step 2: HTTP load client**

```go
func RemoteKeyLoad(ctx context.Context, prof CLIProfile, pemPath string, passphrase []byte, label string) (fingerprint string, err error) {
	pemBytes, _ := os.ReadFile(pemPath)
	body := map[string]string{
		"encrypted_pem": base64.StdEncoding.EncodeToString(pemBytes),
		"passphrase": string(passphrase),
		"label": label,
	}
	// http.Client with tls.Config Certificates + RootCAs
	// POST prof.ProxyURL + "/api/v1/cli/keys/load"
}
```

- [ ] **Step 3: Modify `runKeyLoad`**

```go
func runKeyLoad(cmd *cobra.Command, args []string) error {
	pass, err := readPassphrase()
	...
	if prof, err := resolveCLIProfile(cmd); prof != nil {
		fp, err := httpclient.RemoteKeyLoad(ctx, *prof, args[0], pass, keyLoadLabel)
		fmt.Println(fp)
		return err
	}
	if path, err := resolveSocket(); err == nil {
		// existing socket path — NOTE: still sends path for on-host
	}
	return fmt.Errorf("configure CLI profile (~/.config/luna/cli.yaml) or control socket")
}
```

Add flags: `--proxy-url`, `--cli-cert`, `--cli-key`, `--ca`, `--label` (required for remote load).

- [ ] **Step 4: Commit**

```bash
git add proxy/cmd/luna-proxy/key.go proxy/internal/cli/httpclient/
git commit -m "feat(proxy): key load over CLI mTLS when profile configured"
```

---

## Task 10: End-to-end integration test

**Files:**
- Create: `proxy/internal/api/cli_integration_test.go`

- [ ] **Step 1: Full flow test**

1. Admin enroll CSR → CLI cert  
2. CLI mTLS POST keys/load with `testdata` encrypted key  
3. `GET capabilities` or control `key.list` shows fingerprint  
4. Revoke device → load returns `403`

Run: `cd proxy && go test ./internal/api/... -run TestCLIIntegration -v`

- [ ] **Step 2: Commit**

```bash
git add proxy/internal/api/cli_integration_test.go
git commit -m "test(proxy): integration test for CLI enroll and remote key load"
```

---

## Task 11: Documentation

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: `docs/superpowers/specs/2026-05-31-proxy-cli-keystore-design.md` (cross-link §14)
- Modify: `luna-proxy.testing.example.yaml`

- [ ] **Step 1: Document operator workflow**

CSR init → admin enroll → `cli.yaml` → `key load` from laptop; note restart drops in-memory CLI enrollments (v1).

- [ ] **Step 2: Document env vars**

`LUNA_CLI_CLIENT_OU`, `LUNA_MTLS_CA_CERT`, `LUNA_MTLS_CA_KEY`

- [ ] **Step 3: Run full test suite**

Run: `make test`  
Expected: all packages pass

- [ ] **Step 4: Commit**

```bash
git add README.md AGENTS.md docs/ luna-proxy.testing.example.yaml
git commit -m "docs: document CLI remote key load operator workflow"
```

---

## Spec coverage checklist (self-review)

| Spec requirement | Task |
|------------------|------|
| `internal/cli` store + CSR | 2, 3 |
| mTLS CA paths, 503 if missing | 1, 5 |
| HTTP enroll/list/delete/load | 5, 6 |
| Socket cli.* ops | 7 |
| local-key only on HTTP load | 6 |
| Reject admin on keys/load | 6 |
| Rate limit 10/hour | 6 |
| Cobra cli + key load HTTP | 8, 9 |
| Keep socket key.load | 9 (unchanged branch) |
| Mobile unchanged | (no tasks) |
| Docs | 11 |

---

## Execution handoff

Plan saved to [`docs/superpowers/plans/2026-05-31-cli-remote-key-load.md`](2026-05-31-cli-remote-key-load.md).

**Two execution options:**

1. **Subagent-driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline execution** — run tasks in this session with executing-plans checkpoints  

Which approach do you want?
