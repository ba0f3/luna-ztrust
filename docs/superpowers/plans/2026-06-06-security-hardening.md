# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the confirmed enrollment, signing-target, approval-race, mobile-identity, key-permission, approval-display, and memory-protection findings.

**Architecture:** Assign certificate roles server-side, make verified SSH
session binding the authoritative destination identity for local-key signing,
and make approval transitions atomic. Bind mobile devices to mTLS certificate
fingerprints and fail closed on key-protection errors.

**Tech Stack:** Go 1.25+, `golang.org/x/crypto/ssh`,
`golang.org/x/crypto/ssh/agent`, Go `crypto/x509`, Linux `mlock`, Go tests.

---

### Task 1: Harden mTLS CSR Role Issuance

**Files:**
- Modify: `proxy/internal/cli/csr.go`
- Test: `proxy/internal/cli/csr_test.go`
- Test: `proxy/internal/api/mtls_bootstrap_handler_test.go`

- [ ] Add failing tests proving automation and CLI CSRs cannot inject admin or
  multiple role OUs.
- [ ] Run focused tests and verify they fail for copied CSR subjects.
- [ ] Construct issued subjects server-side and reject protected/additional
  OUs.
- [ ] Run focused tests and verify they pass.

### Task 2: Add and Validate SSH Session Binding

**Files:**
- Create: `proxy/internal/auth/session_binding.go`
- Create: `proxy/internal/auth/session_binding_test.go`
- Modify: `proxy/internal/auth/pipeline.go`
- Modify: `proxy/internal/approval/store.go`
- Modify: `proxy/internal/lease/key.go`
- Modify: `proxy/internal/api/sign_handler.go`
- Modify: `proxy/internal/approval/telegram.go`

- [ ] Add failing tests for valid binding and all malformed/tampered cases.
- [ ] Add failing tests for SSH user-auth payload validation.
- [ ] Run focused tests and verify failures.
- [ ] Implement strict session-binding and user-auth parsing.
- [ ] Bind transactions, leases, and approval displays to destination host-key
  fingerprints.
- [ ] Run focused tests and verify they pass.

### Task 3: Carry Session Binding Through SDK and Agent

**Files:**
- Modify: `sdk/sign/request.go`
- Modify: `sdk/sign/signature.go`
- Modify: `sdk/signature.go`
- Modify: `agent/agent.go`
- Create: `agent/session_bind.go`
- Modify: `agent/cmd/luna-agent/root.go`
- Test: `sdk/sign/client_test.go`
- Test: `agent/agent_test.go`
- Test: `agent/socket_test.go`

- [ ] Add failing SDK tests requiring session binding.
- [ ] Add failing agent tests for `session-bind@openssh.com`, per-connection
  binding state, forwarded binding rejection, and missing-binding denial.
- [ ] Run focused tests and verify failures.
- [ ] Implement SDK wire fields and per-connection `ExtendedAgent` wrapper.
- [ ] Run focused tests and verify they pass.

### Task 4: Make Approval State Transitions Atomic

**Files:**
- Modify: `proxy/internal/approval/store.go`
- Test: `proxy/internal/approval/store_test.go`

- [ ] Add a failing concurrent approve/deny test proving denial cannot leave a
  lease.
- [ ] Run the focused test and verify failure.
- [ ] Implement atomic approval claiming and commit leases only after success.
- [ ] Run approval and lease tests and verify they pass.

### Task 5: Bind Mobile Devices to mTLS Certificates

**Files:**
- Modify: `proxy/internal/mobile/store.go`
- Modify: `proxy/internal/api/mobile_handler.go`
- Modify: `proxy/internal/api/keys_pending_handler.go`
- Modify: `proxy/internal/control/ops.go`
- Test: `proxy/internal/mobile/store_test.go`
- Test: `proxy/internal/api/mobile_handler_test.go`
- Test: `proxy/internal/control/ops_test.go`

- [ ] Add failing tests for certificate fingerprint mismatch and matching
  device requests.
- [ ] Run focused tests and verify failures.
- [ ] Store and enforce enrolled mobile certificate fingerprints.
- [ ] Run focused tests and verify they pass.

### Task 6: Harden Display Fields, Installer Permissions, and Memory Locking

**Files:**
- Modify: `proxy/internal/auth/meta.go`
- Modify: `proxy/internal/auth/pipeline.go`
- Modify: `proxy/internal/install/user_linux.go`
- Modify: `proxy/internal/keystore/mlock_linux.go`
- Modify: `proxy/internal/keystore/mlock_stub.go`
- Modify: `proxy/internal/keystore/keystore.go`
- Test: `proxy/internal/auth/meta_test.go`
- Test: `proxy/internal/install/systemd_test.go`
- Test: `proxy/internal/keystore/keystore_test.go`

- [ ] Add failing tests for control-character rejection, explicit key
  permissions, and fail-closed memory locking.
- [ ] Run focused tests and verify failures.
- [ ] Implement validation, explicit permissions, and propagated mlock errors.
- [ ] Run focused tests and verify they pass.

### Task 7: Update Documentation and Verify

**Files:**
- Modify: `README.md`
- Modify: `AGENTS.md`
- Modify: affected specs under `docs/superpowers/specs/`
- Modify: `docs/security-review-2026-06-06.md`

- [ ] Document session-binding requirements, authoritative host-key identity,
  enrollment role assignment, mobile binding, and key permissions.
- [ ] Run `gofmt` on changed Go files.
- [ ] Run focused tests for all changed packages.
- [ ] Run `make ci`.
- [ ] Run `govulncheck` for all three modules.
- [ ] Review final diff for accidental secret or generated-file changes.
