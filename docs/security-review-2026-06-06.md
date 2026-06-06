# Security Review - 2026-06-06

## Scope

Security review of the Luna Z-Trust codebase and approved design specifications,
focused on:

- Unauthorized enrollment and role escalation
- mTLS identity and transport boundaries
- Approval integrity and race conditions
- SSH signing and target authorization
- Private-key and secret exposure
- Unix control-socket authorization

No files were modified as part of the review other than this report.

## Resolution Status

The confirmed access-control and authorization paths were addressed in the
security-hardening change set:

- Certificate subjects and roles are assigned server-side.
- Local-key signing requires validated OpenSSH session binding and user-auth
  payloads; leases bind the verified destination host key.
- Approval transitions are atomic and leases are created only after commit.
- Agent bootstrap requires a pinned CA fingerprint for insecure first contact,
  does not refresh trust before enrollment, and enrollment is rate-limited and
  audited.
- Mobile devices are bound to exact mTLS certificate fingerprints.
- Client/admin keys are owner-only; only runtime-required server and CA keys
  are service-readable.
- Display controls are rejected and authoritative values are labeled.
- Sensitive key buffers fail closed when `mlock` fails.

Residual defense-in-depth work remains: replace the reusable enrollment token
with single-use CSR-bound grants, move the runtime enrollment CA toward an
offline or hardware-backed issuer, and redesign signer ownership so removed
keys can be zeroed without racing in-flight signatures.

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 4 |
| Medium | 2 |

The most urgent issue is certificate role injection during CSR enrollment. Both
automation and CLI enrollment preserve caller-controlled certificate subjects,
while authorization trusts OU membership. The signing design also does not
cryptographically enforce the target host displayed during approval.

## Findings

### Critical: CSR subject injection allows unauthorized admin certificates

**Affected code:**

- `proxy/internal/api/mtls_bootstrap_handler.go:47`
- `proxy/internal/cli/csr.go:75`
- `proxy/internal/cli/csr.go:91`
- `proxy/internal/cli/csr.go:110`
- `proxy/internal/api/admin_handler.go:30`
- `proxy/internal/api/auth_cli.go:9`

`SignAutomation` accepts a valid CSR without restricting its OU values.
`signCSRWithTTL` then copies the complete attacker-controlled CSR subject into
the issued certificate. Admin authorization grants access whenever the
configured admin OU appears anywhere in the certificate subject.

A holder of the reusable bootstrap token can submit a CSR containing
`OU=luna-admin`, receive a CA-signed client certificate, and call admin-only
endpoints. The CLI enrollment flow also accepts a CSR containing both
`OU=luna-cli` and `OU=luna-admin`, creating a certificate with both roles.

**Remediation:**

- Construct issued certificate subjects server-side.
- Issue automation certificates with no privileged OU.
- Issue CLI certificates with exactly one server-assigned CLI OU.
- Reject CSRs containing protected or additional role OUs.
- Add tests proving automation and CLI enrollment cannot mint admin roles.

### Critical: Displayed targets are not enforced by issued credentials

**Affected code:**

- `proxy/internal/api/sign_handler.go:108`
- `proxy/internal/approval/store.go:198`
- `proxy/internal/approval/store.go:288`
- `proxy/internal/signing/local_key.go:22`
- `proxy/internal/signing/local_ca.go:42`
- `proxy/internal/approval/telegram.go:140`

In `local-key` mode, the proxy signs opaque caller-provided `agent_sign_data`.
The proxy does not parse the SSH authentication payload or verify that it
corresponds to the displayed `target_user` and `target_ip`. An active lease can
sign new arbitrary payloads without another approval.

In `local-ca` mode, the certificate binds the target user and source address,
but it does not bind the destination host. The displayed `target_ip` is not
enforced by the generated certificate.

An authenticated client can request approval for a benign displayed target and
then use the signature or certificate against another compatible SSH server.

**Remediation:**

- Parse and validate SSH user-auth signing payloads before local-key signing.
- Bind approvals to the actual SSH session, user, and host identity.
- Disable local-key lease reuse until each signed payload can be validated.
- For local-CA mode, use per-host CA trust or enforce destination authorization
  on target hosts.
- Clearly document that `target_ip` is display-only until enforcement exists.

### High: Concurrent denial can still leave an active approval lease

**Affected code:**

- `proxy/internal/approval/store.go:190`
- `proxy/internal/approval/store.go:256`
- `proxy/internal/approval/store.go:361`
- `proxy/internal/approval/store.go:370`

Approval checks that a transaction is pending, releases the lock, signs the
credential, and creates a lease before attempting to mark the transaction
approved. A concurrent denial can win the terminal-state race while the
approval path still creates a lease.

The denied request may fail, but later matching requests can use the lease and
receive credentials without another approval.

**Remediation:**

- Atomically claim a pending transaction before signing.
- Make approval, denial, and expiry mutually exclusive state transitions.
- Create leases only after the approved terminal state commits successfully.
- Add a concurrent approve/deny regression test.

### High: Agent bootstrap permits CA substitution and enrollment-token theft

**Affected code:**

- `agent/internal/setup/bootstrap.go:113`
- `agent/internal/setup/bootstrap.go:171`
- `agent/internal/setup/bootstrap.go:229`
- `proxy/internal/api/mtls_bootstrap_handler.go:47`
- `proxy/internal/setup/proxy_config.go:138`

The agent downloads the proxy CA with TLS verification disabled, trusts that
downloaded CA, and then sends the reusable enrollment token through the newly
trusted connection.

An active network attacker can substitute a CA and server certificate, capture
the enrollment token, and use the token against the real proxy. Combined with
the CSR role-injection issue, this can lead directly to admin access.

**Remediation:**

- Require an out-of-band CA fingerprint or trusted CA file for bootstrap.
- Replace the reusable token with short-lived, single-use, CSR-bound grants.
- Rate-limit and audit failed and successful bootstrap enrollment.
- Rotate the current enrollment token after fixing the flow.

### High: Mobile identity is not bound to the request mTLS certificate

**Affected code:**

- `proxy/internal/api/server.go:85`
- `proxy/internal/api/mobile_handler.go:75`
- `proxy/internal/api/keys_pending_handler.go:32`
- `proxy/internal/mobile/store.go:20`

Mobile approval and pending-key upload routes require a valid mTLS certificate,
but the enrolled mobile device record stores only an Ed25519 public key. The
handlers verify the device signature without verifying that the request's mTLS
certificate belongs to that device.

Any valid non-admin automation certificate can transport a stolen mobile
signature or act as the network identity for a compromised device key.

**Remediation:**

- Store the enrolled device certificate fingerprint and verify it per request.
- Use a dedicated mobile client OU or separate client CA.
- Reject automation and CLI certificates from all mobile-only routes.
- Include the expected certificate fingerprint in mobile enrollment tests.

### High: Installation makes CA and admin private keys group-readable

**Affected code:**

- `proxy/internal/setup/mtls.go:50`
- `proxy/internal/setup/admin_client.go:24`
- `proxy/internal/install/systemd.go:120`
- `proxy/internal/install/user_linux.go:68`

Setup places the issuing CA key, server key, admin client key, and optional
automation client key in the same certificate directory. The systemd
installation helper changes every `.key` file in that directory to mode `0640`
and grants the service group read access.

Compromise of any process or account in the service group can expose the mTLS
CA key or admin client key, enabling unrestricted certificate issuance or admin
access.

**Remediation:**

- Move admin client private keys off the proxy host after provisioning.
- Store the issuing CA key separately with minimal access.
- Apply permissions using an explicit filename allowlist.
- Keep `admin-client.key` and automation client keys owner-only. Keep `ca.key`
  service-readable only while runtime CSR enrollment is enabled.
- Prefer an offline CA or hardware-backed issuer for enrollment.

### Medium: Telegram approval messages can mislead operators

**Affected code:**

- `proxy/internal/approval/telegram.go:140`
- `proxy/internal/approval/poller.go:183`
- `proxy/internal/auth/pipeline.go:55`

Client-controlled target and metadata fields are inserted into Telegram
approval messages without character validation. Newlines and control
characters can alter the visual structure of the prompt.

Telegram authorization checks the configured chat ID but not the individual
Telegram user. If a group chat is configured, any member able to press the
button can approve requests.

**Remediation:**

- Reject or escape control characters in all displayed client fields.
- Display cryptographically authoritative values separately from client claims.
- Restrict approvals to configured Telegram user IDs as well as the chat ID.

### Medium: In-memory key protection fails open

**Affected code:**

- `proxy/internal/keystore/mlock_linux.go:14`
- `proxy/internal/keystore/mlock_linux.go:45`
- `proxy/internal/keystore/pool.go:55`

Failures from `mlock` are ignored, so production may run without the documented
memory-locking protection. Removing a key only deletes the map reference and
does not explicitly zero the private-key memory.

**Remediation:**

- Fail startup or key loading when required memory locking fails.
- Expose memory-locking status in health or status output.
- Use owned key buffers that can be explicitly zeroed on removal and shutdown.

## Positive Controls Observed

- Sign requests require mTLS, TLS-exporter HMAC, timestamp validation, replay
  detection, and proof of possession.
- Wait responses are bound to the requesting client certificate fingerprint.
- Source address is derived from the listener `RemoteAddr`, not forwarded
  headers.
- Remote CLI key load verifies an enrolled certificate fingerprint and uses
  HMAC, timestamp, replay protection, body limits, and rate limiting.
- Private keys, passphrases, raw signatures, and TLS exporter keys were not
  found in application logs.
- The Unix control socket uses Linux `SO_PEERCRED` and fails closed for unknown
  peers.

## Verification Evidence

Commands run:

```bash
make test
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Results:

- Full repository test suite passed.
- `govulncheck` reported no known vulnerabilities in `proxy`, `sdk`, or
  `agent`.
- High-confidence production secret scan found no repository matches.
- Structured `autoreview` built the full repository bundle but could not launch
  because no `codex` executable is installed in the environment.

## Recommended Priority

1. Fix CSR subject/OU role injection and rotate the bootstrap enrollment token.
2. Redesign target binding and local-key signing validation.
3. Fix the approval/denial lease race.
4. Bind mobile identities to dedicated mTLS identities.
5. Correct private-key installation permissions.
6. Harden approval presentation and memory-locking behavior.
