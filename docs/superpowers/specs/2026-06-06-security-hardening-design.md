# Security Hardening Design

**Status:** Approved 2026-06-06

**Builds on:** Existing Luna core, proxy/CLI/keystore, and remote-key-load
specifications.

## 1. Summary

This design closes the findings documented in
[`docs/security-review-2026-06-06.md`](../../security-review-2026-06-06.md).
It preserves `local-key` signing while making the destination SSH host key,
rather than caller-supplied `target_ip`, the authoritative target identity.

Security-sensitive identity attributes are assigned by the server, approvals
become atomic state transitions, mobile devices are bound to mTLS identities,
and production key protection fails closed.

## 2. Enrollment Roles

Issued mTLS certificate subjects are server-controlled:

- Automation enrollment issues a fixed automation subject with no privileged
  OU.
- CLI enrollment issues a fixed subject with exactly the configured
  `cli_client_ou`.
- CSR subject OUs are never copied into issued certificates.
- CSRs containing protected role OUs or additional OUs are rejected.

The existing bootstrap enrollment token remains temporarily supported for
compatibility, but enrollment is rate-limited. Agents must use an explicitly
installed CA or an out-of-band pinned CA fingerprint. Automatic insecure CA
refresh before enrollment is removed.

## 3. Host-Bound Local-Key Signing

### 3.1 Authoritative Destination

The authoritative destination identity is the SHA-256 fingerprint of the
destination SSH server host key. `target_ip` remains approval-display and audit
metadata only.

### 3.2 Session Binding

Local-key sign requests include:

```json
{
  "session_binding": {
    "host_public_key": "<base64 SSH wire key>",
    "session_id": "<base64 SSH session identifier>",
    "signature": "<base64 SSH signature wire encoding>",
    "forwarding": false
  }
}
```

Per OpenSSH `PROTOCOL.agent`, the host-key signature is over the SSH session
identifier/exchange hash. The extension message carries the host key, session
identifier, signature, and forwarding flag.

The proxy parses the destination host public key, verifies the binding
signature, derives the destination fingerprint, and rejects malformed,
forwarded, or unverifiable bindings.

### 3.3 User-Authentication Payload

Before local-key signing, the proxy parses `agent_sign_data` as an SSH
user-auth public-key request and verifies:

- The embedded session ID equals the verified binding session ID.
- The requested username equals `target_user`.
- The service is `ssh-connection`.
- The method is `publickey`.
- The public key equals the selected hosted signing key.
- No trailing bytes remain.

Approval messages and leases include and bind to the destination host-key
fingerprint. Local-key requests without a valid session binding fail closed.

### 3.4 Agent Flow

`luna-agent` implements `agent.ExtendedAgent`. A per-connection wrapper records
the most recent valid `session-bind@openssh.com` extension received from
OpenSSH and attaches it to subsequent local-key signature requests on that
connection.

The daemon rejects local-key signing when OpenSSH did not provide a valid
session binding. Forwarded session bindings are rejected.

### 3.5 Direct SDK Flow

In-process `x/crypto/ssh` clients cannot obtain OpenSSH agent
`session-bind@openssh.com` data. Direct SDK callers instead provide
`DestinationHostPublicKey`, captured from the host key accepted by their
`ssh.HostKeyCallback`.

The proxy still parses and validates the SSH user-auth payload, target user,
session ID presence, and selected hosted signing key. Because the destination
host key is a client assertion rather than a server-signed session binding:

- approval messages label it as **client-reported**;
- every signature requires approval;
- lease lookup and lease creation are disabled.

## 4. Atomic Approval State

Approval, denial, and expiry are mutually exclusive transitions:

1. Approval atomically claims a pending transaction.
2. Signing occurs only for the claimed approval.
3. The approved result and lease are committed together.
4. Denial and expiry cannot modify an approval-claimed transaction.
5. Failed signing completes the transaction with an error and creates no
   lease.

This prevents a denied request from leaving an active lease.

## 5. Mobile mTLS Binding

Mobile enrollment records the enrolling admin-authorized request's intended
mobile client certificate fingerprint. Mobile approval and pending-key upload
require the request certificate fingerprint to match the enrolled device.

Mobile-only routes reject admin, CLI, and generic automation identities unless
the exact enrolled fingerprint matches.

## 6. Approval Presentation

All client-controlled display fields reject ASCII control characters.
Approval messages display the authoritative destination host-key fingerprint
for local-key requests and label `target_ip` as a client claim.

Telegram private-chat approvals require the callback user to match the
configured chat/user ID. Group chats require an explicit
`TELEGRAM_USER_IDS` allowlist.

## 7. Key and Memory Protection

- Installer permissions use explicit filenames.
- `admin-client.key`, automation `client.key`, and unrelated keys remain
  owner-only.
- `server.key` and `ca.key` receive service-group read permission because the
  running proxy terminates TLS and signs enrollment CSRs.
- Production key load fails when `mlock` fails.
- Decrypted owned private-key buffers are locked before use; load fails closed
  when locking fails.

## 8. Compatibility

- Agent local-key callers must provide session-binding context.
- Direct SDK local-key callers must provide the destination host key accepted
  by their `HostKeyCallback`; direct requests never use approval leases.
- OpenSSH clients without `session-bind@openssh.com` support are rejected in
  local-key mode.
- Local-CA continues to bind the source address and principal. Destination host
  authorization remains target-side CA trust policy.
- `target_ip` remains in the protocol for display, audit, and local-CA lease
  scoping, but is not described as cryptographically authoritative.

## 9. Testing

- CSR tests reject protected/additional OUs and verify server-assigned roles.
- Bootstrap tests reject insecure automatic CA replacement.
- Session-binding tests verify valid bindings and reject tampering, forwarding,
  wrong users, wrong session IDs, wrong hosted keys, and trailing bytes.
- Agent tests verify per-connection extension state and missing-binding denial.
- Approval concurrency tests prove denial cannot leave a lease.
- Mobile tests prove certificate-fingerprint binding.
- Installer tests prove CA/admin keys remain root-only.
- Keystore tests prove required `mlock` failures fail closed.
- Full `make ci` and `govulncheck` complete before closeout.
