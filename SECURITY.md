# Security Policy

## Supported Versions

Luna Z-Trust is pre-v1.0. Security fixes are applied to the `main` branch and included in subsequent releases. There are no long-term support branches at this time.

| Version | Supported |
|---------|-----------|
| `main` branch | ✅ |
| Latest release | ✅ |
| Older releases | ❌ |

## Reporting a Vulnerability

**Do not file public GitHub issues for security vulnerabilities.**

Instead, please report vulnerabilities via email to:

**security@huy.im**

Include the following information:

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Any suggested mitigations or fixes

We will acknowledge receipt within 48 hours and provide a status update within 7 days. We aim to release a fix within 30 days for Critical/High severity issues.

## Disclosure Process

1. **Private report** sent to security@huy.im
2. **Acknowledgment** within 48 hours
3. **Investigation** and impact assessment
4. **Fix development** on a private branch
5. **Coordinated disclosure** — we will work with you on a timeline for public disclosure after a fix is available
6. **Release** — fix included in next release; CVE requested if applicable
7. **Public advisory** — GitHub Security Advisory published after release

## Security Principles

Luna Z-Trust is built on the following non-negotiable security principles:

### Fail-Closed
All authentication, key-load, and signing operations fail closed. No operation proceeds if any validation step fails.

### Sealed by Default
The signing keystore is sealed at startup. `POST /api/v1/ssh/sign` returns `503` until an operator loads a signing key via the Unix control socket (`luna-proxy key load`).

### Zero Disk Secrets on Clients
- Ephemeral private keys exist only in memory
- No SSH private keys or Vault tokens written to disk on agent or client hosts
- Encrypted signing keys decrypted only in proxy RAM (`internal/keystore`)

### Cryptographic Binding
- **mTLS**: Mutual TLS for all API connections
- **HMAC**: Constant-time `X-Luna-Body-Mac` using TLS exporter (`luna-request-hmac`, 32 bytes)
- **PoP**: Proof of Possession — ephemeral key signs `target_user:target_ip:timestamp`
- **Replay Protection**: LRU cache of `SHA256(raw_body)` with 60s TTL
- **Timestamp Validation**: ±30s clock skew tolerance

### Source Address Integrity
`source-address` on issued certificates is derived from the mTLS listener's `RemoteAddr`. `X-Forwarded-For` and similar headers are **never trusted** on the mTLS listener.

### Local Administration
Key loading, listing, removal, status, CLI enrollment, and mobile enrollment are performed via a Unix control socket (`/run/luna/control.sock`) guarded by Linux `SO_PEERCRED` and a configured admin group (`luna-admin` by default).

### No HTTP Admin Unseal
`POST /api/v1/admin/unseal` and `GET /api/v1/admin/seal-status` return `410 Gone`. Use the control socket only.

### Dev Mode Isolation
`LUNA_ENV=dev` auto-approve is **only** read from the proxy process environment — never from client headers.

## Known Limitations

The following security findings are documented and being addressed. See [Security Review 2026-06-06](docs/security-review-2026-06-06.md) for full details.

### Critical
1. **CSR subject injection** — caller-controlled CSR subjects can include privileged OUs (`luna-admin`)
2. **Displayed targets not enforced** — `target_user`/`target_ip` shown in approval are not cryptographically bound to issued credentials

### High
3. **Approval/denial lease race** — concurrent denial can leave an active lease
4. **Agent bootstrap CA substitution** — enrollment token sent over connection trusting downloaded CA
5. **Mobile identity not bound to mTLS** — device signature verified without checking request mTLS cert
6. **Private key file permissions** — CA/admin keys made group-readable (`0640`) during install

### Medium
7. **Telegram message injection** — client-controlled fields can alter prompt visual structure
8. **Memory locking fails open** — `mlock` failures ignored; keys not zeroed on removal

These issues do not represent leaked secrets or vulnerabilities in the current threat model (they require specific attack conditions), but they should be remediated before production v1.0 deployment.

## Security Hygiene

- **Dependencies**: Minimal, well-maintained (`golang.org/x/crypto`, `spf13/*`, `oklog/ulid`)
- **Vulnerability scanning**: `govulncheck` runs in CI; no known vulnerabilities
- **Secret scanning**: No hardcoded secrets, private keys, or credentials in repository
- **Test data**: All test keys use passphrase `test-pass` and are in `testdata/` (gitignored)

## Secure Deployment Checklist

When deploying Luna Z-Trust in production:

- [ ] Use `env: production` (never `dev`)
- [ ] Set `telegram_bot_token` and `telegram_chat_id` for OOB approval
- [ ] Generate mTLS CA with `luna-proxy setup mtls` using your **public hostname** in SAN
- [ ] Store encrypted signing key at `/etc/luna/ssh/encrypted_ca.key` (mode `0400`, owner `root:luna`)
- [ ] Keep `ca.key` at `0400` root-only; move admin client keys off proxy after provisioning
- [ ] Add operators to `luna-admin` group for control socket access
- [ ] Load signing key via control socket: `luna-proxy --socket /run/luna/control.sock key load /etc/luna/ssh/encrypted_ca.key --passphrase-stdin`
- [ ] Verify `luna-proxy status` shows `sealed: false`
- [ ] Configure firewall: only expose `:8443` (or terminate TLS at ingress preserving client source IP)
- [ ] Monitor proxy logs for `outcome: sealed`, `skipped_unconfigured`, auth failures

## Contact

For security questions or concerns not related to vulnerability reporting:

- Open a [GitHub Discussion](https://github.com/ba0f3/luna-ztrust/discussions)
- Email: security@huy.im