# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Release Process

Changelogs are **automatically generated** by [GoReleaser](.goreleaser.yaml) from conventional commit messages when a `v*` tag is pushed. See [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages) for commit message format.

### Manual Generation

To generate a changelog locally for the next release:

```bash
# Requires GoReleaser
goreleaser release --snapshot --clean --skip=publish
```

The generated changelog will be based on commits since the last tag.

---

## [Unreleased]

### Added
- LICENSE (MIT)
- CONTRIBUTING.md
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- SECURITY.md
- CHANGELOG.md

### Security
- Documented known limitations in SECURITY.md (see Security Review 2026-06-06)

---

## [v0.2.1] - 2026-06-06

### Fixed
- Bolt: optimize Proof of Possession challenge generation
- Bolt: optimize base64 encoding in fingerprint generator
- Sentinel: [MEDIUM] Fix missing input length limits on mobile endpoints

### Changed
- feat(proxy): enhance Telegram approval process with message editing
- feat(agent, proxy): enhance client metadata handling in sign requests
- feat(keystore): add SSH signer stub for memory locking
- feat(proxy): transition to Telegram long polling for approval notifications
- feat(agent): refactor socket path handling and enhance systemd installation
- feat(agent): enhance CA management and error handling during enrollment
- feat(agent, proxy): add agent socket configuration and enhance setup process
- feat(agent, proxy): implement mTLS enrollment and CA fetching
- feat(agent): enhance identity resolution and logging for local key mode
- feat(agent): implement interactive setup for luna-agent
- feat(agent, proxy): enhance systemd installation and configuration handling
- feat(mTLS): implement first-time mTLS setup and configuration

---

## [v0.2.0] - 2026-05-31

### Added
- Self-hosted central server (signing, key load, leases)
- Proxy CLI and control socket (`luna-proxy key load`, `status`, `key list`, etc.)
- In-memory keystore with `local-ca` (single signer) and `local-key` (fingerprint-keyed pool)
- CLI remote key load (`POST /api/v1/cli/keys/load` with enrolled `OU=luna-cli` devices)
- Mobile key upload (`POST /api/v1/mobile/keys/pending` + local `key confirm`)
- Telegram OOB approval (long polling, no webhook required)
- Session lease store (re-approval skipped within TTL)
- mTLS enrollment for agents (`GET /api/v1/mtls/ca`, `POST /api/v1/mtls/enroll`)
- Encrypted PEM key loading via control socket (passphrase via stdin)
- `mlock` for in-memory key protection (Linux)
- Comprehensive specs and implementation plans in `docs/superpowers/`

### Changed
- HTTP admin unseal removed (`410 Gone`); use control socket only
- Vault integration removed (legacy; see `docs/legacy-vault-migration.md`)
- Architecture constraints enforced: `agent → sdk`, `proxy ✗ sdk`, `sdk ✗ agent/proxy`

### Security
- Fail-closed auth pipeline (mTLS → HMAC → timestamp → replay LRU → PoP)
- Sealed keystore by default (`503` until key loaded)
- Source address from mTLS `RemoteAddr` only
- `SO_PEERCRED` for control socket authorization
- Never log private keys, passphrases, TLS exporter keys, raw signatures

---

## [v0.1.0] - 2026-05-21

### Added
- Core protocol: mTLS, HMAC, PoP, transaction/wait, agent
- `luna-sdk`: ephemeral keys, PoP, cert/signature HTTP client
- `luna-proxy`: auth pipeline, in-memory key pool, local CA signing
- `luna-agent`: `SSH_AUTH_SOCK` daemon, blocking `Sign` via SDK
- Test infrastructure: unit, integration, E2E (docker-compose)
- CI/CD: GitHub Actions, GoReleaser, GHCR publishing

---

## Historical

Prior to v0.1.0, development occurred in private repositories. See git history for full commit log.

---

## Links

- [GitHub Releases](https://github.com/ba0f3/luna-ztrust/releases)
- [GitHub Security Advisories](https://github.com/ba0f3/luna-ztrust/security/advisories)
- [Security Review 2026-06-06](docs/security-review-2026-06-06.md)