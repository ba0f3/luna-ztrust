# Luna Z-Trust

Ephemeral SSH authentication for AI agents, DevOps runners, and automation. A self-hosted **luna-proxy** keeps signing keys in an in-memory keystore loaded by local operators or enrolled CLI devices, issues short-lived SSH **certificates** (`local-ca`) or **hosted-key signatures** (`local-key`), and gates access with out-of-band approval (Telegram v1; mobile enroll/approve API on the server).

## Components

| Component | Role |
|-----------|------|
| **luna-sdk** | Publishable Go library: ephemeral keys, PoP, mTLS + HMAC to proxy, cert/signature lifecycle |
| **luna-proxy** | Central gateway: auth pipeline, control socket, in-memory keystore, signing, Telegram OOB, session leases |
| **luna-agent** | OS daemon: `SSH_AUTH_SOCK` interceptor; blocking `Sign` for unmodified `ssh` |

**Out of scope in this repository:** [lunacli](https://github.com/ba0f3/lunacli) (separate project; imports `luna-sdk`), target `sshd` provisioning.

## Architecture

```mermaid
graph TD
    subgraph CENTRAL["Central host"]
        LP["luna-proxy serve :8443 mTLS"]
        CTRL["/run/luna/control.sock"]
        KS["in-memory key pool"]
        KS --> LP
        CTRL --> LP
        LP --> TG["Telegram API"]
    end

    subgraph CLIENT["Client host"]
        LA["luna-agent"]
        SDK["luna-sdk"]
        SSH["ssh / automation"]
        SSH -->|"SSH_AUTH_SOCK"| LA
        LA --> SDK
        SDK -->|"HTTPS mTLS"| LP
    end

    SDK --> Target["Target sshd"]
    LA --> Target
```

**Sign flow (transaction + wait):**

1. Client generates an ephemeral Ed25519 keypair (memory only).
2. `POST /api/v1/ssh/sign` with JSON body, `pop_signature`, mTLS, `X-Luna-Body-Mac`.
3. Proxy validates the auth pipeline; if no signer is loaded → `503`. Otherwise lease fast-path or new `tx_id` + Telegram (or auto-approve in dev).
4. `GET /api/v1/ssh/sign/{tx_id}/wait` blocks until approved, denied, or timeout.
5. Proxy signs via `local-ca` (SSH user cert + `source-address`) or `local-key` (`agent_sign_data` → `ssh_signature`).
6. SDK returns cert + private key, or signature; agent returns `ssh.Signature` to OpenSSH.

## Repository layout

```
luna-ztrust/
  go.work
  sdk/          # github.com/ba0f3/luna-ztrust/sdk
  proxy/        # github.com/ba0f3/luna-ztrust/proxy
  agent/        # github.com/ba0f3/luna-ztrust/agent
  docs/
    superpowers/specs/
      2026-05-30-self-hosted-central-design.md
      2026-05-31-proxy-cli-keystore-design.md
      2026-05-31-cli-remote-key-load-design.md
```

**Module dependency rules:**

- `agent` → `sdk`
- `proxy` does not import `sdk`
- `sdk` does not import `agent` or `proxy`

## Requirements

- Go 1.25+ (see `go.work`)
- Linux recommended (keystore `mlock`, Unix control socket peer credentials)
- Internal mTLS CA (client certs for SDK/agent; admin OU for admin HTTP/device enrollment; CLI OU for remote key load)
- Encrypted signing keys loaded by `luna-proxy key load` or mobile pending upload + `key confirm`
- Telegram bot (production approval path)

## Build and test

```bash
go work sync
make test
make testdata   # mTLS + encrypted SSH keys for CI
make build      # bin/luna-proxy, bin/luna-agent
make ci         # fmt-check, lint, test, build (local CI parity)
```

**CI:** GitHub Actions runs `make ci` on push/PR and Docker E2E (`make e2e-up`, `e2e-wait`, `e2e-test`) in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

**Releases:** Tag `v*` (e.g. `v0.1.0`) triggers [GoReleaser](.goreleaser.yaml) and a [GHCR](https://github.com/ba0f3/luna-ztrust/pkgs/container/luna-ztrust%2Fluna-proxy) image via [`.github/workflows/release.yml`](.github/workflows/release.yml) — cross-platform `luna-proxy` and `luna-agent` archives plus `ghcr.io/ba0f3/luna-ztrust/luna-proxy:<tag>`.

**Deployment:** [docs/deploy.md](docs/deploy.md) — GitHub release binaries, systemd (`luna-proxy install systemd`, `luna-agent install systemd`), Docker Compose.

## E2E

Docker Compose runs `luna-proxy serve` with test mTLS and an encrypted CA key. Tests load the encrypted test CA through the control socket before signing.

```bash
make testdata
make e2e-up
make e2e-test
make e2e-down
```

```bash
LUNA_PROXY_URL=https://localhost:8443 go test -tags=e2e ./sdk/sign/... -v
```

`make e2e-test` runs `luna-proxy --socket /run/luna/control.sock key load /etc/luna/ssh/encrypted_ca.key --passphrase-stdin` inside the compose service.

## Configuration (overview)

### luna-proxy

| Variable | Purpose |
|----------|---------|
| `LUNA_SIGNER_MODE` | `local-key` (default) or `local-ca` |
| `LUNA_CONTROL_SOCKET` | Unix control socket path (default `/run/luna/control.sock`) |
| `LUNA_CONTROL_SOCKET_GROUP` | Group allowed to use the control socket (default `luna-admin`) |
| `LUNA_ADMIN_CLIENT_OU` | Client cert OU for `/api/v1/admin/*` (default `luna-admin`) |
| `LUNA_CLI_CLIENT_OU` | Client cert OU for enrolled CLI devices (default `luna-cli`) |
| `LUNA_MTLS_SERVER_CERT` / `KEY` / `LUNA_MTLS_CLIENT_CA` | mTLS listener material; default `/etc/luna/certs/{server.crt,server.key,ca.crt}` (same as `setup mtls`) |
| `LUNA_MTLS_CA_CERT` | mTLS issuing CA cert path (default `/etc/luna/certs/ca.crt`; CSR enrollment for CLI devices) |
| `LUNA_MTLS_CA_KEY` | mTLS issuing CA key path (default `/etc/luna/certs/ca.key`; required for `cli enroll`) |
| `LUNA_ENV=dev` | Auto-approve (proxy env only) |
| `TELEGRAM_BOT_TOKEN` | Outbound Telegram API |
| `TELEGRAM_WEBHOOK_SECRET` | Webhook validation |
| `TELEGRAM_CHAT_ID` | Admin chat for approval prompts |
| `FCM_CREDENTIALS` | P5 hook for mobile push (stub until implemented) |

Vault / `LUNA_VAULT_*` are removed from the runtime path; see [docs/legacy-vault-migration.md](docs/legacy-vault-migration.md).

`POST /api/v1/admin/unseal` and `GET /api/v1/admin/seal-status` are compatibility routes that return `410 Gone`; use `luna-proxy key load` and `luna-proxy status` instead.

### Operator control socket

Run the server explicitly:

```bash
luna-proxy serve
```

First-time mTLS CA and server certs (Linux, root):

```bash
sudo luna-proxy setup mtls --dir /etc/luna/certs --san luna.example.com
```

Install a systemd unit (Linux, root):

```bash
sudo luna-proxy install systemd --enable
```

Operator commands use the Unix control socket on the central host:

```bash
luna-proxy status
luna-proxy key load /etc/luna/ssh/encrypted_ca.key --passphrase-stdin
luna-proxy key list
luna-proxy key remove <fingerprint>
luna-proxy key confirm <pending-id>
luna-proxy key reject <pending-id>
luna-proxy mobile enroll --label phone --pubkey <base64-ed25519-pubkey>
luna-proxy mobile list
```

In `local-ca`, `key load` replaces the single CA signer. In `local-key`, it adds a signer to the in-memory pool. Process restart clears loaded signers, CLI enrollments, mobile enrollments, and pending uploads in v1.

### Remote key load (`local-key`)

When `signer_mode=local-key`, operators can load host signing keys without copying encrypted PEM to the central host. On-host load uses the control socket (`luna-proxy key load /path/on/server` on the central machine). From a laptop, use enrolled CLI mTLS (`OU=luna-cli`).

**1. Enroll a CLI device (CSR; private key never leaves the laptop)**

```bash
luna-proxy cli init                    # ~/.config/luna/cli.key
luna-proxy cli csr                     # ~/.config/luna/cli.csr.pem
# On central host (admin control socket):
luna-proxy cli enroll --label alice-macbook --csr-file ~/.config/luna/cli.csr.pem
# Writes cli.crt beside the CSR (or use --cert-out)
```

The proxy must have `mtls_ca_cert_path` / `mtls_ca_key_path` set (or `LUNA_MTLS_CA_CERT` / `LUNA_MTLS_CA_KEY`). Without CA key material, enroll returns `503`.

**2. Configure the operator profile**

`~/.config/luna/cli.yaml`:

```yaml
proxy_url: https://luna.example:443
cli_cert: ~/.config/luna/cli.crt
cli_key: ~/.config/luna/cli.key
ca: ~/.config/luna/ca.crt
```

Flags override the file: `--proxy-url`, `--cli-cert`, `--cli-key`, `--ca`.

**3. Load from the laptop**

```bash
luna-proxy key load ./encrypted-host.key --label deploy-prod
```

Uploads base64 encrypted PEM + passphrase over `POST /api/v1/cli/keys/load` inside mTLS with `X-Luna-Body-Mac` and `timestamp` (same auth binding as sign API). Requires `--label` for remote load and `signer_mode=local-key`.

**v1 notes:** CLI device registry is in-memory; proxy restart drops enrollments (re-enroll and re-load). Mobile pending upload + `key confirm` is unchanged.

See [docs/superpowers/specs/2026-05-31-cli-remote-key-load-design.md](docs/superpowers/specs/2026-05-31-cli-remote-key-load-design.md).

### luna-agent

| Variable | Purpose |
|----------|---------|
| `LUNA_PROXY_URL` | Proxy base URL |
| `LUNA_SIGNER_MODE` | `local-ca` or `local-key` (must match proxy) |
| `LUNA_MTLS_CERT` / `LUNA_MTLS_KEY` / `LUNA_MTLS_CA` | Client mTLS material |
| `LUNA_TARGET_USER` | Default SSH principal |
| `LUNA_TARGET_HOST` | Target IP/hostname for PoP / cert binding |
| `LUNA_HOST_KEY_FINGERPRINT` | Optional `local-key` signer hint when multiple host keys are loaded |
| `LUNA_HOSTED_PUBLIC_KEY` | Optional host `.pub` path or authorized_keys line for identity discovery |

Agent socket: `/run/luna/agent.sock` (mode `0600`).

Persistent daemon (Linux, root):

```bash
sudo luna-agent install systemd --enable
export SSH_AUTH_SOCK=/run/luna/agent.sock
```

## HTTP API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/admin/unseal` | `410 Gone`; use control socket `key load` |
| `GET` | `/api/v1/admin/seal-status` | `410 Gone`; use control socket `status` |
| `GET` | `/api/v1/capabilities` | mTLS: signer mode, TTLs, sealed |
| `POST` | `/api/v1/ssh/sign` | Create transaction; `202` + `tx_id` |
| `GET` | `/api/v1/ssh/sign/{tx_id}/wait` | Block until cert/signature or error |
| `POST` | `/api/v1/telegram/webhook` | Telegram approval callback |
| `POST` | `/api/v1/mobile/enroll` | Admin mTLS: register device |
| `POST` | `/api/v1/mobile/approve` | mTLS + device signature |
| `POST` | `/api/v1/mobile/keys/pending` | Enrolled mobile device: upload encrypted key for local confirmation |
| `DELETE` | `/api/v1/mobile/devices/{device_id}` | Admin mTLS: revoke device |
| `POST` | `/api/v1/cli/enroll` | Admin mTLS: sign CSR, register CLI device |
| `GET` | `/api/v1/cli/devices` | Admin mTLS: list CLI devices |
| `DELETE` | `/api/v1/cli/devices/{device_id}` | Admin mTLS: revoke CLI device |
| `POST` | `/api/v1/cli/keys/load` | Enrolled CLI mTLS: upload encrypted key (`local-key` only) |
| `GET` | `/healthz` | Health check (no client cert required) |

Auth order on sign requests: mTLS → HMAC → timestamp → replay LRU → PoP → tx/lease/sign.

## Security principles

- **Fail-closed:** Auth and key-load failures never create transactions or Telegram prompts.
- **Sealed by default:** Sign returns `503` until a signer is loaded into the in-memory keystore.
- **Zero disk keys on clients:** Ephemeral private keys stay in memory.
- **IP binding:** `source-address` on user certs from mTLS `RemoteAddr`.
- **Session leases:** Re-approval skipped for same client + target + approver within TTL.
- **Local administration:** Key load, key list/remove, status, CLI enrollment, and mobile enrollment have Unix socket paths guarded by peer credentials.

## Documentation

| Document | Contents |
|----------|----------|
| [docs/deploy.md](docs/deploy.md) | Install proxy/agent, systemd, Docker Compose, GHCR |
| [docs/setup.md](docs/setup.md) | Target `sshd` trust, operator runbooks, legacy Vault notes |
| [docs/legacy-vault-migration.md](docs/legacy-vault-migration.md) | Vault → self-hosted mapping |
| [docs/superpowers/specs/2026-05-30-self-hosted-central-design.md](docs/superpowers/specs/2026-05-30-self-hosted-central-design.md) | Self-hosted central server design |
| [docs/superpowers/plans/2026-05-30-self-hosted-central.md](docs/superpowers/plans/2026-05-30-self-hosted-central.md) | Implementation plan |
| [docs/superpowers/specs/2026-05-31-proxy-cli-keystore-design.md](docs/superpowers/specs/2026-05-31-proxy-cli-keystore-design.md) | Control socket, Cobra CLI, multi-key keystore |
| [docs/superpowers/specs/2026-05-31-cli-remote-key-load-design.md](docs/superpowers/specs/2026-05-31-cli-remote-key-load-design.md) | Enrolled CLI remote key loading |
| [AGENTS.md](AGENTS.md) | Guidance for AI coding agents |

## License

See repository license file when published.
