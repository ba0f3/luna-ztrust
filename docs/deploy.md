# Luna Z-Trust — Deployment

Install and run **luna-proxy** on a central Linux host and **luna-agent** on client/automation hosts. Binaries ship via [GitHub Releases](https://github.com/ba0f3/luna-ztrust/releases); the proxy container image is published to **GHCR** on each `v*` tag.

| Path | Use |
|------|-----|
| [Central: luna-proxy](#central-server-luna-proxy) | mTLS API, control socket, signing |
| [Client: luna-agent](#client-host-luna-agent) | `SSH_AUTH_SOCK` for `ssh` / automation |
| [Docker Compose (proxy)](#docker-compose-luna-proxy) | Containerized central server |
| [Target sshd](setup.md#3-configure-target-hosts-vault-ssh-ca-trust) | Trust CA public key (`local-ca`) |

Example configs live under [`deploy/`](../deploy/).

---

## Releases and images

### GitHub Releases (binaries)

Tag `v*` (e.g. `v0.2.0`) runs [GoReleaser](../.goreleaser.yaml) and uploads `luna-proxy` and `luna-agent` archives for Linux and macOS (`amd64`, `arm64`) with `checksums.txt`.

```bash
VERSION=v0.2.0
ARCH=linux_amd64   # or linux_arm64, darwin_amd64, darwin_arm64
curl -fsSL -o luna-ztrust.tar.gz \
  "https://github.com/ba0f3/luna-ztrust/releases/download/${VERSION}/luna-ztrust_${VERSION#v}_${ARCH}.tar.gz"
tar -xzf luna-ztrust.tar.gz
sudo install -m 0755 luna-proxy luna-agent /usr/local/bin/
```

### GHCR (luna-proxy container)

Release workflow pushes:

`ghcr.io/ba0f3/luna-ztrust/luna-proxy:<version>`

```bash
docker pull ghcr.io/ba0f3/luna-ztrust/luna-proxy:v0.2.0
```

Make the package public once in GitHub **Packages** settings, or authenticate with a PAT that has `read:packages`.

---

## Central server (luna-proxy)

### 1. Prerequisites

- Linux host (control socket uses peer credentials; production should be Linux)
- Internal mTLS CA: server cert/key, client CA (`ca.crt`)
- Encrypted OpenSSH signing key (CA for `local-ca`, or host key for `local-key`)
- Telegram bot for production approval via outbound long polling (omit only in dev with `LUNA_ENV=dev` on the **proxy process**)

### 2. OS user and directories

```bash
sudo useradd --system --home-dir /var/lib/luna --shell /usr/sbin/nologin luna
sudo install -d -o luna -g luna -m 0750 /etc/luna /etc/luna/certs /etc/luna/ssh
```

### 3. Guided setup (recommended)

Interactive wizard — hostname in mTLS SAN, full `proxy.yml`, Telegram in production, enroll token for agents:

```bash
sudo luna-proxy setup
```

Prompts include: environment (`production` / `dev`), **public hostname**, signer mode, encrypted key path, **Telegram bot token / chat ID** (required in production), cert paths, optional systemd install.

Non-interactive example:

```bash
sudo luna-proxy setup --non-interactive --yes \
  --hostname luna.example.com \
  --telegram-bot-token "$TELEGRAM_BOT_TOKEN" \
  --telegram-chat-id "$TELEGRAM_CHAT_ID" \
  --install-systemd --enable
```

Save the printed **mtls_enroll_token** for `luna-agent setup` on client hosts.

### 4. Advanced: mTLS or config only

```bash
sudo luna-proxy setup mtls --dir /etc/luna/certs --san luna.example.com --san localhost
```

**Do not** use localhost-only `--san` for production — remote agents will fail TLS verification.

| File | Purpose |
|------|---------|
| `ca.crt` / `ca.key` | Issuing CA |
| `server.crt` / `server.key` | Proxy listener (SAN must include your public hostname) |
| `client.crt` / `client.key` | Sample automation client (lab only) |

### 5. Place signing key and adjust ownership

| Path | Mode | Owner |
|------|------|-------|
| `/etc/luna/certs/server.crt` | 0644 | root:luna |
| `/etc/luna/certs/server.key` | 0640 | root:luna |
| `/etc/luna/certs/ca.crt` | 0644 | root:luna |
| `/etc/luna/certs/ca.key` | 0400 | root:luna |
| `/etc/luna/ssh/encrypted_ca.key` | 0400 | root:luna |

### 6. systemd and start

`luna-proxy setup` can install systemd. Or separately (requires existing `proxy.yml` from setup):

```bash
sudo luna-proxy install systemd --enable
```

Environment variables override YAML (see [README.md](../README.md)). Do **not** set `env: dev` in production.

Install notes:

```bash
sudo useradd --system --home-dir /var/lib/luna --shell /usr/sbin/nologin --gid luna luna
sudo chgrp luna /etc/luna/certs/*.key && sudo chmod 640 /etc/luna/certs/*.key
sudo systemctl restart luna-proxy
```

Or re-run `sudo luna-proxy install systemd --enable` with a newer binary that creates the user automatically.

Options: `--binary`, `--config`, `--user`, `--group`, `--dry-run`, `--enable`, `--skip-user-create`.

If the unit fails with **status=217/USER**, the service user does not exist:

```bash
sudo useradd --system --home-dir /var/lib/luna --shell /usr/sbin/nologin --gid luna luna
sudo systemctl restart luna-proxy
```

Manual equivalent: `RuntimeDirectory=luna`; `ExecStart=/usr/local/bin/luna-proxy serve`.

Add operators to `luna-admin` for control socket access:

```bash
sudo groupadd -f luna-admin
sudo usermod -aG luna-admin deploy
```

### 7. Start and unseal

```bash
sudo systemctl status luna-proxy
```

Signing returns `503` until a key is loaded:

```bash
sudo luna-proxy --socket /run/luna/control.sock key load /etc/luna/ssh/encrypted_ca.key --passphrase-stdin
sudo luna-proxy --socket /run/luna/control.sock status
```

`POST /api/v1/admin/unseal` returns `410 Gone`; use the control socket only.

### 7b. Telegram approval (production)

The proxy uses **outbound long polling** (`getUpdates`) to receive inline Approve/Deny button presses. No public webhook endpoint is required — the proxy only makes outbound HTTPS calls to `api.telegram.org`.

Configure in `proxy.yml`:

- `telegram_bot_token`
- `telegram_chat_id`

On startup, `luna-proxy serve` clears any existing Telegram webhook and starts long polling. Each sign request logs JSON to stderr (`outcome: accepted`); Telegram events log as `telegram notify …` / `telegram poll …`.

Check proxy logs after a sign attempt:

```bash
sudo journalctl -u luna-proxy -f
```

Common issues:

| Symptom | Likely cause |
|---------|----------------|
| `skipped_unconfigured` in logs | Empty `telegram_bot_token` or `telegram_chat_id` in `/etc/luna/proxy.yml` |
| `dev mode: auto-approve` at startup | `env: dev` or `LUNA_ENV=dev` on proxy — Telegram OOB is disabled |
| `outcome: sealed` | Signing key not loaded (`luna-proxy key load …`) |
| Message arrives but buttons do nothing | Wrong chat ID, or proxy cannot reach `api.telegram.org` outbound |
| No sign logs at all | Agent not reaching proxy (TLS, mTLS, wrong URL) |

### 8. Firewall and ingress

- Listen on `:8443` or terminate TLS at an ingress that preserves client source IP for `source-address` on certs.
- Do not trust `X-Forwarded-For` on the mTLS listener unless documented otherwise.

---

## Docker Compose (luna-proxy)

On the central host, prepare a compose directory:

```bash
mkdir -p ~/luna-proxy && cd ~/luna-proxy
cp /path/to/luna-ztrust/deploy/docker-compose.yml .
cp /path/to/luna-ztrust/deploy/luna-proxy.production.example.yaml ./proxy.yml
mkdir -p certs ssh
# install server.crt, server.key, ca.crt into certs/
# install encrypted_ca.key into ssh/
```

Set image tag if not using `latest`:

```bash
export LUNA_PROXY_TAG=v0.2.0
docker compose -f deploy/docker-compose.yml up -d
```

Unseal inside the container:

```bash
docker compose -f deploy/docker-compose.yml exec -T luna-proxy \
  luna-proxy --socket /run/luna/control.sock key load /etc/luna/ssh/encrypted_ca.key --passphrase-stdin
```

Health: `curl -sfk https://localhost:8443/healthz`

---

## Client host (luna-agent)

### 1. Download binary

Use the same [release archive](#github-releases-binaries) as the proxy, or copy `luna-agent` from a trusted build.

```bash
sudo install -m 0755 luna-agent /usr/local/bin/luna-agent
```

### 2. Guided setup (recommended)

Run the interactive wizard (repeatable; re-run pre-fills from existing `agent.yml`):

```bash
sudo luna-agent setup
```

Press Enter to accept defaults shown in `[brackets]`. Use `-y` to skip the final confirmation.

**Non-interactive** (scripts/CI):

```bash
sudo luna-agent setup --non-interactive \
  --from-dir ./luna-certs \
  --proxy-url https://luna.example:8443 \
  --target-user deploy \
  --target-host 203.0.113.10 \
  --install-systemd --enable
```

Copy certs from proxy (after `luna-proxy setup mtls` on the central host) — the wizard option **Copy from directory** or use **HTTP bootstrap** (no SCP for `ca.crt`):

1. On the proxy, set a enroll token in `/etc/luna/proxy.yml` and restart:

```yaml
mtls_enroll_token: "your-long-random-secret"
```

2. Obtain the SHA-256 fingerprint of `ca.crt` over a trusted channel, then on
the agent host install that CA or use pinned HTTP bootstrap:

```bash
luna-agent setup --fetch-ca --ca-fingerprint '<sha256-ca-cert>' \
  --enroll-token 'your-long-random-secret' \
  --proxy-url https://luna.example:8443 ...
```

- `GET /api/v1/mtls/ca` — download public CA (no client cert)
- `POST /api/v1/mtls/enroll` — submit CSR, receive `client.crt` (requires `X-Luna-Enroll-Token` header)
- Insecure first-contact CA download fails unless `--ca-fingerprint` matches.
- Enrollment never silently replaces an installed CA before sending the token.

### 3. Manual mTLS layout (alternative)

Issue an automation client certificate (not `luna-admin` or `luna-cli`). Typical layout:

```
/etc/luna/certs/client.crt
/etc/luna/certs/client.key
/etc/luna/certs/ca.crt
```

### 4. Manual configuration

```bash
sudo cp deploy/luna-agent.example.yaml /etc/luna/agent.yml
sudo chmod 600 /etc/luna/agent.yml
sudo chown luna:luna /etc/luna/agent.yml
```

Required fields: `proxy_url`, `mtls_*`, `target_user`, `target_host`, `signer_mode` (must match proxy). Paths default to `/etc/luna/certs/` and socket `/run/luna/agent.sock` when unset.

`target_host` is the SSH destination used for PoP (OpenSSH does not pass the remote host into `Sign`).

### 5. systemd (persistent daemon)

**User service (default, no sudo):**

```bash
luna-agent install systemd --enable
systemctl --user status luna-agent
export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/luna/agent.sock
```

(`setup --install-systemd --enable` runs this as the final step.)

**System service (optional, requires root):**

```bash
sudo luna-agent install systemd --system --enable
sudo systemctl status luna-agent
```

### 6. Use with SSH

Per-user or session:

```bash
# user systemd (default)
export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/luna/agent.sock

# system systemd
export SSH_AUTH_SOCK=/run/luna/agent.sock
ssh deploy@203.0.113.10
```

For a **user** unit, the socket is under `$XDG_RUNTIME_DIR/luna/agent.sock` (see `agent_socket` in `agent.yml`). For a **system** unit under the `luna` user, ensure the connecting user can access the socket (e.g. group `luna` and `chmod 660` on the socket).

For `local-key`, **leave host key fingerprint blank** in normal setups. After mTLS, `luna-agent` calls `GET /api/v1/capabilities` on the proxy and advertises every loaded host signing key to OpenSSH. When the client picks a key, the agent sends that key's fingerprint on sign.

Set `host_key_fingerprint` only when you want to **restrict** the agent to one key while several are loaded on the proxy. To look up a fingerprint for that filter:

```bash
luna-proxy --socket /run/luna/control.sock key list
# or: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

`hosted_public_key` is a legacy fallback when an older proxy returns fingerprints without `public_key` in capabilities.

### 6. Verify

```bash
systemctl --user is-active luna-agent   # user unit
# or: sudo systemctl is-active luna-agent   # system unit
ls -l "${XDG_RUNTIME_DIR}/luna/agent.sock"
journalctl --user -u luna-agent -f
```

---

## Quick reference

| Task | Command |
|------|---------|
| Binary version | `luna-proxy version` / `luna-agent version` (or `-v` / `--version`) |
| Generate mTLS PKI | `sudo luna-proxy setup mtls --dir /etc/luna/certs` |
| Agent guided setup | `luna-agent setup --from-dir … --install-systemd --enable` |
| Install proxy unit | `sudo luna-proxy install systemd --enable` |
| Install agent unit | `luna-agent install systemd --enable` (user) or `sudo luna-agent install systemd --system --enable` |
| Proxy status | `luna-proxy --socket /run/luna/control.sock status` |
| Load signing key | `luna-proxy --socket /run/luna/control.sock key load …` |
| Pull container | `docker pull ghcr.io/ba0f3/luna-ztrust/luna-proxy:TAG` |

---

## Related docs

- [README.md](../README.md) — API, env vars, remote CLI key load
- [setup.md](setup.md) — Target `sshd` CA trust, legacy Vault
- [AGENTS.md](../AGENTS.md) — Architecture for contributors
