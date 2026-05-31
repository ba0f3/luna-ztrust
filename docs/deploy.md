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
- Telegram bot + webhook for production approval (omit only in dev with `LUNA_ENV=dev` on the **proxy process**)

### 2. OS user and directories

```bash
sudo useradd --system --home-dir /var/lib/luna --shell /usr/sbin/nologin luna
sudo install -d -o luna -g luna -m 0750 /etc/luna /etc/luna/certs /etc/luna/ssh
```

### 3. First-time mTLS CA (built-in)

Generate CA, server, and sample client certificates (no OpenSSL required):

```bash
sudo luna-proxy setup mtls --dir /etc/luna/certs \
  --san luna.example.com --san localhost
```

| File | Purpose |
|------|---------|
| `ca.crt` / `ca.key` | Issuing CA (`mtls_ca_*` for CLI enroll; `mtls_client_ca` for client auth) |
| `server.crt` / `server.key` | Proxy listener (`mtls_server_*`) |
| `client.crt` / `client.key` | Sample automation client (copy paths into agent config) |
| `admin-client.crt` / `.key` | Sample admin client (`OU=luna-admin`) for control-socket enroll |

Use `--skip-samples` for CA + server only. Re-run with `--force` to replace. **`luna-proxy serve` uses `/etc/luna/certs/` by default** when mTLS paths are unset (same layout as `setup mtls`).

For development/CI, `make testdata` still uses `scripts/gen-test-ca.sh` under `testdata/ca/` (`LUNA_ENV=dev`).

### 4. Place signing key and adjust ownership

| Path | Mode | Owner |
|------|------|-------|
| `/etc/luna/certs/server.crt` | 0644 | root:luna |
| `/etc/luna/certs/server.key` | 0640 | root:luna |
| `/etc/luna/certs/ca.crt` | 0644 | root:luna |
| `/etc/luna/certs/ca.key` | 0400 | root:luna |
| `/etc/luna/ssh/encrypted_ca.key` | 0400 | root:luna |

### 5. Configuration

```bash
sudo cp deploy/luna-proxy.production.example.yaml /etc/luna/proxy.yml
sudo chmod 600 /etc/luna/proxy.yml
sudo chown luna:luna /etc/luna/proxy.yml
```

Edit `listen_addr`, `signer_mode`, and Telegram fields. mTLS paths default to `/etc/luna/certs/` after `setup mtls` — override in YAML only for a non-default cert directory. Set the control socket for systemd:

```yaml
control_socket: /run/luna/control.sock
control_socket_group: luna-admin
```

Environment variables override YAML (see [README.md](../README.md)). Do **not** set `env: dev` in production.

### 6. systemd (recommended)

Install the unit (as root). This creates the `luna` system user/group if missing and sets group read on `/etc/luna/certs/*.key`:

```bash
sudo luna-proxy install systemd --enable
```

If the unit fails with **status=217/USER**, the service user does not exist. Fix on an already-installed host:

```bash
sudo useradd --system --home-dir /var/lib/luna --shell /usr/sbin/nologin --gid luna luna
sudo chgrp luna /etc/luna/certs/*.key && sudo chmod 640 /etc/luna/certs/*.key
sudo systemctl restart luna-proxy
```

Or re-run `sudo luna-proxy install systemd --enable` with a newer binary that creates the user automatically.

Options: `--binary`, `--config`, `--user`, `--group`, `--dry-run`, `--enable`, `--skip-user-create`.

Manual equivalent: `RuntimeDirectory=luna` so `/run/luna` exists; `ExecStart=/usr/local/bin/luna-proxy serve`. Config merges `/etc/luna/proxy.yml` when present; `install systemd` writes a minimal file if missing. mTLS and control socket use production defaults without a config file.

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

### 2. mTLS client identity

Issue an automation client certificate (not `luna-admin` or `luna-cli` unless that device is enrolled for CLI key load). Typical layout:

```
/etc/luna/certs/client.crt
/etc/luna/certs/client.key
/etc/luna/certs/ca.crt
```

### 3. Configuration

```bash
sudo useradd --system --home-dir /var/lib/luna --shell /usr/sbin/nologin luna
sudo install -d -o luna -g luna -m 0750 /etc/luna /etc/luna/certs
sudo cp deploy/luna-agent.example.yaml /etc/luna/agent.yml
sudo chmod 600 /etc/luna/agent.yml
sudo chown luna:luna /etc/luna/agent.yml
```

Required fields: `proxy_url`, `mtls_*`, `target_user`, `target_host`, `signer_mode` (must match proxy). Socket for production:

```yaml
agent_socket: /run/luna/agent.sock
```

`target_host` is the SSH destination used for PoP (OpenSSH does not pass the remote host into `Sign`).

### 4. systemd (persistent daemon)

```bash
sudo luna-agent install systemd --enable
sudo systemctl status luna-agent
```

### 5. Use with SSH

Per-user or session:

```bash
export SSH_AUTH_SOCK=/run/luna/agent.sock
ssh deploy@203.0.113.10
```

Ensure the connecting user can access the socket (e.g. group `luna` and `chmod 660` on the socket, or run the agent as the login user with a user-writable socket path).

For `local-key`, set `host_key_fingerprint` or `hosted_public_key` when multiple host keys are loaded on the proxy.

### 6. Verify

```bash
systemctl is-active luna-agent
ls -l /run/luna/agent.sock
LUNA_DEBUG=1 journalctl -u luna-agent -f
```

---

## Quick reference

| Task | Command |
|------|---------|
| Binary version | `luna-proxy version` / `luna-agent version` (or `-v` / `--version`) |
| Generate mTLS PKI | `sudo luna-proxy setup mtls --dir /etc/luna/certs` |
| Install proxy unit | `sudo luna-proxy install systemd --enable` |
| Install agent unit | `sudo luna-agent install systemd --enable` |
| Proxy status | `luna-proxy --socket /run/luna/control.sock status` |
| Load signing key | `luna-proxy --socket /run/luna/control.sock key load …` |
| Pull container | `docker pull ghcr.io/ba0f3/luna-ztrust/luna-proxy:TAG` |

---

## Related docs

- [README.md](../README.md) — API, env vars, remote CLI key load
- [setup.md](setup.md) — Target `sshd` CA trust, legacy Vault
- [AGENTS.md](../AGENTS.md) — Architecture for contributors
