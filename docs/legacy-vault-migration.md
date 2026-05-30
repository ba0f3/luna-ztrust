# Migrating from HashiCorp Vault SSH CA to self-hosted luna-proxy

Luna Z-Trust **no longer uses Vault** for SSH certificate signing as of the self-hosted central server design ([`docs/superpowers/specs/2026-05-30-self-hosted-central-design.md`](superpowers/specs/2026-05-30-self-hosted-central-design.md)).

## Summary

| Before (Vault) | After (self-hosted) |
|----------------|---------------------|
| `vault-agent` + `LUNA_VAULT_ADDR` | `LUNA_KEY_PATH` encrypted CA key + admin unseal |
| Vault SSH engine signs certs | `luna-proxy` `local-ca` mode signs in-process |
| `VAULT_AGENT_SOCKET` / `LUNA_VAULT_TOKEN` | Removed |

## Migration steps

1. **Export or rotate SSH CA**
   - Read your Vault SSH CA public key: `vault read -field=public_key <mount>/config/ca > luna-ssh-ca.pub`
   - Or generate a new CA and update `TrustedUserCAKeys` on all targets (preferred for clean break).

2. **Encrypt CA private key for luna-proxy**
   - Store CA private key as passphrase-protected OpenSSH PEM at `LUNA_KEY_PATH` (`chmod 400`).
   - Unseal after each proxy restart: `POST /api/v1/admin/unseal` with admin mTLS cert.

3. **Configure proxy**
   - `LUNA_SIGNER_MODE=local-ca`
   - `LUNA_KEY_PATH=/etc/luna/encrypted-ca.key`
   - `LUNA_ADMIN_CLIENT_OU=luna-admin` (must match admin client cert OU)
   - Remove: `VAULT_*`, `LUNA_VAULT_*`, `VAULT_AGENT_SOCKET`

4. **Target sshd**
   - Install CA public key in `/etc/ssh/trusted-user-ca-keys.pem` (unchanged trust model).

5. **Decommission**
   - Stop `vault-agent` on proxy hosts when no longer needed for other secrets.
   - Revoke old Vault SSH mount roles after cutover.

## Historical reference

Prior setup documentation remains in [`docs/setup.md`](setup.md) sections marked Vault-centric; prefer the self-hosted spec for new deployments.
