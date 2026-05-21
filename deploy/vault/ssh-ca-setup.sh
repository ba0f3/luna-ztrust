#!/usr/bin/env sh
# Configure Vault dev SSH secrets engine for luna-proxy E2E (mount: ssh-agent-signer).
set -eu

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-root}"
export VAULT_ADDR VAULT_TOKEN

echo "Waiting for Vault at ${VAULT_ADDR}..."
i=0
while [ "$i" -lt 60 ]; do
	if vault status >/dev/null 2>&1; then
		break
	fi
	i=$((i + 1))
	sleep 1
done

if ! vault status >/dev/null 2>&1; then
	echo "Vault not reachable after 60s" >&2
	exit 1
fi

echo "Enabling SSH secrets engine at ssh-agent-signer..."
vault secrets enable -path=ssh-agent-signer ssh 2>/dev/null || true

echo "Generating SSH CA signing key..."
if ! vault read -field=public_key ssh-agent-signer/config/ca >/dev/null 2>&1; then
	vault write ssh-agent-signer/config/ca generate_signing_key=true
fi

echo "Writing agent-role..."
vault write ssh-agent-signer/roles/agent-role \
	key_type=ca \
	allow_user_certificates=true \
	allowed_users='*' \
	allowed_critical_options=source-address \
	ttl=5m

echo "Vault SSH CA ready (ssh-agent-signer/sign/agent-role)"
