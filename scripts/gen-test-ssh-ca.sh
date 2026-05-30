#!/usr/bin/env bash
# Generate encrypted SSH signing keys for keystore unseal tests and E2E.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/testdata/ssh"
PASS="test-pass"

mkdir -p "${OUT}"

if ! command -v ssh-keygen >/dev/null 2>&1; then
  echo "ssh-keygen is required" >&2
  exit 1
fi

gen_encrypted() {
  local name="$1"
  local comment="$2"
  local enc="${OUT}/encrypted_${name}.key"
  local pub="${OUT}/${name}.pub"
  local tmp="${OUT}/.${name}.tmp"

  if [[ -f "${enc}" && -f "${pub}" ]]; then
    return 0
  fi

  rm -f "${tmp}" "${tmp}.pub"
  ssh-keygen -t ed25519 -f "${tmp}" -N "${PASS}" -C "${comment}"
  mv "${tmp}" "${enc}"
  mv "${tmp}.pub" "${pub}"
}

gen_encrypted "ca" "luna-test-ssh-ca"
gen_encrypted "host" "luna-test-host-key"

echo "Wrote SSH test keys under ${OUT} (passphrase: ${PASS})"
