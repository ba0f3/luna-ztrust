#!/usr/bin/env bash
# Generate test mTLS CA and leaf certificates for local development and CI.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/testdata/ca"
DAYS=3650

mkdir -p "${OUT}"
cd "${OUT}"

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required" >&2
  exit 1
fi

cleanup() {
  rm -f ca.srl server.csr client.csr admin-client.csr
}
trap cleanup EXIT

ca_key_matches_cert() {
  [[ -f ca.key && -f ca.crt ]] || return 1
  local cert_mod key_mod
  cert_mod="$(openssl x509 -noout -modulus -in ca.crt 2>/dev/null)" || return 1
  key_mod="$(openssl rsa -noout -modulus -in ca.key 2>/dev/null)" || return 1
  [[ "${cert_mod}" == "${key_mod}" ]]
}

wipe_ca_material() {
  rm -f \
    ca.key ca.crt ca.srl \
    server.key server.crt server.csr \
    client.key client.crt client.csr \
    admin-client.key admin-client.crt admin-client.csr
}

ensure_ca() {
  if ca_key_matches_cert; then
    return 0
  fi
  echo "Regenerating mTLS CA (missing or mismatched ca.key / ca.crt)" >&2
  wipe_ca_material
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -nodes -key ca.key -sha256 -days "${DAYS}" \
    -subj "/CN=Luna Test mTLS CA/O=Luna Z-Trust Test" \
    -out ca.crt
}

ensure_ca

# Server (SAN DNS:localhost, serverAuth)
if [[ ! -f server.key ]]; then
  openssl genrsa -out server.key 2048
fi
openssl req -new -key server.key -sha256 \
  -subj "/CN=localhost/O=Luna Z-Trust Test" \
  -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days "${DAYS}" -sha256 \
  -extfile <(printf '%s\n' \
    'basicConstraints=CA:FALSE' \
    'keyUsage=digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:localhost')

# Client (clientAuth EKU)
if [[ ! -f client.key ]]; then
  openssl genrsa -out client.key 2048
fi
openssl req -new -key client.key -sha256 \
  -subj "/CN=Luna Test Client/O=Luna Z-Trust Test" \
  -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days "${DAYS}" -sha256 \
  -extfile <(printf '%s\n' \
    'basicConstraints=CA:FALSE' \
    'keyUsage=digitalSignature' \
    'extendedKeyUsage=clientAuth')

# Admin client (OU=luna-admin for /api/v1/admin/*)
if [[ ! -f admin-client.key ]]; then
  openssl genrsa -out admin-client.key 2048
fi
openssl req -new -key admin-client.key -sha256 \
  -subj "/CN=Luna Test Admin/OU=luna-admin/O=Luna Z-Trust Test" \
  -out admin-client.csr
openssl x509 -req -in admin-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out admin-client.crt -days "${DAYS}" -sha256 \
  -extfile <(printf '%s\n' \
    'basicConstraints=CA:FALSE' \
    'keyUsage=digitalSignature' \
    'extendedKeyUsage=clientAuth')

echo "Wrote mTLS test material under ${OUT}"
