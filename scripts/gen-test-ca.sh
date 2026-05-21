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
  rm -f ca.srl server.csr client.csr
}
trap cleanup EXIT

# CA
if [[ ! -f ca.key ]]; then
  openssl genrsa -out ca.key 4096
fi
if [[ ! -f ca.crt ]]; then
  openssl req -x509 -new -nodes -key ca.key -sha256 -days "${DAYS}" \
    -subj "/CN=Luna Test mTLS CA/O=Luna Z-Trust Test" \
    -out ca.crt
fi

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

echo "Wrote mTLS test material under ${OUT}"
