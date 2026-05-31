package cli

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// CertFingerprint returns the SHA256 digest of cert.Raw, hex-encoded (64 chars).
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}
