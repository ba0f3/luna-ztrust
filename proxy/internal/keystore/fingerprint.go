package keystore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Fingerprint returns the OpenSSH SHA256 fingerprint for pub: base64(SHA256(pub.Marshal()))
// with trailing '=' removed. This matches `ssh-keygen -lf` (e.g. SHA256:ErTRveOa...).
func Fingerprint(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

// NormalizeFingerprintInput strips an optional SHA256: prefix and base64 padding for lookup.
func NormalizeFingerprintInput(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "SHA256:")
	return strings.TrimRight(s, "=")
}

// ParseFingerprintHint validates and normalizes a fingerprint from CLI or API input.
func ParseFingerprintHint(s string) (string, error) {
	s = NormalizeFingerprintInput(s)
	if s == "" {
		return "", errors.New("empty fingerprint")
	}
	if len(s) == 64 {
		if raw, err := hex.DecodeString(s); err == nil && len(raw) == 32 {
			return fingerprintDigest(raw), nil
		}
	}
	raw, err := decodeFingerprintBase64(s)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid fingerprint")
	}
	return fingerprintDigest(raw), nil
}

func fingerprintDigest(raw []byte) string {
	return base64.RawStdEncoding.EncodeToString(raw)
}

func decodeFingerprintBase64(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(s)
}
