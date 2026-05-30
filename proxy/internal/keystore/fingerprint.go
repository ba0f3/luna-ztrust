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
	b64 := base64.StdEncoding.EncodeToString(sum[:])
	return strings.TrimRight(b64, "=")
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
	b64 := base64.StdEncoding.EncodeToString(raw)
	return strings.TrimRight(b64, "=")
}

func decodeFingerprintBase64(s string) ([]byte, error) {
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.StdEncoding.DecodeString(s)
}
