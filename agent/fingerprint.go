package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/ssh"
)

// PublicKeyFingerprint matches proxy keystore fingerprint (SHA256 of ssh wire encoding).
func PublicKeyFingerprint(pub ssh.PublicKey) string {
	sum := sha256.Sum256(pub.Marshal())
	// ⚡ Bolt: Use RawStdEncoding to generate unpadded string directly instead of StdEncoding + TrimRight
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func normalizeFingerprintHint(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "SHA256:")
	return strings.TrimRight(s, "=")
}
