package keystore

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/ssh"
)

// Fingerprint returns a hex SHA-256 over the OpenSSH authorized-keys wire form of pub.
// This matches ssh-keygen -lf style hashing of the public key blob.
func Fingerprint(pub ssh.PublicKey) string {
	b := ssh.MarshalAuthorizedKey(pub)
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
