package auth

import (
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func popChallenge(user, ip string, ts int64) []byte {
	return []byte(fmt.Sprintf("%s:%s:%d", user, ip, ts))
}

// VerifyPoP checks the hex-encoded SSH signature over target_user:target_ip:timestamp.
func VerifyPoP(pub ssh.PublicKey, user, ip string, ts int64, sigHex string) error {
	blob, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}
	sshSig := &ssh.Signature{Format: pub.Type(), Blob: blob}
	return pub.Verify(popChallenge(user, ip, ts), sshSig)
}
