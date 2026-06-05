package auth

import (
	"encoding/hex"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func popChallenge(user, ip string, ts int64) []byte {
	// Optimization: avoid fmt.Sprintf overhead and allocations in hot path
	out := make([]byte, 0, len(user)+len(ip)+2+20)
	out = append(out, user...)
	out = append(out, ':')
	out = append(out, ip...)
	out = append(out, ':')
	return strconv.AppendInt(out, ts, 10)
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
