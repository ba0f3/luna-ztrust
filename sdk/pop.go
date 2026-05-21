package sdk

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func challenge(user, ip string, ts int64) []byte {
	return []byte(fmt.Sprintf("%s:%s:%d", user, ip, ts))
}

func SignPoP(pub ssh.PublicKey, priv ed25519.PrivateKey, user, ip string, ts int64) (string, error) {
	msg := challenge(user, ip, ts)
	sig := ed25519.Sign(priv, msg)
	sshSig := &ssh.Signature{Format: pub.Type(), Blob: sig}
	return hex.EncodeToString(sshSig.Blob), nil
}

func VerifyPoP(pub ssh.PublicKey, user, ip string, ts int64, sigHex string) error {
	blob, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}
	sshSig := &ssh.Signature{Format: pub.Type(), Blob: blob}
	return pub.Verify(challenge(user, ip, ts), sshSig)
}
