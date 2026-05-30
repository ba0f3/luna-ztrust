package keystore

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

var ErrAmbiguousSigner = errors.New("host key fingerprint required")

// ResolveHostKeyFingerprint returns a hex fingerprint from wire key and/or hex hint.
func ResolveHostKeyFingerprint(hostPubB64, fpHex string) (string, error) {
	if hostPubB64 != "" {
		raw, err := base64.StdEncoding.DecodeString(hostPubB64)
		if err != nil {
			return "", fmt.Errorf("decode host_public_key: %w", err)
		}
		pub, err := ssh.ParsePublicKey(raw)
		if err != nil {
			return "", fmt.Errorf("parse host_public_key: %w", err)
		}
		fp := Fingerprint(pub)
		if fpHex != "" && fpHex != fp {
			return "", errors.New("host_key_fingerprint does not match host_public_key")
		}
		return fp, nil
	}
	if fpHex != "" {
		if _, err := hex.DecodeString(fpHex); err != nil || len(fpHex) != 64 {
			return "", errors.New("invalid host_key_fingerprint")
		}
		return fpHex, nil
	}
	return "", ErrAmbiguousSigner
}

// SoleFingerprint returns the fingerprint when exactly one signer is loaded.
func (k *Keystore) SoleFingerprint() (string, error) {
	list := k.ListSigners()
	if len(list) != 1 {
		return "", ErrAmbiguousSigner
	}
	return list[0].Fingerprint, nil
}
