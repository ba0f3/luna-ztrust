//go:build !linux

package keystore

import "golang.org/x/crypto/ssh"

func mlockSigner(_ ssh.Signer) {}

func mlockBytes([]byte) {}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
