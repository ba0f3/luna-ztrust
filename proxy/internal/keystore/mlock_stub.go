//go:build !linux

package keystore

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

func mlockSigner(_ ssh.Signer) error {
	return fmt.Errorf("memory locking is unsupported on this platform")
}

func mlockBytes([]byte) error { return fmt.Errorf("memory locking is unsupported on this platform") }

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
