//go:build linux

package keystore

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func mlockSigner(_ ssh.Signer) {}

func mlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = unix.Mlock(b)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
