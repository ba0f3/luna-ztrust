//go:build !linux

package keystore

func mlockSigner(_ ssh.Signer) {}

func mlockBytes([]byte) {}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
