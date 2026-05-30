package keystore

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"

	"golang.org/x/crypto/ssh"
)

// ErrSealed is returned when signing material has not been unsealed.
var ErrSealed = errors.New("keystore sealed")

// Keystore holds decrypted SSH signing material in memory after unseal.
type Keystore struct {
	mu     sync.RWMutex
	signer ssh.Signer
}

// New returns a sealed keystore.
func New() *Keystore {
	return &Keystore{}
}

// Available reports whether a signer has been loaded.
func (k *Keystore) Available() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.signer != nil
}

// SSHSigner returns the loaded signer or ErrSealed.
func (k *Keystore) SSHSigner() (ssh.Signer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.signer == nil {
		return nil, ErrSealed
	}
	return k.signer, nil
}

// Unseal decrypts the key at path with passphrase and loads it into memory.
func (k *Keystore) Unseal(path string, passphrase string) error {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read key file: %w", err)
	}
	mlockBytes(pemBytes)
	defer func() {
		zeroBytes(pemBytes)
		runtime.KeepAlive(pemBytes)
	}()

	pass := []byte(passphrase)
	mlockBytes(pass)
	defer func() {
		zeroBytes(pass)
		runtime.KeepAlive(pass)
	}()

	signer, err := ssh.ParsePrivateKeyWithPassphrase(pemBytes, pass)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}
	mlockSigner(signer)
	k.mu.Lock()
	k.signer = signer
	k.mu.Unlock()
	return nil
}
