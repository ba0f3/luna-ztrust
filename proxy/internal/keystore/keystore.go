package keystore

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	maxUnsealAttempts = 5
	unsealCooldown    = 15 * time.Minute
)

// ErrSealed is returned when signing material has not been unsealed.
var ErrSealed = errors.New("keystore sealed")

// ErrUnsealLocked is returned after too many failed unseal attempts.
var ErrUnsealLocked = errors.New("unseal temporarily locked")

// Keystore holds decrypted SSH signing material in memory after unseal.
type Keystore struct {
	mu                sync.RWMutex
	signer            ssh.Signer
	unsealFails       int
	unsealLockedUntil time.Time
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
	k.mu.Lock()
	defer k.mu.Unlock()

	if !k.unsealLockedUntil.IsZero() {
		if time.Now().Before(k.unsealLockedUntil) {
			return ErrUnsealLocked
		}
		k.unsealLockedUntil = time.Time{}
		k.unsealFails = 0
	}

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

	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, pass)
	if err != nil {
		k.recordUnsealFailure()
		return fmt.Errorf("decrypt private key: %w", err)
	}

	var signer ssh.Signer
	switch key := raw.(type) {
	case ed25519.PrivateKey:
		mlockBytes(key)
		defer func() {
			zeroBytes(key)
			runtime.KeepAlive(key)
		}()
		signer, err = ssh.NewSignerFromKey(key)
	default:
		signer, err = ssh.NewSignerFromKey(raw)
	}
	if err != nil {
		k.recordUnsealFailure()
		return fmt.Errorf("load signer: %w", err)
	}
	mlockSigner(signer)

	k.signer = signer
	k.unsealFails = 0
	return nil
}

func (k *Keystore) recordUnsealFailure() {
	k.unsealFails++
	if k.unsealFails >= maxUnsealAttempts {
		k.unsealLockedUntil = time.Now().Add(unsealCooldown)
		k.unsealFails = 0
	}
}
