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

// Mode selects CA single-slot vs local-key pool behavior.
type Mode int

const (
	ModeLocalCA Mode = iota
	ModeLocalKey
)

// ErrSealed is returned when signing material has not been unsealed.
var ErrSealed = errors.New("keystore sealed")

// ErrUnsealLocked is returned after too many failed unseal attempts.
var ErrUnsealLocked = errors.New("unseal temporarily locked")

// Keystore holds decrypted SSH signing material in memory after load.
type Keystore struct {
	mode Mode

	mu                sync.RWMutex
	caSigner          ssh.Signer
	pool              *LocalKeyPool
	unsealFails       int
	unsealLockedUntil time.Time
}

// New returns a sealed keystore in local-ca mode (backward compatible).
func New() *Keystore {
	return NewWithMode(ModeLocalCA)
}

// NewWithMode returns a sealed keystore for the given signing mode.
func NewWithMode(mode Mode) *Keystore {
	ks := &Keystore{mode: mode}
	if mode == ModeLocalKey {
		ks.pool = NewLocalKeyPool()
	}
	return ks
}

// Mode returns the keystore operating mode.
func (k *Keystore) Mode() Mode {
	return k.mode
}

// Available reports whether signing material is loaded for the active mode.
func (k *Keystore) Available() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	switch k.mode {
	case ModeLocalKey:
		return k.pool != nil && k.pool.Available()
	default:
		return k.caSigner != nil
	}
}

// SSHSigner returns the CA signer (local-ca mode only).
func (k *Keystore) SSHSigner() (ssh.Signer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.mode == ModeLocalKey {
		return nil, fmt.Errorf("SSHSigner: %w (use SignerForFingerprint)", ErrSealed)
	}
	if k.caSigner == nil {
		return nil, ErrSealed
	}
	return k.caSigner, nil
}

// SignerForFingerprint returns a host signer from the pool (local-key mode).
func (k *Keystore) SignerForFingerprint(fingerprint string) (ssh.Signer, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.mode != ModeLocalKey || k.pool == nil {
		return nil, fmt.Errorf("SignerForFingerprint: %w", ErrSealed)
	}
	signer, err := k.pool.Get(fingerprint)
	if err != nil {
		if errors.Is(err, ErrPoolEmpty) || errors.Is(err, ErrNoSuchSigner) {
			return nil, ErrSealed
		}
		return nil, err
	}
	return signer, nil
}

// ListSigners returns loaded signer metadata (local-key pool or single CA entry).
func (k *Keystore) ListSigners() []SignerInfo {
	k.mu.RLock()
	defer k.mu.RUnlock()
	switch k.mode {
	case ModeLocalKey:
		if k.pool == nil {
			return nil
		}
		return k.pool.List()
	default:
		if k.caSigner == nil {
			return nil
		}
		pub := k.caSigner.PublicKey()
		return []SignerInfo{{
			Fingerprint: Fingerprint(pub),
			PublicKey:   string(ssh.MarshalAuthorizedKey(pub)),
			Comment:     "ca",
		}}
	}
}

// Unseal decrypts the key at path and loads it (CA replace or pool add per mode).
func (k *Keystore) Unseal(path string, passphrase string) error {
	_, err := k.LoadPEMFile(path, passphrase, "")
	return err
}

// LoadPEMFile reads an encrypted PEM from path and loads the signer.
func (k *Keystore) LoadPEMFile(path string, passphrase string, comment string) (fingerprint string, err error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read key file: %w", err)
	}
	return k.LoadPEMBytes(pemBytes, passphrase, comment)
}

// LoadPEMBytes decrypts encrypted PEM bytes and loads the signer.
func (k *Keystore) LoadPEMBytes(pemBytes []byte, passphrase string, comment string) (fingerprint string, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if err := k.checkUnsealLock(); err != nil {
		return "", err
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

	signer, err := parseEncryptedPEM(pemBytes, pass)
	if err != nil {
		k.recordUnsealFailure()
		return "", err
	}
	mlockSigner(signer)
	fp := Fingerprint(signer.PublicKey())

	switch k.mode {
	case ModeLocalKey:
		if k.pool == nil {
			k.pool = NewLocalKeyPool()
		}
		if _, err := k.pool.Add(signer, comment); err != nil {
			return "", err
		}
	default:
		k.caSigner = signer
	}
	k.unsealFails = 0
	return fp, nil
}

// RemoveSigner removes a signer by fingerprint (local-key) or clears CA.
func (k *Keystore) RemoveSigner(fingerprint string) error {
	fingerprint = NormalizeFingerprintInput(fingerprint)
	k.mu.Lock()
	defer k.mu.Unlock()
	switch k.mode {
	case ModeLocalKey:
		if k.pool == nil {
			return ErrNoSuchSigner
		}
		return k.pool.Remove(fingerprint)
	default:
		if k.caSigner == nil {
			return ErrNoSuchSigner
		}
		if fingerprint != "" && Fingerprint(k.caSigner.PublicKey()) != fingerprint {
			return ErrNoSuchSigner
		}
		k.caSigner = nil
		return nil
	}
}

func (k *Keystore) checkUnsealLock() error {
	if !k.unsealLockedUntil.IsZero() {
		if time.Now().Before(k.unsealLockedUntil) {
			return ErrUnsealLocked
		}
		k.unsealLockedUntil = time.Time{}
		k.unsealFails = 0
	}
	return nil
}

func parseEncryptedPEM(pemBytes, pass []byte) (ssh.Signer, error) {
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, pass)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
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
		return nil, fmt.Errorf("load signer: %w", err)
	}
	return signer, nil
}

func (k *Keystore) recordUnsealFailure() {
	k.unsealFails++
	if k.unsealFails >= maxUnsealAttempts {
		k.unsealLockedUntil = time.Now().Add(unsealCooldown)
		k.unsealFails = 0
	}
}
