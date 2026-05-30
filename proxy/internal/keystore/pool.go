package keystore

import (
	"errors"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	ErrNoSuchSigner = errors.New("no such signer in pool")
	ErrPoolEmpty    = errors.New("signer pool empty")
)

// SignerInfo describes a loaded host key (public metadata only).
type SignerInfo struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

type loadedSigner struct {
	signer  ssh.Signer
	comment string
}

// LocalKeyPool holds multiple host signers keyed by fingerprint.
type LocalKeyPool struct {
	mu      sync.RWMutex
	signers map[string]loadedSigner
}

// NewLocalKeyPool returns an empty pool.
func NewLocalKeyPool() *LocalKeyPool {
	return &LocalKeyPool{signers: make(map[string]loadedSigner)}
}

// Add inserts a signer and returns its fingerprint.
func (p *LocalKeyPool) Add(signer ssh.Signer, comment string) (string, error) {
	if signer == nil {
		return "", errors.New("nil signer")
	}
	fp := Fingerprint(signer.PublicKey())
	p.mu.Lock()
	p.signers[fp] = loadedSigner{signer: signer, comment: comment}
	p.mu.Unlock()
	return fp, nil
}

// Remove deletes a signer by fingerprint.
func (p *LocalKeyPool) Remove(fingerprint string) error {
	fingerprint = NormalizeFingerprintInput(fingerprint)
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.signers[fingerprint]; !ok {
		return ErrNoSuchSigner
	}
	delete(p.signers, fingerprint)
	return nil
}

// Get returns a signer by fingerprint.
func (p *LocalKeyPool) Get(fingerprint string) (ssh.Signer, error) {
	fingerprint = NormalizeFingerprintInput(fingerprint)
	p.mu.RLock()
	defer p.mu.RUnlock()
	entry, ok := p.signers[fingerprint]
	if !ok {
		if len(p.signers) == 0 {
			return nil, ErrPoolEmpty
		}
		return nil, ErrNoSuchSigner
	}
	return entry.signer, nil
}

// List returns metadata for all loaded signers.
func (p *LocalKeyPool) List() []SignerInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]SignerInfo, 0, len(p.signers))
	for fp, entry := range p.signers {
		out = append(out, SignerInfo{
			Fingerprint: fp,
			PublicKey:   string(ssh.MarshalAuthorizedKey(entry.signer.PublicKey())),
			Comment:     entry.comment,
		})
	}
	return out
}

// Available reports whether the pool has at least one signer.
func (p *LocalKeyPool) Available() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.signers) > 0
}

// Len returns the number of loaded signers.
func (p *LocalKeyPool) Len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.signers)
}
