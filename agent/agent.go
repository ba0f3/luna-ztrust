package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/ba0f3/luna-ztrust/sdk"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// CertificateProvider obtains ephemeral SSH certificates from luna-proxy via the SDK.
type CertificateProvider interface {
	RequestCertificate(ctx context.Context, req sdk.CertRequest) (*ssh.Certificate, ed25519.PrivateKey, error)
}

// LunaAgent implements the OpenSSH ssh-agent protocol by blocking Sign until a cert is ready.
type LunaAgent struct {
	provider   CertificateProvider
	targetUser string
	targetHost string

	mu     sync.Mutex
	locked bool
}

// NewLunaAgent returns an agent that signs via provider using the configured target identity.
func NewLunaAgent(provider CertificateProvider, targetUser, targetHost string) *LunaAgent {
	return &LunaAgent{
		provider:   provider,
		targetUser: targetUser,
		targetHost: targetHost,
	}
}

// List returns no preloaded keys; certificates are obtained on demand during Sign.
func (a *LunaAgent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.locked {
		return nil, nil
	}
	return []*agent.Key{}, nil
}

// Sign blocks until provider returns a certificate, then signs data with the cert-backed signer.
func (a *LunaAgent) Sign(_ ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.locked {
		return nil, errors.New("agent locked")
	}

	cert, priv, err := a.provider.RequestCertificate(context.Background(), sdk.CertRequest{
		TargetUser: a.targetUser,
		TargetIP:   a.targetHost,
	})
	if err != nil {
		return nil, err
	}

	signer, err := sdk.NewCertSigner(cert, priv)
	if err != nil {
		return nil, err
	}
	return signer.Sign(rand.Reader, data)
}

func (a *LunaAgent) Add(_ agent.AddedKey) error { return nil }

func (a *LunaAgent) Remove(_ ssh.PublicKey) error { return nil }

func (a *LunaAgent) RemoveAll() error { return nil }

func (a *LunaAgent) Lock(_ []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.locked = true
	return nil
}

func (a *LunaAgent) Unlock(_ []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.locked = false
	return nil
}

func (a *LunaAgent) Signers() ([]ssh.Signer, error) { return nil, nil }
