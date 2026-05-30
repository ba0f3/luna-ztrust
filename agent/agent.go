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

const (
	SignerModeLocalCA  = "local-ca"
	SignerModeLocalKey = "local-key"
)

// AccessProvider obtains SSH credentials from luna-proxy via the SDK.
type AccessProvider interface {
	SignerMode() string
	RequestCertificate(ctx context.Context, req sdk.CertRequest) (*ssh.Certificate, ed25519.PrivateKey, error)
	RequestSignature(ctx context.Context, req sdk.SignatureRequest, signData []byte) (*ssh.Signature, error)
}

// LunaAgent implements the OpenSSH ssh-agent protocol by blocking Sign until credentials are ready.
type LunaAgent struct {
	provider   AccessProvider
	signerMode string
	targetUser string
	targetHost         string
	hostKeyFingerprint string

	mu     sync.Mutex
	locked bool
}

// NewLunaAgent returns an agent that signs via provider using the configured target identity.
func NewLunaAgent(provider AccessProvider, signerMode, targetUser, targetHost, hostKeyFingerprint string) *LunaAgent {
	if signerMode == "" {
		signerMode = SignerModeLocalCA
	}
	return &LunaAgent{
		provider:           provider,
		signerMode:         signerMode,
		targetUser:         targetUser,
		targetHost:         targetHost,
		hostKeyFingerprint: hostKeyFingerprint,
	}
}

// List returns no preloaded keys; credentials are obtained on demand during Sign.
func (a *LunaAgent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.locked {
		return nil, nil
	}
	return []*agent.Key{}, nil
}

// Sign blocks until provider returns credentials, then returns the SSH signature.
func (a *LunaAgent) Sign(pub ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.locked {
		return nil, errors.New("agent locked")
	}

	mode := a.signerMode
	if p := a.provider.SignerMode(); p != "" {
		mode = p
	}

	if mode == SignerModeLocalKey {
		return a.provider.RequestSignature(context.Background(), sdk.SignatureRequest{
			TargetUser:         a.targetUser,
			TargetIP:           a.targetHost,
			HostKeyFingerprint: a.hostKeyFingerprint,
		}, data)
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
