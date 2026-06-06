package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log"
	"sync"
	"time"

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
	provider           AccessProvider
	signerMode         string
	targetUser         string
	targetHost         string
	hostKeyFingerprint string
	approvalTimeout    time.Duration
	identities         []*agent.Key

	mu     sync.Mutex
	locked bool
}

// NewLunaAgent returns an agent that signs via provider using the configured target identity.
// identities must be non-empty for OpenSSH to use the agent (see ResolveIdentities).
func NewLunaAgent(provider AccessProvider, signerMode, targetUser, targetHost, hostKeyFingerprint string, identities []*agent.Key, approvalTimeout time.Duration) *LunaAgent {
	if signerMode == "" {
		signerMode = SignerModeLocalCA
	}
	if approvalTimeout <= 0 {
		approvalTimeout = defaultApprovalTimeout
	}
	return &LunaAgent{
		provider:           provider,
		signerMode:         signerMode,
		targetUser:         targetUser,
		targetHost:         targetHost,
		hostKeyFingerprint: hostKeyFingerprint,
		approvalTimeout:    approvalTimeout,
		identities:         identities,
	}
}

// List returns identities advertised to OpenSSH for authentication attempts.
func (a *LunaAgent) List() ([]*agent.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.locked {
		return nil, nil
	}
	out := make([]*agent.Key, len(a.identities))
	copy(out, a.identities)
	if DebugEnabled() {
		log.Printf("luna-agent: LIST %d identities", len(out))
	}
	return out, nil
}

// Sign blocks until provider returns credentials, then returns the SSH signature.
func (a *LunaAgent) Sign(pub ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.signWithBinding(pub, data, sdk.SessionBinding{})
}

func (a *LunaAgent) signWithBinding(pub ssh.PublicKey, data []byte, binding sdk.SessionBinding) (*ssh.Signature, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.locked {
		return nil, errors.New("agent locked")
	}

	mode := a.signerMode
	if p := a.provider.SignerMode(); p != "" {
		mode = p
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.approvalTimeout)
	defer cancel()

	if mode == SignerModeLocalKey {
		if len(binding.HostPublicKey) == 0 || len(binding.SessionID) == 0 || len(binding.Signature) == 0 {
			return nil, errors.New("session-bind@openssh.com required for local-key signing")
		}
		fp := a.hostKeyFingerprint
		if pub != nil {
			fp = PublicKeyFingerprint(pub)
		}
		if DebugEnabled() {
			log.Printf("luna-agent: SIGN local-key user=%s host=%s fp=%s", a.targetUser, a.targetHost, fp)
		}
		return a.provider.RequestSignature(ctx, sdk.SignatureRequest{
			TargetUser:         a.targetUser,
			TargetIP:           a.targetHost,
			HostKeyFingerprint: fp,
			SessionBinding:     binding,
			Client:             DefaultClientInfo(),
		}, data)
	}

	if DebugEnabled() {
		log.Printf("luna-agent: SIGN local-ca user=%s host=%s", a.targetUser, a.targetHost)
	}
	cert, priv, err := a.provider.RequestCertificate(ctx, sdk.CertRequest{
		TargetUser: a.targetUser,
		TargetIP:   a.targetHost,
		Client:     DefaultClientInfo(),
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
