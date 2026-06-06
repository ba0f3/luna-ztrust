package agent

import (
	"fmt"
	"sync"

	"github.com/ba0f3/luna-ztrust/sdk"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

const sessionBindExtension = "session-bind@openssh.com"

// ConnectionAgent isolates OpenSSH session binding to one agent connection.
type ConnectionAgent struct {
	parent  *LunaAgent
	mu      sync.Mutex
	binding sdk.SessionBinding
}

// NewConnectionAgent returns a per-socket-connection agent wrapper.
func NewConnectionAgent(parent *LunaAgent) *ConnectionAgent {
	return &ConnectionAgent{parent: parent}
}

func (a *ConnectionAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType != sessionBindExtension {
		return nil, sshagent.ErrExtensionUnsupported
	}
	var msg struct {
		HostPublicKey []byte
		SessionID     []byte
		Signature     []byte
		Forwarding    bool
	}
	if err := ssh.Unmarshal(contents, &msg); err != nil {
		return nil, fmt.Errorf("invalid session binding: %w", err)
	}
	if msg.Forwarding {
		return nil, fmt.Errorf("forwarded session binding is not allowed")
	}
	hostKey, err := ssh.ParsePublicKey(msg.HostPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid session host key: %w", err)
	}
	var sig ssh.Signature
	if err := ssh.Unmarshal(msg.Signature, &sig); err != nil {
		return nil, fmt.Errorf("invalid session signature: %w", err)
	}
	if err := hostKey.Verify(msg.SessionID, &sig); err != nil {
		return nil, fmt.Errorf("verify session binding: %w", err)
	}
	a.mu.Lock()
	a.binding = sdk.SessionBinding{
		HostPublicKey: append([]byte(nil), msg.HostPublicKey...),
		SessionID:     append([]byte(nil), msg.SessionID...),
		Signature:     append([]byte(nil), msg.Signature...),
	}
	a.mu.Unlock()
	return nil, nil
}

func (a *ConnectionAgent) Sign(pub ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(pub, data, 0)
}

func (a *ConnectionAgent) SignWithFlags(pub ssh.PublicKey, data []byte, _ sshagent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	binding := a.binding
	a.mu.Unlock()
	return a.parent.signWithBinding(pub, data, binding)
}

func (a *ConnectionAgent) List() ([]*sshagent.Key, error) { return a.parent.List() }
func (a *ConnectionAgent) Add(k sshagent.AddedKey) error  { return a.parent.Add(k) }
func (a *ConnectionAgent) Remove(k ssh.PublicKey) error   { return a.parent.Remove(k) }
func (a *ConnectionAgent) RemoveAll() error               { return a.parent.RemoveAll() }
func (a *ConnectionAgent) Lock(p []byte) error            { return a.parent.Lock(p) }
func (a *ConnectionAgent) Unlock(p []byte) error          { return a.parent.Unlock(p) }
func (a *ConnectionAgent) Signers() ([]ssh.Signer, error) { return a.parent.Signers() }

var _ sshagent.ExtendedAgent = (*ConnectionAgent)(nil)
