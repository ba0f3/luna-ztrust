package vault

import "context"

// AgentTokenProvider reads a Vault API token from vault-agent over a Unix socket.
type AgentTokenProvider struct {
	SocketPath string
	AllowedUID int
}

func (p AgentTokenProvider) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return ReadTokenFromAgent(p.SocketPath, p.AllowedUID)
}
