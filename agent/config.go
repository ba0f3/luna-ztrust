package agent

const defaultSocketPath = "/run/luna/agent.sock"

// Config holds luna-agent runtime settings.
type Config struct {
	ProxyURL   string
	MTLSCert   string
	MTLSKey    string
	MTLSCA     string
	TargetUser string
	TargetHost string
	SocketPath string
	SignerMode string
}
