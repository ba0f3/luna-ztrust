package agent

import "time"

const (
	defaultSocketPath      = "/run/luna/agent.sock"
	defaultApprovalTimeout = 90 * time.Second
)

// Config holds luna-agent runtime settings.
type Config struct {
	ProxyURL           string
	MTLSCert           string
	MTLSKey            string
	MTLSCA             string
	TargetUser         string
	TargetHost         string
	SocketPath         string
	SignerMode         string
	ApprovalTimeout    time.Duration
	HostKeyFingerprint string
	// HostedPublicKey is an optional path to the host .pub file (or inline authorized_keys line).
	// Used when the proxy capabilities response lists fingerprints without public_key (older proxies).
	HostedPublicKey string
}
