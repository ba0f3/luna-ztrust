package setup

import (
	lunaagent "github.com/ba0f3/luna-ztrust/agent"
)

const (
	// DefaultCertsDir matches luna-proxy setup mtls output layout.
	DefaultCertsDir = "/etc/luna/certs"
	// DefaultConfigPath is the conventional agent.yml location.
	DefaultConfigPath = "/etc/luna/agent.yml"
	// ProductionAgentSocket is used with systemd RuntimeDirectory=luna (root or luna service user).
	ProductionAgentSocket = "/run/luna/agent.sock"
)

// DefaultAgentSocket returns the socket path for the current user (see agent.ResolveSocketPath).
func DefaultAgentSocket() string {
	return lunaagent.ResolveSocketPath(ProductionAgentSocket)
}
