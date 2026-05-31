package setup

const (
	// DefaultCertsDir matches luna-proxy setup mtls output layout.
	DefaultCertsDir = "/etc/luna/certs"
	// DefaultConfigPath is the conventional agent.yml location.
	DefaultConfigPath = "/etc/luna/agent.yml"
	// ProductionAgentSocket matches systemd RuntimeDirectory=luna.
	ProductionAgentSocket = "/run/luna/agent.sock"
)
