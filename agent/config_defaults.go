package agent

import (
	"os"
	"path/filepath"
	"strings"
)

func isDevEnv() bool {
	switch strings.TrimSpace(os.Getenv("LUNA_ENV")) {
	case "dev", "test":
		return true
	default:
		return false
	}
}

func applyAgentDefaults(cfg *Config) {
	if isDevEnv() {
		return
	}
	certsDir := filepath.Join("/etc/luna/certs")
	if cfg.MTLSCert == "" {
		cfg.MTLSCert = filepath.Join(certsDir, "client.crt")
	}
	if cfg.MTLSKey == "" {
		cfg.MTLSKey = filepath.Join(certsDir, "client.key")
	}
	if cfg.MTLSCA == "" {
		cfg.MTLSCA = filepath.Join(certsDir, "ca.crt")
	}
	if cfg.SocketPath == "" || cfg.SocketPath == defaultSocketPath {
		cfg.SocketPath = "/run/luna/agent.sock"
	}
}
