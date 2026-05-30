package agent

import (
	"fmt"
	"os"
	"strings"
)

const defaultSocketPath = "/run/luna/agent.sock"

// Config holds luna-agent runtime settings loaded from the environment.
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

// LoadFromEnv reads agent configuration from process environment variables.
func LoadFromEnv() (Config, error) {
	cfg := Config{
		ProxyURL:   strings.TrimSpace(os.Getenv("LUNA_PROXY_URL")),
		MTLSCert:   strings.TrimSpace(os.Getenv("LUNA_MTLS_CERT")),
		MTLSKey:    strings.TrimSpace(os.Getenv("LUNA_MTLS_KEY")),
		MTLSCA:     strings.TrimSpace(os.Getenv("LUNA_MTLS_CA")),
		TargetUser: strings.TrimSpace(os.Getenv("LUNA_TARGET_USER")),
		TargetHost: strings.TrimSpace(os.Getenv("LUNA_TARGET_HOST")),
		SocketPath: strings.TrimSpace(os.Getenv("LUNA_AGENT_SOCKET")),
		SignerMode: strings.TrimSpace(os.Getenv("LUNA_SIGNER_MODE")),
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = defaultSocketPath
	}

	var missing []string
	if cfg.ProxyURL == "" {
		missing = append(missing, "LUNA_PROXY_URL")
	}
	if cfg.MTLSCert == "" {
		missing = append(missing, "LUNA_MTLS_CERT")
	}
	if cfg.MTLSKey == "" {
		missing = append(missing, "LUNA_MTLS_KEY")
	}
	if cfg.MTLSCA == "" {
		missing = append(missing, "LUNA_MTLS_CA")
	}
	if cfg.TargetUser == "" {
		missing = append(missing, "LUNA_TARGET_USER")
	}
	if cfg.TargetHost == "" {
		missing = append(missing, "LUNA_TARGET_HOST")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}
