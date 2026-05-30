package agent_test

import (
	"testing"

	"github.com/ba0f3/luna-ztrust/agent"
)

func TestLoadDefaultsAndRequired(t *testing.T) {
	clearAgentEnv(t)

	_, err := agent.Load()
	if err == nil {
		t.Fatal("expected missing required env error")
	}

	t.Setenv("LUNA_PROXY_URL", "https://proxy:8443")
	t.Setenv("LUNA_MTLS_CERT", "client.crt")
	t.Setenv("LUNA_MTLS_KEY", "client.key")
	t.Setenv("LUNA_MTLS_CA", "ca.crt")
	t.Setenv("LUNA_TARGET_USER", "deploy")
	t.Setenv("LUNA_TARGET_HOST", "10.0.0.5")

	cfg, err := agent.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ProxyURL != "https://proxy:8443" {
		t.Fatalf("ProxyURL = %q", cfg.ProxyURL)
	}
	if cfg.SocketPath != "/run/luna/agent.sock" {
		t.Fatalf("SocketPath = %q", cfg.SocketPath)
	}
	if cfg.SignerMode != agent.SignerModeLocalCA {
		t.Fatalf("SignerMode = %q", cfg.SignerMode)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	clearAgentEnv(t)
	t.Setenv("LUNA_PROXY_URL", "https://proxy:8443")
	t.Setenv("LUNA_MTLS_CERT", "client.crt")
	t.Setenv("LUNA_MTLS_KEY", "client.key")
	t.Setenv("LUNA_MTLS_CA", "ca.crt")
	t.Setenv("LUNA_TARGET_USER", "deploy")
	t.Setenv("LUNA_TARGET_HOST", "10.0.0.5")
	t.Setenv("LUNA_AGENT_SOCKET", "/tmp/luna.sock")
	t.Setenv("LUNA_SIGNER_MODE", agent.SignerModeLocalKey)

	cfg, err := agent.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SocketPath != "/tmp/luna.sock" {
		t.Fatalf("SocketPath = %q", cfg.SocketPath)
	}
	if cfg.SignerMode != agent.SignerModeLocalKey {
		t.Fatalf("SignerMode = %q", cfg.SignerMode)
	}
}

func clearAgentEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"LUNA_CONFIG",
		"LUNA_PROXY_URL",
		"LUNA_MTLS_CERT",
		"LUNA_MTLS_KEY",
		"LUNA_MTLS_CA",
		"LUNA_TARGET_USER",
		"LUNA_TARGET_HOST",
		"LUNA_AGENT_SOCKET",
		"LUNA_SIGNER_MODE",
	} {
		t.Setenv(key, "")
	}
}
