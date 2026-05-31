package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func chdirIsolated(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	cfgFile := filepath.Join(dir, "test-proxy.yaml")
	if err := os.WriteFile(cfgFile, []byte("signer_mode: local-ca\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LUNA_CONFIG", cfgFile)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
}

func TestLoadDefaults(t *testing.T) {
	clearProxyEnv(t)
	chdirIsolated(t)
	t.Setenv("LUNA_ENV", "dev")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":8443" {
		t.Fatalf("ListenAddr = %q, want :8443", cfg.ListenAddr)
	}
	if cfg.AdminClientOU != "luna-admin" {
		t.Fatalf("AdminClientOU = %q", cfg.AdminClientOU)
	}
	if cfg.SignerMode != "local-ca" {
		t.Fatalf("SignerMode = %q", cfg.SignerMode)
	}
	if cfg.ApprovalTimeout != 60*time.Second {
		t.Fatalf("ApprovalTimeout = %v", cfg.ApprovalTimeout)
	}
}

func TestLoadEnvOverride(t *testing.T) {
	clearProxyEnv(t)
	chdirIsolated(t)
	t.Setenv("LUNA_ENV", "dev")
	t.Setenv("LUNA_LISTEN_ADDR", ":9443")
	t.Setenv("LUNA_SIGNER_MODE", "local-key")
	t.Setenv("LUNA_APPROVAL_TIMEOUT", "90s")
	t.Setenv("LUNA_ADMIN_CLIENT_OU", "ops-admin")
	t.Setenv("TELEGRAM_BOT_TOKEN", "bot-token")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Env != "dev" {
		t.Fatalf("Env = %q", cfg.Env)
	}
	if cfg.ListenAddr != ":9443" {
		t.Fatalf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.SignerMode != "local-key" {
		t.Fatalf("SignerMode = %q", cfg.SignerMode)
	}
	if cfg.ApprovalTimeout != 90*time.Second {
		t.Fatalf("ApprovalTimeout = %v", cfg.ApprovalTimeout)
	}
	if cfg.AdminClientOU != "ops-admin" {
		t.Fatalf("AdminClientOU = %q", cfg.AdminClientOU)
	}
	if cfg.TelegramBotToken != "bot-token" {
		t.Fatalf("TelegramBotToken = %q", cfg.TelegramBotToken)
	}
}

func TestLoad_CliClientOUDefaults(t *testing.T) {
	clearProxyEnv(t)
	chdirIsolated(t)
	t.Setenv("LUNA_ENV", "dev")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CliClientOU != "luna-cli" {
		t.Fatalf("CliClientOU = %q, want luna-cli", cfg.CliClientOU)
	}
}

func TestLoadInvalidApprovalTimeout(t *testing.T) {
	clearProxyEnv(t)
	chdirIsolated(t)
	t.Setenv("LUNA_APPROVAL_TIMEOUT", "not-a-duration")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for invalid approval_timeout")
	}
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"LUNA_CONFIG",
		"LUNA_ENV",
		"LUNA_LISTEN_ADDR",
		"LUNA_SIGNER_MODE",
		"LUNA_APPROVAL_TIMEOUT",
		"LUNA_ADMIN_CLIENT_OU",
		"LUNA_CLI_CLIENT_OU",
		"LUNA_KEY_PATH",
		"LUNA_MTLS_SERVER_CERT",
		"LUNA_MTLS_SERVER_KEY",
		"LUNA_MTLS_CLIENT_CA",
		"LUNA_MTLS_CA_CERT",
		"LUNA_MTLS_CA_KEY",
		"TELEGRAM_BOT_TOKEN",
		"TELEGRAM_WEBHOOK_SECRET",
		"TELEGRAM_CHAT_ID",
		"FCM_CREDENTIALS",
	} {
		t.Setenv(key, "")
	}
}
