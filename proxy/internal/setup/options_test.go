package setup_test

import (
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/setup"
)

func TestNormalizeHostname(t *testing.T) {
	got := setup.NormalizeHostname("https://luna.example.com:8443/path")
	if got != "luna.example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestValidateProductionRequiresTelegram(t *testing.T) {
	err := setup.Options{Env: "production", Hostname: "luna.test"}.Validate()
	if err == nil || !strings.Contains(err.Error(), "telegram") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateDevAllowsEmptyTelegram(t *testing.T) {
	if err := (setup.Options{Env: "dev", Hostname: "luna.test"}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWriteProxyConfigFull(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/proxy.yml"
	res, err := setup.WriteProxyConfig(setup.ProxyConfigOptions{
		Path:                  path,
		Force:                 true,
		Env:                   "production",
		Hostname:              "luna.example.com",
		ListenAddr:            ":8443",
		SignerMode:            "local-ca",
		KeyPath:               "/etc/luna/ssh/encrypted_ca.key",
		TelegramBotToken:      "bot123",
		TelegramWebhookSecret: "secret",
		TelegramChatID:        "999",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Path, "proxy.yml") {
		t.Fatal(res)
	}
}
