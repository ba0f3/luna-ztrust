package setup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateClientKey(t *testing.T) {
	dir := t.TempDir()
	res, err := GenerateClientKey(ClientOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{res.KeyPath, res.CSRPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("missing %s: %v", p, err)
		}
	}
	if _, err := GenerateClientKey(ClientOptions{Dir: dir}); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
}

func TestWriteAgentConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.yml")
	out, err := WriteAgentConfig(ConfigOptions{
		Path:       path,
		ProxyURL:   "https://luna.test:8443",
		CertsDir:   "/etc/luna/certs",
		TargetUser: "deploy",
		TargetHost: "10.0.0.1",
		SignerMode: "local-ca",
		Force:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != path {
		t.Fatalf("path %q", out)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proxy_url: https://luna.test:8443", "target_host: 10.0.0.1", ProductionAgentSocket} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("missing %q in %s", want, body)
		}
	}
}
