package setup

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInteractivePrefill(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath := filepath.Join(dir, "agent.yml")

	in := strings.NewReader(strings.Repeat("\n", 16))
	var out bytes.Buffer
	opts, err := RunInteractive(InteractiveOptions{
		Prefill: Options{
			ProxyURL:   "https://luna.test:8443",
			TargetUser: "deploy",
			TargetHost: "10.0.0.1",
			SignerMode: "local-ca",
			CertsDir:   dir,
			ConfigPath: cfgPath,
		},
		AssumeYes: true,
		In:        in,
		Out:       &out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ProxyURL != "https://luna.test:8443" {
		t.Fatalf("proxy url %q", opts.ProxyURL)
	}
	if opts.TargetUser != "deploy" {
		t.Fatalf("target user %q", opts.TargetUser)
	}
	if !opts.RewriteConfig {
		t.Fatal("expected rewrite config")
	}
}

func TestPrompterAskOptionalStringSkips(t *testing.T) {
	p := newPrompter(strings.NewReader("\n"), io.Discard)
	got, err := p.askOptionalString("Host key fingerprint (optional)", "")
	if err != nil || got != "" {
		t.Fatalf("got %q err=%v", got, err)
	}
}

func TestPrompterAskYesNo(t *testing.T) {
	p := newPrompter(strings.NewReader("y\n"), io.Discard)
	ok, err := p.askYesNo("test", false)
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
}

func TestLoadExistingConfigMissing(t *testing.T) {
	if got := loadExistingConfig("/nonexistent/agent.yml"); got.ProxyURL != "" {
		t.Fatal("expected empty")
	}
}
