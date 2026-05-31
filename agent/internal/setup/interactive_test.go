package setup

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunInteractivePrefill(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(ts.Close)

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
			ProxyURL:   ts.URL,
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
	if opts.ProxyURL != ts.URL {
		t.Fatalf("proxy url %q", opts.ProxyURL)
	}
	if opts.TargetUser != "deploy" {
		t.Fatalf("target user %q", opts.TargetUser)
	}
	if !opts.RewriteConfig {
		t.Fatal("expected rewrite config")
	}
	if !strings.Contains(out.String(), "proxy reachable") {
		t.Fatalf("expected early reachability message in output: %s", out.String())
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

func TestPromptProxyURLRetriesOnFailure(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	in := strings.NewReader("https://127.0.0.1:1\ny\n" + ts.URL + "\n")
	var out bytes.Buffer
	p := newPrompter(in, &out)
	got, err := promptProxyURL(p, "https://luna.test:8443")
	if err != nil {
		t.Fatal(err)
	}
	if got != ts.URL {
		t.Fatalf("url = %q", got)
	}
	if !strings.Contains(out.String(), "unreachable") {
		t.Fatalf("expected unreachable message: %s", out.String())
	}
}
