package setup_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/setup"
)

func TestGenerateEnrollToken(t *testing.T) {
	a, err := setup.GenerateEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := setup.GenerateEnrollToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 64 || len(b) != 64 {
		t.Fatalf("token lengths %d %d", len(a), len(b))
	}
	if a == b {
		t.Fatal("expected unique tokens")
	}
}

func TestWriteProxyConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.yml")
	res, err := setup.WriteProxyConfig(setup.ProxyConfigOptions{
		Path:  path,
		Force: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.EnrollToken == "" {
		t.Fatal("empty token")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	if !strings.Contains(s, `mtls_enroll_token: "`+res.EnrollToken+`"`) {
		t.Fatalf("missing token in config: %s", s)
	}
	if !strings.Contains(s, `listen_addr: ":8443"`) {
		t.Fatalf("missing listen_addr: %s", s)
	}
}

func TestWriteProxyConfigErrExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.yml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := setup.WriteProxyConfig(setup.ProxyConfigOptions{Path: path})
	if !errors.Is(err, setup.ErrConfigExists) {
		t.Fatalf("err = %v", err)
	}
}
