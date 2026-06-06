package setup_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/agent/internal/setup"
)

func TestFetchCA_RejectsNonPEM(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not a cert"))
	}))
	t.Cleanup(ts.Close)

	_, err := setup.FetchCA(setup.BootstrapOptions{
		ProxyURL:           ts.URL,
		CertsDir:           t.TempDir(),
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Fatal("expected error for non-PEM body")
	}
}

func TestFetchCA_WritesPEM(t *testing.T) {
	var certPEM []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(certPEM)
	}))
	t.Cleanup(ts.Close)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	sum := sha256.Sum256(ts.Certificate().Raw)

	dir := t.TempDir()
	path, err := setup.FetchCA(setup.BootstrapOptions{
		ProxyURL:           ts.URL,
		CertsDir:           dir,
		InsecureSkipVerify: true,
		CAFingerprint:      hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(dir, "ca.crt") {
		t.Fatalf("path = %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestFetchCA_RequiresFingerprintForInsecureFirstContact(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: []byte("invalid")})
	}))
	t.Cleanup(ts.Close)

	_, err := setup.FetchCA(setup.BootstrapOptions{
		ProxyURL:           ts.URL,
		CertsDir:           t.TempDir(),
		InsecureSkipVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint required") {
		t.Fatalf("err = %v, want fingerprint required", err)
	}
}

func TestProbeProxyURL_Healthz(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	if err := setup.ProbeProxyURL(ts.URL, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestProbeProxyURL_ConnectionRefused(t *testing.T) {
	err := setup.ProbeProxyURL("https://127.0.0.1:1", time.Second)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnrollClientCSR_RequiresToken(t *testing.T) {
	dir := t.TempDir()
	_, err := setup.GenerateClientKey(setup.ClientOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	_, err = setup.EnrollClientCSR(setup.BootstrapOptions{
		ProxyURL: "https://example.test",
		CertsDir: dir,
	})
	if err == nil {
		t.Fatal("expected error without token")
	}
}
