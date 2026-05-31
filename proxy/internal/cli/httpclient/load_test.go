package httpclient_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli/httpclient"
)

func testCADir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "..", "testdata", "ca")
}

func TestLoad_Success(t *testing.T) {
	dir := testCADir(t)
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("append ca")
	}
	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	const wantFP = "deadbeef"
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/keys/load" {
			http.NotFound(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		var req struct {
			EncryptedPEM string `json:"encrypted_pem"`
			Passphrase   string `json:"passphrase"`
			Label        string `json:"label"`
		}
		if err := json.Unmarshal(raw, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if req.EncryptedPEM == "" || req.Passphrase != "secret" || req.Label != "host-a" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"fingerprint": wantFP})
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	pemPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(pemPath, []byte("encrypted-pem-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	proxyURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	fp, err := httpclient.Load(context.Background(), httpclient.Config{
		ProxyURL: proxyURL,
		CliCert:  filepath.Join(dir, "client.crt"),
		CliKey:   filepath.Join(dir, "client.key"),
		CA:       filepath.Join(dir, "ca.crt"),
	}, pemPath, []byte("secret"), "host-a")
	if err != nil {
		t.Fatal(err)
	}
	if fp != wantFP {
		t.Fatalf("fingerprint = %q, want %q", fp, wantFP)
	}
}

func TestLoad_MissingCert(t *testing.T) {
	pemPath := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(pemPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := httpclient.Load(context.Background(), httpclient.Config{
		ProxyURL: "https://example.test",
		CliCert:  "/nonexistent/cli.crt",
		CliKey:   "/nonexistent/cli.key",
		CA:       "/nonexistent/ca.crt",
	}, pemPath, []byte("p"), "label")
	if err == nil {
		t.Fatal("expected error")
	}
}
