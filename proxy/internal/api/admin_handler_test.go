package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/api"
	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
	"golang.org/x/crypto/ssh"
)

func startAdminServer(t *testing.T, cfg config.Config, ks *keystore.Keystore) (*httptest.Server, *mtlsClient, *mtlsClient) {
	t.Helper()
	store := approval.NewStore(60 * time.Second)
	store.SetIssuer(signing.NewLocalCA(ks))
	store.SetLeases(lease.NewStore())
	replay := auth.NewReplayLRU(60*time.Second, 1000)
	handler := api.NewServer(cfg, ks, store, replay, nil)
	serverTLS, adminTLS, autoTLS := loadAdminTLSConfigs(t)
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = serverTLS
	ts.Config.ConnContext = api.ConnContext
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, newMTLSClient(t, ts, adminTLS), newMTLSClient(t, ts, autoTLS)
}

func loadAdminTLSConfigs(t *testing.T) (server, admin, automation *tls.Config) {
	t.Helper()
	server, client := loadTestTLSConfigs(t)
	adminCert, err := tls.LoadX509KeyPair(
		filepath.Join(testCADir(t), "admin-client.crt"),
		filepath.Join(testCADir(t), "admin-client.key"),
	)
	if err != nil {
		t.Skipf("admin client cert missing (run make testdata): %v", err)
	}
	admin = &tls.Config{
		Certificates: []tls.Certificate{adminCert},
		RootCAs:      client.RootCAs,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
	return server, admin, client
}

func writeEncryptedKeyFileAPI(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "luna-test", []byte("test-pass"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o400); err != nil {
		t.Fatal(err)
	}
}

func TestAdmin_UnsealAndSealStatus(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "ca.key")
	writeEncryptedKeyFileAPI(t, keyPath)

	ks := keystore.New()
	cfg := config.Config{AdminClientOU: "luna-admin", KeyPath: keyPath}
	ts, adminClient, _ := startAdminServer(t, cfg, ks)

	body, _ := json.Marshal(map[string]string{"passphrase": "test-pass"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminClient.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unseal %d: %s", resp.StatusCode, b)
	}
	if !ks.Available() {
		t.Fatal("expected unsealed keystore")
	}

	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/seal-status", nil)
	resp2, err := adminClient.http.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	var status struct {
		Sealed bool `json:"sealed"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}
	if status.Sealed {
		t.Fatal("expected sealed=false")
	}
}

func TestAdmin_UnsealRejectsOversizedBody(t *testing.T) {
	ks := keystore.New()
	cfg := config.Config{AdminClientOU: "luna-admin", KeyPath: "/tmp/unused"}
	ts, adminClient, _ := startAdminServer(t, cfg, ks)

	body := []byte(`{"passphrase":"` + strings.Repeat("x", 2048) + `"}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := adminClient.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", resp.StatusCode)
	}
}

func TestAdmin_UnsealForbiddenForAutomationCert(t *testing.T) {
	ks := keystore.New()
	cfg := config.Config{AdminClientOU: "luna-admin", KeyPath: "/tmp/unused"}
	ts, _, autoClient := startAdminServer(t, cfg, ks)

	body, _ := json.Marshal(map[string]string{"passphrase": "x"})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/unseal", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := autoClient.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestSign_SealedReturns503(t *testing.T) {
	cfg := config.Config{Env: "production"}
	ks := keystore.New()
	env := startTestServer(t, cfg, ks)

	conn, err := env.client.shared.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rawBody := buildSignBody(t, "deploy", "10.0.0.1")
	mac, err := auth.ComputeBodyHMAC(conn, rawBody)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, env.ts.URL+"/api/v1/ssh/sign", bytes.NewReader(rawBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Body-Mac", hex.EncodeToString(mac))
	resp, err := env.client.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}
