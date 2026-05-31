package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

func generateCLIEnrollCSR(t *testing.T, ou string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{ou},
			CommonName:         "Luna CLI Test",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}

func TestCLIEnroll_IssuesCert(t *testing.T) {
	dir := testCADir(t)
	cfg := config.Config{
		AdminClientOU:  "luna-admin",
		CliClientOU:    "luna-cli",
		MTLSCACertPath: filepath.Join(dir, "ca.crt"),
		MTLSCAKeyPath:  filepath.Join(dir, "ca.key"),
	}
	env := startTestServer(t, cfg, nil)
	_, adminTLS, _ := loadAdminTLSConfigs(t)
	admin := newMTLSClient(t, env.ts, adminTLS)

	enrollBody, _ := json.Marshal(map[string]string{
		"label":   "test-laptop",
		"csr_pem": generateCLIEnrollCSR(t, "luna-cli"),
	})
	resp, err := admin.http.Post(env.ts.URL+"/api/v1/cli/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		DeviceID       string `json:"device_id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.DeviceID == "" || out.CertificatePEM == "" {
		t.Fatalf("missing fields: %+v", out)
	}
	block, _ := pem.Decode([]byte(out.CertificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE PEM in response")
	}
}

func generateCLIKeyAndCSR(t *testing.T, ou string) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			OrganizationalUnit: []string{ou},
			CommonName:         "Luna CLI Test",
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return key, csrPEM
}

func cliTestServerConfig(t *testing.T) config.Config {
	t.Helper()
	dir := testCADir(t)
	return config.Config{
		AdminClientOU:   "luna-admin",
		CliClientOU:     "luna-cli",
		MTLSCACertPath:  filepath.Join(dir, "ca.crt"),
		MTLSCAKeyPath:   filepath.Join(dir, "ca.key"),
		ApprovalTimeout: 60 * time.Second,
		SignerMode:      approval.SignerModeLocalKey,
	}
}

func enrollCLIDevice(t *testing.T, env *testEnv, cfg config.Config) (*mtlsClient, string) {
	t.Helper()
	_, adminTLS, _ := loadAdminTLSConfigs(t)
	admin := newMTLSClient(t, env.ts, adminTLS)

	key, csrPEM := generateCLIKeyAndCSR(t, cfg.CliClientOU)
	enrollBody, _ := json.Marshal(map[string]string{
		"label":   "load-test-laptop",
		"csr_pem": csrPEM,
	})
	resp, err := admin.http.Post(env.ts.URL+"/api/v1/cli/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		DeviceID       string `json:"device_id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	cliTLS := tlsConfigFromCertPEM(t, out.CertificatePEM, key)
	return newMTLSClient(t, env.ts, cliTLS), out.DeviceID
}

func tlsConfigFromCertPEM(t *testing.T, certPEM string, key *rsa.PrivateKey) *tls.Config {
	t.Helper()
	_, baseClient := loadTestTLSConfigs(t)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsCert, err := tls.X509KeyPair([]byte(certPEM), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg := baseClient.Clone()
	cfg.Certificates = []tls.Certificate{tlsCert}
	return cfg
}

func makeEncryptedHostPEM(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "ssh", "encrypted_host.key")
	if pemBytes, err := os.ReadFile(path); err == nil {
		return pemBytes
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(key, "luna-host", []byte("test-pass"))
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func postCLIKeysLoad(t *testing.T, cli *mtlsClient, baseURL string, pemBytes []byte, label string) *http.Response {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"encrypted_pem": base64.StdEncoding.EncodeToString(pemBytes),
		"passphrase":    "test-pass",
		"label":         label,
		"timestamp":     time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := cli.shared.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auth.ComputeBodyHMAC(conn, body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/cli/keys/load", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Body-Mac", hex.EncodeToString(mac))
	resp, err := cli.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestCLIKeysLoad_AddsToPool(t *testing.T) {
	cfg := cliTestServerConfig(t)
	env := startTestServerLocalKeyWithConfig(t, cfg)
	cliClient, _ := enrollCLIDevice(t, env, cfg)
	pemBytes := makeEncryptedHostPEM(t)

	resp := postCLIKeysLoad(t, cliClient, env.ts.URL, pemBytes, "deploy-host")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("load status %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Fingerprint == "" {
		t.Fatal("missing fingerprint")
	}
	found := false
	for _, s := range env.ks.ListSigners() {
		if strings.EqualFold(s.Fingerprint, out.Fingerprint) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("pool missing fingerprint %q, have %+v", out.Fingerprint, env.ks.ListSigners())
	}
}

func TestCLIKeysLoad_RejectsAdminCert(t *testing.T) {
	cfg := cliTestServerConfig(t)
	env := startTestServerLocalKeyWithConfig(t, cfg)
	_, adminTLS, _ := loadAdminTLSConfigs(t)
	admin := newMTLSClient(t, env.ts, adminTLS)

	resp := postCLIKeysLoad(t, admin, env.ts.URL, makeEncryptedHostPEM(t), "admin-attempt")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 403: %s", resp.StatusCode, b)
	}
}

func TestCLIKeysLoad_RejectsLocalCA(t *testing.T) {
	cfg := cliTestServerConfig(t)
	cfg.SignerMode = approval.SignerModeLocalCA
	env := startTestServer(t, cfg, nil)
	cliClient, _ := enrollCLIDevice(t, env, cfg)

	resp := postCLIKeysLoad(t, cliClient, env.ts.URL, makeEncryptedHostPEM(t), "ca-mode")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 400: %s", resp.StatusCode, b)
	}
}

func TestCLIKeysLoad_UnknownDevice(t *testing.T) {
	cfg := cliTestServerConfig(t)
	env := startTestServerLocalKeyWithConfig(t, cfg)

	key, csrPEM := generateCLIKeyAndCSR(t, cfg.CliClientOU)
	signer, err := cli.NewCSRSignerFromConfig(cfg)
	if err != nil || signer == nil {
		t.Fatalf("CSR signer: %v", err)
	}
	certPEM, _, err := signer.Sign([]byte(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	cliTLS := tlsConfigFromCertPEM(t, string(certPEM), key)
	cliClient := newMTLSClient(t, env.ts, cliTLS)

	resp := postCLIKeysLoad(t, cliClient, env.ts.URL, makeEncryptedHostPEM(t), "unknown")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status %d, want 403: %s", resp.StatusCode, b)
	}
}

func startTestServerLocalKeyWithConfig(t *testing.T, cfg config.Config) *testEnv {
	t.Helper()
	ks := keystore.NewWithMode(keystore.ModeLocalKey)
	unsealTestKeystore(t, ks)
	env := startTestServer(t, cfg, ks)
	return env
}
