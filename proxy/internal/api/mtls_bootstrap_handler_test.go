package api_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func generateAutomationCSR(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Luna Automation Client",
			Organization: []string{"Luna Z-Trust"},
		},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func testCAConfig(t *testing.T, enrollToken string) config.Config {
	t.Helper()
	dir := testCADir(t)
	return config.Config{
		MTLSClientCA:    filepath.Join(dir, "ca.crt"),
		MTLSCACertPath:  filepath.Join(dir, "ca.crt"),
		MTLSCAKeyPath:   filepath.Join(dir, "ca.key"),
		MTLSEnrollToken: enrollToken,
	}
}

func bootstrapHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	_, clientTLS := loadTestTLSConfigs(t)
	clientTLS.Certificates = nil
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: clientTLS},
		Timeout:   10 * time.Second,
	}
}

func TestMTLSCA_NoClientCertRequired(t *testing.T) {
	env := startTestServer(t, testCAConfig(t, "secret"), nil)
	client := bootstrapHTTPClient(t)

	resp, err := client.Get(env.ts.URL + "/api/v1/mtls/ca")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := make([]byte, 4096)
	n, _ := resp.Body.Read(body)
	if !bytes.Contains(body[:n], []byte("BEGIN CERTIFICATE")) {
		t.Fatal("expected PEM certificate")
	}
}

func TestMTLSEnroll_SignsAutomationCSR(t *testing.T) {
	const token = "enroll-test-token"
	env := startTestServer(t, testCAConfig(t, token), nil)
	client := bootstrapHTTPClient(t)

	csrPEM := generateAutomationCSR(t)
	body, _ := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	req, err := http.NewRequest(http.MethodPost, env.ts.URL+"/api/v1/mtls/enroll", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Enroll-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(out.CertificatePEM), []byte("BEGIN CERTIFICATE")) {
		t.Fatal("expected certificate_pem")
	}
}

func TestMTLSEnroll_RequiresToken(t *testing.T) {
	env := startTestServer(t, testCAConfig(t, "secret"), nil)
	client := bootstrapHTTPClient(t)

	csrPEM := generateAutomationCSR(t)
	body, _ := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	req, err := http.NewRequest(http.MethodPost, env.ts.URL+"/api/v1/mtls/enroll", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestMTLSEnroll_DisabledWithoutTokenConfig(t *testing.T) {
	env := startTestServer(t, testCAConfig(t, ""), nil)
	client := bootstrapHTTPClient(t)

	body := []byte(`{"csr_pem":"x"}`)
	req, err := http.NewRequest(http.MethodPost, env.ts.URL+"/api/v1/mtls/enroll", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Enroll-Token", "any")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMTLSCA_FileMissing(t *testing.T) {
	cfg := testCAConfig(t, "")
	cfg.MTLSClientCA = filepath.Join(t.TempDir(), "missing.crt")
	cfg.MTLSCACertPath = cfg.MTLSClientCA
	env := startTestServer(t, cfg, nil)
	client := bootstrapHTTPClient(t)

	resp, err := client.Get(env.ts.URL + "/api/v1/mtls/ca")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	_ = os.ErrNotExist
}
