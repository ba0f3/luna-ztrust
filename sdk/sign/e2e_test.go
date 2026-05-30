//go:build e2e

package sign_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/sdk"
	"github.com/ba0f3/luna-ztrust/sdk/sign"
	"golang.org/x/crypto/ssh"
)

const e2eKeyPassphrase = "test-pass"

func TestE2ERequestCertificate(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker not available")
	}
	if !e2eProxyReady(t) {
		t.Skip("e2e proxy not reachable (run: make e2e-up)")
	}

	caDir := e2eCADir(t)
	cert, pool, err := sdk.LoadTLSConfig(
		filepath.Join(caDir, "client.crt"),
		filepath.Join(caDir, "client.key"),
		filepath.Join(caDir, "ca.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}

	adminCert, _, err := sdk.LoadTLSConfig(
		filepath.Join(caDir, "admin-client.crt"),
		filepath.Join(caDir, "admin-client.key"),
		filepath.Join(caDir, "ca.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}

	proxyURL := os.Getenv("LUNA_PROXY_URL")
	if proxyURL == "" {
		proxyURL = "https://localhost:8443"
	}

	e2eUnseal(t, proxyURL, adminCert, pool)

	client, err := sign.NewClient(sign.Config{
		ProxyURL:   proxyURL,
		TLSCert:    cert,
		TLSRootCAs: pool,
		Timeout:    90 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	got, priv, err := client.RequestCertificate(ctx, sign.CertRequest{
		TargetUser: "deploy",
		TargetIP:   "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("RequestCertificate: %v", err)
	}
	if got == nil || len(priv) == 0 {
		t.Fatal("expected certificate and private key")
	}
	if got.Key.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("cert key type = %q", got.Key.Type())
	}
	if got.CertType != ssh.UserCert {
		t.Fatalf("cert type = %d, want user cert", got.CertType)
	}
}

func dockerAvailable() bool {
	cmd := exec.Command("docker", "info")
	cmd.Stdout = nil
	cmd.Stderr = nil
	return cmd.Run() == nil
}

func e2eProxyReady(t *testing.T) bool {
	t.Helper()
	proxyURL := os.Getenv("LUNA_PROXY_URL")
	if proxyURL == "" {
		proxyURL = "https://localhost:8443"
	}
	caDir := e2eCADir(t)
	caPEM, err := os.ReadFile(filepath.Join(caDir, "ca.crt"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parse CA")
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	resp, err := client.Get(proxyURL + "/healthz")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func e2eUnseal(t *testing.T, proxyURL string, adminCert tls.Certificate, pool *x509.CertPool) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"passphrase": e2eKeyPassphrase})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, proxyURL+"/api/v1/admin/unseal", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{adminCert},
				RootCAs:      pool,
				MinVersion:   tls.VersionTLS12,
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("admin unseal: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusGone {
		t.Skip("HTTP admin unseal removed; E2E must use luna-proxy key load on control socket")
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin unseal status %d: %s", resp.StatusCode, b)
	}
}

func e2eCADir(t *testing.T) string {
	t.Helper()
	for _, base := range []string{
		"../../testdata/ca",
		"../testdata/ca",
		"testdata/ca",
	} {
		if _, err := os.Stat(filepath.Join(base, "ca.crt")); err == nil {
			return base
		}
	}
	t.Fatal("testdata/ca not found; run: make testdata")
	return ""
}
