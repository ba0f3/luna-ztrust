//go:build e2e

package sign_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

	proxyURL := os.Getenv("LUNA_PROXY_URL")
	if proxyURL == "" {
		proxyURL = "https://localhost:8443"
	}

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
