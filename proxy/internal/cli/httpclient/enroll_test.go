package httpclient_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli/httpclient"
)

func TestEnroll_AdminMTLS(t *testing.T) {
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

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cli/enroll" {
			http.NotFound(w, r)
			return
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"device_id":       "dev1",
			"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		})
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

	csrPEM := generateTestCSR(t, "luna-cli")

	proxyURL := strings.Replace(ts.URL, "127.0.0.1", "localhost", 1)
	out, err := httpclient.Enroll(context.Background(), httpclient.MTLSConfig{
		ProxyURL: proxyURL,
		Cert:     filepath.Join(dir, "admin-client.crt"),
		Key:      filepath.Join(dir, "admin-client.key"),
		CA:       filepath.Join(dir, "ca.crt"),
	}, "laptop", string(csrPEM))
	if err != nil {
		t.Fatal(err)
	}
	if out.DeviceID != "dev1" || out.CertificatePEM == "" {
		t.Fatalf("out = %+v", out)
	}
}

func generateTestCSR(t *testing.T, ou string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{OrganizationalUnit: []string{ou}, CommonName: "test"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
}
