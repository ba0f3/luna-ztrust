package setup

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateMTLS(t *testing.T) {
	dir := t.TempDir()
	res, err := GenerateMTLS(MTLSOptions{
		Dir:                  dir,
		IncludeSampleClients: true,
		ServerDNSNames:       []string{"luna.example.com", "localhost"},
		ValidityDays:         30,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 8 {
		t.Fatalf("expected 8 files, got %d: %v", len(res.Files), res.Files)
	}

	caCert := loadCert(t, filepath.Join(dir, "ca.crt"))
	if !caCert.IsCA {
		t.Fatal("CA cert IsCA=false")
	}
	serverCert := loadCert(t, filepath.Join(dir, "server.crt"))
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := serverCert.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("server cert not signed by CA: %v", err)
	}
	if len(serverCert.DNSNames) != 2 {
		t.Fatalf("server SANs: %v", serverCert.DNSNames)
	}
	adminCert := loadCert(t, filepath.Join(dir, "admin-client.crt"))
	if !subjectHasOU(adminCert.Subject, "luna-admin") {
		t.Fatalf("admin OU missing: %v", adminCert.Subject.OrganizationalUnit)
	}

	if _, err := GenerateMTLS(MTLSOptions{Dir: dir}); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
}

func TestGenerateMTLSForce(t *testing.T) {
	dir := t.TempDir()
	if _, err := GenerateMTLS(MTLSOptions{Dir: dir, IncludeSampleClients: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "admin-client.crt")); err != nil {
		t.Fatal("expected admin-client.crt without sample automation client")
	}
	if _, err := GenerateMTLS(MTLSOptions{Dir: dir, Force: true, IncludeSampleClients: false}); err != nil {
		t.Fatal(err)
	}
}

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func subjectHasOU(subject pkix.Name, ou string) bool {
	for _, v := range subject.OrganizationalUnit {
		if v == ou {
			return true
		}
	}
	return false
}
