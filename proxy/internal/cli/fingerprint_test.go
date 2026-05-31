package cli

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestCertFingerprint_Deterministic(t *testing.T) {
	cert := loadTestClientCert(t)
	fp := CertFingerprint(cert)
	if len(fp) != 64 {
		t.Fatalf("len=%d", len(fp))
	}
	if fp2 := CertFingerprint(cert); fp2 != fp {
		t.Fatalf("fingerprint not deterministic: %q vs %q", fp, fp2)
	}
}

func loadTestClientCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ca", "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("no certificate block in client.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
