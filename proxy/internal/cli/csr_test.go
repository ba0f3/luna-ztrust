package cli

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignCSR_IssuesClientCert(t *testing.T) {
	caCert, caKey := loadTestCA(t)
	csrPEM := generateTestCSR(t, "luna-cli")
	signer := NewCSRSigner(caCert, caKey, "luna-cli", 24*time.Hour)

	certPEM, fp, err := signer.Sign(csrPEM)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(certPEM) == 0 || fp == "" {
		t.Fatal("expected cert PEM and fingerprint")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("expected CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if fp != CertFingerprint(cert) {
		t.Fatalf("fingerprint mismatch: got %q want %q", fp, CertFingerprint(cert))
	}
	if !certHasClientAuthEKU(cert) {
		t.Fatal("missing clientAuth EKU")
	}
}

func TestSignAutomation_AcceptsAutomationCSR(t *testing.T) {
	caCert, caKey := loadTestCA(t)
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
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	signer := NewCSRSigner(caCert, caKey, "luna-cli", 24*time.Hour)
	certPEM, _, err := signer.SignAutomation(csrPEM)
	if err != nil {
		t.Fatalf("SignAutomation: %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatal("expected cert PEM")
	}
}

func TestSignCSR_RejectsWrongOU(t *testing.T) {
	caCert, caKey := loadTestCA(t)
	signer := NewCSRSigner(caCert, caKey, "luna-cli", 24*time.Hour)

	_, _, err := signer.Sign(generateTestCSR(t, "wrong-ou"))
	if !errors.Is(err, ErrCSRInvalid) {
		t.Fatalf("expected ErrCSRInvalid, got %v", err)
	}
}

func TestSignCSR_RejectsMalformedPEM(t *testing.T) {
	caCert, caKey := loadTestCA(t)
	signer := NewCSRSigner(caCert, caKey, "luna-cli", 24*time.Hour)

	_, _, err := signer.Sign([]byte("not a pem"))
	if !errors.Is(err, ErrCSRInvalid) {
		t.Fatalf("expected ErrCSRInvalid, got %v", err)
	}
}

func loadTestCA(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "testdata", "ca")

	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("no certificate block in ca.crt")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatal("no key block in ca.key")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return caCert, caKey
}

func generateTestCSR(t *testing.T, ou string) []byte {
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
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func certHasClientAuthEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}
