package api

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
)

func TestCliClientAllowed_RequiresOU(t *testing.T) {
	cert := certWithOU("luna-cli")
	if !cliClientAllowed("luna-cli", cert) {
		t.Fatal("expected allowed")
	}
	if cliClientAllowed("luna-cli", certWithOU("luna-admin")) {
		t.Fatal("admin should not pass cli check")
	}
	if cliClientAllowed("", cert) {
		t.Fatal("empty required OU should deny")
	}
}

func TestCliDeviceFromPeer_FoundAndMissing(t *testing.T) {
	cert := loadTestClientCertForAuth(t)
	fp := cli.CertFingerprint(cert)

	store := cli.NewStore()
	enrolled, err := store.Enroll("laptop", fp)
	if err != nil {
		t.Fatal(err)
	}

	s := &server{cli: store}
	got, ok := s.cliDeviceFromPeer(cert)
	if !ok || got.ID != enrolled.ID {
		t.Fatalf("expected enrolled device %q, got ok=%v id=%q", enrolled.ID, ok, got.ID)
	}

	other, err := loadTestCertFile("admin-client.crt")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.cliDeviceFromPeer(other); ok {
		t.Fatal("unenrolled cert should not resolve device")
	}

	nilStore := &server{}
	if _, ok := nilStore.cliDeviceFromPeer(cert); ok {
		t.Fatal("nil cli store should not resolve device")
	}
}

func certWithOU(ou string) *x509.Certificate {
	base := mustLoadTestClientCert()
	c := *base
	c.Subject.OrganizationalUnit = []string{ou}
	return &c
}

func loadTestClientCertForAuth(t *testing.T) *x509.Certificate {
	t.Helper()
	return mustLoadTestClientCert()
}

func mustLoadTestClientCert() *x509.Certificate {
	cert, err := loadTestCertFile("client.crt")
	if err != nil {
		panic(err)
	}
	return cert
}

func loadTestCertFile(name string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ca", name))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no certificate block in %s", name)
	}
	return x509.ParseCertificate(block.Bytes)
}
