package signing_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
	"golang.org/x/crypto/ssh"
)

func TestLocalCA_IssueCert(t *testing.T) {
	caKS := keystore.New()
	caPath := writeEncryptedCA(t)
	if err := caKS.Unseal(caPath, "test-pass"); err != nil {
		t.Fatal(err)
	}

	_, clientPubLine := generateClientSSHKey(t)
	issuer := signing.NewLocalCA(caKS)
	until := time.Now().Add(5 * time.Minute)
	res, err := issuer.IssueCert(context.Background(), signing.IssueRequest{
		ClientPubKey: clientPubLine,
		TargetUser:   "deploy",
		TargetIP:     "10.0.1.50",
		SourceIP:     "203.0.113.10",
		ValidUntil:   until,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Certificate == "" {
		t.Fatal("empty certificate")
	}

	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(res.Certificate))
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("not a certificate")
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("cert type = %v", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" {
		t.Fatalf("principals = %v", cert.ValidPrincipals)
	}
	if cert.Permissions.CriticalOptions["source-address"] != "203.0.113.10" {
		t.Fatalf("source-address = %q", cert.Permissions.CriticalOptions["source-address"])
	}
	if cert.SignatureKey == nil {
		t.Fatal("missing signature key on certificate")
	}
}

func writeEncryptedCA(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "luna-ca", []byte("test-pass"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func generateClientSSHKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub, string(ssh.MarshalAuthorizedKey(sshPub))
}
