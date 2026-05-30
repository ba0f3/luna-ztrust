package signing_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
	"golang.org/x/crypto/ssh"
)

func writeEncryptedKeyForHost(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "luna-host", []byte("test-pass"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o400); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLocalKey_SignAgent(t *testing.T) {
	ks := keystore.New()
	path := writeEncryptedCA(t)
	if err := ks.Unseal(path, "test-pass"); err != nil {
		t.Fatal(err)
	}

	hostKey := signing.NewLocalKey(ks)
	challenge := []byte("ssh-userauth challenge")
	blob, err := hostKey.SignAgent(context.Background(), challenge)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ks.SSHSigner()
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()
	sshSig := &ssh.Signature{Format: pub.Type(), Blob: blob}
	if err := pub.Verify(challenge, sshSig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestLocalKey_SignAgentMatchesHostedKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks := keystore.New()
	path := writeEncryptedKeyForHost(t, priv)
	if err := ks.Unseal(path, "test-pass"); err != nil {
		t.Fatal(err)
	}

	local := signing.NewLocalKey(ks)
	data := []byte("session-id-123")
	blob, err := local.SignAgent(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}

	direct, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	want, err := direct.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != string(want.Blob) {
		t.Fatal("signature mismatch")
	}
}
