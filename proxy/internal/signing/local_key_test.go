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

func loadHostKeyPool(t *testing.T, path string) (*keystore.Keystore, string) {
	t.Helper()
	ks := keystore.NewWithMode(keystore.ModeLocalKey)
	fp, err := ks.LoadPEMFile(path, "test-pass", "host")
	if err != nil {
		t.Fatal(err)
	}
	return ks, fp
}

func TestLocalKey_SignAgent(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := writeEncryptedKeyForHost(t, priv)
	ks, fp := loadHostKeyPool(t, path)

	hostKey := signing.NewLocalKey(ks)
	challenge := []byte("ssh-userauth challenge")
	blob, err := hostKey.SignAgent(context.Background(), fp, challenge)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ks.SignerForFingerprint(fp)
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
	path := writeEncryptedKeyForHost(t, priv)
	ks, fp := loadHostKeyPool(t, path)

	local := signing.NewLocalKey(ks)
	data := []byte("session-id-123")
	blob, err := local.SignAgent(context.Background(), fp, data)
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
