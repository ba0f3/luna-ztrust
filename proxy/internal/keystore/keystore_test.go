package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

const testPassphrase = "test-pass"

func writeEncryptedKeyFile(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "luna-test", []byte(testPassphrase))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o400); err != nil {
		t.Fatal(err)
	}
}

func TestKeystore_SealedBlocksSigner(t *testing.T) {
	ks := keystore.New()
	if ks.Available() {
		t.Fatal("new keystore should be sealed")
	}
	_, err := ks.SSHSigner()
	if !errors.Is(err, keystore.ErrSealed) {
		t.Fatalf("got %v", err)
	}
}

func TestKeystore_UnsealLoadsSigner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted.key")
	writeEncryptedKeyFile(t, path)

	ks := keystore.New()
	if err := ks.Unseal(path, testPassphrase); err != nil {
		t.Fatalf("unseal: %v", err)
	}
	if !ks.Available() {
		t.Fatal("expected available after unseal")
	}
	signer, err := ks.SSHSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	if signer == nil {
		t.Fatal("nil signer")
	}
}

func TestKeystore_UnsealWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted.key")
	writeEncryptedKeyFile(t, path)

	ks := keystore.New()
	err := ks.Unseal(path, "wrong")
	if err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
	if ks.Available() {
		t.Fatal("keystore must stay sealed on failed unseal")
	}
}

func TestKeystore_UnsealLockoutAfterFailures(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "encrypted.key")
	writeEncryptedKeyFile(t, path)

	ks := keystore.New()
	for i := 0; i < 5; i++ {
		_ = ks.Unseal(path, "wrong")
	}
	err := ks.Unseal(path, "wrong")
	if !errors.Is(err, keystore.ErrUnsealLocked) {
		t.Fatalf("attempt 6: got %v, want ErrUnsealLocked", err)
	}
	if err := ks.Unseal(path, testPassphrase); !errors.Is(err, keystore.ErrUnsealLocked) {
		t.Fatalf("correct passphrase during lockout: got %v", err)
	}
}

func TestKeystore_UnsealMissingFile(t *testing.T) {
	ks := keystore.New()
	err := ks.Unseal(filepath.Join(t.TempDir(), "missing.key"), testPassphrase)
	if err == nil {
		t.Fatal("expected error")
	}
	if ks.Available() {
		t.Fatal("should remain sealed")
	}
}
