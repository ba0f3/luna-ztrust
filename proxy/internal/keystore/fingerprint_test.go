package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

func TestFingerprint_Deterministic(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	sshPub := signer.PublicKey()
	a := keystore.Fingerprint(sshPub)
	b := keystore.Fingerprint(sshPub)
	if a != b || len(a) != 64 {
		t.Fatalf("fingerprint = %q", a)
	}
}
