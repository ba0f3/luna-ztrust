package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

func TestFingerprint_MatchesSSHKeygen(t *testing.T) {
	pub := loadTestPubKey(t, "ca.pub")
	got := keystore.Fingerprint(pub)
	want := "ErTRveOaqaSJSj9pi4mTOQdskJUmTE45h2AFw2qmIYw"
	if got != want {
		t.Fatalf("Fingerprint() = %q, want %q (ssh-keygen -lf)", got, want)
	}
}

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
	if a != b || a == "" {
		t.Fatalf("fingerprint = %q", a)
	}
}

func TestParseFingerprintHint(t *testing.T) {
	pub := loadTestPubKey(t, "host.pub")
	want := keystore.Fingerprint(pub)
	for _, in := range []string{
		want,
		"SHA256:" + want,
	} {
		got, err := keystore.ParseFingerprintHint(in)
		if err != nil {
			t.Fatalf("ParseFingerprintHint(%q): %v", in, err)
		}
		if got != want {
			t.Fatalf("ParseFingerprintHint(%q) = %q, want %q", in, got, want)
		}
	}
}

func loadTestPubKey(t *testing.T, name string) ssh.PublicKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ssh", name))
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
