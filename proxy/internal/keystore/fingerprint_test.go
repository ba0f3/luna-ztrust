package keystore_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"golang.org/x/crypto/ssh"
)

func TestFingerprint_MatchesSSHKeygen(t *testing.T) {
	pubPath := filepath.Join("..", "..", "..", "testdata", "ssh", "ca.pub")
	pub := loadTestPubKey(t, "ca.pub")
	got := keystore.Fingerprint(pub)
	want, err := sshKeygenSHA256Fingerprint(pubPath)
	if err != nil {
		t.Skip(err)
	}
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

func sshKeygenSHA256Fingerprint(pubPath string) (string, error) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		return "", err
	}
	out, err := exec.Command("ssh-keygen", "-lf", pubPath).CombinedOutput()
	if err != nil {
		return "", err
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if strings.HasPrefix(f, "SHA256:") {
			return strings.TrimPrefix(f, "SHA256:"), nil
		}
		if f == "SHA256:" && i+1 < len(fields) {
			return fields[i+1], nil
		}
	}
	return "", errors.New("ssh-keygen output missing SHA256 fingerprint")
}
