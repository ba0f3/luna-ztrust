package sdk_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/sdk"
	"golang.org/x/crypto/ssh"
)

func TestBuildAndVerifyPoP(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Now().Unix()
	sigHex, err := sdk.SignPoP(sshPub, priv, "deploy", "10.0.0.5", ts)
	if err != nil {
		t.Fatal(err)
	}
	if err := sdk.VerifyPoP(sshPub, "deploy", "10.0.0.5", ts, sigHex); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
