package agent_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/ba0f3/luna-ztrust/agent"
	"github.com/ba0f3/luna-ztrust/sdk"
	"golang.org/x/crypto/ssh"
)

func TestResolveIdentitiesLocalKeyFromCapabilities(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))

	mock := &mockProvider{
		caps: sdk.Capabilities{
			SignerMode: agent.SignerModeLocalKey,
			LoadedSigners: []sdk.LoadedSigner{
				{PublicKey: pubLine, Fingerprint: "testfp"},
			},
		},
	}

	keys, err := agent.ResolveIdentities(mock, agent.Config{SignerMode: agent.SignerModeLocalKey})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1", len(keys))
	}
}

func TestResolveIdentitiesLocalKeySealed(t *testing.T) {
	mock := &mockProvider{
		caps: sdk.Capabilities{
			SignerMode: agent.SignerModeLocalKey,
			Sealed:     true,
		},
	}
	_, err := agent.ResolveIdentities(mock, agent.Config{SignerMode: agent.SignerModeLocalKey})
	if err == nil {
		t.Fatal("expected error when sealed")
	}
}

func TestResolveIdentitiesLocalKeyFingerprintOnlyWithFallback(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	fp := agent.PublicKeyFingerprint(signer.PublicKey())

	mock := &mockProvider{
		caps: sdk.Capabilities{
			SignerMode: agent.SignerModeLocalKey,
			LoadedSigners: []sdk.LoadedSigner{
				{Fingerprint: fp},
			},
		},
	}

	keys, err := agent.ResolveIdentities(mock, agent.Config{
		SignerMode:      agent.SignerModeLocalKey,
		HostedPublicKey: pubLine,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1", len(keys))
	}
}
