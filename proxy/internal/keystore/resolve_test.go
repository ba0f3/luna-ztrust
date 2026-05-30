package keystore_test

import (
	"encoding/base64"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
)

func TestResolveHostKeyFingerprintFromHint(t *testing.T) {
	pub := loadTestPubKey(t, "host.pub")
	want := keystore.Fingerprint(pub)
	got, err := keystore.ResolveHostKeyFingerprint("", "SHA256:"+want)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveHostKeyFingerprintFromWire(t *testing.T) {
	pub := loadTestPubKey(t, "host.pub")
	want := keystore.Fingerprint(pub)
	wire := base64.StdEncoding.EncodeToString(pub.Marshal())
	got, err := keystore.ResolveHostKeyFingerprint(wire, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveHostKeyFingerprintMismatch(t *testing.T) {
	pub := loadTestPubKey(t, "host.pub")
	wire := base64.StdEncoding.EncodeToString(pub.Marshal())
	_, err := keystore.ResolveHostKeyFingerprint(wire, "ErTRveOaqaSJSj9pi4mTOQdskJUmTE45h2AFw2qmIYw")
	if err == nil {
		t.Fatal("expected mismatch error")
	}
}
