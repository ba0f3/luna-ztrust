package mobile_test

import (
	"encoding/base64"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/mobile"
	"golang.org/x/crypto/ed25519"
)

func TestStoreEnrollReturnsDeviceID(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := mobile.NewStore()
	dev, err := s.Enroll("phone", base64.StdEncoding.EncodeToString(pub))
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if dev.ID == "" || len(dev.ID) < 8 {
		t.Fatalf("device_id = %q", dev.ID)
	}
	got, ok := s.Get(dev.ID)
	if !ok || got.Label != "phone" {
		t.Fatal("device not stored")
	}
}

func TestStoreDelete(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	s := mobile.NewStore()
	dev, _ := s.Enroll("x", base64.StdEncoding.EncodeToString(pub))
	if err := s.Delete(dev.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(dev.ID); err != mobile.ErrNotFound {
		t.Fatalf("second delete: %v", err)
	}
}
