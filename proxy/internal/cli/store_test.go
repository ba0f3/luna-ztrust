package cli_test

import (
	"errors"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
)

func TestStore_EnrollGetDelete(t *testing.T) {
	s := cli.NewStore()
	dev, err := s.Enroll("laptop", "abc123")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if dev.ID == "" || len(dev.ID) < 8 {
		t.Fatalf("device_id = %q", dev.ID)
	}
	got, ok := s.GetByFingerprint("abc123")
	if !ok || got.ID != dev.ID || got.Label != "laptop" {
		t.Fatal("GetByFingerprint miss")
	}
	if err := s.Delete(dev.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetByFingerprint("abc123"); ok {
		t.Fatal("expected miss after delete")
	}
	if err := s.Delete(dev.ID); !errors.Is(err, cli.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}
