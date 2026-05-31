package setup

import (
	"os"
	"strings"
	"testing"
)

func TestNeedsEnrollResume(t *testing.T) {
	s := ExistingState{HasKey: true, HasCSR: true, HasCert: false}
	if !s.needsEnrollResume() {
		t.Fatal("expected resume")
	}
	s.HasCert = true
	if s.needsEnrollResume() {
		t.Fatal("expected no resume when cert present")
	}
}

func TestEnsureEnrollTokenFromValue(t *testing.T) {
	opts := Options{EnrollToken: "secret"}
	if err := ensureEnrollToken(&opts); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureEnrollTokenEmptyNonInteractive(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	oldStdin := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = oldStdin })

	opts := Options{}
	err = ensureEnrollToken(&opts)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "enroll token required") {
		t.Fatalf("err = %v", err)
	}
}
