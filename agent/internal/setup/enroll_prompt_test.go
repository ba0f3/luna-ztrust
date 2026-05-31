package setup

import (
	"fmt"
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

func TestFormatEnrollError_TLS(t *testing.T) {
	err := formatEnrollError(fmt.Errorf("Post: tls: failed to verify certificate: x509: unknown"), "/etc/luna/certs")
	if err == nil || !strings.Contains(err.Error(), "TLS trust problem") {
		t.Fatalf("err = %v", err)
	}
}

func TestFormatEnrollError_Token(t *testing.T) {
	err := formatEnrollError(fmt.Errorf("POST /api/v1/mtls/enroll: HTTP 401: invalid enroll token"), "/etc/luna/certs")
	if err == nil || !strings.Contains(err.Error(), "mtls_enroll_token") {
		t.Fatalf("err = %v", err)
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
