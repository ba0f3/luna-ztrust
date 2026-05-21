package api

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
)

func captureSignLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	old := signLogOut
	signLogOut = buf
	t.Cleanup(func() { signLogOut = old })
	return buf
}

func TestEmitSignLogJSON(t *testing.T) {
	buf := captureSignLog(t)
	emitSignLog(signLogEntry{
		TxID:         "tx_01TEST",
		ClientCertFP: "abc123",
		TargetUser:   "deploy",
		TargetIP:     "10.0.0.5",
		Outcome:      "accepted",
		LatencyMS:    12,
	})

	var got signLogEntry
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal log: %v, raw=%q", err, buf.Bytes())
	}
	if got.TxID != "tx_01TEST" || got.ClientCertFP != "abc123" {
		t.Fatalf("got %+v", got)
	}
	if got.TargetUser != "deploy" || got.TargetIP != "10.0.0.5" {
		t.Fatalf("target fields: %+v", got)
	}
	if got.Outcome != "accepted" || got.LatencyMS != 12 {
		t.Fatalf("outcome/latency: %+v", got)
	}
	raw := string(buf.Bytes())
	for _, forbidden := range []string{"pop_signature", "public_key", "BodyMAC", "private"} {
		if bytes.Contains(buf.Bytes(), []byte(forbidden)) {
			t.Fatalf("log must not contain %q: %s", forbidden, raw)
		}
	}
}

func TestSignOutcomeFromAuthErr(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{auth.ErrReplay, "replay"},
		{auth.ErrInvalidHMAC, "invalid_hmac"},
		{auth.ErrInvalidPoP, "invalid_pop"},
		{auth.ErrTimestampOutsideWindow, "timestamp_outside_window"},
		{errors.New("other"), "auth_rejected"},
	}
	for _, tc := range cases {
		if got := signOutcomeFromAuthErr(tc.err); got != tc.want {
			t.Fatalf("%v: got %q want %q", tc.err, got, tc.want)
		}
	}
}

func TestClientCertFingerprint(t *testing.T) {
	cert := loadTestClientCert(t)
	fp := clientCertFingerprint(cert)
	if fp == "" || len(fp) != 64 {
		t.Fatalf("fingerprint = %q", fp)
	}
	if fp2 := clientCertFingerprint(nil); fp2 != "" {
		t.Fatalf("nil cert fp = %q", fp2)
	}
}

func loadTestClientCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "ca", "client.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("no certificate block in client.crt")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
