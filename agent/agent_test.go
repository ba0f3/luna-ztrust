package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/agent"
	"github.com/ba0f3/luna-ztrust/sdk"
	"golang.org/x/crypto/ssh"
)

type mockProvider struct {
	lastReq sdk.CertRequest
	cert    *ssh.Certificate
	priv    ed25519.PrivateKey
	err     error
}

func (m *mockProvider) RequestCertificate(_ context.Context, req sdk.CertRequest) (*ssh.Certificate, ed25519.PrivateKey, error) {
	m.lastReq = req
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.cert, m.priv, nil
}

func testCertAndKey(t *testing.T) (*ssh.Certificate, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pub := signer.PublicKey()

	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caSigner, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		t.Fatal(err)
	}

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           "test",
		ValidPrincipals: []string{"deploy"},
		ValidAfter:      uint64(time.Now().Add(-time.Hour).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, caSigner); err != nil {
		t.Fatal(err)
	}
	return cert, priv
}

func TestLunaAgentSignCallsProvider(t *testing.T) {
	cert, priv := testCertAndKey(t)
	mock := &mockProvider{cert: cert, priv: priv}

	la := agent.NewLunaAgent(mock, "deploy", "10.0.0.5")
	data := []byte("ssh-auth challenge")

	sig, err := la.Sign(nil, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig == nil {
		t.Fatal("nil signature")
	}

	if mock.lastReq.TargetUser != "deploy" {
		t.Fatalf("TargetUser = %q, want deploy", mock.lastReq.TargetUser)
	}
	if mock.lastReq.TargetIP != "10.0.0.5" {
		t.Fatalf("TargetIP = %q, want 10.0.0.5", mock.lastReq.TargetIP)
	}

	signer, err := sdk.NewCertSigner(cert, priv)
	if err != nil {
		t.Fatal(err)
	}
	want, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != want.Format || string(sig.Blob) != string(want.Blob) {
		t.Fatalf("signature mismatch: got %+v want %+v", sig, want)
	}
}

func TestLunaAgentListEmpty(t *testing.T) {
	la := agent.NewLunaAgent(&mockProvider{}, "u", "1.2.3.4")
	keys, err := la.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 0 {
		t.Fatalf("List len = %d, want 0", len(keys))
	}
}

func TestLunaAgentSignProviderError(t *testing.T) {
	mock := &mockProvider{err: context.DeadlineExceeded}
	la := agent.NewLunaAgent(mock, "deploy", "10.0.0.5")
	_, err := la.Sign(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error from provider")
	}
}
