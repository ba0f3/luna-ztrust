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
	sshagent "golang.org/x/crypto/ssh/agent"
)

type mockProvider struct {
	signerMode string
	caps       sdk.Capabilities
	lastReq    sdk.CertRequest
	lastSigReq sdk.SignatureRequest
	lastData   []byte
	cert       *ssh.Certificate
	priv       ed25519.PrivateKey
	sig        *ssh.Signature
	err        error
}

func (m *mockProvider) SignerMode() string { return m.signerMode }

func (m *mockProvider) FetchCapabilities(context.Context) (sdk.Capabilities, error) {
	if m.err != nil {
		return sdk.Capabilities{}, m.err
	}
	return m.caps, nil
}

func (m *mockProvider) RequestCertificate(_ context.Context, req sdk.CertRequest) (*ssh.Certificate, ed25519.PrivateKey, error) {
	m.lastReq = req
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.cert, m.priv, nil
}

func (m *mockProvider) RequestSignature(_ context.Context, req sdk.SignatureRequest, data []byte) (*ssh.Signature, error) {
	m.lastSigReq = req
	m.lastData = data
	if m.err != nil {
		return nil, m.err
	}
	return m.sig, nil
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

	keys, _ := agent.ResolveIdentities(&mockProvider{signerMode: agent.SignerModeLocalCA}, agent.Config{SignerMode: agent.SignerModeLocalCA})
	la := agent.NewLunaAgent(mock, agent.SignerModeLocalCA, "deploy", "10.0.0.5", "", keys)
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

func TestLunaAgentSignLocalKeyMode(t *testing.T) {
	cert, priv := testCertAndKey(t)
	signer, err := sdk.NewCertSigner(cert, priv)
	if err != nil {
		t.Fatal(err)
	}
	want, err := signer.Sign(rand.Reader, []byte("challenge"))
	if err != nil {
		t.Fatal(err)
	}

	mock := &mockProvider{
		signerMode: agent.SignerModeLocalKey,
		sig:        want,
	}
	keys := []*sshagent.Key{{Format: want.Format, Blob: cert.Key.Marshal()}}
	la := agent.NewLunaAgent(mock, agent.SignerModeLocalKey, "deploy", "10.0.0.5", "abc", keys)
	got, err := la.Sign(cert.Key, []byte("challenge"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if string(got.Blob) != string(want.Blob) {
		t.Fatal("signature mismatch")
	}
	if mock.lastSigReq.TargetUser != "deploy" {
		t.Fatalf("TargetUser = %q", mock.lastSigReq.TargetUser)
	}
}

func TestLunaAgentListReturnsIdentities(t *testing.T) {
	keys, err := agent.ResolveIdentities(&mockProvider{signerMode: agent.SignerModeLocalCA}, agent.Config{SignerMode: agent.SignerModeLocalCA})
	if err != nil {
		t.Fatal(err)
	}
	la := agent.NewLunaAgent(&mockProvider{}, agent.SignerModeLocalCA, "u", "1.2.3.4", "", keys)
	got, err := la.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(keys) {
		t.Fatalf("List len = %d, want %d", len(got), len(keys))
	}
}

func TestLunaAgentSignProviderError(t *testing.T) {
	mock := &mockProvider{err: context.DeadlineExceeded}
	keys, _ := agent.ResolveIdentities(&mockProvider{signerMode: agent.SignerModeLocalCA}, agent.Config{SignerMode: agent.SignerModeLocalCA})
	la := agent.NewLunaAgent(mock, agent.SignerModeLocalCA, "deploy", "10.0.0.5", "", keys)
	_, err := la.Sign(nil, []byte("data"))
	if err == nil {
		t.Fatal("expected error from provider")
	}
}
