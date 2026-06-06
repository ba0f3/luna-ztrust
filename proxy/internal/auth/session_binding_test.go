package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestValidateLocalKeySignData(t *testing.T) {
	hostPub, hostSigner := testSigner(t)
	userPub, _ := testSigner(t)
	sessionID := []byte("exchange-hash")
	hostSig, err := hostSigner.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
	}
	binding := SessionBinding{
		HostPublicKey: base64.StdEncoding.EncodeToString(hostPub.Marshal()),
		SessionID:     base64.StdEncoding.EncodeToString(sessionID),
		Signature:     base64.StdEncoding.EncodeToString(ssh.Marshal(hostSig)),
	}
	data := ssh.Marshal(struct {
		SessionID []byte
		User      string `sshtype:"50"`
		Service   string
		Method    string
		HasSig    bool
		Algorithm string
		PublicKey []byte
	}{
		SessionID: sessionID,
		User:      "deploy",
		Service:   "ssh-connection",
		Method:    "publickey",
		HasSig:    true,
		Algorithm: userPub.Type(),
		PublicKey: userPub.Marshal(),
	})

	got, err := ValidateLocalKeySignData(binding, data, "deploy", userPub)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostKeyFingerprint == "" {
		t.Fatal("missing host key fingerprint")
	}
}

func TestValidateLocalKeySignDataRejectsWrongUser(t *testing.T) {
	hostPub, hostSigner := testSigner(t)
	userPub, _ := testSigner(t)
	sessionID := []byte("exchange-hash")
	hostSig, _ := hostSigner.Sign(rand.Reader, sessionID)
	binding := SessionBinding{
		HostPublicKey: base64.StdEncoding.EncodeToString(hostPub.Marshal()),
		SessionID:     base64.StdEncoding.EncodeToString(sessionID),
		Signature:     base64.StdEncoding.EncodeToString(ssh.Marshal(hostSig)),
	}
	data := marshalUserAuth(t, sessionID, "root", userPub)

	if _, err := ValidateLocalKeySignData(binding, data, "deploy", userPub); err == nil {
		t.Fatal("expected wrong user rejection")
	}
}

func TestValidateLocalKeySignDataRejectsWrongSession(t *testing.T) {
	hostPub, hostSigner := testSigner(t)
	userPub, _ := testSigner(t)
	hostSig, _ := hostSigner.Sign(rand.Reader, []byte("bound-session"))
	binding := SessionBinding{
		HostPublicKey: base64.StdEncoding.EncodeToString(hostPub.Marshal()),
		SessionID:     base64.StdEncoding.EncodeToString([]byte("bound-session")),
		Signature:     base64.StdEncoding.EncodeToString(ssh.Marshal(hostSig)),
	}

	if _, err := ValidateLocalKeySignData(binding, marshalUserAuth(t, []byte("other"), "deploy", userPub), "deploy", userPub); err == nil {
		t.Fatal("expected wrong session rejection")
	}
}

func TestValidateLocalKeySignDataRejectsForwarding(t *testing.T) {
	hostPub, hostSigner := testSigner(t)
	userPub, _ := testSigner(t)
	sessionID := []byte("exchange-hash")
	hostSig, _ := hostSigner.Sign(rand.Reader, sessionID)
	binding := SessionBinding{
		HostPublicKey: base64.StdEncoding.EncodeToString(hostPub.Marshal()),
		SessionID:     base64.StdEncoding.EncodeToString(sessionID),
		Signature:     base64.StdEncoding.EncodeToString(ssh.Marshal(hostSig)),
		Forwarding:    true,
	}

	if _, err := ValidateLocalKeySignData(binding, marshalUserAuth(t, sessionID, "deploy", userPub), "deploy", userPub); err == nil {
		t.Fatal("expected forwarding rejection")
	}
}

func TestValidateLocalKeySignDataRejectsWrongHostedKey(t *testing.T) {
	hostPub, hostSigner := testSigner(t)
	userPub, _ := testSigner(t)
	otherPub, _ := testSigner(t)
	sessionID := []byte("exchange-hash")
	hostSig, _ := hostSigner.Sign(rand.Reader, sessionID)
	binding := SessionBinding{
		HostPublicKey: base64.StdEncoding.EncodeToString(hostPub.Marshal()),
		SessionID:     base64.StdEncoding.EncodeToString(sessionID),
		Signature:     base64.StdEncoding.EncodeToString(ssh.Marshal(hostSig)),
	}

	if _, err := ValidateLocalKeySignData(binding, marshalUserAuth(t, sessionID, "deploy", otherPub), "deploy", userPub); err == nil {
		t.Fatal("expected hosted key rejection")
	}
}

func TestValidateDirectLocalKeySignData(t *testing.T) {
	hostPub, _ := testSigner(t)
	userPub, _ := testSigner(t)
	data := marshalUserAuth(t, []byte("exchange-hash"), "deploy", userPub)

	got, err := ValidateDirectLocalKeySignData(
		base64.StdEncoding.EncodeToString(hostPub.Marshal()),
		data,
		"deploy",
		userPub,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got.HostKeyFingerprint == "" {
		t.Fatal("missing host key fingerprint")
	}
}

func TestValidateDirectLocalKeySignDataRejectsWrongUser(t *testing.T) {
	hostPub, _ := testSigner(t)
	userPub, _ := testSigner(t)
	data := marshalUserAuth(t, []byte("exchange-hash"), "root", userPub)

	if _, err := ValidateDirectLocalKeySignData(
		base64.StdEncoding.EncodeToString(hostPub.Marshal()),
		data,
		"deploy",
		userPub,
	); err == nil {
		t.Fatal("expected wrong user rejection")
	}
}

func testSigner(t *testing.T) (ssh.PublicKey, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey(), signer
}

func marshalUserAuth(t *testing.T, sessionID []byte, user string, pub ssh.PublicKey) []byte {
	t.Helper()
	return ssh.Marshal(struct {
		SessionID []byte
		User      string `sshtype:"50"`
		Service   string
		Method    string
		HasSig    bool
		Algorithm string
		PublicKey []byte
	}{
		SessionID: sessionID,
		User:      user,
		Service:   "ssh-connection",
		Method:    "publickey",
		HasSig:    true,
		Algorithm: pub.Type(),
		PublicKey: pub.Marshal(),
	})
}
