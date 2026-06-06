package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
	"golang.org/x/crypto/ssh"
)

func startTestServerLocalKey(t *testing.T) *testEnv {
	t.Helper()
	cfg := config.Config{
		ApprovalTimeout: 60 * time.Second,
		SignerMode:      approval.SignerModeLocalKey,
	}
	ks := keystore.NewWithMode(keystore.ModeLocalKey)
	unsealTestKeystore(t, ks)
	env := startTestServer(t, cfg, ks)
	env.store.SetKeySigner(signing.NewLocalKey(ks))
	return env
}

func TestLocalKeySignReturnsSignature(t *testing.T) {
	env := startTestServerLocalKey(t)

	fp, err := env.ks.SoleFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	hostedPub, err := env.ks.PublicKeyForFingerprint(fp)
	if err != nil {
		t.Fatal(err)
	}
	body := buildBoundSignBody(t, "deploy", "10.0.0.5", hostedPub, fp)
	txID := postSign(t, env, body)
	env.store.Approve(txID, 5*time.Minute, "telegram:1")

	resp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		SSHSignature string `json:"ssh_signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.SSHSignature == "" {
		t.Fatal("expected ssh_signature")
	}
}

func TestLocalKeyDirectSDKSignReturnsSignatureWithoutLease(t *testing.T) {
	env := startTestServerLocalKey(t)
	fp, err := env.ks.SoleFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	hostedPub, err := env.ks.PublicKeyForFingerprint(fp)
	if err != nil {
		t.Fatal(err)
	}
	body := buildDirectSignBody(t, "deploy", "10.0.0.5", hostedPub, fp)
	txID := postSign(t, env, body)
	env.store.Approve(txID, 5*time.Minute, "telegram:1")

	tx := env.store.Snapshot(txID)
	if tx == nil || tx.DestinationHostKeySource != "client-reported" || !tx.DisableLease {
		t.Fatalf("transaction = %+v", tx)
	}
}

func buildBoundSignBody(t *testing.T, user, ip string, hostedPub ssh.PublicKey, hostFP string) []byte {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := []byte("test-exchange-hash")
	hostSig, err := hostSigner.Sign(rand.Reader, sessionID)
	if err != nil {
		t.Fatal(err)
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
		User:      user,
		Service:   "ssh-connection",
		Method:    "publickey",
		HasSig:    true,
		Algorithm: hostedPub.Type(),
		PublicKey: hostedPub.Marshal(),
	})
	body := buildSignBody(t, user, ip)
	var m map[string]any
	if err = json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["agent_sign_data"] = base64.StdEncoding.EncodeToString(data)
	m["host_key_fingerprint"] = hostFP
	m["session_binding"] = auth.SessionBinding{
		HostPublicKey: base64.StdEncoding.EncodeToString(hostSigner.PublicKey().Marshal()),
		SessionID:     base64.StdEncoding.EncodeToString(sessionID),
		Signature:     base64.StdEncoding.EncodeToString(ssh.Marshal(hostSig)),
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func buildDirectSignBody(t *testing.T, user, ip string, hostedPub ssh.PublicKey, hostFP string) []byte {
	t.Helper()
	hostPub, _, err := testSSHSigner(t)
	if err != nil {
		t.Fatal(err)
	}
	data := marshalLocalKeyUserAuth([]byte("test-exchange-hash"), user, hostedPub)
	body := buildSignBody(t, user, ip)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["agent_sign_data"] = base64.StdEncoding.EncodeToString(data)
	m["host_key_fingerprint"] = hostFP
	m["destination_host_public_key"] = base64.StdEncoding.EncodeToString(hostPub.Marshal())
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func testSSHSigner(t *testing.T) (ssh.PublicKey, ssh.Signer, error) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return signer.PublicKey(), signer, nil
}

func marshalLocalKeyUserAuth(sessionID []byte, user string, pub ssh.PublicKey) []byte {
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
