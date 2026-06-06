package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	sign "github.com/ba0f3/luna-ztrust/sdk/sign"
	"golang.org/x/crypto/ssh"
)

func TestValidateDirectLocalKeySignData_SDKJSONDestinationHostKey(t *testing.T) {
	hostPub, hostSigner := testSigner(t)
	_, destPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destSigner, err := ssh.NewSignerFromKey(destPriv)
	if err != nil {
		t.Fatal(err)
	}
	destPub := destSigner.PublicKey()

	signData := marshalGoUserAuth(t, []byte("exchange-hash"), "root", hostPub)
	body, err := json.Marshal(sign.Request{
		AgentSignData:            base64.StdEncoding.EncodeToString(signData),
		DestinationHostPublicKey: destPub.Marshal(),
	})
	if err != nil {
		t.Fatal(err)
	}
	var req SignRequest
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	if req.DestinationHostPublicKey == "" {
		t.Fatal("destination_host_public_key missing after JSON round trip")
	}

	got, err := ValidateDirectLocalKeySignData(req.DestinationHostPublicKey, signData, "root", hostSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if got.HostKeyFingerprint == "" {
		t.Fatal("missing destination host key fingerprint")
	}
}

func marshalGoUserAuth(t *testing.T, sessionID []byte, user string, pub ssh.PublicKey) []byte {
	t.Helper()
	return ssh.Marshal(struct {
		Session []byte
		Type    byte
		User    string
		Service string
		Method  string
		Sign    bool
		Algo    string
		PubKey  []byte
	}{
		Session: sessionID,
		Type:    msgUserAuthRequest,
		User:    user,
		Service: "ssh-connection",
		Method:  "publickey",
		Sign:    true,
		Algo:    pub.Type(),
		PubKey:  pub.Marshal(),
	})
}
