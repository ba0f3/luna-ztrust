package api_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
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

	challenge := []byte("ssh-auth-challenge")
	fp, err := env.ks.SoleFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	body := buildSignBodyWithAgentData(t, "deploy", "10.0.0.5", challenge, fp)
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

func buildSignBodyWithAgentData(t *testing.T, user, ip string, data []byte, hostFP string) []byte {
	t.Helper()
	body := buildSignBody(t, user, ip)
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	m["agent_sign_data"] = base64.StdEncoding.EncodeToString(data)
	m["host_key_fingerprint"] = hostFP
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
