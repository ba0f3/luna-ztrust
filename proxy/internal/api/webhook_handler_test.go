package api_test

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/api"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func postTelegramWebhook(t *testing.T, env *testEnv, secret string, body []byte) *http.Response {
	t.Helper()
	_, clientTLS := loadTestTLSConfigs(t)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    clientTLS.RootCAs,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}

	req, err := http.NewRequest(http.MethodPost, env.ts.URL+"/api/v1/telegram/webhook", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		req.Header.Set("X-Telegram-Bot-Api-Secret-Token", secret)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestTelegramWebhookApprove(t *testing.T) {
	env := startTestServerDefault(t, config.Config{
		ApprovalTimeout:       60 * time.Second,
		TelegramWebhookSecret: "whsec-test",
	})
	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))

	upd := map[string]any{
		"callback_query": map[string]any{
			"id":   "cq1",
			"data": "approve:" + txID,
		},
	}
	raw, _ := json.Marshal(upd)
	resp := postTelegramWebhook(t, env, "whsec-test", raw)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status = %d", resp.StatusCode)
	}

	waitResp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatal(err)
	}
	defer waitResp.Body.Close()
	if waitResp.StatusCode != http.StatusOK {
		t.Fatalf("wait status = %d, want 200", waitResp.StatusCode)
	}
}

func TestTelegramWebhookDeny(t *testing.T) {
	env := startTestServerDefault(t, config.Config{
		ApprovalTimeout:       60 * time.Second,
		TelegramWebhookSecret: "whsec-test",
	})
	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))

	upd := map[string]any{
		"callback_query": map[string]any{
			"id":   "cq2",
			"data": "deny:" + txID,
		},
	}
	raw, _ := json.Marshal(upd)
	resp := postTelegramWebhook(t, env, "whsec-test", raw)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook status = %d", resp.StatusCode)
	}

	waitResp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatal(err)
	}
	defer waitResp.Body.Close()
	if waitResp.StatusCode != http.StatusForbidden {
		t.Fatalf("wait status = %d, want 403", waitResp.StatusCode)
	}
}

func TestTelegramWebhookBadSecret401(t *testing.T) {
	env := startTestServerDefault(t, config.Config{TelegramWebhookSecret: "whsec-test"})
	resp := postTelegramWebhook(t, env, "", []byte(`{}`))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestParseCallbackData(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in     string
		action string
		txID   string
		ok     bool
	}{
		{"approve:tx_01ABC", "approve", "tx_01ABC", true},
		{"deny:tx_01ABC", "deny", "tx_01ABC", true},
		{"approve:", "", "", false},
		{"bad:tx_01", "", "", false},
		{"approve:notx", "", "", false},
	}
	for _, tc := range cases {
		action, txID, ok := api.ParseCallbackData(tc.in)
		if ok != tc.ok || action != tc.action || txID != tc.txID {
			t.Errorf("ParseCallbackData(%q) = %q,%q,%v; want %q,%q,%v",
				tc.in, action, txID, ok, tc.action, tc.txID, tc.ok)
		}
	}
}
