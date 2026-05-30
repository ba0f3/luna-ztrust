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
		AllowedTTLSeconds:     []int{180, 300, 900},
	})
	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))

	upd := map[string]any{
		"callback_query": map[string]any{
			"id":   "cq1",
			"data": "approve:" + txID + ":300",
			"message": map[string]any{
				"chat": map[string]any{"id": 4242},
			},
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
	allowed := []int{180, 300, 900}
	cases := []struct {
		in     string
		action string
		txID   string
		ttlOK  bool
		ok     bool
	}{
		{"approve:tx_01ABC:300", "approve", "tx_01ABC", true, true},
		{"deny:tx_01ABC", "deny", "tx_01ABC", false, true},
		{"approve:tx_01ABC:999", "", "", false, false},
		{"approve:", "", "", false, false},
		{"bad:tx_01", "", "", false, false},
		{"approve:notx", "", "", false, false},
	}
	for _, tc := range cases {
		action, txID, ttl, ok := api.ParseCallbackData(tc.in, allowed)
		if ok != tc.ok || action != tc.action || txID != tc.txID {
			t.Errorf("ParseCallbackData(%q) = %q,%q,%v,%v; want %q,%q,_,%v",
				tc.in, action, txID, ttl, ok, tc.action, tc.txID, tc.ok)
		}
		if tc.ok && tc.ttlOK && ttl != 300*time.Second {
			t.Errorf("ttl = %v, want 300s", ttl)
		}
	}
}

func TestSign_SecondRequestUsesLease(t *testing.T) {
	cfg := config.Config{
		ApprovalTimeout:       60 * time.Second,
		TelegramWebhookSecret: "whsec-test",
		AllowedTTLSeconds:     []int{300},
	}
	env := startTestServer(t, cfg, nil)

	body := buildSignBody(t, "deploy", "10.0.0.5")
	txID := postSign(t, env, body)

	upd := map[string]any{
		"callback_query": map[string]any{
			"id":   "cq1",
			"data": "approve:" + txID + ":300",
			"message": map[string]any{
				"chat": map[string]any{"id": 99},
			},
		},
	}
	raw, _ := json.Marshal(upd)
	resp := postTelegramWebhook(t, env, "whsec-test", raw)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook %d", resp.StatusCode)
	}

	waitResp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatal(err)
	}
	waitResp.Body.Close()
	if waitResp.StatusCode != http.StatusOK {
		t.Fatalf("first wait %d", waitResp.StatusCode)
	}

	_, clientTLS := loadTestTLSConfigs(t)
	env.client = newMTLSClient(t, env.ts, clientTLS)
	txID2 := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))
	waitResp2, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID2 + "/wait")
	if err != nil {
		t.Fatal(err)
	}
	defer waitResp2.Body.Close()
	if waitResp2.StatusCode != http.StatusOK {
		t.Fatalf("lease wait status = %d, want 200", waitResp2.StatusCode)
	}
}
