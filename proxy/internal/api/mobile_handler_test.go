package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func TestMobileEnrollAndApprove(t *testing.T) {
	cfg := config.Config{
		ApprovalTimeout:   60 * time.Second,
		AdminClientOU:     "luna-admin",
		AllowedTTLSeconds: []int{180, 300, 900},
	}
	env := startTestServerDefault(t, cfg)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	enrollBody, _ := json.Marshal(map[string]string{
		"label":         "test-phone",
		"device_pubkey": base64.StdEncoding.EncodeToString(pub),
	})
	_, adminTLS, automationTLS := loadAdminTLSConfigs(t)
	admin := newMTLSClient(t, env.ts, adminTLS)
	enrollBody, _ = json.Marshal(map[string]string{
		"label":            "test-phone",
		"device_pubkey":    base64.StdEncoding.EncodeToString(pub),
		"cert_fingerprint": tlsCertFingerprint(t, automationTLS),
	})
	resp, err := admin.http.Post(env.ts.URL+"/api/v1/mobile/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll status %d: %s", resp.StatusCode, b)
	}
	var enrollOut struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&enrollOut); err != nil {
		t.Fatal(err)
	}
	if enrollOut.DeviceID == "" {
		t.Fatal("empty device_id")
	}

	signBody := buildSignBody(t, "deploy", "10.0.0.5")
	txID := postSign(t, env, signBody)

	ts := time.Now().Unix()
	type signPayload struct {
		TxID       string `json:"tx_id"`
		Action     string `json:"action"`
		TTLSeconds int    `json:"ttl_seconds"`
		DeviceID   string `json:"device_id"`
		Timestamp  int64  `json:"timestamp"`
	}
	sp := signPayload{
		TxID:       txID,
		Action:     "approve",
		TTLSeconds: 300,
		DeviceID:   enrollOut.DeviceID,
		Timestamp:  ts,
	}
	payloadBytes, err := json.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payloadBytes)
	approveBody, _ := json.Marshal(struct {
		signPayload
		Signature string `json:"signature"`
	}{sp, hex.EncodeToString(sig)})

	resp, err = admin.http.Post(env.ts.URL+"/api/v1/mobile/approve", "application/json", bytes.NewReader(approveBody))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("mismatched mobile cert status %d, want 403", resp.StatusCode)
	}

	resp, err = env.client.http.Post(env.ts.URL+"/api/v1/mobile/approve", "application/json", bytes.NewReader(approveBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("approve status %d: %s", resp.StatusCode, b)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cert, _, _, _, err := env.store.Wait(ctx, txID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if cert == "" {
		t.Fatal("expected certificate after mobile approve")
	}
}

func TestMobileDeleteDevice(t *testing.T) {
	cfg := config.Config{
		ApprovalTimeout: 60 * time.Second,
		AdminClientOU:   "luna-admin",
	}
	env := startTestServerDefault(t, cfg)
	_, adminTLS, automationTLS := loadAdminTLSConfigs(t)
	admin := newMTLSClient(t, env.ts, adminTLS)

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	enrollBody, _ := json.Marshal(map[string]string{
		"label":            "d",
		"device_pubkey":    base64.StdEncoding.EncodeToString(pub),
		"cert_fingerprint": tlsCertFingerprint(t, automationTLS),
	})
	resp, err := admin.http.Post(env.ts.URL+"/api/v1/mobile/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		DeviceID string `json:"device_id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()

	req, _ := http.NewRequest(http.MethodDelete, env.ts.URL+"/api/v1/mobile/devices/"+out.DeviceID, nil)
	resp, err = admin.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
}

func TestMobileKeysPendingRequiresDeviceSignature(t *testing.T) {
	cfg := config.Config{
		ApprovalTimeout: 60 * time.Second,
		AdminClientOU:   "luna-admin",
	}
	env := startTestServerDefault(t, cfg)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, adminTLS, automationTLS := loadAdminTLSConfigs(t)
	admin := newMTLSClient(t, env.ts, adminTLS)
	enrollBody, _ := json.Marshal(map[string]string{
		"label":            "upload-phone",
		"device_pubkey":    base64.StdEncoding.EncodeToString(pub),
		"cert_fingerprint": tlsCertFingerprint(t, automationTLS),
	})
	resp, err := admin.http.Post(env.ts.URL+"/api/v1/mobile/enroll", "application/json", bytes.NewReader(enrollBody))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var enrollOut struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&enrollOut); err != nil {
		t.Fatal(err)
	}

	postPending := func(body []byte) (int, []byte) {
		t.Helper()
		resp, err := env.client.http.Post(env.ts.URL+"/api/v1/mobile/keys/pending", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}

	unsigned, _ := json.Marshal(map[string]any{
		"device_id":     enrollOut.DeviceID,
		"encrypted_pem": base64.StdEncoding.EncodeToString([]byte("blob")),
		"label":         "k1",
	})
	if st, _ := postPending(unsigned); st != http.StatusBadRequest {
		t.Fatalf("unsigned status = %d, want 400", st)
	}

	now := time.Now().Unix()
	enc := base64.StdEncoding.EncodeToString([]byte("blob"))
	type signPayload struct {
		DeviceID     string `json:"device_id"`
		EncryptedPEM string `json:"encrypted_pem"`
		Label        string `json:"label"`
		Timestamp    int64  `json:"timestamp"`
	}
	sp := signPayload{
		DeviceID:     enrollOut.DeviceID,
		EncryptedPEM: enc,
		Label:        "k1",
		Timestamp:    now,
	}
	payloadBytes, err := json.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, payloadBytes)
	signed, _ := json.Marshal(struct {
		signPayload
		Signature string `json:"signature"`
	}{sp, hex.EncodeToString(sig)})

	st, body := postPending(signed)
	if st != http.StatusAccepted {
		t.Fatalf("signed status = %d, body = %s", st, body)
	}
}
