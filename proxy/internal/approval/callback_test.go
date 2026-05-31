package approval_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
)

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
		action, txID, ttl, ok := approval.ParseCallbackData(tc.in, allowed)
		if ok != tc.ok || action != tc.action || txID != tc.txID {
			t.Errorf("ParseCallbackData(%q) = %q,%q,%v,%v; want %q,%q,_,%v",
				tc.in, action, txID, ttl, ok, tc.action, tc.txID, tc.ok)
		}
		if tc.ok && tc.ttlOK && ttl != 300*time.Second {
			t.Errorf("ttl = %v, want 300s", ttl)
		}
	}
}

func TestChatAllowed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cfg  string
		chat int64
		want bool
	}{
		{"4242", 4242, true},
		{"4242", 4243, false},
		{"", 4242, false},
		{" 99 ", 99, true},
		{"not-a-number", 1, false},
	}
	for _, tc := range cases {
		if got := approval.ChatAllowed(tc.cfg, tc.chat); got != tc.want {
			t.Errorf("ChatAllowed(%q, %d) = %v, want %v", tc.cfg, tc.chat, got, tc.want)
		}
	}
}

func TestPollerApproveCallback(t *testing.T) {
	store := approval.NewStore(time.Minute)
	store.SetConfig(config.Config{SignerMode: approval.SignerModeLocalCA})
	store.SetLeases(lease.NewStore())
	tx, _ := store.Create("deploy", "10.0.0.5", "ssh-ed25519 AAAA", "127.0.0.1", "fp", "", "")

	var mu sync.Mutex
	var outcomes []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/deleteWebhook"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			payload := map[string]any{
				"ok": true,
				"result": []any{
					map[string]any{
						"update_id": 1,
						"callback_query": map[string]any{
							"id":   "cq1",
							"data": "approve:" + tx.ID + ":300",
							"message": map[string]any{
								"chat": map[string]any{"id": 4242},
							},
						},
					},
				},
			}
			raw, _ := json.Marshal(payload)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(raw)
		case strings.HasSuffix(r.URL.Path, "/answerCallbackQuery"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	poller := approval.NewPoller(approval.PollerConfig{
		NotifierConfig: approval.NotifierConfig{
			BotToken:          "test-token",
			ChatID:            "4242",
			AllowedTTLSeconds: []int{300},
			BaseURL:           srv.URL,
			Client:            srv.Client(),
		},
		Store:       store,
		PollTimeout: 1 * time.Second,
		LogEvent: func(_, _, outcome, _ string) {
			mu.Lock()
			outcomes = append(outcomes, outcome)
			mu.Unlock()
		},
	})

	go poller.Run(ctx)
	time.Sleep(1500 * time.Millisecond)
	cancel()

	mu.Lock()
	defer mu.Unlock()
	for _, o := range outcomes {
		if o == "approved" {
			return
		}
	}
	t.Fatalf("outcomes = %v, want approved", outcomes)
}

func TestDeleteWebhook(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/deleteWebhook") {
			t.Fatalf("path = %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if len(body) == 0 {
			t.Fatal("expected body")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	if err := approval.DeleteWebhook(context.Background(), approval.NotifierConfig{
		BotToken: "test-token",
		BaseURL:  srv.URL,
		Client:   srv.Client(),
	}); err != nil {
		t.Fatal(err)
	}
}
