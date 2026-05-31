package approval_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
)

func TestNotifierIdempotent(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
			t.Errorf("path = %s", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var payload struct {
			ChatID string `json:"chat_id"`
			Text   string `json:"text"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.ChatID != "12345" {
			t.Fatalf("chat_id = %q", payload.ChatID)
		}
		if !strings.Contains(payload.Text, "tx_") {
			t.Fatalf("text = %q", payload.Text)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	n := approval.NewNotifier(approval.NotifierConfig{
		BotToken: "test-token",
		ChatID:   "12345",
		BaseURL:  srv.URL,
		Client:   srv.Client(),
	})
	tx := &approval.Transaction{
		ID:         "tx_01TEST",
		TargetUser: "deploy",
		TargetIP:   "10.0.0.5",
		CreatedAt:  time.Now(),
	}

	ctx := context.Background()
	if err := n.Notify(ctx, tx); err != nil {
		t.Fatalf("first notify: %v", err)
	}
	if err := n.Notify(ctx, tx); err != nil {
		t.Fatalf("second notify: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("HTTP calls = %d, want 1", got)
	}
}

func TestNotifierNoOpWhenUnconfigured(t *testing.T) {
	n := approval.NewNotifier(approval.NotifierConfig{})
	if n.Configured() {
		t.Fatal("expected unconfigured")
	}
	tx := &approval.Transaction{ID: "tx_01"}
	if err := n.Notify(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
}
