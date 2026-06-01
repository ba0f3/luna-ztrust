package approval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFormatApprovalMessage(t *testing.T) {
	msg := formatApprovalMessage(&Transaction{
		ID:            "tx_01",
		TargetUser:    "deploy",
		TargetIP:      "10.0.0.5",
		SourceIP:      "203.0.113.1",
		SourceUser:    "goclaw",
		ClientName:    "luna-agent",
		ClientVersion: "v0.1.0",
	})
	for _, want := range []string{
		"Target user: deploy",
		"Target host: 10.0.0.5",
		"Source IP: 203.0.113.1",
		"Source user: goclaw",
		"Client: luna-agent v0.1.0",
		"tx_01",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing %q in:\n%s", want, msg)
		}
	}
}

func TestFormatResolvedApprovalMessage(t *testing.T) {
	at := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	msg := formatResolvedApprovalMessage(&Transaction{
		ID:         "tx_01",
		TargetUser: "deploy",
		TargetIP:   "10.0.0.5",
	}, Resolution{
		Decision: "APPROVED",
		Approver: "telegram:4242",
		At:       at,
		TTL:      5 * time.Minute,
	})
	for _, want := range []string{
		"Status: APPROVED",
		"By: Telegram chat 4242",
		"At: 2026-06-01T12:00:00Z",
		"Lease TTL: 5m0s",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing %q in:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "Approve 3m") {
		t.Fatalf("should not contain keyboard labels: %s", msg)
	}
}

func TestEditMessageText(t *testing.T) {
	var gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	err := EditMessageText(context.Background(), NotifierConfig{
		BotToken: "tok",
		BaseURL:  srv.URL,
		Client:   srv.Client(),
	}, 4242, 99, "done")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(gotMethod, "/editMessageText") {
		t.Fatalf("method = %s", gotMethod)
	}
	if gotBody["message_id"] != float64(99) {
		t.Fatalf("message_id = %v", gotBody["message_id"])
	}
}
