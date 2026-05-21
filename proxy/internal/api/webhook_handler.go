package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

type telegramUpdate struct {
	CallbackQuery *telegramCallbackQuery `json:"callback_query"`
}

type telegramCallbackQuery struct {
	ID   string `json:"id"`
	Data string `json:"data"`
}

func (s *server) handleTelegramWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.TelegramWebhookSecret == "" {
		http.Error(w, "webhook not configured", http.StatusServiceUnavailable)
		return
	}
	secret := r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
	if secret == "" {
		secret = r.URL.Query().Get("secret")
	}
	if subtle.ConstantTimeCompare([]byte(secret), []byte(s.cfg.TelegramWebhookSecret)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}

	var upd telegramUpdate
	if err := json.Unmarshal(raw, &upd); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if upd.CallbackQuery == nil || upd.CallbackQuery.Data == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	action, txID, ok := ParseCallbackData(upd.CallbackQuery.Data)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch action {
	case "approve":
		s.store.Approve(txID, "")
	case "deny":
		s.store.Deny(txID)
	}

	w.WriteHeader(http.StatusOK)
}

// ParseCallbackData parses Telegram inline keyboard callback_data (approve:tx_… / deny:tx_…).
func ParseCallbackData(data string) (action, txID string, ok bool) {
	idx := strings.IndexByte(data, ':')
	if idx <= 0 || idx >= len(data)-1 {
		return "", "", false
	}
	action = data[:idx]
	txID = data[idx+1:]
	if !strings.HasPrefix(txID, "tx_") {
		return "", "", false
	}
	switch action {
	case "approve", "deny":
		return action, txID, true
	default:
		return "", "", false
	}
}
