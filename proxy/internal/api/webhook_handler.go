package api

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
)

type telegramUpdate struct {
	CallbackQuery *telegramCallbackQuery `json:"callback_query"`
}

type telegramCallbackQuery struct {
	ID      string           `json:"id"`
	Data    string           `json:"data"`
	Message *telegramMessage `json:"message"`
}

type telegramMessage struct {
	Chat telegramChat `json:"chat"`
}

type telegramChat struct {
	ID int64 `json:"id"`
}

func (s *server) handleTelegramWebhook(w http.ResponseWriter, r *http.Request) {
	if s.cfg.TelegramWebhookSecret == "" {
		http.Error(w, "webhook not configured", http.StatusServiceUnavailable)
		return
	}
	secret := r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
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

	action, txID, ttl, ok := ParseCallbackData(upd.CallbackQuery.Data, s.cfg.AllowedTTLSeconds)
	if !ok {
		w.WriteHeader(http.StatusOK)
		return
	}

	if upd.CallbackQuery.Message == nil || !telegramChatAllowed(s.cfg.TelegramChatID, upd.CallbackQuery.Message.Chat.ID) {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch action {
	case "approve":
		if ttl <= 0 {
			ttl = DefaultTTLFromAllowed(s.cfg.AllowedTTLSeconds)
		}
		approver := lease.FormatApproverChatID(upd.CallbackQuery.Message.Chat.ID)
		s.store.Approve(txID, ttl, approver)
	case "deny":
		s.store.Deny(txID)
	}

	w.WriteHeader(http.StatusOK)
}

// telegramChatAllowed reports whether chatID matches configured TELEGRAM_CHAT_ID.
func telegramChatAllowed(configuredChatID string, chatID int64) bool {
	configuredChatID = strings.TrimSpace(configuredChatID)
	if configuredChatID == "" {
		return false
	}
	allowed, err := strconv.ParseInt(configuredChatID, 10, 64)
	if err != nil {
		return false
	}
	return chatID == allowed
}
