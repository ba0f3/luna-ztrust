package approval

import (
	"strconv"
	"strings"
	"time"
)

// ParseCallbackData parses Telegram inline keyboard callback_data.
// Forms: deny:tx_… | approve:tx_…:ttl_seconds
func ParseCallbackData(data string, allowedTTLs []int) (action, txID string, ttl time.Duration, ok bool) {
	parts := strings.Split(data, ":")
	if len(parts) < 2 {
		return "", "", 0, false
	}
	action = parts[0]
	switch action {
	case "deny":
		if len(parts) != 2 || !strings.HasPrefix(parts[1], "tx_") {
			return "", "", 0, false
		}
		return action, parts[1], 0, true
	case "approve":
		if len(parts) < 2 || !strings.HasPrefix(parts[1], "tx_") {
			return "", "", 0, false
		}
		txID = parts[1]
		if len(parts) >= 3 {
			sec, err := strconv.Atoi(parts[2])
			if err != nil || !TTLAllowed(sec, allowedTTLs) {
				return "", "", 0, false
			}
			return action, txID, time.Duration(sec) * time.Second, true
		}
		return action, txID, 0, true
	default:
		return "", "", 0, false
	}
}

// TTLAllowed reports whether sec is in the configured approval TTL list.
func TTLAllowed(sec int, allowed []int) bool {
	for _, a := range allowed {
		if a == sec {
			return true
		}
	}
	return false
}

// DefaultTTLFromAllowed picks the first configured TTL or 5 minutes.
func DefaultTTLFromAllowed(allowed []int) time.Duration {
	if len(allowed) > 0 {
		return time.Duration(allowed[0]) * time.Second
	}
	return 5 * time.Minute
}

// ChatAllowed reports whether chatID matches configured TELEGRAM_CHAT_ID.
func ChatAllowed(configuredChatID string, chatID int64) bool {
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

// TelegramUserAllowed authorizes callback users. Private chats default to the
// configured positive chat ID; group chats require an explicit CSV allowlist.
func TelegramUserAllowed(configuredChatID, configuredUserIDs string, userID int64) bool {
	for _, raw := range strings.Split(configuredUserIDs, ",") {
		allowed, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
		if err == nil && allowed == userID {
			return true
		}
	}
	chatID, err := strconv.ParseInt(strings.TrimSpace(configuredChatID), 10, 64)
	return err == nil && chatID > 0 && chatID == userID
}
