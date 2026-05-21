package config

import "time"

// Config holds proxy runtime settings.
type Config struct {
	Env                  string
	ApprovalTimeout      time.Duration
	TelegramBotToken     string
	TelegramWebhookSecret string
	TelegramChatID       string
}
