package config

import "time"

// Config holds proxy runtime settings.
type Config struct {
	Env                   string
	ApprovalTimeout       time.Duration
	ListenAddr            string
	TelegramBotToken      string
	TelegramWebhookSecret string
	TelegramChatID        string
	AdminClientOU         string
	KeyPath               string
	SignerMode            string
	AllowedTTLSeconds     []int
	MTLSServerCert        string
	MTLSServerKey         string
	MTLSClientCA          string
	FCMCredentials        string
	ControlSocket         string
	ControlSocketGroup    string
}
