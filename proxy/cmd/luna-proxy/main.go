package main

import (
	"log"
	"os"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/api"
	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
)

func main() {
	cfg := config.Config{
		Env:                   os.Getenv("LUNA_ENV"),
		ApprovalTimeout:       60 * time.Second,
		TelegramBotToken:      os.Getenv("TELEGRAM_BOT_TOKEN"),
		TelegramWebhookSecret: os.Getenv("TELEGRAM_WEBHOOK_SECRET"),
		TelegramChatID:        os.Getenv("TELEGRAM_CHAT_ID"),
		AdminClientOU:         envOrDefault("LUNA_ADMIN_CLIENT_OU", "luna-admin"),
		KeyPath:               os.Getenv("LUNA_KEY_PATH"),
		SignerMode:            envOrDefault("LUNA_SIGNER_MODE", "local-ca"),
		AllowedTTLSeconds:     []int{180, 300, 900},
	}
	if v := os.Getenv("LUNA_APPROVAL_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("LUNA_APPROVAL_TIMEOUT: %v", err)
		}
		cfg.ApprovalTimeout = d
	}

	store := approval.NewStore(cfg.ApprovalTimeout)
	store.SetConfig(cfg)
	replay := auth.NewReplayLRU(60*time.Second, 1000)

	ks := keystore.New()
	if cfg.SignerMode == approval.SignerModeLocalKey {
		store.SetKeySigner(signing.NewLocalKey(ks))
	} else {
		store.SetIssuer(signing.NewLocalCA(ks))
	}
	store.SetLeases(lease.NewStore())

	tlsCfg, err := api.TLSConfigFromEnv()
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	addr := ":8443"
	if v := os.Getenv("LUNA_LISTEN_ADDR"); v != "" {
		addr = v
	}

	telegram := approval.NewNotifier(approval.NotifierConfig{
		BotToken:          cfg.TelegramBotToken,
		ChatID:            cfg.TelegramChatID,
		AllowedTTLSeconds: cfg.AllowedTTLSeconds,
	})
	handler := api.NewServer(cfg, ks, store, replay, telegram)
	srv := api.NewHTTPServer(addr, handler, tlsCfg)
	log.Printf("luna-proxy listening on %s (signer=%s)", addr, cfg.SignerMode)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
