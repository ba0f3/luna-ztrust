package main

import (
	"log"
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
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
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

	tlsCfg, err := api.LoadTLSConfig(cfg.MTLSServerCert, cfg.MTLSServerKey, cfg.MTLSClientCA)
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	telegram := approval.NewNotifier(approval.NotifierConfig{
		BotToken:          cfg.TelegramBotToken,
		ChatID:            cfg.TelegramChatID,
		AllowedTTLSeconds: cfg.AllowedTTLSeconds,
	})
	handler := api.NewServer(cfg, ks, store, replay, telegram)
	srv := api.NewHTTPServer(cfg.ListenAddr, handler, tlsCfg)
	log.Printf("luna-proxy listening on %s (signer=%s)", cfg.ListenAddr, cfg.SignerMode)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}
