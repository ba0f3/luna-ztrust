package main

import (
	"log"
	"os"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/api"
	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/vault"
)

func main() {
	cfg := config.Config{
		Env:             os.Getenv("LUNA_ENV"),
		ApprovalTimeout: 60 * time.Second,
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

	tlsCfg, err := api.TLSConfigFromEnv()
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	addr := ":8443"
	if v := os.Getenv("LUNA_LISTEN_ADDR"); v != "" {
		addr = v
	}

	vaultCfg := vault.SignConfig{VaultAddr: os.Getenv("LUNA_VAULT_ADDR")}
	handler := api.NewServer(cfg, store, replay, vaultCfg, vault.UnavailableTokenProvider{})
	srv := api.NewHTTPServer(addr, handler, tlsCfg)
	log.Printf("luna-proxy listening on %s", addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}
