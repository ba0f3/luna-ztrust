package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
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

	vaultAddr := os.Getenv("LUNA_VAULT_ADDR")
	if vaultAddr == "" {
		vaultAddr = os.Getenv("VAULT_ADDR")
	}
	vaultCfg := vault.SignConfig{VaultAddr: vaultAddr}
	if mount := os.Getenv("VAULT_SSH_MOUNT"); mount != "" {
		role := os.Getenv("VAULT_SSH_ROLE")
		if role == "" {
			role = "agent-role"
		}
		vaultCfg.SignPath = fmt.Sprintf("/v1/%s/sign/%s", mount, role)
	}

	var tokens vault.TokenProvider = vault.UnavailableTokenProvider{}
	if sock := os.Getenv("VAULT_AGENT_SOCKET"); sock != "" {
		uidStr := os.Getenv("VAULT_AGENT_UID")
		if uidStr == "" {
			log.Fatal("VAULT_AGENT_UID required when VAULT_AGENT_SOCKET is set")
		}
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			log.Fatalf("VAULT_AGENT_UID: %v", err)
		}
		tokens = vault.AgentTokenProvider{SocketPath: sock, AllowedUID: uid}
	}

	handler := api.NewServer(cfg, store, replay, vaultCfg, tokens)
	srv := api.NewHTTPServer(addr, handler, tlsCfg)
	log.Printf("luna-proxy listening on %s", addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}
