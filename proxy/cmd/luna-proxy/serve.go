package main

import (
	"log"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/api"
	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/cli"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/control"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
	"github.com/ba0f3/luna-ztrust/proxy/internal/mobile"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the mTLS API and control socket",
	RunE:  runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

func runServe(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	store := approval.NewStore(cfg.ApprovalTimeout)
	store.SetConfig(cfg)
	replay := auth.NewReplayLRU(60*time.Second, 1000)

	ksMode := keystore.ModeLocalCA
	if cfg.SignerMode == approval.SignerModeLocalKey {
		ksMode = keystore.ModeLocalKey
	}
	ks := keystore.NewWithMode(ksMode)
	if cfg.SignerMode == approval.SignerModeLocalKey {
		store.SetKeySigner(signing.NewLocalKey(ks))
	} else {
		store.SetIssuer(signing.NewLocalCA(ks))
	}
	store.SetLeases(lease.NewStore())

	pending := keystore.NewPendingStore()
	mob := mobile.NewStore()

	tlsCfg, err := api.LoadTLSConfig(cfg.MTLSServerCert, cfg.MTLSServerKey, cfg.MTLSClientCA)
	if err != nil {
		return err
	}

	telegram := approval.NewNotifier(approval.NotifierConfig{
		BotToken:          cfg.TelegramBotToken,
		ChatID:            cfg.TelegramChatID,
		AllowedTTLSeconds: cfg.AllowedTTLSeconds,
	})
	cliStore := cli.NewStore()
	csrSigner, csrErr := cli.NewCSRSignerFromConfig(cfg)
	if csrErr != nil {
		log.Printf("luna-proxy: CLI CSR signer config: %v", csrErr)
	}
	loadLimiter := cli.NewLoadRateLimiter()
	handler := api.NewServer(api.ServerDeps{
		Config:      cfg,
		Keystore:    ks,
		Pending:     pending,
		Store:       store,
		Replay:      replay,
		Telegram:    telegram,
		Mobile:      mob,
		CLI:         cliStore,
		CSRSigner:   csrSigner,
		LoadLimiter: loadLimiter,
	})
	srv := api.NewHTTPServer(cfg.ListenAddr, handler, tlsCfg)

	ctrlPath := socketPath
	if ctrlPath == "" {
		ctrlPath = cfg.ControlSocket
	}
	if ctrlPath == "" {
		ctrlPath = config.DefaultControlSocket()
	}
	ctrl := control.NewServer(control.ServerDeps{
		Config:      cfg,
		Keystore:    ks,
		Mobile:      mob,
		Pending:     pending,
		Cli:         cliStore,
		CSRSigner:   csrSigner,
		LoadLimiter: loadLimiter,
	})
	go func() {
		log.Printf("luna-proxy control socket %s", ctrlPath)
		if err := ctrl.ServeUnix(ctrlPath, cfg.ControlSocketGroup); err != nil {
			log.Fatalf("control socket: %v", err)
		}
	}()

	log.Printf("luna-proxy listening on %s (signer=%s)", cfg.ListenAddr, cfg.SignerMode)
	return srv.ListenAndServeTLS("", "")
}
