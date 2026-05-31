package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ba0f3/luna-ztrust/agent"
	"github.com/ba0f3/luna-ztrust/agent/internal/version"
	"github.com/ba0f3/luna-ztrust/sdk"
	"github.com/spf13/cobra"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var rootCmd = &cobra.Command{
	Use:   "luna-agent",
	Short: "Luna Z-Trust SSH agent daemon",
	Long:  "SSH_AUTH_SOCK interceptor; blocks Sign until luna-proxy returns a cert or signature.",
	RunE:  runAgent,
}

func init() {
	rootCmd.AddCommand(installCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runAgent(_ *cobra.Command, _ []string) error {
	cfg, err := agent.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	tlsCert, tlsCA, err := sdk.LoadTLSConfig(cfg.MTLSCert, cfg.MTLSKey, cfg.MTLSCA)
	if err != nil {
		return fmt.Errorf("tls: %w", err)
	}

	signerMode := cfg.SignerMode

	client, err := sdk.NewClient(sdk.Config{
		ProxyURL:   cfg.ProxyURL,
		TLSCert:    tlsCert,
		TLSRootCAs: tlsCA,
		Timeout:    cfg.ApprovalTimeout,
		SignerMode: signerMode,
	})
	if err != nil {
		return fmt.Errorf("sdk client: %w", err)
	}

	identities, err := agent.ResolveIdentities(client, cfg)
	if err != nil {
		return fmt.Errorf("identities: %w", err)
	}

	la := agent.NewLunaAgent(client, signerMode, cfg.TargetUser, cfg.TargetHost, cfg.HostKeyFingerprint, identities, cfg.ApprovalTimeout)

	if agent.DebugEnabled() {
		log.Printf("luna-agent: signer_mode=%s target=%s@%s identities=%d",
			signerMode, cfg.TargetUser, cfg.TargetHost, len(identities))
	}

	if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove socket: %w", err)
	}

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.SocketPath, err)
	}
	defer ln.Close()

	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		return fmt.Errorf("chmod socket: %w", err)
	}

	if signerMode == agent.SignerModeLocalKey {
		log.Printf("luna-agent %s listening on %s (%d host key(s) from proxy capabilities)",
			version.String(), cfg.SocketPath, len(identities))
	} else {
		log.Printf("luna-agent %s listening on %s", version.String(), cfg.SocketPath)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = os.Remove(cfg.SocketPath)
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			sshagent.ServeAgent(la, c)
		}(conn)
	}
}
