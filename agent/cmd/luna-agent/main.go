package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ba0f3/luna-ztrust/agent"
	"github.com/ba0f3/luna-ztrust/sdk"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func main() {
	cfg, err := agent.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	tlsCert, tlsCA, err := sdk.LoadTLSConfig(cfg.MTLSCert, cfg.MTLSKey, cfg.MTLSCA)
	if err != nil {
		log.Fatalf("tls: %v", err)
	}

	signerMode := cfg.SignerMode

	client, err := sdk.NewClient(sdk.Config{
		ProxyURL:   cfg.ProxyURL,
		TLSCert:    tlsCert,
		TLSRootCAs: tlsCA,
		Timeout:    90 * time.Second,
		SignerMode: signerMode,
	})
	if err != nil {
		log.Fatalf("sdk client: %v", err)
	}

	la := agent.NewLunaAgent(client, signerMode, cfg.TargetUser, cfg.TargetHost)

	if err := os.Remove(cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("remove socket: %v", err)
	}

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.SocketPath, err)
	}
	defer ln.Close()

	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		log.Fatalf("chmod socket: %v", err)
	}

	log.Printf("luna-agent listening on %s", cfg.SocketPath)

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
