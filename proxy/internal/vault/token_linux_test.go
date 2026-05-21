//go:build linux

package vault_test

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/vault"
)

func TestReadTokenFromAgent(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	want := "hvs.test-token-abc"
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(want + "\n"))
	}()

	got, err := vault.ReadTokenFromAgent(socketPath, os.Getuid())
	if err != nil {
		t.Fatalf("ReadTokenFromAgent: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want %q", got, want)
	}
	<-done
}

func TestReadTokenFromAgent_wrongUID(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("token\n"))
	}()

	const impossibleUID = 2147483646
	_, err = vault.ReadTokenFromAgent(socketPath, impossibleUID)
	if err == nil {
		t.Fatal("expected error for mismatched peer uid")
	}
}

func TestAgentTokenProvider(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "agent.sock")

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	want := "hvs.provider-token"
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(want))
	}()

	p := vault.AgentTokenProvider{SocketPath: socketPath, AllowedUID: int(os.Getuid())}
	got, err := p.Token(t.Context())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if got != want {
		t.Fatalf("token = %q, want %q", got, want)
	}
}
