//go:build linux

package control

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestCredAllowed_rootAndEUID(t *testing.T) {
	euid := uint32(os.Geteuid())
	if err := credAllowed(0, 0, ""); err != nil {
		t.Fatalf("root uid: %v", err)
	}
	if err := credAllowed(euid, 0, ""); err != nil {
		t.Fatalf("same euid: %v", err)
	}
}

func TestCredAllowed_foreignUIDRequiresGroup(t *testing.T) {
	euid := uint32(os.Geteuid())
	foreign := euid + 1
	if foreign == 0 {
		foreign = euid + 2
	}
	if err := credAllowed(foreign, 0, ""); err == nil {
		t.Fatal("expected error for foreign uid without group")
	}
}

func TestCredAllowed_unknownGroup(t *testing.T) {
	euid := uint32(os.Geteuid())
	foreign := euid + 1
	if foreign == 0 {
		foreign = euid + 2
	}
	err := credAllowed(foreign, 0, "luna-ztrust-nonexistent-group-xyz")
	if err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestPeerAllowed_sameEUIDUnixConn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctl.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			errCh <- net.InvalidAddrError("expected unix conn")
			return
		}
		errCh <- peerAllowed(uc, "")
	}()

	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := <-errCh; err != nil {
		t.Fatalf("peerAllowed: %v", err)
	}
}
