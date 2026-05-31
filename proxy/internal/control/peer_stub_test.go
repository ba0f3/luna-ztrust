//go:build !linux

package control

import (
	"net"
	"path/filepath"
	"testing"
)

func TestPeerAllowed_stubRejects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ctl.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix listen: %v", err)
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
	if err := <-errCh; err == nil {
		t.Fatal("expected stub rejection on non-linux")
	}
}
