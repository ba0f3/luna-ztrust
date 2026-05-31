package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"time"
)

const controlReadTimeout = 30 * time.Second

// ServeUnix listens on path and handles one request per connection.
func (s *Server) ServeUnix(path, group string) error {
	dirMode := os.FileMode(0o700)
	sockMode := os.FileMode(0o600)
	if group != "" {
		if _, err := user.LookupGroup(group); err == nil {
			dirMode = 0o750
			sockMode = 0o660
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil && !os.IsExist(err) {
		return err
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", path, err)
	}
	// Best-effort permissions; production should set group via systemd.
	_ = os.Chmod(path, sockMode)

	uLn, ok := ln.(*net.UnixListener)
	if !ok {
		return fmt.Errorf("expected unix listener")
	}

	for {
		conn, err := uLn.AcceptUnix()
		if err != nil {
			return err
		}
		go s.serveConn(conn, group)
	}
}

func (s *Server) serveConn(conn *net.UnixConn, group string) {
	defer conn.Close()
	if err := peerAllowed(conn, group); err != nil {
		log.Printf("control: peer denied: %v", err)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(controlReadTimeout))
	sc := bufio.NewScanner(conn)
	if !sc.Scan() {
		return
	}
	var req Request
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		_ = writeResponse(conn, Response{OK: false, Error: "invalid json", Code: "BAD_REQUEST"})
		return
	}
	resp := s.handle(req)
	_ = writeResponse(conn, resp)
}

func writeResponse(conn *net.UnixConn, resp Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_, err = conn.Write(b)
	return err
}
