//go:build linux

package vault

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
)

const maxVaultTokenBytes = 64 * 1024

// ReadTokenFromAgent dials the vault-agent Unix socket, verifies the peer UID via
// SO_PEERCRED, and returns the token (trailing newline trimmed).
func ReadTokenFromAgent(socketPath string, allowedUID int) (string, error) {
	if socketPath == "" {
		return "", errors.New("vault agent socket path empty")
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("dial vault agent socket: %w", err)
	}
	defer conn.Close()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "", errors.New("vault agent connection is not unix")
	}
	peerUID, err := peerUID(uc)
	if err != nil {
		return "", fmt.Errorf("peer credentials: %w", err)
	}
	if int(peerUID) != allowedUID {
		return "", fmt.Errorf("peer uid %d does not match allowed uid %d", peerUID, allowedUID)
	}

	raw, err := io.ReadAll(io.LimitReader(conn, maxVaultTokenBytes+1))
	if err != nil {
		return "", fmt.Errorf("read vault agent token: %w", err)
	}
	if len(raw) > maxVaultTokenBytes {
		return "", fmt.Errorf("vault agent token exceeds %d bytes", maxVaultTokenBytes)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("vault agent token empty")
	}
	return token, nil
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		uid   uint32
		ucred *syscall.Ucred
		serr  error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, serr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if serr == nil {
			uid = ucred.Uid
		}
	})
	if ctrlErr != nil {
		return 0, ctrlErr
	}
	if serr != nil {
		return 0, serr
	}
	return uid, nil
}
