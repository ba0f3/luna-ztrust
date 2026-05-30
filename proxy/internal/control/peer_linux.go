//go:build linux

package control

import (
	"fmt"
	"net"
	"os/user"
	"syscall"
)

func peerAllowed(conn *net.UnixConn, groupName string) error {
	raw, err := conn.File()
	if err != nil {
		return fmt.Errorf("peer file: %w", err)
	}
	defer raw.Close()

	ucred, err := syscall.GetsockoptUcred(int(raw.Fd()), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return fmt.Errorf("peer cred: %w", err)
	}
	if ucred.Uid == 0 {
		return nil
	}
	if groupName == "" {
		return fmt.Errorf("peer uid %d not allowed", ucred.Uid)
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("lookup group %q: %w", groupName, err)
	}
	var wantGID uint32
	if _, err := fmt.Sscanf(g.Gid, "%d", &wantGID); err != nil {
		return fmt.Errorf("parse gid: %w", err)
	}
	if uint32(ucred.Gid) == wantGID {
		return nil
	}
	return fmt.Errorf("peer uid %d gid %d not in group %s", ucred.Uid, ucred.Gid, groupName)
}
