//go:build linux

package control

import (
	"fmt"
	"net"
	"os"
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
	return credAllowed(ucred.Uid, ucred.Gid, groupName)
}

func credAllowed(peerUID, peerGID uint32, groupName string) error {
	if peerUID == 0 {
		return nil
	}
	if peerUID == uint32(os.Geteuid()) {
		return nil
	}
	if groupName == "" {
		return fmt.Errorf("peer uid %d not allowed", peerUID)
	}
	g, err := user.LookupGroup(groupName)
	if err != nil {
		return fmt.Errorf("lookup group %q: %w", groupName, err)
	}
	var wantGID uint32
	if _, err := fmt.Sscanf(g.Gid, "%d", &wantGID); err != nil {
		return fmt.Errorf("parse gid: %w", err)
	}
	if peerGID == wantGID {
		return nil
	}
	return fmt.Errorf("peer uid %d gid %d not in group %s", peerUID, peerGID, groupName)
}
