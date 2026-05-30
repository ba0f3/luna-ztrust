//go:build !linux

package control

import (
	"fmt"
	"net"
)

func peerAllowed(_ *net.UnixConn, _ string) error {
	return fmt.Errorf("control socket requires linux")
}
