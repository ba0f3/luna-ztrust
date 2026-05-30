package api

import "net"

// clientIPFromRemoteAddr returns the host part of a TCP RemoteAddr (no port).
func clientIPFromRemoteAddr(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return host
}
