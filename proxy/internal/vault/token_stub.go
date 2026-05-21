//go:build !linux

package vault

import "errors"

// ErrNotSupported is returned when vault-agent token handoff is unavailable on this platform.
var ErrNotSupported = errors.New("vault-agent token handoff not supported on this platform")

// ReadTokenFromAgent is only implemented on Linux.
func ReadTokenFromAgent(socketPath string, allowedUID int) (string, error) {
	_ = socketPath
	_ = allowedUID
	return "", ErrNotSupported
}
