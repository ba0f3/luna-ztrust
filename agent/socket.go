package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// UserSocketPath returns a user-writable agent socket path (XDG runtime or ~/.cache).
func UserSocketPath() string {
	if d := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); d != "" {
		return filepath.Join(d, "luna", "agent.sock")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".cache", "luna", "agent.sock")
	}
	return filepath.Join(home, ".cache", "luna", "agent.sock")
}

// ResolveSocketPath picks a Unix socket path the current process can bind.
// Explicit non-/run/luna paths are unchanged. Production paths are kept when
// /run/luna already exists and is writable (systemd RuntimeDirectory=luna).
func ResolveSocketPath(configured string) string {
	configured = strings.TrimSpace(configured)
	if configured == "" {
		configured = defaultSocketPath
	}
	if !isProductionRuntimeSocket(configured) {
		return configured
	}
	if productionSocketDirUsable(filepath.Dir(configured)) {
		return configured
	}
	if os.Geteuid() == 0 {
		return configured
	}
	return UserSocketPath()
}

// EnsureSocketDir creates the parent directory for a Unix socket path.
func EnsureSocketDir(socketPath string) error {
	dir := filepath.Dir(socketPath)
	if dir == "" || dir == "." {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return formatSocketDirError(socketPath, dir, err)
	}
	return nil
}

func productionSocketDirUsable(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	f, err := os.CreateTemp(dir, ".luna-writetest-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
}

func formatSocketDirError(socketPath, dir string, err error) error {
	if !isProductionRuntimeSocket(socketPath) {
		return fmt.Errorf("create socket directory %s: %w", dir, err)
	}
	return fmt.Errorf(`create socket directory %s: %w

/run/luna requires root or systemd (RuntimeDirectory=luna).
Start with: sudo systemctl enable --now luna-agent

For a manual non-root run, set agent_socket in agent.yml, for example:
  agent_socket: %s`, dir, err, UserSocketPath())
}

func isProductionRuntimeSocket(socketPath string) bool {
	socketPath = filepath.Clean(socketPath)
	return socketPath == defaultSocketPath || strings.HasPrefix(socketPath, "/run/luna/")
}
