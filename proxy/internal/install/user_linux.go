//go:build linux

package install

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
)

// EnsureServiceUser creates a system user and group when missing (Linux useradd/groupadd).
func EnsureServiceUser(username, group string) error {
	if username == "" {
		return fmt.Errorf("service user name required")
	}
	if group == "" {
		group = username
	}
	if err := ensureGroup(group); err != nil {
		return err
	}
	if _, err := user.Lookup(username); err == nil {
		return nil
	}
	home := filepath.Join("/var/lib", username)
	args := []string{
		"--system",
		"--home-dir", home,
		"--shell", "/usr/sbin/nologin",
		"--no-create-home",
		"--gid", group,
		username,
	}
	cmd := exec.Command("useradd", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("useradd %s: %w (%s)", username, err, trimOutput(out))
	}
	return nil
}

// EnsureLunaDirs creates standard config paths for the service user.
func EnsureLunaDirs(username, group string) error {
	gid := lookupGID(group)
	dirs := []string{
		"/etc/luna",
		"/etc/luna/certs",
		"/etc/luna/ssh",
		filepath.Join("/var/lib", username),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if gid >= 0 {
			if err := os.Chown(dir, 0, gid); err != nil {
				return fmt.Errorf("chown %s: %w", dir, err)
			}
		}
	}
	return nil
}

// EnsureCertPermissions grants the service group read access to mTLS PEM files.
func EnsureCertPermissions(dir, group string) error {
	gid := lookupGID(group)
	if gid < 0 {
		return fmt.Errorf("group %q not found", group)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(dir, e.Name())
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if err := os.Chown(path, int(stat.Uid), gid); err != nil {
			return fmt.Errorf("chown %s: %w", path, err)
		}
		switch {
		case e.Name() == "server.key" || e.Name() == "ca.key":
			if err := os.Chmod(path, 0o640); err != nil {
				return err
			}
		case e.Name() == "admin-client.key" || e.Name() == "client.key":
			if err := os.Chmod(path, 0o600); err != nil {
				return err
			}
		case strings.HasSuffix(e.Name(), ".key"):
			if err := os.Chmod(path, 0o600); err != nil {
				return err
			}
		case strings.HasSuffix(e.Name(), ".crt"):
			if err := os.Chmod(path, 0o644); err != nil {
				return err
			}
		}
	}
	return nil
}

func ensureGroup(group string) error {
	if lookupGID(group) >= 0 {
		return nil
	}
	cmd := exec.Command("groupadd", "--system", group)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("groupadd %s: %w (%s)", group, err, trimOutput(out))
	}
	return nil
}

func lookupGID(group string) int {
	g, err := user.LookupGroup(group)
	if err != nil {
		return -1
	}
	var gid int
	if _, err := fmt.Sscanf(g.Gid, "%d", &gid); err != nil {
		return -1
	}
	return gid
}

func trimOutput(b []byte) string {
	return strings.TrimSpace(string(b))
}
