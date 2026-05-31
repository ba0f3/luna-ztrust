package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const defaultControlSocketName = "control.sock"

// ProductionControlSocket is the default Unix control socket for systemd (RuntimeDirectory=luna).
const ProductionControlSocket = "/run/luna/control.sock"

// DefaultProxyConfigPath is the conventional production proxy.yml location.
const DefaultProxyConfigPath = "/etc/luna/proxy.yml"

const proxyConfigName = "proxy"

func userLunaConfigDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "luna")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "luna")
	}
	return filepath.Join(home, ".config", "luna")
}

// DefaultControlSocket returns a user-writable path for dev/non-root runs.
// Production systemd units should set control_socket explicitly (e.g. /run/luna/control.sock
// with RuntimeDirectory=luna).
func DefaultControlSocket() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "luna", defaultControlSocketName)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "run", "luna", defaultControlSocketName)
	}
	return filepath.Join("/run", "luna", defaultControlSocketName)
}

// proxyConfigPaths returns config file paths in merge order (later entries override earlier).
// Each location accepts proxy.yml or proxy.yaml.
func proxyConfigPaths() []string {
	bases := []string{
		".",
		userLunaConfigDir(),
		"/etc/luna",
	}
	var paths []string
	for _, base := range bases {
		for _, ext := range []string{".yml", ".yaml"} {
			paths = append(paths, filepath.Join(base, proxyConfigName+ext))
		}
	}
	return paths
}

func mergeConfigFiles(v *viper.Viper, paths []string) error {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		v.SetConfigFile(path)
		if err := v.MergeInConfig(); err != nil {
			return fmt.Errorf("read config %q: %w", path, err)
		}
	}
	return nil
}
