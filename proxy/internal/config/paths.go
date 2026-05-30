package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const proxyConfigFile = "proxy.yml"

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

// proxyConfigPaths returns config file paths in merge order (later entries override earlier).
func proxyConfigPaths() []string {
	return []string{
		filepath.Join(".", proxyConfigFile),
		filepath.Join(userLunaConfigDir(), proxyConfigFile),
		filepath.Join("/etc/luna", proxyConfigFile),
	}
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
