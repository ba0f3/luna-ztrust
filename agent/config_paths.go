package agent

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

const agentConfigName = "agent"

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

func agentConfigPaths() []string {
	bases := []string{
		".",
		userLunaConfigDir(),
		"/etc/luna",
	}
	var paths []string
	for _, base := range bases {
		for _, ext := range []string{".yml", ".yaml"} {
			paths = append(paths, filepath.Join(base, agentConfigName+ext))
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
