package install

import (
	"fmt"
	"os"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

// EnsureDefaultProxyConfig requires proxy.yml from luna-proxy setup.
func EnsureDefaultProxyConfig(path, _, _ string) error {
	if path == "" {
		path = config.DefaultProxyConfigPath
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return fmt.Errorf("missing %s — run: sudo luna-proxy setup", path)
}
