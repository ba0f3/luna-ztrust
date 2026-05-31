package install

import (
	"fmt"
	"os"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/setup"
)

// EnsureDefaultProxyConfig writes proxy.yml with a generated mtls_enroll_token when missing.
func EnsureDefaultProxyConfig(path, username, group string) error {
	if path == "" {
		path = config.DefaultProxyConfigPath
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	res, err := setup.WriteProxyConfig(setup.ProxyConfigOptions{
		Path:  path,
		User:  username,
		Group: group,
	})
	if err != nil {
		return err
	}
	fmt.Printf("wrote default config %s\n", res.Path)
	fmt.Println()
	fmt.Println("Agent bootstrap password (mtls_enroll_token):")
	fmt.Printf("  %s\n", res.EnrollToken)
	fmt.Println("  on agent host: export LUNA_MTLS_ENROLL_TOKEN='...'  or  luna-agent setup")
	return nil
}
