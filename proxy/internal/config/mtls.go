package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func isDevOrTestEnv(env string) bool {
	switch strings.TrimSpace(env) {
	case "dev", "test":
		return true
	default:
		return false
	}
}

func validateMTLS(cfg Config) error {
	if isDevOrTestEnv(cfg.Env) {
		return nil
	}
	var missing []string
	if cfg.MTLSServerCert == "" {
		missing = append(missing, "mtls_server_cert (LUNA_MTLS_SERVER_CERT)")
	}
	if cfg.MTLSServerKey == "" {
		missing = append(missing, "mtls_server_key (LUNA_MTLS_SERVER_KEY)")
	}
	if cfg.MTLSClientCA == "" {
		missing = append(missing, "mtls_client_ca (LUNA_MTLS_CLIENT_CA)")
	}
	if len(missing) > 0 {
		return fmt.Errorf("production requires explicit mTLS paths: %s", strings.Join(missing, ", "))
	}
	for _, p := range []struct {
		name, path string
	}{
		{"mtls_server_cert", cfg.MTLSServerCert},
		{"mtls_server_key", cfg.MTLSServerKey},
		{"mtls_client_ca", cfg.MTLSClientCA},
	} {
		if err := rejectTestdataCAPath(p.name, p.path); err != nil {
			return err
		}
		if _, err := os.Stat(p.path); err != nil {
			return fmt.Errorf("%s %q: %w", p.name, p.path, err)
		}
	}
	return nil
}

func rejectTestdataCAPath(name, path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	abs = filepath.Clean(abs)
	if strings.Contains(abs, string(filepath.Separator)+"testdata"+string(filepath.Separator)+"ca"+string(filepath.Separator)) {
		return fmt.Errorf("%s must not use repository testdata/ca (got %q)", name, path)
	}
	return nil
}
