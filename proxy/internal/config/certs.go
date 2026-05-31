package config

import (
	"os"
	"path/filepath"
)

// DefaultCertsDir is the production mTLS directory written by `luna-proxy setup mtls`.
const DefaultCertsDir = "/etc/luna/certs"

// ProductionCertPath returns the default on-disk path for a PEM under DefaultCertsDir.
func ProductionCertPath(name string) string {
	return filepath.Join(DefaultCertsDir, name)
}

func devCertPath(name string) string {
	for _, base := range []string{
		"testdata/ca",
		filepath.Join("..", "..", "testdata", "ca"),
	} {
		p := filepath.Join(base, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join("testdata", "ca", name)
}

func applyMTLSDefaults(cfg *Config) {
	if isDevOrTestEnv(cfg.Env) {
		if cfg.MTLSServerCert == "" {
			cfg.MTLSServerCert = devCertPath("server.crt")
		}
		if cfg.MTLSServerKey == "" {
			cfg.MTLSServerKey = devCertPath("server.key")
		}
		if cfg.MTLSClientCA == "" {
			cfg.MTLSClientCA = devCertPath("ca.crt")
		}
		return
	}
	if cfg.MTLSServerCert == "" {
		cfg.MTLSServerCert = ProductionCertPath("server.crt")
	}
	if cfg.MTLSServerKey == "" {
		cfg.MTLSServerKey = ProductionCertPath("server.key")
	}
	if cfg.MTLSClientCA == "" {
		cfg.MTLSClientCA = ProductionCertPath("ca.crt")
	}
	if cfg.MTLSCACertPath == "" {
		cfg.MTLSCACertPath = ProductionCertPath("ca.crt")
	}
	if cfg.MTLSCAKeyPath == "" {
		cfg.MTLSCAKeyPath = ProductionCertPath("ca.key")
	}
}
