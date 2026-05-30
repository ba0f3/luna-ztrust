package config_test

import (
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func TestLoadRequiresMTLSOutsideDev(t *testing.T) {
	clearProxyEnv(t)
	chdirIsolated(t)
	t.Setenv("LUNA_ENV", "production")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error without explicit mTLS paths in production")
	}
}

func TestLoadRejectsTestdataCAInProduction(t *testing.T) {
	clearProxyEnv(t)
	chdirIsolated(t)
	t.Setenv("LUNA_ENV", "production")
	t.Setenv("LUNA_MTLS_SERVER_CERT", "testdata/ca/server.crt")
	t.Setenv("LUNA_MTLS_SERVER_KEY", "testdata/ca/server.key")
	t.Setenv("LUNA_MTLS_CLIENT_CA", "testdata/ca/ca.crt")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected error for testdata/ca paths")
	}
}

func TestLoadDevAllowsDefaultMTLS(t *testing.T) {
	clearProxyEnv(t)
	chdirIsolated(t)
	t.Setenv("LUNA_ENV", "dev")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.MTLSServerCert == "" || cfg.MTLSClientCA == "" {
		t.Fatal("expected dev default mTLS paths")
	}
}
