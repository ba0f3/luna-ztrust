package config

import "testing"

func TestApplyMTLSDefaultsProduction(t *testing.T) {
	cfg := Config{Env: "production"}
	applyMTLSDefaults(&cfg)
	if cfg.MTLSServerCert != ProductionCertPath("server.crt") {
		t.Fatalf("server cert: %q", cfg.MTLSServerCert)
	}
	if cfg.MTLSServerKey != ProductionCertPath("server.key") {
		t.Fatalf("server key: %q", cfg.MTLSServerKey)
	}
	if cfg.MTLSClientCA != ProductionCertPath("ca.crt") {
		t.Fatalf("client ca: %q", cfg.MTLSClientCA)
	}
	if cfg.MTLSCACertPath != ProductionCertPath("ca.crt") {
		t.Fatalf("ca cert path: %q", cfg.MTLSCACertPath)
	}
	if cfg.MTLSCAKeyPath != ProductionCertPath("ca.key") {
		t.Fatalf("ca key path: %q", cfg.MTLSCAKeyPath)
	}
}

func TestApplyMTLSDefaultsDev(t *testing.T) {
	cfg := Config{Env: "dev"}
	applyMTLSDefaults(&cfg)
	if cfg.MTLSServerCert == "" || cfg.MTLSClientCA == "" {
		t.Fatal("expected dev testdata defaults")
	}
	if cfg.MTLSCACertPath != "" || cfg.MTLSCAKeyPath != "" {
		t.Fatal("dev should not default CLI CA paths")
	}
}

func TestApplyMTLSDefaultsPreservesExplicit(t *testing.T) {
	cfg := Config{
		Env:            "production",
		MTLSServerCert: "/custom/server.crt",
	}
	applyMTLSDefaults(&cfg)
	if cfg.MTLSServerCert != "/custom/server.crt" {
		t.Fatalf("explicit path overwritten: %q", cfg.MTLSServerCert)
	}
	if cfg.MTLSServerKey != ProductionCertPath("server.key") {
		t.Fatalf("other defaults not applied: %q", cfg.MTLSServerKey)
	}
}
