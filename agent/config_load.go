package agent

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	"github.com/subosito/gotenv"
)

// Load reads configuration from defaults, optional config files, .env, and environment variables.
// Config files are merged in order (later overrides earlier):
//
//	./agent.yml|.yaml, ~/.config/luna/agent.yml|.yaml, /etc/luna/agent.yml|.yaml
//
// Set LUNA_CONFIG to load a single explicit file instead.
func Load() (Config, error) {
	v, err := newAgentViper()
	if err != nil {
		return Config{}, err
	}
	return configFromViper(v)
}

// LoadFromEnv loads configuration using Viper (env vars, optional file, and .env).
func LoadFromEnv() (Config, error) {
	return Load()
}

func newAgentViper() (*viper.Viper, error) {
	_ = gotenv.Load()

	v := viper.New()
	v.SetDefault("agent_socket", defaultSocketPath)
	v.SetDefault("signer_mode", SignerModeLocalCA)

	if path := os.Getenv("LUNA_CONFIG"); path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
	} else if err := mergeConfigFiles(v, agentConfigPaths()); err != nil {
		return nil, err
	}

	bindEnv := func(key, envKey string) {
		_ = v.BindEnv(key, envKey)
	}
	bindEnv("proxy_url", "LUNA_PROXY_URL")
	bindEnv("mtls_cert", "LUNA_MTLS_CERT")
	bindEnv("mtls_key", "LUNA_MTLS_KEY")
	bindEnv("mtls_ca", "LUNA_MTLS_CA")
	bindEnv("target_user", "LUNA_TARGET_USER")
	bindEnv("target_host", "LUNA_TARGET_HOST")
	bindEnv("agent_socket", "LUNA_AGENT_SOCKET")
	bindEnv("signer_mode", "LUNA_SIGNER_MODE")

	v.AutomaticEnv()
	return v, nil
}

func configFromViper(v *viper.Viper) (Config, error) {
	cfg := Config{
		ProxyURL:   strings.TrimSpace(v.GetString("proxy_url")),
		MTLSCert:   strings.TrimSpace(v.GetString("mtls_cert")),
		MTLSKey:    strings.TrimSpace(v.GetString("mtls_key")),
		MTLSCA:     strings.TrimSpace(v.GetString("mtls_ca")),
		TargetUser: strings.TrimSpace(v.GetString("target_user")),
		TargetHost: strings.TrimSpace(v.GetString("target_host")),
		SocketPath: strings.TrimSpace(v.GetString("agent_socket")),
		SignerMode: strings.TrimSpace(v.GetString("signer_mode")),
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = defaultSocketPath
	}
	if cfg.SignerMode == "" {
		cfg.SignerMode = SignerModeLocalCA
	}

	var missing []string
	if cfg.ProxyURL == "" {
		missing = append(missing, "LUNA_PROXY_URL")
	}
	if cfg.MTLSCert == "" {
		missing = append(missing, "LUNA_MTLS_CERT")
	}
	if cfg.MTLSKey == "" {
		missing = append(missing, "LUNA_MTLS_KEY")
	}
	if cfg.MTLSCA == "" {
		missing = append(missing, "LUNA_MTLS_CA")
	}
	if cfg.TargetUser == "" {
		missing = append(missing, "LUNA_TARGET_USER")
	}
	if cfg.TargetHost == "" {
		missing = append(missing, "LUNA_TARGET_HOST")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}
