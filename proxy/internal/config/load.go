package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/subosito/gotenv"
)

const (
	defaultListenAddr     = ":8443"
	defaultAdminClientOU  = "luna-admin"
	defaultSignerMode     = "local-key"
	defaultApprovalPeriod = 60 * time.Second
)

var defaultAllowedTTLSeconds = []int{180, 300, 900}

// Load reads configuration from defaults, optional config files, .env, and environment variables.
// Config files are merged in order (later overrides earlier):
//
//	./proxy.yml|.yaml, ~/.config/luna/proxy.yml|.yaml, /etc/luna/proxy.yml|.yaml
//
// Set LUNA_CONFIG to load a single explicit file when present (missing file is ignored).
func Load() (Config, error) {
	v, err := newViper()
	if err != nil {
		return Config{}, err
	}
	return configFromViper(v)
}

func newViper() (*viper.Viper, error) {
	_ = gotenv.Load()

	v := viper.New()
	v.SetDefault("listen_addr", defaultListenAddr)
	v.SetDefault("admin_client_ou", defaultAdminClientOU)
	v.SetDefault("cli_client_ou", "luna-cli")
	v.SetDefault("signer_mode", defaultSignerMode)
	v.SetDefault("approval_timeout", defaultApprovalPeriod.String())

	if path := os.Getenv("LUNA_CONFIG"); path != "" {
		if err := readConfigFileIfExists(v, path); err != nil {
			return nil, err
		}
	} else if err := mergeConfigFiles(v, proxyConfigPaths()); err != nil {
		return nil, err
	}

	bindEnv := func(key, envKey string) {
		_ = v.BindEnv(key, envKey)
	}
	bindEnv("env", "LUNA_ENV")
	bindEnv("approval_timeout", "LUNA_APPROVAL_TIMEOUT")
	bindEnv("listen_addr", "LUNA_LISTEN_ADDR")
	bindEnv("telegram_bot_token", "TELEGRAM_BOT_TOKEN")
	bindEnv("telegram_webhook_secret", "TELEGRAM_WEBHOOK_SECRET")
	bindEnv("telegram_chat_id", "TELEGRAM_CHAT_ID")
	bindEnv("telegram_user_ids", "TELEGRAM_USER_IDS")
	bindEnv("admin_client_ou", "LUNA_ADMIN_CLIENT_OU")
	bindEnv("cli_client_ou", "LUNA_CLI_CLIENT_OU")
	bindEnv("key_path", "LUNA_KEY_PATH")
	bindEnv("signer_mode", "LUNA_SIGNER_MODE")
	bindEnv("mtls_server_cert", "LUNA_MTLS_SERVER_CERT")
	bindEnv("mtls_server_key", "LUNA_MTLS_SERVER_KEY")
	bindEnv("mtls_client_ca", "LUNA_MTLS_CLIENT_CA")
	bindEnv("mtls_ca_cert_path", "LUNA_MTLS_CA_CERT")
	bindEnv("mtls_ca_key_path", "LUNA_MTLS_CA_KEY")
	bindEnv("mtls_enroll_token", "LUNA_MTLS_ENROLL_TOKEN")
	bindEnv("fcm_credentials", "FCM_CREDENTIALS")
	bindEnv("control_socket", "LUNA_CONTROL_SOCKET")
	bindEnv("control_socket_group", "LUNA_CONTROL_SOCKET_GROUP")

	v.AutomaticEnv()
	return v, nil
}

func configFromViper(v *viper.Viper) (Config, error) {
	approvalTimeout, err := time.ParseDuration(v.GetString("approval_timeout"))
	if err != nil {
		return Config{}, fmt.Errorf("approval_timeout: %w", err)
	}

	cfg := Config{
		Env:                   strings.TrimSpace(v.GetString("env")),
		ApprovalTimeout:       approvalTimeout,
		ListenAddr:            strings.TrimSpace(v.GetString("listen_addr")),
		TelegramBotToken:      strings.TrimSpace(v.GetString("telegram_bot_token")),
		TelegramWebhookSecret: strings.TrimSpace(v.GetString("telegram_webhook_secret")),
		TelegramChatID:        strings.TrimSpace(v.GetString("telegram_chat_id")),
		TelegramUserIDs:       strings.TrimSpace(v.GetString("telegram_user_ids")),
		AdminClientOU:         strings.TrimSpace(v.GetString("admin_client_ou")),
		CliClientOU:           strings.TrimSpace(v.GetString("cli_client_ou")),
		KeyPath:               strings.TrimSpace(v.GetString("key_path")),
		SignerMode:            strings.TrimSpace(v.GetString("signer_mode")),
		AllowedTTLSeconds:     append([]int(nil), defaultAllowedTTLSeconds...),
		FCMCredentials:        strings.TrimSpace(v.GetString("fcm_credentials")),
		ControlSocket:         strings.TrimSpace(v.GetString("control_socket")),
		ControlSocketGroup:    strings.TrimSpace(v.GetString("control_socket_group")),
		MTLSServerCert:        strings.TrimSpace(v.GetString("mtls_server_cert")),
		MTLSServerKey:         strings.TrimSpace(v.GetString("mtls_server_key")),
		MTLSClientCA:          strings.TrimSpace(v.GetString("mtls_client_ca")),
		MTLSCACertPath:        strings.TrimSpace(v.GetString("mtls_ca_cert_path")),
		MTLSCAKeyPath:         strings.TrimSpace(v.GetString("mtls_ca_key_path")),
		MTLSEnrollToken:       strings.TrimSpace(v.GetString("mtls_enroll_token")),
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = defaultListenAddr
	}
	if cfg.AdminClientOU == "" {
		cfg.AdminClientOU = defaultAdminClientOU
	}
	if cfg.SignerMode == "" {
		cfg.SignerMode = defaultSignerMode
	}
	applyMTLSDefaults(&cfg)
	applyRuntimeDefaults(&cfg)
	if err := validateMTLS(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func readConfigFileIfExists(v *viper.Viper, path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat config %q: %w", path, err)
	}
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	return nil
}

func applyRuntimeDefaults(cfg *Config) {
	if cfg.ControlSocketGroup == "" {
		cfg.ControlSocketGroup = "luna-admin"
	}
	if isDevOrTestEnv(cfg.Env) {
		if cfg.ControlSocket == "" {
			cfg.ControlSocket = DefaultControlSocket()
		}
		return
	}
	if cfg.ControlSocket == "" {
		cfg.ControlSocket = ProductionControlSocket
	}
}
