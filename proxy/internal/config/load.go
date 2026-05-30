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
	defaultSignerMode     = "local-ca"
	defaultApprovalPeriod = 60 * time.Second
)

var defaultAllowedTTLSeconds = []int{180, 300, 900}

// Load reads configuration from defaults, optional config file, .env, and environment variables.
// Set LUNA_CONFIG to an explicit file path, or place luna-proxy.yaml in . or /etc/luna.
func Load() (Config, error) {
	v, err := newViper("luna-proxy")
	if err != nil {
		return Config{}, err
	}
	return configFromViper(v)
}

func newViper(name string) (*viper.Viper, error) {
	_ = gotenv.Load()

	v := viper.New()
	v.SetDefault("listen_addr", defaultListenAddr)
	v.SetDefault("admin_client_ou", defaultAdminClientOU)
	v.SetDefault("signer_mode", defaultSignerMode)
	v.SetDefault("approval_timeout", defaultApprovalPeriod.String())

	if path := os.Getenv("LUNA_CONFIG"); path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
	} else {
		v.SetConfigName(name)
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("/etc/luna")
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("read config: %w", err)
			}
		}
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
	bindEnv("admin_client_ou", "LUNA_ADMIN_CLIENT_OU")
	bindEnv("key_path", "LUNA_KEY_PATH")
	bindEnv("signer_mode", "LUNA_SIGNER_MODE")
	bindEnv("mtls_server_cert", "LUNA_MTLS_SERVER_CERT")
	bindEnv("mtls_server_key", "LUNA_MTLS_SERVER_KEY")
	bindEnv("mtls_client_ca", "LUNA_MTLS_CLIENT_CA")
	bindEnv("fcm_credentials", "FCM_CREDENTIALS")

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
		AdminClientOU:         strings.TrimSpace(v.GetString("admin_client_ou")),
		KeyPath:               strings.TrimSpace(v.GetString("key_path")),
		SignerMode:            strings.TrimSpace(v.GetString("signer_mode")),
		AllowedTTLSeconds:     append([]int(nil), defaultAllowedTTLSeconds...),
		FCMCredentials:        strings.TrimSpace(v.GetString("fcm_credentials")),
		MTLSServerCert:        strings.TrimSpace(v.GetString("mtls_server_cert")),
		MTLSServerKey:         strings.TrimSpace(v.GetString("mtls_server_key")),
		MTLSClientCA:          strings.TrimSpace(v.GetString("mtls_client_ca")),
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
	if cfg.MTLSServerCert == "" {
		cfg.MTLSServerCert = defaultCertPath("server.crt")
	}
	if cfg.MTLSServerKey == "" {
		cfg.MTLSServerKey = defaultCertPath("server.key")
	}
	if cfg.MTLSClientCA == "" {
		cfg.MTLSClientCA = defaultCertPath("ca.crt")
	}
	return cfg, nil
}
