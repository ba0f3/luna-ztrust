package setup

import (
	"fmt"
	"os"
	"strings"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

const (
	envProduction = "production"
	envDev        = "dev"
)

// Options configures the full luna-proxy setup pipeline.
type Options struct {
	Env                   string
	Hostname              string
	ListenAddr            string
	SignerMode            string
	KeyPath               string
	TelegramBotToken      string
	TelegramWebhookSecret string
	TelegramChatID        string
	CertsDir              string
	ConfigPath            string
	EnrollToken           string
	IncludeLocalhostSAN   bool
	SkipSampleClients     bool
	Force                 bool
	RewriteConfig         bool
	InstallSystemd        bool
	SystemdEnable         bool
	SkipUserCreate        bool
}

// Result summarizes setup output.
type Result struct {
	CertsDir    string
	ConfigPath  string
	EnrollToken string
	Hostname    string
}

func (o Options) withDefaults() Options {
	if o.Env == "" {
		o.Env = envProduction
	}
	if o.ListenAddr == "" {
		o.ListenAddr = ":8443"
	}
	if o.SignerMode == "" {
		o.SignerMode = "local-ca"
	}
	if o.CertsDir == "" {
		if os.Geteuid() == 0 {
			o.CertsDir = config.DefaultCertsDir
		} else {
			o.CertsDir = defaultUserCertsDir()
		}
	}
	if o.ConfigPath == "" {
		if os.Geteuid() == 0 {
			o.ConfigPath = config.DefaultProxyConfigPath
		} else {
			o.ConfigPath = defaultUserProxyConfigPath()
		}
	}
	if o.KeyPath == "" {
		o.KeyPath = defaultKeyPath(o.SignerMode)
	}
	o.Hostname = NormalizeHostname(o.Hostname)
	o.CertsDir = strings.TrimSpace(o.CertsDir)
	o.ConfigPath = strings.TrimSpace(o.ConfigPath)
	return o
}

// Validate checks required fields before Run.
func (o Options) Validate() error {
	o = o.withDefaults()
	if o.Hostname == "" {
		return fmt.Errorf("hostname is required (used for mTLS server certificate DNS name)")
	}
	if o.Env != envDev {
		if strings.TrimSpace(o.TelegramBotToken) == "" {
			return fmt.Errorf("telegram_bot_token is required in production (or choose env=dev for lab only)")
		}
		if strings.TrimSpace(o.TelegramWebhookSecret) == "" {
			return fmt.Errorf("telegram_webhook_secret is required in production")
		}
		if strings.TrimSpace(o.TelegramChatID) == "" {
			return fmt.Errorf("telegram_chat_id is required in production")
		}
	}
	if o.SignerMode != "local-ca" && o.SignerMode != "local-key" {
		return fmt.Errorf("signer_mode must be local-ca or local-key")
	}
	return nil
}

// NormalizeHostname strips scheme/port/path from a host or URL string.
func NormalizeHostname(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func defaultKeyPath(signerMode string) string {
	if signerMode == "local-key" {
		return "/etc/luna/ssh/encrypted_host.key"
	}
	return "/etc/luna/ssh/encrypted_ca.key"
}

func defaultUserCertsDir() string {
	return defaultUserConfigDir() + "/certs"
}

func defaultUserProxyConfigPath() string {
	return defaultUserConfigDir() + "/proxy.yml"
}

func defaultUserConfigDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return dir + "/luna"
	}
	home, _ := os.UserHomeDir()
	return home + "/.config/luna"
}

func defaultPublicProxyURL(hostname, listenAddr string) string {
	port := "8443"
	if strings.HasPrefix(listenAddr, ":") {
		port = strings.TrimPrefix(listenAddr, ":")
	}
	return fmt.Sprintf("https://%s:%s", hostname, port)
}
