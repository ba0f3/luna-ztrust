package setup

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

// InteractiveOptions configures the proxy setup wizard.
type InteractiveOptions struct {
	Prefill   Options
	AssumeYes bool
	Out       io.Writer
	In        io.Reader
}

// RunInteractive walks through proxy setup prompts.
func RunInteractive(ioOpts InteractiveOptions) (Options, error) {
	p := newPrompter(ioOpts.In, ioOpts.Out)
	opts := ioOpts.Prefill.withDefaults()
	existing := loadExistingProxyConfig(opts.ConfigPath)

	fmt.Fprintln(p.out, "Luna Z-Trust — luna-proxy setup")
	if fileExists(opts.ConfigPath) || fileExists(filepath.Join(opts.CertsDir, "server.crt")) {
		fmt.Fprintln(p.out, "(re-run: existing files detected; press Enter to keep shown defaults)")
	}
	fmt.Fprintln(p.out)

	env, err := p.askChoice("Environment", []string{envProduction, envDev},
		envChoiceIndex(firstNonEmpty(opts.Env, existing.Env, envProduction)))
	if err != nil {
		return Options{}, err
	}
	opts.Env = env

	opts.Hostname, err = p.askString("Public hostname (mTLS DNS name, e.g. luna.example.com)",
		firstNonEmpty(opts.Hostname, existing.Hostname))
	if err != nil {
		return Options{}, err
	}
	opts.Hostname = NormalizeHostname(opts.Hostname)
	if opts.Hostname == "" {
		return Options{}, fmt.Errorf("hostname is required")
	}

	opts.ListenAddr, err = p.askString("Listen address", firstNonEmpty(opts.ListenAddr, existing.ListenAddr, ":8443"))
	if err != nil {
		return Options{}, err
	}

	signer, err := p.askChoice("Signer mode", []string{"local-ca", "local-key"},
		signerChoiceIndex(firstNonEmpty(opts.SignerMode, existing.SignerMode, "local-ca")))
	if err != nil {
		return Options{}, err
	}
	opts.SignerMode = signer
	opts.KeyPath, err = p.askString("Encrypted signing key path on this host",
		firstNonEmpty(opts.KeyPath, existing.KeyPath, defaultKeyPath(signer)))
	if err != nil {
		return Options{}, err
	}

	fmt.Fprintln(p.out)
	if opts.Env == envDev {
		fmt.Fprintln(p.out, "  dev: sign requests auto-approve (LUNA_ENV=dev on proxy process). Telegram optional.")
	} else {
		fmt.Fprintln(p.out, "  production: Telegram OOB approval is required.")
	}
	opts.TelegramBotToken, err = p.askString("Telegram bot token",
		firstNonEmpty(opts.TelegramBotToken, existing.TelegramBotToken))
	if err != nil {
		return Options{}, err
	}
	opts.TelegramWebhookSecret, err = p.askString("Telegram webhook secret",
		firstNonEmpty(opts.TelegramWebhookSecret, existing.TelegramWebhookSecret))
	if err != nil {
		return Options{}, err
	}
	opts.TelegramChatID, err = p.askString("Telegram chat ID",
		firstNonEmpty(opts.TelegramChatID, existing.TelegramChatID))
	if err != nil {
		return Options{}, err
	}

	fmt.Fprintln(p.out)
	opts.CertsDir, err = p.askString("mTLS certificate directory",
		firstNonEmpty(opts.CertsDir, existing.CertsDir, opts.CertsDir))
	if err != nil {
		return Options{}, err
	}
	opts.CertsDir = filepath.Clean(opts.CertsDir)

	opts.ConfigPath, err = p.askString("proxy.yml path",
		firstNonEmpty(opts.ConfigPath, existing.ConfigPath, opts.ConfigPath))
	if err != nil {
		return Options{}, err
	}

	includeLocalhost, err := p.askYesNo("Include localhost in server certificate SANs (same-host testing)?", true)
	if err != nil {
		return Options{}, err
	}
	opts.IncludeLocalhostSAN = includeLocalhost
	opts.SkipSampleClients = true

	if os.Geteuid() == 0 {
		install, err := p.askYesNo("Install systemd service (luna-proxy.service)?", ioOpts.AssumeYes || !fileExists(opts.ConfigPath))
		if err != nil {
			return Options{}, err
		}
		opts.InstallSystemd = install
		if install {
			enable, err := p.askYesNo("Enable and start service now?", true)
			if err != nil {
				return Options{}, err
			}
			opts.SystemdEnable = enable
		}
	} else {
		fmt.Fprintln(p.out, "Note: run with sudo to install systemd service.")
	}

	opts.RewriteConfig = true
	opts.Force = fileExists(filepath.Join(opts.CertsDir, "ca.crt")) || fileExists(opts.ConfigPath)

	if err := opts.Validate(); err != nil {
		return Options{}, err
	}

	fmt.Fprintln(p.out)
	fmt.Fprintf(p.out, "Agent hosts should use proxy URL: %s\n", defaultPublicProxyURL(opts.Hostname, opts.ListenAddr))
	fmt.Fprintln(p.out, "After setup: luna-proxy key load <encrypted-key> on this host.")

	if !ioOpts.AssumeYes {
		ok, err := p.askYesNo("Proceed with setup?", true)
		if err != nil {
			return Options{}, err
		}
		if !ok {
			return Options{}, fmt.Errorf("setup cancelled")
		}
	}

	return opts, nil
}

func loadExistingProxyConfig(path string) Options {
	if path == "" {
		path = configDefaultPath()
	}
	if _, err := os.Stat(path); err != nil {
		return Options{}
	}
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return Options{}
	}
	return Options{
		Env:                   v.GetString("env"),
		ListenAddr:            v.GetString("listen_addr"),
		SignerMode:            v.GetString("signer_mode"),
		KeyPath:               v.GetString("key_path"),
		TelegramBotToken:      v.GetString("telegram_bot_token"),
		TelegramWebhookSecret: v.GetString("telegram_webhook_secret"),
		TelegramChatID:        v.GetString("telegram_chat_id"),
		ConfigPath:            path,
		EnrollToken:           v.GetString("mtls_enroll_token"),
	}
}

func configDefaultPath() string {
	if os.Geteuid() == 0 {
		return "/etc/luna/proxy.yml"
	}
	return defaultUserProxyConfigPath()
}

func envChoiceIndex(env string) int {
	if env == envDev {
		return 1
	}
	return 0
}

func signerChoiceIndex(mode string) int {
	if mode == "local-key" {
		return 1
	}
	return 0
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
