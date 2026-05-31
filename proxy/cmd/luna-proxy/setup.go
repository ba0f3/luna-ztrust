package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/setup"
	"github.com/spf13/cobra"
)

var (
	setupNonInteractive  bool
	setupAssumeYes       bool
	setupForce           bool
	setupHostname        string
	setupEnv             string
	setupListen          string
	setupSignerMode      string
	setupKeyPath         string
	setupTelegramToken   string
	setupTelegramSecret  string
	setupTelegramChat    string
	setupCertsDir        string
	setupConfigPath      string
	setupEnrollToken     string
	setupInstallSystemd  bool
	setupSystemdEnable   bool
	setupSkipUserCreate  bool
	setupMTLSDir         string
	setupMTLSForce       bool
	setupMTLSCACN        string
	setupMTLSOrg         string
	setupMTLSServerCN    string
	setupMTLSDNS         []string
	setupMTLSAdminOU     string
	setupMTLSDays        int
	setupMTLSSkipSamples bool
	setupMTLSHints       bool
	setupMTLSWriteConfig bool
	setupConfigForce     bool
	setupConfigToken     string
	setupConfigListen    string
	setupConfigSigner    string
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive first-time proxy deployment",
	Long: `Guided setup for a new luna-proxy central server.

Creates mTLS PKI (hostname in server certificate SANs), writes proxy.yml
(Telegram required in production), and optionally installs systemd.

  sudo luna-proxy setup`,
	RunE: runSetupAll,
}

var setupMTLSCmd = &cobra.Command{
	Use:   "mtls",
	Short: "Generate mTLS material only (advanced)",
	Long:  `Prefer "luna-proxy setup". Use --san your.hostname (not localhost-only).`,
	RunE:  runSetupMTLS,
}

var setupConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Write proxy.yml only (advanced)",
	RunE:  runSetupConfigOnly,
}

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.AddCommand(setupMTLSCmd, setupConfigCmd)

	setupCmd.Flags().BoolVar(&setupNonInteractive, "non-interactive", false, "require flags; disable wizard")
	setupCmd.Flags().BoolVarP(&setupAssumeYes, "yes", "y", false, "accept default confirmations")
	setupCmd.Flags().BoolVar(&setupForce, "force", false, "overwrite existing certs and proxy.yml")
	setupCmd.Flags().StringVar(&setupHostname, "hostname", "", "public DNS name for mTLS (required)")
	setupCmd.Flags().StringVar(&setupEnv, "env", "", "production or dev (default production)")
	setupCmd.Flags().StringVar(&setupListen, "listen", "", "listen_addr (default :8443)")
	setupCmd.Flags().StringVar(&setupSignerMode, "signer-mode", "", "local-ca or local-key")
	setupCmd.Flags().StringVar(&setupKeyPath, "key-path", "", "encrypted signing key path")
	setupCmd.Flags().StringVar(&setupTelegramToken, "telegram-bot-token", "", "Telegram bot token")
	setupCmd.Flags().StringVar(&setupTelegramSecret, "telegram-webhook-secret", "", "Telegram webhook secret")
	setupCmd.Flags().StringVar(&setupTelegramChat, "telegram-chat-id", "", "Telegram chat ID")
	setupCmd.Flags().StringVar(&setupCertsDir, "dir", "", "mTLS cert directory")
	setupCmd.Flags().StringVar(&setupConfigPath, "config", "", "proxy.yml path")
	setupCmd.Flags().StringVar(&setupEnrollToken, "enroll-token", "", "agent bootstrap token")
	setupCmd.Flags().BoolVar(&setupInstallSystemd, "install-systemd", false, "install luna-proxy.service")
	setupCmd.Flags().BoolVar(&setupSystemdEnable, "enable", false, "with --install-systemd: enable --now")
	setupCmd.Flags().BoolVar(&setupSkipUserCreate, "skip-user-create", false, "skip luna user creation")

	f := setupMTLSCmd.Flags()
	f.StringVar(&setupMTLSDir, "dir", "", "output directory")
	f.BoolVar(&setupMTLSForce, "force", false, "overwrite existing files")
	f.StringVar(&setupMTLSCACN, "ca-cn", "", "CA common name")
	f.StringVar(&setupMTLSOrg, "org", "", "organization")
	f.StringVar(&setupMTLSServerCN, "server-cn", "", "server certificate CN")
	f.StringSliceVar(&setupMTLSDNS, "san", nil, "DNS SANs (required; use your public hostname)")
	f.StringVar(&setupMTLSAdminOU, "admin-ou", "", "admin client OU")
	f.IntVar(&setupMTLSDays, "days", 0, "validity days")
	f.BoolVar(&setupMTLSSkipSamples, "skip-samples", false, "skip sample client certs")
	f.BoolVar(&setupMTLSHints, "hints", true, "print proxy.yml path hints")
	f.BoolVar(&setupMTLSWriteConfig, "write-config", false, "deprecated; use luna-proxy setup")

	cf := setupConfigCmd.Flags()
	cf.StringVar(&setupConfigPath, "path", "", "proxy.yml path")
	cf.BoolVar(&setupConfigForce, "force", false, "overwrite proxy.yml")
	cf.StringVar(&setupConfigToken, "token", "", "bootstrap token")
	cf.StringVar(&setupConfigListen, "listen", "", "listen_addr")
	cf.StringVar(&setupConfigSigner, "signer-mode", "", "signer_mode")
}

func runSetupAll(_ *cobra.Command, _ []string) error {
	opts := flagsToSetupOptions()
	if !setupNonInteractive && setup.IsInteractive(os.Stdin) {
		wizard, err := setup.RunInteractive(setup.InteractiveOptions{
			Prefill:   opts,
			AssumeYes: setupAssumeYes,
		})
		if err != nil {
			return err
		}
		opts = wizard
	} else if err := validateSetupNonInteractive(opts); err != nil {
		return err
	}
	if opts.InstallSystemd && os.Geteuid() != 0 {
		return fmt.Errorf("install systemd requires root (sudo luna-proxy setup)")
	}
	_, err := setup.Run(opts)
	return err
}

func flagsToSetupOptions() setup.Options {
	return setup.Options{
		Env:                   setupEnv,
		Hostname:              setupHostname,
		ListenAddr:            setupListen,
		SignerMode:            setupSignerMode,
		KeyPath:               setupKeyPath,
		TelegramBotToken:      setupTelegramToken,
		TelegramWebhookSecret: setupTelegramSecret,
		TelegramChatID:        setupTelegramChat,
		CertsDir:              setupCertsDir,
		ConfigPath:            setupConfigPath,
		EnrollToken:           setupEnrollToken,
		Force:                 setupForce,
		InstallSystemd:        setupInstallSystemd,
		SystemdEnable:         setupSystemdEnable,
		SkipUserCreate:        setupSkipUserCreate,
		IncludeLocalhostSAN:   true,
		SkipSampleClients:     true,
	}
}

func validateSetupNonInteractive(opts setup.Options) error {
	if setup.NormalizeHostname(opts.Hostname) == "" {
		return fmt.Errorf("--hostname is required in non-interactive mode")
	}
	return opts.Validate()
}

func runSetupMTLS(_ *cobra.Command, _ []string) error {
	dir := setupMTLSDir
	if dir == "" {
		dir = defaultSetupDir()
	}
	if len(setupMTLSDNS) == 0 {
		return fmt.Errorf("specify --san with your public hostname (localhost-only breaks remote agents)")
	}
	res, err := setup.GenerateMTLS(setup.MTLSOptions{
		Dir:                  dir,
		Force:                setupMTLSForce,
		CACommonName:         setupMTLSCACN,
		Organization:         setupMTLSOrg,
		ServerCommonName:     setupMTLSServerCN,
		ServerDNSNames:       setupMTLSDNS,
		AdminClientOU:        setupMTLSAdminOU,
		ValidityDays:         setupMTLSDays,
		IncludeSampleClients: !setupMTLSSkipSamples,
	})
	if err != nil {
		if errors.Is(err, setup.ErrExists) {
			return fmt.Errorf("%w — re-run with --force", err)
		}
		return err
	}
	fmt.Printf("wrote mTLS material to %s\n", dir)
	for _, p := range res.Files {
		fmt.Printf("  %s\n", p)
	}
	if setupMTLSHints {
		fmt.Println()
		fmt.Print(setup.ProxyYAMLHints(dir))
	}
	return nil
}

func runSetupConfigOnly(_ *cobra.Command, _ []string) error {
	path := setupConfigPath
	if path == "" {
		path = defaultProxyConfigPath()
	}
	res, err := setup.WriteProxyConfig(setup.ProxyConfigOptions{
		Path:        path,
		Force:       setupConfigForce,
		EnrollToken: setupConfigToken,
		ListenAddr:  setupConfigListen,
		SignerMode:  setupConfigSigner,
		Env:         setupEnv,
		Hostname:    setupHostname,
	})
	if err != nil {
		if errors.Is(err, setup.ErrConfigExists) {
			return fmt.Errorf("%w — re-run with --force", err)
		}
		return err
	}
	fmt.Printf("wrote %s\nmtls_enroll_token: %s\n", res.Path, res.EnrollToken)
	return nil
}

func defaultProxyConfigPath() string {
	if os.Geteuid() == 0 {
		return config.DefaultProxyConfigPath
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./proxy.yml"
	}
	return strings.TrimSpace(home) + "/.config/luna/proxy.yml"
}

func defaultSetupDir() string {
	if os.Geteuid() == 0 {
		return config.DefaultCertsDir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "./certs"
	}
	return strings.TrimSpace(home) + "/.config/luna/certs"
}
