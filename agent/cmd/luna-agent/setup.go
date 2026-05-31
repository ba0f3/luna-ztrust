package main

import (
	"errors"
	"fmt"
	"os"

	agentsetup "github.com/ba0f3/luna-ztrust/agent/internal/setup"
	"github.com/spf13/cobra"
)

var (
	setupCertsDir           string
	setupConfigPath         string
	setupFromDir            string
	setupCAFile             string
	setupCAKeyFile          string
	setupCertFile           string
	setupKeyFile            string
	setupProxyURL           string
	setupTargetUser         string
	setupTargetHost         string
	setupSignerMode         string
	setupHostKeyFingerprint string
	setupForce              bool
	setupSkipVerify         bool
	setupInstallSystemd     bool
	setupSystemdEnable      bool
	setupSkipUserCreate     bool
	setupNonInteractive     bool
	setupAssumeYes          bool
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive client host setup (certs, config, verify, systemd)",
	Long: `All-in-one interactive wizard for luna-agent on a client/automation host.

Run without flags on a TTY for step-by-step prompts (repeatable; re-run updates config
and optionally replaces certs). Use --non-interactive with flags for scripts/CI.

  sudo luna-agent setup
  sudo luna-agent setup -y

Non-interactive example:
  sudo luna-agent setup --non-interactive \
    --from-dir ./certs --proxy-url https://luna.example:8443 \
    --target-user deploy --target-host 10.0.0.1 \
    --install-systemd --enable`,
	RunE: runSetupAll,
}

func init() {
	rootCmd.AddCommand(setupCmd)
	addSetupFlags(setupCmd)
	setupCmd.Flags().BoolVar(&setupNonInteractive, "non-interactive", false, "require flags; disable wizard")
	setupCmd.Flags().BoolVarP(&setupAssumeYes, "yes", "y", false, "accept default answers without confirmation")
}

func addSetupFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&setupCertsDir, "dir", "", "cert directory (default /etc/luna/certs as root)")
	f.StringVar(&setupConfigPath, "config", "", "agent.yml path (default /etc/luna/agent.yml as root)")
	f.StringVar(&setupFromDir, "from-dir", "", "copy ca.crt, client.crt, client.key from proxy setup output")
	f.StringVar(&setupCAFile, "ca", "", "install CA certificate as ca.crt")
	f.StringVar(&setupCAKeyFile, "ca-key", "", "CA private key for signing client CSR (optional)")
	f.StringVar(&setupCertFile, "cert", "", "install existing client certificate")
	f.StringVar(&setupKeyFile, "key", "", "install existing client private key")
	f.StringVar(&setupProxyURL, "proxy-url", "", "luna-proxy base URL")
	f.StringVar(&setupTargetUser, "target-user", "", "SSH username for PoP")
	f.StringVar(&setupTargetHost, "target-host", "", "SSH target host/IP for PoP")
	f.StringVar(&setupSignerMode, "signer-mode", "", "local-ca or local-key (default local-ca)")
	f.StringVar(&setupHostKeyFingerprint, "host-key-fingerprint", "", "optional local-key signer hint")
	f.BoolVar(&setupForce, "force", false, "overwrite existing cert files")
	f.BoolVar(&setupSkipVerify, "skip-verify", false, "skip proxy capabilities check")
	f.BoolVar(&setupInstallSystemd, "install-systemd", false, "install luna-agent.service")
	f.BoolVar(&setupSystemdEnable, "enable", false, "with --install-systemd: systemctl enable --now")
	f.BoolVar(&setupSkipUserCreate, "skip-user-create", false, "with --install-systemd: do not create luna user")
}

func runSetupAll(_ *cobra.Command, _ []string) error {
	opts := flagsToSetupOptions()
	useWizard := !setupNonInteractive && agentsetup.IsInteractive(os.Stdin)
	if useWizard {
		wizard, err := agentsetup.RunInteractive(agentsetup.InteractiveOptions{
			Prefill:   opts,
			AssumeYes: setupAssumeYes,
		})
		if err != nil {
			return err
		}
		opts = wizard
	} else if err := validateNonInteractive(opts); err != nil {
		return err
	}
	if opts.InstallSystemd && os.Geteuid() != 0 {
		return fmt.Errorf("install systemd requires root (sudo luna-agent setup)")
	}
	res, err := agentsetup.Run(opts)
	if err != nil {
		if errors.Is(err, agentsetup.ErrExists) {
			return fmt.Errorf("%w — choose to replace in wizard or use --force", err)
		}
		return err
	}
	fmt.Printf("\nsetup complete: certs=%s config=%s\n", res.CertsDir, res.ConfigPath)
	fmt.Println("use: export SSH_AUTH_SOCK=/run/luna/agent.sock")
	return nil
}

func flagsToSetupOptions() agentsetup.Options {
	return agentsetup.Options{
		CertsDir:           setupCertsDir,
		ConfigPath:         setupConfigPath,
		FromDir:            setupFromDir,
		CAFile:             setupCAFile,
		CAKeyFile:          setupCAKeyFile,
		CertFile:           setupCertFile,
		KeyFile:            setupKeyFile,
		ProxyURL:           setupProxyURL,
		TargetUser:         setupTargetUser,
		TargetHost:         setupTargetHost,
		SignerMode:         setupSignerMode,
		HostKeyFingerprint: setupHostKeyFingerprint,
		Force:              setupForce,
		SkipVerify:         setupSkipVerify,
		InstallSystemd:     setupInstallSystemd,
		SystemdEnable:      setupSystemdEnable,
		SkipUserCreate:     setupSkipUserCreate,
	}
}

func validateNonInteractive(opts agentsetup.Options) error {
	if opts.ProxyURL == "" {
		return fmt.Errorf("--proxy-url is required in non-interactive mode (or run interactively: luna-agent setup)")
	}
	if opts.TargetUser == "" {
		return fmt.Errorf("--target-user is required in non-interactive mode")
	}
	if opts.TargetHost == "" {
		return fmt.Errorf("--target-host is required in non-interactive mode")
	}
	return nil
}
