package main

import (
	"github.com/ba0f3/luna-ztrust/proxy/internal/install"
	"github.com/spf13/cobra"
)

var (
	installBinary   string
	installConfig   string
	installUser     string
	installGroup    string
	installUnit     string
	installDryRun   bool
	installEnable   bool
	installSkipUser bool
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install OS integration (systemd)",
}

var installSystemdCmd = &cobra.Command{
	Use:   "systemd",
	Short: "Write and optionally enable luna-proxy.service",
	Long: `Install a systemd unit for luna-proxy serve.

Requires root unless --dry-run (prints unit to stdout).
Creates the luna system user/group if missing.

Example:
  sudo luna-proxy install systemd --enable
  luna-proxy install systemd --dry-run`,
	RunE: runInstallSystemd,
}

func init() {
	rootCmd.AddCommand(installCmd)
	installCmd.AddCommand(installSystemdCmd)

	f := installSystemdCmd.Flags()
	f.StringVar(&installBinary, "binary", "", "path to luna-proxy binary (default /usr/local/bin/luna-proxy)")
	f.StringVar(&installConfig, "config", "", "LUNA_CONFIG path (default /etc/luna/proxy.yml)")
	f.StringVar(&installUser, "user", "", "service user (default luna)")
	f.StringVar(&installGroup, "group", "", "service group (default luna)")
	f.StringVar(&installUnit, "unit-path", "", "unit file path (default /etc/systemd/system/luna-proxy.service)")
	f.BoolVar(&installDryRun, "dry-run", false, "print unit file instead of writing")
	f.BoolVar(&installEnable, "enable", false, "systemctl daemon-reload && enable --now after install")
	f.BoolVar(&installSkipUser, "skip-user-create", false, "do not create the service user/group (must already exist)")
}

func runInstallSystemd(_ *cobra.Command, _ []string) error {
	return install.InstallProxySystemd(install.SystemdOptions{
		BinaryPath:     installBinary,
		ConfigPath:     installConfig,
		User:           installUser,
		Group:          installGroup,
		UnitPath:       installUnit,
		DryRun:         installDryRun,
		Enable:         installEnable,
		SkipUserCreate: installSkipUser,
	})
}
