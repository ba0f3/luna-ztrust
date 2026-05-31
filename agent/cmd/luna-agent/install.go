package main

import (
	"github.com/ba0f3/luna-ztrust/agent/internal/install"
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
	Short: "Write and optionally enable luna-agent.service",
	Long: `Install a systemd unit for the luna-agent daemon.

Requires root unless --dry-run (prints unit to stdout).
Creates the luna system user/group if missing.

Example:
  sudo luna-agent install systemd --enable
  luna-agent install systemd --dry-run`,
	RunE: runInstallSystemd,
}

func init() {
	installCmd.AddCommand(installSystemdCmd)

	f := installSystemdCmd.Flags()
	f.StringVar(&installBinary, "binary", "", "path to luna-agent binary (default /usr/local/bin/luna-agent)")
	f.StringVar(&installConfig, "config", "", "LUNA_CONFIG path (default /etc/luna/agent.yml)")
	f.StringVar(&installUser, "user", "", "service user (default luna)")
	f.StringVar(&installGroup, "group", "", "service group (default luna)")
	f.StringVar(&installUnit, "unit-path", "", "unit file path (default /etc/systemd/system/luna-agent.service)")
	f.BoolVar(&installDryRun, "dry-run", false, "print unit file instead of writing")
	f.BoolVar(&installEnable, "enable", false, "systemctl daemon-reload && enable --now after install")
	f.BoolVar(&installSkipUser, "skip-user-create", false, "do not create the service user/group (must already exist)")
}

func runInstallSystemd(_ *cobra.Command, _ []string) error {
	return install.InstallAgentSystemd(install.SystemdOptions{
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
