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
	installSystem   bool
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install OS integration (systemd)",
}

var installSystemdCmd = &cobra.Command{
	Use:   "systemd",
	Short: "Write and optionally enable luna-agent.service (user unit by default)",
	Long: `Install a systemd unit for the luna-agent daemon.

Default: user service (~/.config/systemd/user/luna-agent.service, no sudo).
Use --system for a system-wide unit under /etc/systemd/system (requires root).

Examples:
  luna-agent install systemd --enable
  luna-agent install systemd --dry-run
  sudo luna-agent install systemd --system --enable`,
	RunE: runInstallSystemd,
}

func init() {
	installCmd.AddCommand(installSystemdCmd)

	f := installSystemdCmd.Flags()
	f.StringVar(&installBinary, "binary", "", "path to luna-agent binary (default: this executable, or /usr/local/bin for --system)")
	f.StringVar(&installConfig, "config", "", "LUNA_CONFIG path (default ~/.config/luna/agent.yml, or /etc/luna/agent.yml for --system)")
	f.StringVar(&installUser, "user", "", "service user for --system (default luna)")
	f.StringVar(&installGroup, "group", "", "service group for --system (default luna)")
	f.StringVar(&installUnit, "unit-path", "", "unit file path (default ~/.config/systemd/user/ or /etc/systemd/system/)")
	f.BoolVar(&installDryRun, "dry-run", false, "print unit file instead of writing")
	f.BoolVar(&installEnable, "enable", false, "systemctl daemon-reload && enable --now after install")
	f.BoolVar(&installSkipUser, "skip-user-create", false, "with --system: do not create the luna system user")
	f.BoolVar(&installSystem, "system", false, "install system unit (requires root); default is user unit")
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
		System:         installSystem,
	})
}
