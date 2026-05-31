package install

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"text/template"
)

const agentUnitName = "luna-agent.service"

// SystemdOptions configures luna-agent systemd unit installation.
type SystemdOptions struct {
	BinaryPath     string
	ConfigPath     string
	User           string
	Group          string
	UnitPath       string
	DryRun         bool
	Enable         bool
	SkipUserCreate bool
	// System installs a system unit under /etc/systemd/system (requires root).
	// Default is a user unit under ~/.config/systemd/user (no sudo).
	System bool
}

// DefaultAgentSystemdOptions returns system-wide production defaults.
func DefaultAgentSystemdOptions() SystemdOptions {
	return SystemdOptions{
		BinaryPath: "/usr/local/bin/luna-agent",
		ConfigPath: "/etc/luna/agent.yml",
		User:       "luna",
		Group:      "luna",
		UnitPath:   filepath.Join("/etc/systemd/system", agentUnitName),
		System:     true,
	}
}

// DefaultAgentUserSystemdOptions returns per-user systemd defaults.
func DefaultAgentUserSystemdOptions() SystemdOptions {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".config", "luna")
	return SystemdOptions{
		BinaryPath: defaultUserBinaryPath(),
		ConfigPath: filepath.Join(configDir, "agent.yml"),
		UnitPath:   filepath.Join(home, ".config", "systemd", "user", agentUnitName),
		System:     false,
	}
}

var agentSystemUnitTemplate = template.Must(template.New("luna-agent-system").Parse(`[Unit]
Description=Luna Z-Trust SSH agent (SSH_AUTH_SOCK interceptor)
Documentation=https://github.com/ba0f3/luna-ztrust/blob/main/docs/deploy.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{ .User }}
Group={{ .Group }}
ExecStart={{ .BinaryPath }}
Environment=LUNA_CONFIG={{ .ConfigPath }}
Restart=on-failure
RestartSec=5
RuntimeDirectory=luna
RuntimeDirectoryMode=0700

[Install]
WantedBy=multi-user.target
`))

var agentUserUnitTemplate = template.Must(template.New("luna-agent-user").Parse(`[Unit]
Description=Luna Z-Trust SSH agent (SSH_AUTH_SOCK interceptor)
Documentation=https://github.com/ba0f3/luna-ztrust/blob/main/docs/deploy.md
After=network-online.target default.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{ .BinaryPath }}
Environment=LUNA_CONFIG={{ .ConfigPath }}
Restart=on-failure
RestartSec=5
RuntimeDirectory=luna
RuntimeDirectoryMode=0700

[Install]
WantedBy=default.target
`))

type agentUnitData struct {
	BinaryPath string
	ConfigPath string
	User       string
	Group      string
}

// RenderAgentUnit returns the systemd unit file contents.
func RenderAgentUnit(opts SystemdOptions) (string, error) {
	opts = opts.withDefaults()
	var buf bytes.Buffer
	data := agentUnitData{
		BinaryPath: opts.BinaryPath,
		ConfigPath: opts.ConfigPath,
		User:       opts.User,
		Group:      opts.Group,
	}
	tmpl := agentUserUnitTemplate
	if opts.System {
		tmpl = agentSystemUnitTemplate
	}
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// InstallAgentSystemd writes the unit file and optionally enables the service.
func InstallAgentSystemd(opts SystemdOptions) error {
	opts = opts.withDefaults()
	body, err := RenderAgentUnit(opts)
	if err != nil {
		return err
	}
	if opts.DryRun {
		fmt.Print(body)
		return nil
	}
	if opts.System {
		return installAgentSystemUnit(opts, body)
	}
	return installAgentUserUnit(opts, body)
}

func installAgentUserUnit(opts SystemdOptions, body string) error {
	if err := os.MkdirAll(filepath.Dir(opts.UnitPath), 0o755); err != nil {
		return fmt.Errorf("create unit directory: %w", err)
	}
	if err := os.WriteFile(opts.UnitPath, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", opts.UnitPath, err)
	}
	if opts.Enable {
		if err := runSystemctlUser("daemon-reload"); err != nil {
			return err
		}
		if err := runSystemctlUser("enable", "--now", agentUnitName); err != nil {
			return err
		}
		fmt.Printf("enabled user service %s\n", agentUnitName)
		printUserSSHAuthSockHint()
	} else {
		fmt.Printf("wrote %s\nrun: systemctl --user daemon-reload && systemctl --user enable --now %s\n", opts.UnitPath, agentUnitName)
		printUserSSHAuthSockHint()
	}
	return nil
}

func installAgentSystemUnit(opts SystemdOptions, body string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("install system systemd unit requires root (sudo luna-agent install systemd --system), or omit --system for a user service")
	}
	if err := prepareServiceUser(opts); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opts.UnitPath), 0o755); err != nil {
		return fmt.Errorf("create unit directory: %w", err)
	}
	if err := os.WriteFile(opts.UnitPath, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", opts.UnitPath, err)
	}
	if opts.Enable {
		if err := runSystemctl("daemon-reload"); err != nil {
			return err
		}
		if err := runSystemctl("enable", "--now", agentUnitName); err != nil {
			return err
		}
	} else {
		fmt.Printf("wrote %s\nrun: sudo systemctl daemon-reload && sudo systemctl enable --now %s\n", opts.UnitPath, agentUnitName)
	}
	return nil
}

func printUserSSHAuthSockHint() {
	fmt.Println("add to shell profile (or use the path from agent.yml agent_socket):")
	fmt.Println("  export SSH_AUTH_SOCK=${XDG_RUNTIME_DIR}/luna/agent.sock")
}

func prepareServiceUser(opts SystemdOptions) error {
	if _, err := user.Lookup(opts.User); err == nil {
		// User exists.
	} else if opts.SkipUserCreate {
		return fmt.Errorf("systemd user %q does not exist (create with: useradd --system --home-dir /var/lib/%[1]s --shell /usr/sbin/nologin --gid %[1]s %[1]s, or re-run without --skip-user-create)", opts.User)
	} else if err := EnsureServiceUser(opts.User, opts.Group); err != nil {
		return err
	} else {
		fmt.Printf("created system user %q\n", opts.User)
	}
	if err := EnsureLunaDirs(opts.User, opts.Group); err != nil {
		return err
	}
	return EnsureCertPermissions("/etc/luna/certs", opts.Group)
}

func (o SystemdOptions) withDefaults() SystemdOptions {
	if o.System {
		d := DefaultAgentSystemdOptions()
		if o.BinaryPath == "" {
			o.BinaryPath = d.BinaryPath
		}
		if o.ConfigPath == "" {
			o.ConfigPath = d.ConfigPath
		}
		if o.User == "" {
			o.User = d.User
		}
		if o.Group == "" {
			o.Group = d.Group
		}
		if o.UnitPath == "" {
			o.UnitPath = d.UnitPath
		}
		return o
	}
	d := DefaultAgentUserSystemdOptions()
	if o.BinaryPath == "" {
		o.BinaryPath = d.BinaryPath
	}
	if o.ConfigPath == "" {
		o.ConfigPath = d.ConfigPath
	}
	if o.UnitPath == "" {
		o.UnitPath = d.UnitPath
	}
	return o
}

func defaultUserBinaryPath() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return exe
	}
	return "luna-agent"
}

func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", args[0], err)
	}
	return nil
}

func runSystemctlUser(args ...string) error {
	cmd := exec.Command("systemctl", append([]string{"--user"}, args...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl --user %s: %w", args[0], err)
	}
	return nil
}
