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
}

// DefaultAgentSystemdOptions returns production-oriented defaults.
func DefaultAgentSystemdOptions() SystemdOptions {
	return SystemdOptions{
		BinaryPath: "/usr/local/bin/luna-agent",
		ConfigPath: "/etc/luna/agent.yml",
		User:       "luna",
		Group:      "luna",
		UnitPath:   filepath.Join("/etc/systemd/system", agentUnitName),
	}
}

var agentUnitTemplate = template.Must(template.New("luna-agent").Parse(`[Unit]
Description=Luna Z-Trust SSH agent (SSH_AUTH_SOCK interceptor)
Documentation=https://github.com/ba0f3/luna-ztrust/blob/main/docs/deploy.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{ .User }}
Group={{ .Group }}
ExecStart={{ .BinaryPath }}
Restart=on-failure
RestartSec=5
RuntimeDirectory=luna
RuntimeDirectoryMode=0700
# Set agent_socket: /run/luna/agent.sock in agent.yml (matches RuntimeDirectory).

[Install]
WantedBy=multi-user.target
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
	if err := agentUnitTemplate.Execute(&buf, agentUnitData{
		BinaryPath: opts.BinaryPath,
		ConfigPath: opts.ConfigPath,
		User:       opts.User,
		Group:      opts.Group,
	}); err != nil {
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
	if os.Geteuid() != 0 {
		return fmt.Errorf("install systemd: must run as root (e.g. sudo luna-agent install systemd)")
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
	return EnsureLunaDirs(opts.User, opts.Group)
}

func (o SystemdOptions) withDefaults() SystemdOptions {
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

func runSystemctl(args ...string) error {
	cmd := exec.Command("systemctl", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("systemctl %s: %w", args[0], err)
	}
	return nil
}
