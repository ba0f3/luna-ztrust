package install

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"text/template"

	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

const proxyUnitName = "luna-proxy.service"

// SystemdOptions configures luna-proxy systemd unit installation.
type SystemdOptions struct {
	BinaryPath     string
	ConfigPath     string
	User           string
	Group          string
	UnitPath       string
	CertsDir       string
	DryRun         bool
	Enable         bool
	SkipUserCreate bool
}

// DefaultProxySystemdOptions returns production-oriented defaults.
func DefaultProxySystemdOptions() SystemdOptions {
	return SystemdOptions{
		BinaryPath: "/usr/local/bin/luna-proxy",
		ConfigPath: "/etc/luna/proxy.yml",
		User:       "luna",
		Group:      "luna",
		UnitPath:   filepath.Join("/etc/systemd/system", proxyUnitName),
	}
}

var proxyUnitTemplate = template.Must(template.New("luna-proxy").Parse(`[Unit]
Description=Luna Z-Trust central proxy (mTLS API and control socket)
Documentation=https://github.com/ba0f3/luna-ztrust/blob/main/docs/deploy.md
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={{ .User }}
Group={{ .Group }}
ExecStart={{ .BinaryPath }} serve
Restart=on-failure
RestartSec=5
RuntimeDirectory=luna
RuntimeDirectoryMode=0750
# Set control_socket: /run/luna/control.sock in proxy.yml (matches RuntimeDirectory).

[Install]
WantedBy=multi-user.target
`))

type proxyUnitData struct {
	BinaryPath string
	ConfigPath string
	User       string
	Group      string
}

// RenderProxyUnit returns the systemd unit file contents.
func RenderProxyUnit(opts SystemdOptions) (string, error) {
	opts = opts.withDefaults()
	var buf bytes.Buffer
	if err := proxyUnitTemplate.Execute(&buf, proxyUnitData{
		BinaryPath: opts.BinaryPath,
		ConfigPath: opts.ConfigPath,
		User:       opts.User,
		Group:      opts.Group,
	}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// InstallProxySystemd writes the unit file and optionally enables the service.
func InstallProxySystemd(opts SystemdOptions) error {
	opts = opts.withDefaults()
	body, err := RenderProxyUnit(opts)
	if err != nil {
		return err
	}
	if opts.DryRun {
		fmt.Print(body)
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("install systemd: must run as root (e.g. sudo luna-proxy install systemd)")
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
		if err := runSystemctl("enable", "--now", proxyUnitName); err != nil {
			return err
		}
	} else {
		fmt.Printf("wrote %s\nrun: sudo systemctl daemon-reload && sudo systemctl enable --now %s\n", opts.UnitPath, proxyUnitName)
	}
	return nil
}

func prepareServiceUser(opts SystemdOptions) error {
	if _, err := user.Lookup(opts.User); err == nil {
		// User exists; still ensure dirs and cert group perms.
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
	certsDir := opts.CertsDir
	if certsDir == "" {
		certsDir = config.DefaultCertsDir
	}
	if err := EnsureCertPermissions(certsDir, opts.Group); err != nil {
		return fmt.Errorf("cert permissions: %w", err)
	}
	if err := EnsureDefaultProxyConfig(opts.ConfigPath, opts.User, opts.Group); err != nil {
		return err
	}
	return nil
}

func (o SystemdOptions) withDefaults() SystemdOptions {
	d := DefaultProxySystemdOptions()
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
