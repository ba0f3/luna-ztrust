package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli/httpclient"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// CLIProfile holds remote mTLS settings for luna-proxy CLI commands.
type CLIProfile struct {
	ProxyURL  string
	AdminCert string
	AdminKey  string
	CA        string
	CliCert   string
	CliKey    string
}

type cliYAML struct {
	ProxyURL  string `yaml:"proxy_url"`
	AdminCert string `yaml:"admin_cert"`
	AdminKey  string `yaml:"admin_key"`
	CA        string `yaml:"ca"`
	CliCert   string `yaml:"cli_cert"`
	CliKey    string `yaml:"cli_key"`
}

func cliProfilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "luna", "cli.yaml")
	}
	return filepath.Join(home, ".config", "luna", "cli.yaml")
}

func defaultCLIAutoCAPath() string {
	return filepath.Join(filepath.Dir(cliProfilePath()), "ca.crt")
}

// ensureProfileCA downloads ca.crt from GET /api/v1/mtls/ca when CA is unset.
func (p *CLIProfile) ensureProfileCA(ctx context.Context) error {
	if strings.TrimSpace(p.CA) != "" {
		return nil
	}
	path, err := httpclient.FetchCA(ctx, p.ProxyURL, defaultCLIAutoCAPath())
	if err != nil {
		return err
	}
	p.CA = path
	fmt.Fprintf(os.Stderr, "downloaded CA to %s\n", path)
	return nil
}

// LoadCLIProfile reads ~/.config/luna/cli.yaml when present.
func LoadCLIProfile() (*CLIProfile, error) {
	return loadCLIProfileFile(cliProfilePath())
}

func loadCLIProfileFile(path string) (*CLIProfile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var y cliYAML
	if err := yaml.Unmarshal(raw, &y); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	prof := &CLIProfile{
		ProxyURL:  strings.TrimSpace(y.ProxyURL),
		AdminCert: strings.TrimSpace(y.AdminCert),
		AdminKey:  strings.TrimSpace(y.AdminKey),
		CA:        strings.TrimSpace(y.CA),
		CliCert:   strings.TrimSpace(y.CliCert),
		CliKey:    strings.TrimSpace(y.CliKey),
	}
	if err := prof.expandPaths(); err != nil {
		return nil, err
	}
	return prof, nil
}

func resolveCLIProfile(cmd *cobra.Command) (*CLIProfile, error) {
	var prof CLIProfile

	fileProf, err := LoadCLIProfile()
	if err != nil {
		return nil, err
	}
	if fileProf != nil {
		prof = *fileProf
	}

	if v, err := cmd.Flags().GetString("proxy-url"); err == nil && strings.TrimSpace(v) != "" {
		prof.ProxyURL = strings.TrimSpace(v)
	}
	if v, err := cmd.Flags().GetString("admin-cert"); err == nil && strings.TrimSpace(v) != "" {
		prof.AdminCert = strings.TrimSpace(v)
	}
	if v, err := cmd.Flags().GetString("admin-key"); err == nil && strings.TrimSpace(v) != "" {
		prof.AdminKey = strings.TrimSpace(v)
	}
	if v, err := cmd.Flags().GetString("cli-cert"); err == nil && strings.TrimSpace(v) != "" {
		prof.CliCert = strings.TrimSpace(v)
	}
	if v, err := cmd.Flags().GetString("cli-key"); err == nil && strings.TrimSpace(v) != "" {
		prof.CliKey = strings.TrimSpace(v)
	}
	if v, err := cmd.Flags().GetString("ca"); err == nil && strings.TrimSpace(v) != "" {
		prof.CA = strings.TrimSpace(v)
	}

	if prof.ProxyURL == "" {
		return nil, nil
	}

	if err := prof.expandPaths(); err != nil {
		return nil, err
	}
	return &prof, nil
}

func (p *CLIProfile) expandPaths() error {
	var err error
	if p.AdminCert, err = expandCLIPath(p.AdminCert); err != nil {
		return err
	}
	if p.AdminKey, err = expandCLIPath(p.AdminKey); err != nil {
		return err
	}
	if p.CliCert, err = expandCLIPath(p.CliCert); err != nil {
		return err
	}
	if p.CliKey, err = expandCLIPath(p.CliKey); err != nil {
		return err
	}
	if p.CA, err = expandCLIPath(p.CA); err != nil {
		return err
	}
	return nil
}

func expandCLIPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	if p == "~" {
		return os.UserHomeDir()
	}
	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, p[2:]), nil
	}
	return p, nil
}

func (p *CLIProfile) validateKeyLoad() error {
	if p.ProxyURL == "" {
		return fmt.Errorf("proxy URL required")
	}
	if p.CliCert == "" {
		return fmt.Errorf("cli client certificate path required")
	}
	if p.CliKey == "" {
		return fmt.Errorf("cli client key path required")
	}
	return nil
}

// applyAdminDefaults fills admin cert paths from common locations when unset.
func (p *CLIProfile) applyAdminDefaults(csrPath string) {
	if p.AdminCert != "" && p.AdminKey != "" {
		return
	}
	for _, dir := range adminMaterialDirs(csrPath) {
		cert := filepath.Join(dir, "admin-client.crt")
		key := filepath.Join(dir, "admin-client.key")
		if !fileExistsCLI(cert) || !fileExistsCLI(key) {
			continue
		}
		if p.AdminCert == "" {
			p.AdminCert = cert
		}
		if p.AdminKey == "" {
			p.AdminKey = key
		}
		return
	}
}

func adminMaterialDirs(csrPath string) []string {
	seen := make(map[string]struct{})
	var dirs []string
	add := func(d string) {
		d = strings.TrimSpace(d)
		if d == "" || d == "." {
			return
		}
		if _, ok := seen[d]; ok {
			return
		}
		seen[d] = struct{}{}
		dirs = append(dirs, d)
	}
	if csrPath != "" {
		add(filepath.Dir(csrPath))
	}
	add(filepath.Dir(cliProfilePath()))
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, ".config", "luna"))
		add(filepath.Join(home, ".config", "luna", "certs"))
	}
	add("/etc/luna/certs")
	return dirs
}

func fileExistsCLI(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (p *CLIProfile) validateAdminEnroll() error {
	if p.ProxyURL == "" {
		return fmt.Errorf("proxy URL required")
	}
	if p.AdminCert == "" {
		return fmt.Errorf(`admin client certificate required (OU=luna-admin)

Set --admin-cert or place admin-client.crt in ~/.config/luna/ or next to your CSR.
On the proxy host, files are created by luna-proxy setup at /etc/luna/certs/admin-client.crt — copy that pair to this machine.`)
	}
	if p.AdminKey == "" {
		return fmt.Errorf("admin client key required (--admin-key or admin-client.key beside admin-client.crt)")
	}
	if !fileExistsCLI(p.AdminCert) {
		return fmt.Errorf(`admin certificate not found: %s

Copy admin-client.crt and admin-client.key from the proxy (e.g. /etc/luna/certs/ after luna-proxy setup).
If setup ran before admin certs were generated, on the proxy: sudo luna-proxy setup mtls --force --dir /etc/luna/certs
Or enroll on the proxy host without HTTP: sudo luna-proxy cli enroll --label ... --csr-file ...`, p.AdminCert)
	}
	if !fileExistsCLI(p.AdminKey) {
		return fmt.Errorf("admin client key not found: %s", p.AdminKey)
	}
	return nil
}
