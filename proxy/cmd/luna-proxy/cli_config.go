package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// CLIProfile holds remote key-load mTLS settings for luna-proxy key load.
type CLIProfile struct {
	ProxyURL string
	CliCert  string
	CliKey   string
	CA       string
}

type cliYAML struct {
	ProxyURL string `yaml:"proxy_url"`
	CliCert  string `yaml:"cli_cert"`
	CliKey   string `yaml:"cli_key"`
	CA       string `yaml:"ca"`
}

func cliProfilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "luna", "cli.yaml")
	}
	return filepath.Join(home, ".config", "luna", "cli.yaml")
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
		ProxyURL: strings.TrimSpace(y.ProxyURL),
		CliCert:  strings.TrimSpace(y.CliCert),
		CliKey:   strings.TrimSpace(y.CliKey),
		CA:       strings.TrimSpace(y.CA),
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

func (p *CLIProfile) validate() error {
	if p.ProxyURL == "" {
		return fmt.Errorf("proxy URL required")
	}
	if p.CliCert == "" {
		return fmt.Errorf("cli client certificate path required")
	}
	if p.CliKey == "" {
		return fmt.Errorf("cli client key path required")
	}
	if p.CA == "" {
		return fmt.Errorf("CA certificate path required")
	}
	return nil
}
