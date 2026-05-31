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
	setupConfigPath      string
	setupConfigForce     bool
	setupConfigToken     string
	setupConfigListen    string
	setupConfigSigner    string
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "First-time installation helpers",
}

var setupMTLSCmd = &cobra.Command{
	Use:   "mtls",
	Short: "Generate mTLS CA, server cert, and sample client certificates",
	Long: `Create a new Luna mTLS PKI for first-time proxy deployment.

Writes under --dir (default /etc/luna/certs):
  ca.crt, ca.key          — issuing CA (CLI enroll, client trust)
  server.crt, server.key  — proxy mTLS listener
  client.crt, client.key  — sample automation client (unless --skip-samples)
  admin-client.crt/.key   — sample admin client with OU=luna-admin

Point proxy.yml at these paths. Use ca.crt for both mtls_client_ca and mtls_ca_cert_path.
Protect ca.key (mode 0400); never commit keys to git.

Requires write access to --dir (typically run with sudo for /etc/luna/certs).`,
	RunE: runSetupMTLS,
}

var setupConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Write proxy.yml with generated agent bootstrap token",
	Long: `Create /etc/luna/proxy.yml (or --path) with production defaults and mtls_enroll_token.

The bootstrap password lets luna-agent hosts obtain client.crt via POST /api/v1/mtls/enroll
without copying ca.key. Print and save the token for agent setup.

Requires write access to --path (typically sudo for /etc/luna/proxy.yml).`,
	RunE: runSetupConfig,
}

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.AddCommand(setupMTLSCmd, setupConfigCmd)

	f := setupMTLSCmd.Flags()
	f.StringVar(&setupMTLSDir, "dir", "", "output directory (default /etc/luna/certs as root, else ~/.config/luna/certs)")
	f.BoolVar(&setupMTLSForce, "force", false, "overwrite existing files")
	f.StringVar(&setupMTLSCACN, "ca-cn", "", "CA certificate common name (default Luna mTLS CA)")
	f.StringVar(&setupMTLSOrg, "org", "", "organization name (default Luna Z-Trust)")
	f.StringVar(&setupMTLSServerCN, "server-cn", "", "server certificate CN (default luna-proxy)")
	f.StringSliceVar(&setupMTLSDNS, "san", nil, "server certificate DNS SANs (repeatable; default localhost)")
	f.StringVar(&setupMTLSAdminOU, "admin-ou", "", "OU for sample admin client (default luna-admin)")
	f.IntVar(&setupMTLSDays, "days", 0, "certificate validity in days (default 3650)")
	f.BoolVar(&setupMTLSSkipSamples, "skip-samples", false, "only generate CA and server material")
	f.BoolVar(&setupMTLSHints, "hints", true, "print suggested proxy.yml paths after generation")
	f.BoolVar(&setupMTLSWriteConfig, "write-config", false, "write proxy.yml with generated mtls_enroll_token")

	cf := setupConfigCmd.Flags()
	cf.StringVar(&setupConfigPath, "path", "", "proxy.yml path (default /etc/luna/proxy.yml as root)")
	cf.BoolVar(&setupConfigForce, "force", false, "overwrite existing proxy.yml")
	cf.StringVar(&setupConfigToken, "token", "", "use this bootstrap token (default: generate random)")
	cf.StringVar(&setupConfigListen, "listen", "", "listen_addr (default :8443)")
	cf.StringVar(&setupConfigSigner, "signer-mode", "", "signer_mode (default local-ca)")
}

func runSetupMTLS(_ *cobra.Command, _ []string) error {
	dir := setupMTLSDir
	if dir == "" {
		dir = defaultSetupDir()
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
			return fmt.Errorf("%w — re-run with --force to replace", err)
		}
		return err
	}

	fmt.Printf("wrote mTLS material to %s\n", dir)
	for _, p := range res.Files {
		fmt.Printf("  %s\n", p)
	}
	if setupMTLSSkipSamples {
		fmt.Println("next: issue automation/admin client certs from this CA, or re-run without --skip-samples for examples")
	} else {
		fmt.Println("sample client certs are for lab use — issue production client certs per host")
	}
	if setupMTLSHints {
		fmt.Println()
		fmt.Print(setup.ProxyYAMLHints(dir))
	}
	if setupMTLSWriteConfig {
		if err := writeSetupProxyConfig(""); err != nil {
			return err
		}
	}
	fmt.Println("then: luna-proxy key load … && systemctl restart luna-proxy")
	return nil
}

func runSetupConfig(_ *cobra.Command, _ []string) error {
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
	})
	if err != nil {
		if errors.Is(err, setup.ErrConfigExists) {
			return fmt.Errorf("%w — re-run with --force to replace", err)
		}
		return err
	}
	printProxyConfigResult(res)
	return nil
}

func writeSetupProxyConfig(token string) error {
	path := defaultProxyConfigPath()
	res, err := setup.WriteProxyConfig(setup.ProxyConfigOptions{
		Path:        path,
		Force:       setupMTLSForce,
		EnrollToken: token,
	})
	if err != nil {
		if errors.Is(err, setup.ErrConfigExists) {
			fmt.Printf("proxy.yml already exists at %s (skipped; use setup config --force)\n", path)
			return nil
		}
		return err
	}
	printProxyConfigResult(res)
	return nil
}

func printProxyConfigResult(res setup.ProxyConfigResult) {
	fmt.Printf("wrote %s\n", res.Path)
	fmt.Println()
	fmt.Println("Agent bootstrap password (mtls_enroll_token) — give this to luna-agent setup:")
	fmt.Printf("  %s\n", res.EnrollToken)
	fmt.Println()
	fmt.Println("  export LUNA_MTLS_ENROLL_TOKEN='...'")
	fmt.Println("  luna-agent setup --enroll-token '...'")
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
