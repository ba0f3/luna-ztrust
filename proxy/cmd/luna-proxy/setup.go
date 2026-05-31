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
	setupMTLSDir       string
	setupMTLSForce     bool
	setupMTLSCACN      string
	setupMTLSOrg       string
	setupMTLSServerCN  string
	setupMTLSDNS       []string
	setupMTLSAdminOU   string
	setupMTLSDays      int
	setupMTLSSkipSamples bool
	setupMTLSHints     bool
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

func init() {
	rootCmd.AddCommand(setupCmd)
	setupCmd.AddCommand(setupMTLSCmd)

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
	fmt.Println("then: luna-proxy key load … && systemctl restart luna-proxy")
	return nil
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
