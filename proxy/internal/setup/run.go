package setup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ba0f3/luna-ztrust/proxy/internal/install"
)

// Run executes proxy setup: mTLS PKI → proxy.yml → optional systemd.
func Run(opts Options) (Result, error) {
	opts = opts.withDefaults()
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}

	force := opts.Force || opts.RewriteConfig

	sans := []string{opts.Hostname}
	if opts.IncludeLocalhostSAN {
		sans = append(sans, "localhost")
	}

	fmt.Println("step 1/3: generate mTLS CA and server certificate")
	mtlsRes, err := GenerateMTLS(MTLSOptions{
		Dir:                  opts.CertsDir,
		Force:                force,
		ServerCommonName:     opts.Hostname,
		ServerDNSNames:       sans,
		IncludeSampleClients: !opts.SkipSampleClients,
	})
	if err != nil {
		return Result{}, fmt.Errorf("mTLS: %w", err)
	}
	fmt.Printf("  wrote %d files under %s\n", len(mtlsRes.Files), opts.CertsDir)
	fmt.Printf("  server certificate DNS names: %v\n", sans)

	fmt.Println("step 2/3: write proxy.yml")
	cfgRes, err := WriteProxyConfig(ProxyConfigOptions{
		Path:                  opts.ConfigPath,
		Force:                 force,
		EnrollToken:           opts.EnrollToken,
		Env:                   opts.Env,
		Hostname:              opts.Hostname,
		ListenAddr:            opts.ListenAddr,
		SignerMode:            opts.SignerMode,
		KeyPath:               opts.KeyPath,
		TelegramBotToken:      opts.TelegramBotToken,
		TelegramWebhookSecret: opts.TelegramWebhookSecret,
		TelegramChatID:        opts.TelegramChatID,
		User:                  "luna",
		Group:                 "luna",
	})
	if err != nil {
		return Result{}, fmt.Errorf("proxy.yml: %w", err)
	}
	fmt.Printf("  %s\n", cfgRes.Path)

	fmt.Println("step 3/3: summary")
	fmt.Printf("  proxy URL for agents: %s\n", defaultPublicProxyURL(opts.Hostname, opts.ListenAddr))
	fmt.Println("  agent bootstrap password (mtls_enroll_token):")
	fmt.Printf("    %s\n", cfgRes.EnrollToken)
	fmt.Println("  on agent host:")
	fmt.Printf("    export LUNA_MTLS_ENROLL_TOKEN='%s'\n", cfgRes.EnrollToken)
	fmt.Println("    luna-agent setup")

	if opts.InstallSystemd {
		fmt.Println("installing systemd unit")
		if os.Geteuid() != 0 {
			return Result{}, fmt.Errorf("install systemd: must run as root (sudo luna-proxy setup)")
		}
		if err := install.EnsureCertPermissions(opts.CertsDir, "luna"); err != nil {
			return Result{}, err
		}
		if err := install.InstallProxySystemd(install.SystemdOptions{
			ConfigPath:     opts.ConfigPath,
			CertsDir:       opts.CertsDir,
			Enable:         opts.SystemdEnable,
			SkipUserCreate: opts.SkipUserCreate,
		}); err != nil {
			return Result{}, err
		}
	}

	fmt.Println()
	fmt.Printf("next: place encrypted signing key at %s, then:\n", opts.KeyPath)
	fmt.Printf("  luna-proxy --socket /run/luna/control.sock key load %s\n", opts.KeyPath)

	return Result{
		CertsDir:    opts.CertsDir,
		ConfigPath:  cfgRes.Path,
		EnrollToken: cfgRes.EnrollToken,
		Hostname:    opts.Hostname,
	}, nil
}

func EnsureCertDirLayout(certsDir string) error {
	return os.MkdirAll(filepath.Clean(certsDir), 0o750)
}
