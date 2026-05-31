package setup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ba0f3/luna-ztrust/agent/internal/install"
	"github.com/ba0f3/luna-ztrust/sdk"
)

// Options configures the full luna-agent setup pipeline.
type Options struct {
	CertsDir           string
	ConfigPath         string
	FromDir            string
	CAFile             string
	CAKeyFile          string
	CertFile           string
	KeyFile            string
	ProxyURL           string
	TargetUser         string
	TargetHost         string
	SignerMode         string
	HostKeyFingerprint string
	EnrollToken        string
	EnrollViaProxy     bool
	FetchCA            bool
	Force              bool
	RewriteConfig      bool
	SkipVerify         bool
	InstallSystemd     bool
	SystemdEnable      bool
	SkipUserCreate     bool
}

// Result summarizes setup output.
type Result struct {
	CertsDir   string
	ConfigPath string
}

// Run executes setup steps: dirs → certs → agent.yml → verify → optional systemd.
func Run(opts Options) (Result, error) {
	opts = opts.withDefaults()
	if opts.ProxyURL != "" {
		if err := ProbeProxyURL(opts.ProxyURL, defaultProbeTimeout); err != nil {
			return Result{}, fmt.Errorf("proxy unreachable: %w", err)
		}
	}
	if err := os.MkdirAll(opts.CertsDir, 0o750); err != nil {
		return Result{}, fmt.Errorf("create certs dir: %w", err)
	}

	if opts.FromDir != "" {
		fmt.Printf("step 1/5: install mTLS material from %s\n", opts.FromDir)
		if err := InstallFromDir(opts.FromDir, opts.CertsDir, opts.Force); err != nil {
			return Result{}, err
		}
	}
	if opts.CAFile != "" {
		fmt.Println("step 1/5: install CA certificate")
		if err := InstallFile(opts.CAFile, filepath.Join(opts.CertsDir, "ca.crt"), 0o644, opts.Force); err != nil {
			return Result{}, err
		}
	} else if opts.FetchCA {
		fmt.Println("step 1/5: download CA certificate from proxy")
		caPath, err := FetchCA(BootstrapOptions{
			ProxyURL:           opts.ProxyURL,
			CertsDir:           opts.CertsDir,
			InsecureSkipVerify: true,
		})
		if err != nil {
			return Result{}, fmt.Errorf("fetch CA: %w", err)
		}
		fmt.Printf("  %s\n", caPath)
	}
	if opts.CertFile != "" {
		if err := InstallFile(opts.CertFile, filepath.Join(opts.CertsDir, "client.crt"), 0o644, opts.Force); err != nil {
			return Result{}, err
		}
	}
	if opts.KeyFile != "" {
		if err := InstallFile(opts.KeyFile, filepath.Join(opts.CertsDir, "client.key"), 0o600, opts.Force); err != nil {
			return Result{}, err
		}
	}

	if opts.CAKeyFile != "" {
		fmt.Println("step 1/5: install CA key for client cert signing")
		if err := InstallFile(opts.CAKeyFile, filepath.Join(opts.CertsDir, "ca.key"), 0o400, opts.Force); err != nil {
			return Result{}, err
		}
	}

	if !fileExists(filepath.Join(opts.CertsDir, "client.key")) {
		fmt.Println("step 2/5: generate client key and CSR")
		res, err := GenerateClientKey(ClientOptions{Dir: opts.CertsDir, Force: opts.Force})
		if err != nil {
			return Result{}, err
		}
		fmt.Printf("  %s\n  %s\n", res.KeyPath, res.CSRPath)
	} else {
		fmt.Println("step 2/5: client.key already present")
	}

	if !fileExists(filepath.Join(opts.CertsDir, "client.crt")) {
		caKey := opts.CAKeyFile
		if caKey == "" {
			caKey = filepath.Join(opts.CertsDir, "ca.key")
		}
		if fileExists(caKey) && fileExists(filepath.Join(opts.CertsDir, "client.csr.pem")) {
			fmt.Println("step 3/5: sign client certificate with CA key")
			certPath, err := SignClientCSR(opts.CertsDir, 0, opts.Force)
			if err != nil {
				return Result{}, err
			}
			fmt.Printf("  %s\n", certPath)
		} else if opts.ProxyURL != "" && fileExists(filepath.Join(opts.CertsDir, "ca.crt")) &&
			fileExists(filepath.Join(opts.CertsDir, "client.csr.pem")) {
			fmt.Println("step 3/5: enroll client certificate via proxy")
			if err := ensureEnrollToken(&opts); err != nil {
				return Result{}, fmt.Errorf("step 3/5: %w", err)
			}
			certPath, err := EnrollClientCSR(BootstrapOptions{
				ProxyURL:    opts.ProxyURL,
				CertsDir:    opts.CertsDir,
				EnrollToken: opts.EnrollToken,
			})
			if err != nil {
				return Result{}, fmt.Errorf(`step 3/5: proxy enroll failed: %w

Check mtls_enroll_token on the proxy matches the token you entered.
On the proxy: set mtls_enroll_token in proxy.yml and restart luna-proxy.`, err)
			}
			fmt.Printf("  %s\n", certPath)
		} else {
			return Result{}, fmt.Errorf(`step 3/5: client.crt missing — enroll via proxy (recommended):
  # on proxy: set mtls_enroll_token in proxy.yml and restart luna-proxy
  luna-agent setup --proxy-url %s --enroll-token '<token>'

Or sign on the proxy host:
  openssl x509 -req -in %s/client.csr.pem -CA %s/ca.crt -CAkey /path/to/ca.key \
    -CAcreateserial -out client.crt -days 3650 -sha256 \
    -extfile <(printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n')
  scp client.crt this-host:%s/client.crt
Or re-run with --ca-key /path/to/ca.key`, opts.ProxyURL, opts.CertsDir, opts.CertsDir, opts.CertsDir)
		}
	} else {
		fmt.Println("step 3/5: client.crt already present")
	}

	if !clientMaterialReady(opts.CertsDir) {
		return Result{}, fmt.Errorf("incomplete mTLS material under %s", opts.CertsDir)
	}

	fmt.Println("step 4/5: write agent config")
	cfgPath, err := WriteAgentConfig(ConfigOptions{
		Path:               opts.ConfigPath,
		ProxyURL:           opts.ProxyURL,
		SignerMode:         opts.SignerMode,
		CertsDir:           opts.CertsDir,
		TargetUser:         opts.TargetUser,
		TargetHost:         opts.TargetHost,
		HostKeyFingerprint: opts.HostKeyFingerprint,
		Force:              opts.Force || opts.RewriteConfig,
	})
	if err != nil {
		return Result{}, err
	}
	fmt.Printf("  %s\n", cfgPath)

	if !opts.SkipVerify {
		fmt.Println("step 5/5: verify proxy connection")
		if err := VerifyProxy(VerifyOptions{
			ProxyURL:   opts.ProxyURL,
			CertsDir:   opts.CertsDir,
			SignerMode: opts.SignerMode,
		}); err != nil {
			return Result{}, fmt.Errorf("verify proxy: %w", err)
		}
		fmt.Println("  proxy reachable (capabilities OK)")
	} else {
		fmt.Println("step 5/5: skipped proxy verify")
	}

	if opts.InstallSystemd {
		fmt.Println("installing systemd unit")
		if os.Geteuid() != 0 {
			return Result{}, fmt.Errorf("install systemd: must run as root (sudo luna-agent setup ...)")
		}
		if err := install.EnsureCertPermissions(opts.CertsDir, "luna"); err != nil {
			return Result{}, err
		}
		if err := install.InstallAgentSystemd(install.SystemdOptions{
			ConfigPath:     opts.ConfigPath,
			Enable:         opts.SystemdEnable,
			SkipUserCreate: opts.SkipUserCreate,
		}); err != nil {
			return Result{}, err
		}
	}

	return Result{CertsDir: opts.CertsDir, ConfigPath: cfgPath}, nil
}

// VerifyOptions configures a proxy capabilities check.
type VerifyOptions struct {
	ProxyURL   string
	CertsDir   string
	SignerMode string
	Timeout    time.Duration
}

// VerifyProxy checks mTLS connectivity and fetches capabilities.
func VerifyProxy(opts VerifyOptions) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	dir := opts.CertsDir
	if dir == "" {
		dir = DefaultCertsDir
	}
	tlsCert, tlsCA, err := sdk.LoadTLSConfig(
		filepath.Join(dir, "client.crt"),
		filepath.Join(dir, "client.key"),
		filepath.Join(dir, "ca.crt"),
	)
	if err != nil {
		return err
	}
	client, err := sdk.NewClient(sdk.Config{
		ProxyURL:   opts.ProxyURL,
		TLSCert:    tlsCert,
		TLSRootCAs: tlsCA,
		Timeout:    opts.Timeout,
		SignerMode: opts.SignerMode,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()
	_, err = client.FetchCapabilities(ctx)
	return err
}

func (o Options) withDefaults() Options {
	if o.CertsDir == "" {
		if os.Geteuid() == 0 {
			o.CertsDir = DefaultCertsDir
		} else {
			o.CertsDir = defaultUserCertsDir()
		}
	}
	if o.ConfigPath == "" {
		if os.Geteuid() == 0 {
			o.ConfigPath = DefaultConfigPath
		} else {
			o.ConfigPath = filepath.Join(defaultUserConfigDir(), "agent.yml")
		}
	}
	if o.SignerMode == "" {
		o.SignerMode = "local-ca"
	}
	if o.EnrollToken == "" {
		o.EnrollToken = strings.TrimSpace(os.Getenv("LUNA_MTLS_ENROLL_TOKEN"))
	}
	return o
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func defaultUserCertsDir() string {
	return filepath.Join(defaultUserConfigDir(), "certs")
}

func defaultUserConfigDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "luna")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "luna")
}
