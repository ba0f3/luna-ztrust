package setup

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// ExistingState describes on-disk material for repeatable setup.
type ExistingState struct {
	ConfigPath string
	CertsDir   string
	HasConfig  bool
	HasCA      bool
	HasCert    bool
	HasKey     bool
	HasCSR     bool
	Options    Options
}

// InteractiveOptions configures the setup wizard.
type InteractiveOptions struct {
	Prefill   Options
	AssumeYes bool
	Out       io.Writer
	In        io.Reader
}

// RunInteractive walks through setup prompts and returns Options for Run.
func RunInteractive(ioOpts InteractiveOptions) (Options, error) {
	p := newPrompter(ioOpts.In, ioOpts.Out)
	state := scanExisting(ioOpts.Prefill)

	fmt.Fprintln(p.out, "Luna Z-Trust — luna-agent setup")
	if state.HasConfig || state.HasCA || state.HasCert {
		fmt.Fprintln(p.out, "(re-run: existing files detected; press Enter to keep shown defaults)")
	}
	fmt.Fprintln(p.out)

	opts := ioOpts.Prefill.withDefaults()
	existing := state.Options

	proxyURL, err := p.askString("Proxy URL", firstNonEmpty(opts.ProxyURL, existing.ProxyURL))
	if err != nil {
		return Options{}, err
	}
	opts.ProxyURL = strings.TrimSpace(proxyURL)

	signer, err := p.askChoice("Signer mode (must match luna-proxy)", []string{"local-ca", "local-key"},
		firstNonEmpty(opts.SignerMode, existing.SignerMode, "local-ca"))
	if err != nil {
		return Options{}, err
	}
	opts.SignerMode = signer

	opts.TargetUser, err = p.askString("SSH target user (PoP principal)", firstNonEmpty(opts.TargetUser, existing.TargetUser, "deploy"))
	if err != nil {
		return Options{}, err
	}
	opts.TargetHost, err = p.askString("SSH target host/IP (PoP binding)", firstNonEmpty(opts.TargetHost, existing.TargetHost))
	if err != nil {
		return Options{}, err
	}

	certsDefault := firstNonEmpty(opts.CertsDir, existing.CertsDir, state.CertsDir)
	opts.CertsDir, err = p.askString("Certificate directory", certsDefault)
	if err != nil {
		return Options{}, err
	}
	opts.CertsDir = filepath.Clean(opts.CertsDir)

	cfgDefault := firstNonEmpty(opts.ConfigPath, existing.ConfigPath, state.ConfigPath)
	opts.ConfigPath, err = p.askString("Agent config file", cfgDefault)
	if err != nil {
		return Options{}, err
	}

	if opts.SignerMode == "local-key" {
		fmt.Fprintln(p.out, "  Host keys are discovered from GET /api/v1/capabilities after mTLS (all loaded signers).")
		fmt.Fprintln(p.out, "  Leave fingerprint blank to offer every key loaded on the proxy.")
		fmt.Fprintln(p.out, "  Set fingerprint only to restrict the agent to one key when several are loaded.")
		fp, err := p.askOptionalString("Host key fingerprint filter (optional)", firstNonEmpty(opts.HostKeyFingerprint, existing.HostKeyFingerprint))
		if err != nil {
			return Options{}, err
		}
		opts.HostKeyFingerprint = strings.TrimSpace(fp)
	}

	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, "mTLS client material:")
	state = rescanCerts(opts.CertsDir, state)
	switch state.materialSummary() {
	case "complete":
		fmt.Fprintf(p.out, "  found ca.crt, client.crt, client.key in %s\n", opts.CertsDir)
		useExisting, err := p.askYesNo("Use existing client certificate?", true)
		if err != nil {
			return Options{}, err
		}
		if !useExisting {
			opts.Force = true
			if err := opts.applyCertStrategy(p, state); err != nil {
				return Options{}, err
			}
		}
	default:
		if err := opts.applyCertStrategy(p, state); err != nil {
			return Options{}, err
		}
	}

	if os.Geteuid() == 0 {
		install, err := p.askYesNo("Install systemd service (luna-agent.service)?", !state.HasConfig || ioOpts.AssumeYes)
		if err != nil {
			return Options{}, err
		}
		opts.InstallSystemd = install
		if install {
			enable, err := p.askYesNo("Enable and start service now?", true)
			if err != nil {
				return Options{}, err
			}
			opts.SystemdEnable = enable
		}
	} else {
		fmt.Fprintln(p.out, "Note: run with sudo to install systemd service.")
	}

	verify, err := p.askYesNo("Verify proxy connection after setup?", true)
	if err != nil {
		return Options{}, err
	}
	opts.SkipVerify = !verify

	opts.RewriteConfig = true
	if !ioOpts.AssumeYes {
		fmt.Fprintln(p.out)
		ok, err := p.askYesNo("Proceed with setup?", true)
		if err != nil {
			return Options{}, err
		}
		if !ok {
			return Options{}, fmt.Errorf("setup cancelled")
		}
	}

	return opts.withDefaults(), nil
}

func (o *Options) applyCertStrategy(p *prompter, state ExistingState) error {
	choices := []string{
		"Copy from directory (scp from luna-proxy setup mtls)",
		"Provide CA cert + CA key and generate/sign client cert here",
		"Provide CA cert only — generate key/CSR (sign on proxy host)",
		"Provide individual file paths (ca, cert, key)",
	}
	idx, err := p.askIndex("How to provide mTLS material?", choices, 0)
	if err != nil {
		return err
	}
	switch idx {
	case 0:
		dir, err := p.askString("Source directory (contains ca.crt, client.crt, client.key)", "")
		if err != nil {
			return err
		}
		o.FromDir = strings.TrimSpace(dir)
		if o.FromDir == "" {
			return fmt.Errorf("source directory required")
		}
	case 1:
		ca, err := p.askString("Path to ca.crt", "")
		if err != nil {
			return err
		}
		o.CAFile = strings.TrimSpace(ca)
		caKey, err := p.askString("Path to ca.key (for signing)", "")
		if err != nil {
			return err
		}
		o.CAKeyFile = strings.TrimSpace(caKey)
		o.Force = true
	case 2:
		ca, err := p.askString("Path to ca.crt", "")
		if err != nil {
			return err
		}
		o.CAFile = strings.TrimSpace(ca)
		o.Force = true
	case 3:
		o.CAFile, err = p.askOptionalPath("Path to ca.crt (Enter to skip)")
		if err != nil {
			return err
		}
		o.CertFile, err = p.askOptionalPath("Path to client.crt (Enter to skip)")
		if err != nil {
			return err
		}
		o.KeyFile, err = p.askOptionalPath("Path to client.key (Enter to skip)")
		if err != nil {
			return err
		}
	}
	return nil
}

func scanExisting(prefill Options) ExistingState {
	prefill = prefill.withDefaults()
	state := ExistingState{
		ConfigPath: prefill.ConfigPath,
		CertsDir:   prefill.CertsDir,
		Options:    loadExistingConfig(prefill.ConfigPath),
	}
	if state.Options.CertsDir != "" {
		state.CertsDir = state.Options.CertsDir
	}
	state = rescanCerts(state.CertsDir, state)
	if _, err := os.Stat(prefill.ConfigPath); err == nil {
		state.HasConfig = true
	}
	return state
}

func rescanCerts(dir string, state ExistingState) ExistingState {
	state.CertsDir = dir
	state.HasCA = fileExists(filepath.Join(dir, "ca.crt"))
	state.HasCert = fileExists(filepath.Join(dir, "client.crt"))
	state.HasKey = fileExists(filepath.Join(dir, "client.key"))
	state.HasCSR = fileExists(filepath.Join(dir, "client.csr.pem"))
	return state
}

func (s ExistingState) materialSummary() string {
	if s.HasCA && s.HasCert && s.HasKey {
		return "complete"
	}
	return "incomplete"
}

func loadExistingConfig(path string) Options {
	if path == "" {
		return Options{}
	}
	if _, err := os.Stat(path); err != nil {
		return Options{}
	}
	v := viper.New()
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return Options{}
	}
	certsDir := DefaultCertsDir
	if p := strings.TrimSpace(v.GetString("mtls_ca")); p != "" {
		certsDir = filepath.Dir(p)
	}
	return Options{
		ProxyURL:           v.GetString("proxy_url"),
		SignerMode:         v.GetString("signer_mode"),
		TargetUser:         v.GetString("target_user"),
		TargetHost:         v.GetString("target_host"),
		HostKeyFingerprint: v.GetString("host_key_fingerprint"),
		CertsDir:           certsDir,
		ConfigPath:         path,
	}
}

type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func newPrompter(in io.Reader, out io.Writer) *prompter {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	r, ok := in.(*bufio.Reader)
	if !ok {
		r = bufio.NewReader(in)
	}
	return &prompter{in: r, out: out}
}

func (p *prompter) askString(label, defaultVal string) (string, error) {
	for {
		if defaultVal != "" {
			fmt.Fprintf(p.out, "%s [%s]: ", label, defaultVal)
		} else {
			fmt.Fprintf(p.out, "%s: ", label)
		}
		line, err := p.readLine()
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			if defaultVal != "" {
				return defaultVal, nil
			}
			fmt.Fprintln(p.out, "  value required")
			continue
		}
		return line, nil
	}
}

func (p *prompter) askOptionalString(label, defaultVal string) (string, error) {
	if defaultVal != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", label, defaultVal)
	} else {
		fmt.Fprintf(p.out, "%s (Enter to skip): ", label)
	}
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal, nil
	}
	return line, nil
}

func (p *prompter) askOptionalPath(label string) (string, error) {
	fmt.Fprintf(p.out, "%s: ", label)
	line, err := p.readLine()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (p *prompter) askYesNo(label string, defaultYes bool) (bool, error) {
	def := "y/N"
	if defaultYes {
		def = "Y/n"
	}
	for {
		fmt.Fprintf(p.out, "%s [%s]: ", label, def)
		line, err := p.readLine()
		if err != nil {
			return false, err
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			return defaultYes, nil
		}
		switch line {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(p.out, "  enter y or n")
		}
	}
}

func (p *prompter) askChoice(label string, choices []string, defaultVal string) (string, error) {
	defIdx := 0
	for i, c := range choices {
		if c == defaultVal {
			defIdx = i
			break
		}
	}
	idx, err := p.askIndex(label, choices, defIdx)
	if err != nil {
		return "", err
	}
	return choices[idx], nil
}

func (p *prompter) askIndex(label string, choices []string, defaultIdx int) (int, error) {
	fmt.Fprintln(p.out, label+":")
	for i, c := range choices {
		marker := " "
		if i == defaultIdx {
			marker = "*"
		}
		fmt.Fprintf(p.out, "  %s %d) %s\n", marker, i+1, c)
	}
	for {
		fmt.Fprintf(p.out, "Choice [%d]: ", defaultIdx+1)
		line, err := p.readLine()
		if err != nil {
			return 0, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			return defaultIdx, nil
		}
		var n int
		if _, err := fmt.Sscanf(line, "%d", &n); err != nil || n < 1 || n > len(choices) {
			fmt.Fprintf(p.out, "  enter 1-%d\n", len(choices))
			continue
		}
		return n - 1, nil
	}
}

func (p *prompter) readLine() (string, error) {
	line, err := p.in.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func IsInteractive(in *os.File) bool {
	if in == nil {
		in = os.Stdin
	}
	fi, err := in.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
