package setup

import (
	"fmt"
	"os"
	"strings"
)

func ensureEnrollToken(opts *Options) error {
	if opts == nil {
		return fmt.Errorf("enroll token required")
	}
	*opts = opts.withDefaults()
	if opts.EnrollToken != "" {
		return nil
	}
	if !IsInteractive(nil) {
		return fmt.Errorf(`enroll token required — on the proxy set mtls_enroll_token in proxy.yml, then run:
  luna-agent setup --enroll-token '<token>'
Or: export LUNA_MTLS_ENROLL_TOKEN='<token>'`)
	}
	fmt.Fprintln(os.Stdout, "  enroll token required (must match proxy mtls_enroll_token)")
	p := newPrompter(os.Stdin, os.Stdout)
	token, err := promptEnrollToken(p, "")
	if err != nil {
		return err
	}
	opts.EnrollToken = strings.TrimSpace(token)
	if opts.EnrollToken == "" {
		return fmt.Errorf("enroll token required")
	}
	return nil
}

func promptEnrollToken(p *prompter, defaultVal string) (string, error) {
	fmt.Fprintln(p.out)
	fmt.Fprintln(p.out, "  Bootstrap password for client certificate signing (you invent this string).")
	fmt.Fprintln(p.out, "  1. On the PROXY host, add the same string to /etc/luna/proxy.yml:")
	fmt.Fprintln(p.out, "       mtls_enroll_token: \"your-secret-here\"")
	fmt.Fprintln(p.out, "     then: sudo systemctl restart luna-proxy")
	fmt.Fprintln(p.out, "  2. Type that exact string below (like a one-time API key).")
	fmt.Fprintln(p.out)
	return p.askString("Bootstrap password (mtls_enroll_token)", defaultVal)
}
