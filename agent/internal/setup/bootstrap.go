package setup

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	mtlsCAPath          = "/api/v1/mtls/ca"
	mtlsEnrollPath      = "/api/v1/mtls/enroll"
	enrollTokenHeader   = "X-Luna-Enroll-Token"
	defaultProbeTimeout = 10 * time.Second
)

// ProbeProxyURL checks that the proxy HTTPS listener responds (healthz or mTLS CA endpoint).
// TLS verification is skipped; this is a network/listener check only.
func ProbeProxyURL(proxyURL string, timeout time.Duration) error {
	proxyURL = strings.TrimRight(strings.TrimSpace(proxyURL), "/")
	if proxyURL == "" {
		return fmt.Errorf("proxy URL is empty")
	}
	if !strings.HasPrefix(proxyURL, "https://") {
		return fmt.Errorf("proxy URL must use https://")
	}
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}

	client := bootstrapHTTPClient("", true, timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var lastErr error
	for _, path := range []string{"/healthz", mtlsCAPath} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, proxyURL+path, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("%s returned HTTP %d", path, resp.StatusCode)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no response")
	}
	return fmt.Errorf("%s: %w", proxyURL, lastErr)
}

// BootstrapOptions configures HTTP mTLS bootstrap against luna-proxy.
type BootstrapOptions struct {
	ProxyURL    string
	CertsDir    string
	EnrollToken string
	Timeout     time.Duration
	// InsecureSkipVerify allows fetching the CA before trust is installed (first contact only).
	InsecureSkipVerify bool
	// RefreshCA replaces ca.crt from the proxy before enroll (default for proxy enrollment).
	RefreshCA bool
}

// FetchCA downloads the proxy mTLS CA PEM to certsDir/ca.crt.
func FetchCA(opts BootstrapOptions) (string, error) {
	opts = opts.withDefaults()
	dest := filepath.Join(opts.CertsDir, "ca.crt")
	url := strings.TrimRight(opts.ProxyURL, "/") + mtlsCAPath

	client := bootstrapHTTPClient(opts.CertsDir, opts.InsecureSkipVerify, opts.Timeout)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", mtlsCAPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: HTTP %d: %s", mtlsCAPath, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if !looksLikePEMCert(body) {
		return "", fmt.Errorf("GET %s: response is not a PEM certificate", mtlsCAPath)
	}
	if err := writeFile(dest, body, 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

// RefreshTrustAnchor downloads ca.crt from the proxy and verifies it trusts the server TLS certificate.
func RefreshTrustAnchor(opts BootstrapOptions) error {
	opts = opts.withDefaults()
	if _, err := FetchCA(BootstrapOptions{
		ProxyURL:           opts.ProxyURL,
		CertsDir:           opts.CertsDir,
		InsecureSkipVerify: true,
		Timeout:            opts.Timeout,
	}); err != nil {
		return fmt.Errorf("download CA: %w", err)
	}
	if err := VerifyProxyServerTrust(opts.ProxyURL, opts.CertsDir, opts.Timeout); err != nil {
		return err
	}
	return nil
}

// VerifyProxyServerTrust checks that ca.crt in certsDir validates the proxy HTTPS server certificate.
func VerifyProxyServerTrust(proxyURL, certsDir string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	pool, err := loadCAPool(filepath.Join(certsDir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("load ca.crt: %w", err)
	}
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(proxyURL), "/"))
	if err != nil {
		return fmt.Errorf("parse proxy URL: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("proxy URL missing hostname")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: timeout},
		Config: &tls.Config{
			RootCAs:    pool,
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return formatServerTrustError(proxyURL, err)
	}
	_ = conn.Close()
	return nil
}

// EnrollClientCSR posts client.csr.pem to the proxy enroll endpoint and writes client.crt.
func EnrollClientCSR(opts BootstrapOptions) (string, error) {
	opts = opts.withDefaults()
	if strings.TrimSpace(opts.EnrollToken) == "" {
		return "", fmt.Errorf("enroll token required (set LUNA_MTLS_ENROLL_TOKEN or proxy mtls_enroll_token)")
	}
	if opts.RefreshCA {
		if err := RefreshTrustAnchor(opts); err != nil {
			return "", err
		}
	}
	csrPath := filepath.Join(opts.CertsDir, "client.csr.pem")
	csrPEM, err := os.ReadFile(csrPath)
	if err != nil {
		return "", fmt.Errorf("read client.csr.pem: %w", err)
	}
	url := strings.TrimRight(opts.ProxyURL, "/") + mtlsEnrollPath
	payload, err := json.Marshal(map[string]string{"csr_pem": string(csrPEM)})
	if err != nil {
		return "", err
	}

	client := bootstrapHTTPClient(opts.CertsDir, false, opts.Timeout)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(enrollTokenHeader, opts.EnrollToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", mtlsEnrollPath, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("POST %s: HTTP %d: %s", mtlsEnrollPath, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("decode enroll response: %w", err)
	}
	if !looksLikePEMCert([]byte(out.CertificatePEM)) {
		return "", fmt.Errorf("enroll response missing certificate_pem")
	}
	dest := filepath.Join(opts.CertsDir, "client.crt")
	if err := writeFile(dest, []byte(out.CertificatePEM), 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

func bootstrapHTTPClient(certsDir string, insecure bool, timeout time.Duration) *http.Client {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if !insecure {
		if pool, err := loadCAPool(filepath.Join(certsDir, "ca.crt")); err == nil {
			tlsCfg.RootCAs = pool
		}
	} else {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // bootstrap first contact only
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}
}

func formatServerTrustError(proxyURL string, err error) error {
	msg := err.Error()
	hints := []string{
		"ca.crt does not trust the server certificate at " + proxyURL,
		"common causes:",
		"  - stale ca.crt from an earlier luna-proxy setup (re-run setup; ca.crt is refreshed automatically)",
		"  - proxy PKI was regenerated with luna-proxy setup --force but the agent still has the old CA",
		"  - TLS terminates in front of luna-proxy (nginx/ingress) with a different certificate",
		"  - proxy hostname in the server cert SAN does not match the URL you entered",
	}
	if strings.Contains(msg, "x509:") || strings.Contains(msg, "tls:") {
		return fmt.Errorf("%s\n\n%s", strings.Join(hints, "\n"), msg)
	}
	return fmt.Errorf("verify server TLS: %w", err)
}

func formatEnrollError(err error, certsDir string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "invalid enroll token") || strings.Contains(msg, "HTTP 401") {
		return fmt.Errorf(`%w

Check mtls_enroll_token on the proxy matches the token you entered.
On the proxy: set mtls_enroll_token in proxy.yml and restart luna-proxy.`, err)
	}
	if strings.Contains(msg, "x509:") || strings.Contains(msg, "tls:") ||
		strings.Contains(msg, "does not trust the server certificate") {
		return fmt.Errorf(`%w

This is a TLS trust problem, not an enroll token mismatch.
Re-run luna-agent setup (ca.crt will be re-downloaded), or delete %s/ca.crt and try again.
Ensure the proxy URL hostname matches the certificate from luna-proxy setup.`, err, certsDir)
	}
	return err
}

func loadCAPool(caPath string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("parse CA PEM")
	}
	return pool, nil
}

func looksLikePEMCert(pemBytes []byte) bool {
	return bytes.Contains(pemBytes, []byte("BEGIN CERTIFICATE"))
}

func (o BootstrapOptions) withDefaults() BootstrapOptions {
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	o.ProxyURL = strings.TrimSpace(o.ProxyURL)
	o.CertsDir = filepath.Clean(o.CertsDir)
	o.EnrollToken = strings.TrimSpace(o.EnrollToken)
	return o
}
