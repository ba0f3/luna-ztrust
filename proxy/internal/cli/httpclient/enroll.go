package httpclient

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type enrollRequest struct {
	Label  string `json:"label"`
	CSRPEM string `json:"csr_pem"`
}

// EnrollResult is returned from POST /api/v1/cli/enroll (admin mTLS).
type EnrollResult struct {
	DeviceID       string
	CertificatePEM string
}

// Enroll registers a CLI device CSR over admin mTLS (no HMAC; admin cert only).
func Enroll(ctx context.Context, cfg MTLSConfig, label, csrPEM string) (EnrollResult, error) {
	label = strings.TrimSpace(label)
	csrPEM = strings.TrimSpace(csrPEM)
	if label == "" {
		return EnrollResult{}, fmt.Errorf("label required")
	}
	if csrPEM == "" {
		return EnrollResult{}, fmt.Errorf("csr_pem required")
	}

	tlsCfg, _, err := cfg.tlsConfigAndHost()
	if err != nil {
		return EnrollResult{}, err
	}
	if err := VerifyClientCertAgainstCA(cfg.Cert, cfg.CA); err != nil {
		return EnrollResult{}, err
	}

	body, err := json.Marshal(enrollRequest{Label: label, CSRPEM: csrPEM})
	if err != nil {
		return EnrollResult{}, err
	}

	endpoint := strings.TrimRight(cfg.ProxyURL, "/") + "/api/v1/cli/enroll"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return EnrollResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return EnrollResult{}, formatEnrollTLS(err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return EnrollResult{}, err
	}
	if resp.StatusCode != http.StatusCreated {
		return EnrollResult{}, enrollHTTPError(resp.StatusCode, respBody)
	}

	var out struct {
		DeviceID       string `json:"device_id"`
		CertificatePEM string `json:"certificate_pem"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return EnrollResult{}, fmt.Errorf("decode response: %w", err)
	}
	if out.DeviceID == "" || out.CertificatePEM == "" {
		return EnrollResult{}, fmt.Errorf("response missing device_id or certificate_pem")
	}
	return EnrollResult{
		DeviceID:       out.DeviceID,
		CertificatePEM: out.CertificatePEM,
	}, nil
}

func enrollHTTPError(status int, body []byte) error {
	return fmt.Errorf("cli enroll: HTTP %d", status)
}

// VerifyClientCertAgainstCA checks that clientCertPath is signed by caPath.
func VerifyClientCertAgainstCA(clientCertPath, caPath string) error {
	clientCert, err := loadPEMCertificate(clientCertPath)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("parse CA certificate")
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf(`admin certificate is not signed by the proxy CA at %s: %w

On the proxy host run:
  sudo luna-proxy setup admin-client --dir /etc/luna/certs --force
Then copy admin-client.crt and admin-client.key here again.`, caPath, err)
	}
	return nil
}

func loadPEMCertificate(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client certificate: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("parse client certificate: no CERTIFICATE PEM in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}
	return cert, nil
}

func formatEnrollTLS(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if strings.Contains(msg, "unknown certificate authority") || strings.Contains(msg, "bad certificate") {
		return fmt.Errorf(`proxy rejected the admin client certificate during mTLS

The admin-client.crt on this machine is not signed by the CA the proxy trusts (often after PKI was regenerated).
On the proxy:
  sudo luna-proxy setup admin-client --dir /etc/luna/certs --force
Copy the new admin-client.crt and admin-client.key here, then re-run enroll.

Original error: %w`, err)
	}
	return err
}
