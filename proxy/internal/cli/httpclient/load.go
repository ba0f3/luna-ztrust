package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds mTLS settings for remote CLI key load.
type Config struct {
	ProxyURL string
	CliCert  string
	CliKey   string
	CA       string
}

type loadRequest struct {
	EncryptedPEM string `json:"encrypted_pem"`
	Passphrase   string `json:"passphrase"`
	Label        string `json:"label"`
}

type loadResponse struct {
	Fingerprint string `json:"fingerprint"`
}

type loadErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// Load uploads a local encrypted PEM to POST /api/v1/cli/keys/load over mTLS.
func Load(ctx context.Context, cfg Config, pemPath string, passphrase []byte, label string) (string, error) {
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}

	client, err := newMTLSClient(cfg)
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(loadRequest{
		EncryptedPEM: base64.StdEncoding.EncodeToString(pemBytes),
		Passphrase:   string(passphrase),
		Label:        label,
	})
	if err != nil {
		return "", err
	}

	endpoint := strings.TrimRight(cfg.ProxyURL, "/") + "/api/v1/cli/keys/load"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", loadHTTPError(resp.StatusCode, respBody)
	}

	var out loadResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.Fingerprint == "" {
		return "", fmt.Errorf("response missing fingerprint")
	}
	return out.Fingerprint, nil
}

func newMTLSClient(cfg Config) (*http.Client, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CliCert, cfg.CliKey)
	if err != nil {
		return nil, fmt.Errorf("load cli cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.CA)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA certificate")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}
	if u, err := url.Parse(cfg.ProxyURL); err == nil {
		if host := u.Hostname(); host != "" {
			tlsCfg.ServerName = host
		}
	}

	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}

func loadHTTPError(status int, body []byte) error {
	msg := strings.TrimSpace(string(body))
	var j loadErrorResponse
	if json.Unmarshal(body, &j) == nil && j.Error != "" {
		if j.Code != "" {
			return fmt.Errorf("remote key load (%d): %s [%s]", status, j.Error, j.Code)
		}
		return fmt.Errorf("remote key load (%d): %s", status, j.Error)
	}
	if msg == "" {
		return fmt.Errorf("remote key load: HTTP %d", status)
	}
	return fmt.Errorf("remote key load (%d): %s", status, msg)
}
