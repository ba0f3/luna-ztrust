package httpclient

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
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
	Timestamp    int64  `json:"timestamp"`
}

type loadResponse struct {
	Fingerprint string `json:"fingerprint"`
}

type loadErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// Load uploads a local encrypted PEM to POST /api/v1/cli/keys/load over mTLS.
// Each call dials one TLS session; HMAC and the HTTP request share it, then the
// connection is closed when Load returns.
func Load(ctx context.Context, cfg Config, pemPath string, passphrase []byte, label string) (string, error) {
	pemBytes, err := os.ReadFile(pemPath)
	if err != nil {
		return "", err
	}

	mtls := MTLSConfig{
		ProxyURL: cfg.ProxyURL,
		Cert:     cfg.CliCert,
		Key:      cfg.CliKey,
		CA:       cfg.CA,
	}
	tlsCfg, host, err := mtls.tlsConfigAndHost()
	if err != nil {
		return "", err
	}

	ts := time.Now().Unix()
	body, err := json.Marshal(loadRequest{
		EncryptedPEM: base64.StdEncoding.EncodeToString(pemBytes),
		Passphrase:   string(passphrase),
		Label:        label,
		Timestamp:    ts,
	})
	if err != nil {
		return "", err
	}

	conn, err := dialTLS(ctx, host, tlsCfg)
	if err != nil {
		return "", fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

	mac, err := auth.ComputeBodyHMAC(conn, body)
	if err != nil {
		return "", fmt.Errorf("body HMAC: %w", err)
	}

	client := &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
			DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
				return conn, nil
			},
		},
	}

	endpoint := strings.TrimRight(cfg.ProxyURL, "/") + "/api/v1/cli/keys/load"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Body-Mac", hex.EncodeToString(mac))

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
