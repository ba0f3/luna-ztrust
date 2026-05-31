package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const mtlsCAPath = "/api/v1/mtls/ca"

// FetchCA downloads the proxy mTLS CA PEM from GET /api/v1/mtls/ca (no client certificate).
func FetchCA(ctx context.Context, proxyURL, destPath string) (string, error) {
	proxyURL = strings.TrimRight(strings.TrimSpace(proxyURL), "/")
	if proxyURL == "" {
		return "", fmt.Errorf("proxy URL is empty")
	}
	if !strings.HasPrefix(proxyURL, "https://") {
		return "", fmt.Errorf("proxy URL must use https://")
	}
	destPath = filepath.Clean(destPath)
	if destPath == "" {
		return "", fmt.Errorf("destination path is empty")
	}

	if ctx == nil {
		ctx = context.Background()
	}
	timeout := 30 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // bootstrap first contact only
				MinVersion:         tls.VersionTLS12,
			},
		},
	}

	url := proxyURL + mtlsCAPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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
	if !bytes.Contains(body, []byte("BEGIN CERTIFICATE")) {
		return "", fmt.Errorf("GET %s: response is not a PEM certificate", mtlsCAPath)
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return "", err
	}
	tmp := destPath + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, destPath); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return destPath, nil
}
