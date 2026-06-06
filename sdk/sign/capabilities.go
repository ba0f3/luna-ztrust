package sign

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	SignerModeLocalCA  = "local-ca"
	SignerModeLocalKey = "local-key"
)

// LoadedSigner is a host signing key currently available on the proxy.
type LoadedSigner struct {
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key,omitempty"`
	Comment     string `json:"comment,omitempty"`
}

// Capabilities describes luna-proxy signing and approval features.
type Capabilities struct {
	SignerMode        string         `json:"signer_mode"`
	LeaseSupported    bool           `json:"lease_supported"`
	AllowedTTLSeconds []int          `json:"allowed_ttl_seconds"`
	Sealed            bool           `json:"sealed"`
	LoadedSigners     []LoadedSigner `json:"loaded_signers,omitempty"`
}

// FetchCapabilities returns proxy capabilities (requires mTLS, no request body).
func (c *Client) FetchCapabilities(ctx context.Context) (Capabilities, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.proxyURL+"/api/v1/capabilities", nil)
	if err != nil {
		return Capabilities{}, err
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		caps, err := c.fetchCapabilitiesOnce(req)
		if err == nil {
			return caps, nil
		}
		lastErr = err
		if attempt == 0 && isRetryableConnErr(err) {
			c.httpClient.CloseIdleConnections()
			continue
		}
		break
	}
	return Capabilities{}, lastErr
}

func (c *Client) fetchCapabilitiesOnce(req *http.Request) (Capabilities, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Capabilities{}, fmt.Errorf("GET capabilities: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Capabilities{}, readHTTPError(resp, "GET capabilities")
	}

	var caps Capabilities
	if err := json.NewDecoder(resp.Body).Decode(&caps); err != nil {
		return Capabilities{}, fmt.Errorf("decode capabilities: %w", err)
	}
	if caps.SignerMode == "" {
		return Capabilities{}, fmt.Errorf("capabilities: empty signer_mode")
	}
	return caps, nil
}
