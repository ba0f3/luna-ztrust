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

// Capabilities describes luna-proxy signing and approval features.
type Capabilities struct {
	SignerMode        string `json:"signer_mode"`
	LeaseSupported    bool   `json:"lease_supported"`
	AllowedTTLSeconds []int  `json:"allowed_ttl_seconds"`
	Sealed            bool   `json:"sealed"`
}

// FetchCapabilities returns proxy capabilities (requires mTLS, no request body).
func (c *Client) FetchCapabilities(ctx context.Context) (Capabilities, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.proxyURL+"/api/v1/capabilities", nil)
	if err != nil {
		return Capabilities{}, err
	}

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
