package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const defaultSignPath = "/v1/ssh-agent-signer/sign/agent-role"

// SignConfig holds Vault SSH CA signing endpoint settings.
type SignConfig struct {
	VaultAddr  string
	SignPath   string
	HTTPClient *http.Client
}

// TokenProvider supplies a Vault API token for signing requests.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}

// SignSSHKey requests an SSH certificate from the Vault SSH secrets engine.
func SignSSHKey(ctx context.Context, cfg SignConfig, token, pubKey, user, clientIP string) (string, error) {
	if cfg.VaultAddr == "" {
		return "", fmt.Errorf("vault address not configured")
	}
	path := cfg.SignPath
	if path == "" {
		path = defaultSignPath
	}
	url := strings.TrimRight(cfg.VaultAddr, "/") + path

	payload := map[string]any{
		"public_key":       pubKey,
		"valid_principals": user,
		"critical_options": map[string]string{
			"source-address": clientIP,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal sign request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)

	client := cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault sign request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read vault response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault sign: status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var vaultResp struct {
		Data struct {
			SignedKey string `json:"signed_key"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &vaultResp); err != nil {
		return "", fmt.Errorf("decode vault response: %w", err)
	}
	if vaultResp.Data.SignedKey == "" {
		return "", fmt.Errorf("vault sign: empty signed_key")
	}
	return vaultResp.Data.SignedKey, nil
}
