package sdk

import (
	"context"

	"github.com/ba0f3/luna-ztrust/sdk/sign"
)

// Capabilities describes luna-proxy signing and approval features.
type Capabilities = sign.Capabilities

// LoadedSigner is a host signing key currently available on the proxy.
type LoadedSigner = sign.LoadedSigner

// FetchCapabilities returns proxy capabilities using the configured mTLS client.
func (c *Client) FetchCapabilities(ctx context.Context) (Capabilities, error) {
	return c.inner.FetchCapabilities(ctx)
}
