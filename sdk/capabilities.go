package sdk

import (
	"context"

	"github.com/ba0f3/luna-ztrust/sdk/sign"
)

// Capabilities describes luna-proxy signing and approval features.
type Capabilities = sign.Capabilities

// FetchCapabilities returns proxy capabilities using the configured mTLS client.
func (c *Client) FetchCapabilities(ctx context.Context) (Capabilities, error) {
	return c.inner.FetchCapabilities(ctx)
}
