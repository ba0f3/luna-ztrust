package sdk

import (
	"context"

	"github.com/ba0f3/luna-ztrust/sdk/sign"
	"golang.org/x/crypto/ssh"
)

// SignatureRequest identifies the SSH session for hosted-key signing.
type SignatureRequest = sign.SignatureRequest

// SessionBinding proves the destination SSH host key and exchange hash.
type SessionBinding = sign.SessionBinding

// RequestSignature obtains a hosted-key SSH signature for signData. Agent
// callers provide SessionBinding; direct x/crypto/ssh callers provide the host
// key accepted by their HostKeyCallback in DestinationHostPublicKey.
func (c *Client) RequestSignature(ctx context.Context, req SignatureRequest, signData []byte) (*ssh.Signature, error) {
	return c.inner.RequestSignature(ctx, req, signData)
}
