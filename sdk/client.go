package sdk

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"time"

	"github.com/ba0f3/luna-ztrust/sdk/sign"
	"golang.org/x/crypto/ssh"
)

// CertRequest identifies the SSH session to certify.
type CertRequest struct {
	TargetUser string
	TargetIP   string
	Client     ClientInfo
}

// Config configures the Luna SDK HTTP client.
type Config struct {
	ProxyURL   string
	TLSCert    tls.Certificate
	TLSRootCAs *x509.CertPool
	Timeout    time.Duration
	SignerMode string
}

// Client requests ephemeral SSH credentials from luna-proxy.
type Client struct {
	inner      *sign.Client
	signerMode string
}

// NewClient creates an SDK client backed by the sign HTTP transport.
func NewClient(cfg Config) (*Client, error) {
	inner, err := sign.NewClient(sign.Config{
		ProxyURL:   cfg.ProxyURL,
		TLSCert:    cfg.TLSCert,
		TLSRootCAs: cfg.TLSRootCAs,
		Timeout:    cfg.Timeout,
	})
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner, signerMode: cfg.SignerMode}, nil
}

// SignerMode returns the configured signer mode (local-ca or local-key).
func (c *Client) SignerMode() string {
	if c.signerMode != "" {
		return c.signerMode
	}
	return sign.SignerModeLocalCA
}

// RequestCertificate obtains a signed SSH user certificate and ephemeral private key.
func (c *Client) RequestCertificate(ctx context.Context, req CertRequest) (*ssh.Certificate, ed25519.PrivateKey, error) {
	return c.inner.RequestCertificate(ctx, sign.CertRequest{
		TargetUser: req.TargetUser,
		TargetIP:   req.TargetIP,
		Client: sign.ClientInfo{
			SourceUser:    req.Client.SourceUser,
			ClientName:    req.Client.ClientName,
			ClientVersion: req.Client.ClientVersion,
		},
	})
}
