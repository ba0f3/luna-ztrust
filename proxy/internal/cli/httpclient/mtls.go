package httpclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

// MTLSConfig holds client certificate paths for proxy HTTPS APIs.
type MTLSConfig struct {
	ProxyURL string
	Cert     string
	Key      string
	CA       string
}

func (c MTLSConfig) tlsConfigAndHost() (*tls.Config, string, error) {
	cert, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, "", fmt.Errorf("load client cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(c.CA)
	if err != nil {
		return nil, "", fmt.Errorf("read CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, "", fmt.Errorf("parse CA certificate")
	}

	serverName := "localhost"
	if u, err := url.Parse(c.ProxyURL); err == nil {
		if host := u.Hostname(); host != "" {
			serverName = host
		}
	}
	if serverName == "127.0.0.1" || serverName == "::1" {
		serverName = "localhost"
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	host := serverName
	if u, err := url.Parse(c.ProxyURL); err == nil && u.Host != "" {
		host = u.Host
	}
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}

	return tlsCfg, host, nil
}

func dialTLS(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, cfg)
	if err := tc.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	return tc, nil
}
