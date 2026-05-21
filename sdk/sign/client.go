package sign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultTimeout = 90 * time.Second

// Config configures the sign HTTP client.
type Config struct {
	ProxyURL   string
	TLSCert    tls.Certificate
	TLSRootCAs *x509.CertPool
	Timeout    time.Duration
}

// Client performs mTLS sign and wait requests against luna-proxy.
type Client struct {
	httpClient *http.Client
	proxyURL   string
	shared     *sharedTLSConn
}

// NewClient builds a sign client with a reused TLS session for request HMAC.
func NewClient(cfg Config) (*Client, error) {
	if cfg.ProxyURL == "" {
		return nil, fmt.Errorf("ProxyURL is required")
	}
	u, err := url.Parse(cfg.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("parse ProxyURL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("ProxyURL must use https")
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}

	serverName := u.Hostname()
	if serverName == "" || serverName == "127.0.0.1" || serverName == "::1" {
		serverName = "localhost"
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cfg.TLSCert},
		RootCAs:      cfg.TLSRootCAs,
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "443")
	}

	shared := &sharedTLSConn{cfg: tlsCfg, addr: host}
	tr := &http.Transport{
		TLSClientConfig: tlsCfg,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return shared.dial(ctx)
		},
	}

	return &Client{
		httpClient: &http.Client{Transport: tr, Timeout: timeout},
		proxyURL:   strings.TrimRight(cfg.ProxyURL, "/"),
		shared:     shared,
	}, nil
}

// RequestCertificate runs POST sign then GET wait and parses the SSH certificate.
func (c *Client) RequestCertificate(ctx context.Context, req CertRequest) (*ssh.Certificate, ed25519.PrivateKey, error) {
	if req.TargetUser == "" || req.TargetIP == "" {
		return nil, nil, fmt.Errorf("TargetUser and TargetIP are required")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ssh public key: %w", err)
	}

	ts := time.Now().Unix()
	popSig, err := signPoP(sshPub, priv, req.TargetUser, req.TargetIP, ts)
	if err != nil {
		return nil, nil, err
	}

	body, err := json.Marshal(Request{
		PublicKey:    string(ssh.MarshalAuthorizedKey(sshPub)),
		TargetUser:   req.TargetUser,
		TargetIP:     req.TargetIP,
		Timestamp:    ts,
		PopSignature: popSig,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	txID, err := c.postSign(ctx, body)
	if err != nil {
		return nil, nil, err
	}

	certLine, err := c.getWait(ctx, txID)
	if err != nil {
		return nil, nil, err
	}

	cert, err := parseCertificate(certLine)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func (c *Client) postSign(ctx context.Context, body []byte) (string, error) {
	conn, err := c.shared.dial(ctx)
	if err != nil {
		return "", fmt.Errorf("tls dial: %w", err)
	}
	mac, err := ComputeBodyHMAC(conn, body)
	if err != nil {
		return "", fmt.Errorf("body HMAC: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.proxyURL+"/api/v1/ssh/sign", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Body-Mac", FormatMACHeader(mac))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST sign: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return "", readHTTPError(resp, "POST sign")
	}

	var out Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode sign response: %w", err)
	}
	if out.TxID == "" {
		return "", fmt.Errorf("empty tx_id in sign response")
	}
	return out.TxID, nil
}

func (c *Client) getWait(ctx context.Context, txID string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.proxyURL+"/api/v1/ssh/sign/"+txID+"/wait", nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET wait: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", readHTTPError(resp, "GET wait")
	}

	var out WaitResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode wait response: %w", err)
	}
	if out.SSHCertificate == "" {
		return "", fmt.Errorf("empty ssh_certificate in wait response")
	}
	return out.SSHCertificate, nil
}

func parseCertificate(line string) (*ssh.Certificate, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse ssh certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("authorized key is not an SSH certificate")
	}
	return cert, nil
}

func signPoP(pub ssh.PublicKey, priv ed25519.PrivateKey, user, ip string, ts int64) (string, error) {
	msg := []byte(fmt.Sprintf("%s:%s:%d", user, ip, ts))
	sig := ed25519.Sign(priv, msg)
	sshSig := &ssh.Signature{Format: pub.Type(), Blob: sig}
	return hex.EncodeToString(sshSig.Blob), nil
}

func readHTTPError(resp *http.Response, op string) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("%s: HTTP %d", op, resp.StatusCode)
	}
	return fmt.Errorf("%s: HTTP %d: %s", op, resp.StatusCode, msg)
}

type sharedTLSConn struct {
	once sync.Once
	conn *tls.Conn
	err  error
	cfg  *tls.Config
	addr string
}

func (s *sharedTLSConn) dial(ctx context.Context) (*tls.Conn, error) {
	s.once.Do(func() {
		var d net.Dialer
		raw, err := d.DialContext(ctx, "tcp", s.addr)
		if err != nil {
			s.err = err
			return
		}
		tc := tls.Client(raw, s.cfg)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			s.err = err
			return
		}
		s.conn = tc
	})
	return s.conn, s.err
}
