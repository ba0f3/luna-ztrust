package sign

import (
	"bufio"
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
	"strconv"
	"strings"
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
	tlsCfg     *tls.Config
	addr       string
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

	tr := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     90 * time.Second,
	}

	return &Client{
		httpClient: &http.Client{Transport: tr, Timeout: timeout},
		proxyURL:   strings.TrimRight(cfg.ProxyURL, "/"),
		tlsCfg:     tlsCfg,
		addr:       host,
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
		PublicKey:     string(ssh.MarshalAuthorizedKey(sshPub)),
		TargetUser:    req.TargetUser,
		TargetIP:      req.TargetIP,
		Timestamp:     ts,
		PopSignature:  popSig,
		SourceUser:    req.Client.SourceUser,
		ClientName:    req.Client.ClientName,
		ClientVersion: req.Client.ClientVersion,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal request: %w", err)
	}

	txID, err := c.postSign(ctx, body)
	if err != nil {
		return nil, nil, err
	}

	wait, err := c.getWait(ctx, txID)
	if err != nil {
		return nil, nil, err
	}
	if wait.SSHCertificate == "" {
		return nil, nil, fmt.Errorf("empty ssh_certificate in wait response")
	}

	cert, err := parseCertificate(wait.SSHCertificate)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

func (c *Client) postSign(ctx context.Context, body []byte) (string, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		txID, err := c.postSignOnce(ctx, body)
		if err == nil {
			return txID, nil
		}
		lastErr = err
		if attempt == 0 && isRetryableConnErr(err) {
			continue
		}
		break
	}
	return "", lastErr
}

func (c *Client) postSignOnce(ctx context.Context, body []byte) (string, error) {
	conn, err := c.dialTLS(ctx)
	if err != nil {
		return "", fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()

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
	req.ContentLength = int64(len(body))

	resp, err := doHTTPOverConn(ctx, conn, req)
	if err != nil {
		return "", fmt.Errorf("POST sign: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		return "", readHTTPError(resp, "POST sign")
	}

	var out Response
	// 🛡️ Sentinel: Enforce maximum response size to prevent memory exhaustion DoS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", fmt.Errorf("decode sign response: %w", err)
	}
	if out.TxID == "" {
		return "", fmt.Errorf("empty tx_id in sign response")
	}
	return out.TxID, nil
}

func (c *Client) getWait(ctx context.Context, txID string) (WaitResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.proxyURL+"/api/v1/ssh/sign/"+txID+"/wait", nil)
	if err != nil {
		return WaitResponse{}, err
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		resp, err := c.httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return WaitResponse{}, readHTTPError(resp, "GET wait")
			}
			var out WaitResponse
			// 🛡️ Sentinel: Enforce maximum response size to prevent memory exhaustion DoS
			if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
				return WaitResponse{}, fmt.Errorf("decode wait response: %w", err)
			}
			return out, nil
		}
		lastErr = err
		if attempt == 0 && isRetryableConnErr(err) {
			c.httpClient.CloseIdleConnections()
			continue
		}
		break
	}
	return WaitResponse{}, fmt.Errorf("GET wait: %w", lastErr)
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
	// Optimization: avoid fmt.Sprintf overhead and allocations in hot path
	msg := make([]byte, 0, len(user)+len(ip)+2+20)
	msg = append(msg, user...)
	msg = append(msg, ':')
	msg = append(msg, ip...)
	msg = append(msg, ':')
	msg = strconv.AppendInt(msg, ts, 10)

	sig := ed25519.Sign(priv, msg)
	sshSig := &ssh.Signature{Format: pub.Type(), Blob: sig}
	return hex.EncodeToString(sshSig.Blob), nil
}

func readHTTPError(resp *http.Response, op string) error {
	// Drain body but do not include it in the error to prevent information disclosure
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("%s: HTTP %d", op, resp.StatusCode)
}

func (c *Client) dialTLS(ctx context.Context) (*tls.Conn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	tc := tls.Client(raw, c.tlsCfg.Clone())
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return tc, nil
}

func doHTTPOverConn(ctx context.Context, conn net.Conn, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(conn), req)
}

func isRetryableConnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "eof") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "use of closed network connection") ||
		strings.Contains(msg, "tls: ")
}
