package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/api"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
	"golang.org/x/crypto/ssh"
)

func testCADir(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "..", "testdata", "ca")
}

func loadTestTLSConfigs(t *testing.T) (server, client *tls.Config) {
	t.Helper()
	dir := testCADir(t)

	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		t.Fatal("append ca.crt")
	}

	serverCert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "server.key"),
	)
	if err != nil {
		t.Fatalf("load server cert: %v", err)
	}
	clientCert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "client.crt"),
		filepath.Join(dir, "client.key"),
	)
	if err != nil {
		t.Fatalf("load client cert: %v", err)
	}

	server = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}
	client = &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
	return server, client
}

// sharedTLSConn reuses one TLS connection so the HMAC exporter matches the server session.
type sharedTLSConn struct {
	once sync.Once
	conn *tls.Conn
	err  error
	cfg  *tls.Config
	addr string
}

func (s *sharedTLSConn) dial(ctx context.Context) (*tls.Conn, error) {
	s.once.Do(func() {
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", s.addr)
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

func (s *sharedTLSConn) transport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: s.cfg,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return s.dial(ctx)
		},
	}
}

type mtlsClient struct {
	http    *http.Client
	shared  *sharedTLSConn
}

func newMTLSClient(t *testing.T, ts *httptest.Server, clientTLS *tls.Config) *mtlsClient {
	t.Helper()
	shared := &sharedTLSConn{
		cfg:  clientTLS,
		addr: ts.Listener.Addr().String(),
	}
	tr := shared.transport()
	t.Cleanup(func() { tr.CloseIdleConnections() })
	return &mtlsClient{
		http:   &http.Client{Transport: tr, Timeout: 10 * time.Second},
		shared: shared,
	}
}

type testEnv struct {
	ts     *httptest.Server
	store  *approval.Store
	client *mtlsClient
}

func startTestServer(t *testing.T, cfg config.Config, ks *keystore.Keystore) *testEnv {
	t.Helper()
	if ks == nil {
		ks = keystore.New()
	}
	if cfg.Env != "production" {
		unsealTestKeystore(t, ks)
	}
	store := approval.NewStore(cfg.ApprovalTimeout)
	store.SetConfig(cfg)
	if cfg.SignerMode == approval.SignerModeLocalKey {
		store.SetKeySigner(signing.NewLocalKey(ks))
	} else {
		store.SetIssuer(signing.NewLocalCA(ks))
	}
	store.SetLeases(lease.NewStore())
	replay := auth.NewReplayLRU(60*time.Second, 1000)
	handler := api.NewServer(cfg, ks, store, replay, nil)

	serverTLS, clientTLS := loadTestTLSConfigs(t)
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = serverTLS
	ts.Config.ConnContext = api.ConnContext
	ts.StartTLS()
	t.Cleanup(ts.Close)

	return &testEnv{
		ts:     ts,
		store:  store,
		client: newMTLSClient(t, ts, clientTLS),
	}
}

func signPoP(t *testing.T, sshPub ssh.PublicKey, priv ed25519.PrivateKey, user, ip string, ts int64) string {
	t.Helper()
	msg := []byte(fmt.Sprintf("%s:%s:%d", user, ip, ts))
	sig := ed25519.Sign(priv, msg)
	return hex.EncodeToString(sig)
}

func buildSignBody(t *testing.T, user, ip string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(sshPub))
	ts := time.Now().Unix()
	popSig := signPoP(t, sshPub, priv, user, ip, ts)
	rawBody, err := json.Marshal(map[string]any{
		"public_key":    pubLine,
		"target_user":   user,
		"target_ip":     ip,
		"timestamp":     ts,
		"pop_signature": popSig,
	})
	if err != nil {
		t.Fatal(err)
	}
	return rawBody
}

func postSign(t *testing.T, env *testEnv, rawBody []byte) string {
	t.Helper()
	conn, err := env.client.shared.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auth.ComputeBodyHMAC(conn, rawBody)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, env.ts.URL+"/api/v1/ssh/sign", strings.NewReader(string(rawBody)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Body-Mac", hex.EncodeToString(mac))

	resp, err := env.client.http.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST status = %d, body = %s", resp.StatusCode, body)
	}

	var out struct {
		TxID string `json:"tx_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.TxID == "" || !strings.HasPrefix(out.TxID, "tx_") {
		t.Fatalf("tx_id = %q", out.TxID)
	}
	return out.TxID
}

func unsealTestKeystore(t *testing.T, ks *keystore.Keystore) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.key")
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "luna-test", []byte("test-pass"))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := ks.Unseal(path, "test-pass"); err != nil {
		t.Fatalf("unseal test keystore: %v", err)
	}
}

func startTestServerDefault(t *testing.T, cfg config.Config) *testEnv {
	t.Helper()
	return startTestServer(t, cfg, nil)
}

func TestPostSignReturns202(t *testing.T) {
	env := startTestServerDefault(t, config.Config{ApprovalTimeout: 60 * time.Second})
	body := buildSignBody(t, "deploy", "10.0.0.5")
	postSign(t, env, body)
}

func TestGetWaitReturns200AfterApprove(t *testing.T) {
	env := startTestServerDefault(t, config.Config{ApprovalTimeout: 60 * time.Second})
	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))

	env.store.Approve(txID, 5*time.Minute, "telegram:1")

	resp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatalf("GET wait: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}

	var out struct {
		SSHCertificate string `json:"ssh_certificate"`
		ExpiresAt      string `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.SSHCertificate, "ssh-ed25519-cert-v01@openssh.com") {
		t.Fatalf("cert = %q, want OpenSSH user certificate", out.SSHCertificate)
	}
	if out.ExpiresAt == "" {
		t.Fatal("missing expires_at")
	}
}

func TestGetWaitWrongClientCert403(t *testing.T) {
	env := startTestServerDefault(t, config.Config{ApprovalTimeout: 60 * time.Second})
	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))
	env.store.Approve(txID, 5*time.Minute, "telegram:1")

	dir := testCADir(t)
	adminCert, err := tls.LoadX509KeyPair(
		filepath.Join(dir, "admin-client.crt"),
		filepath.Join(dir, "admin-client.key"),
	)
	if err != nil {
		t.Fatalf("load admin client cert: %v", err)
	}
	_, clientTLS := loadTestTLSConfigs(t)
	otherTLS := clientTLS.Clone()
	otherTLS.Certificates = []tls.Certificate{adminCert}
	otherClient := newMTLSClient(t, env.ts, otherTLS)

	resp, err := otherClient.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403, body = %s", resp.StatusCode, body)
	}
}

func TestGetWaitTimeout408(t *testing.T) {
	env := startTestServerDefault(t, config.Config{ApprovalTimeout: 50 * time.Millisecond})
	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))

	resp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatalf("GET wait: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestTimeout {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 408, body = %s", resp.StatusCode, body)
	}
}

func TestHealthzNoMTLS(t *testing.T) {
	env := startTestServerDefault(t, config.Config{})
	_, clientTLS := loadTestTLSConfigs(t)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    clientTLS.RootCAs,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
	}
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr}).Get(env.ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "ok\n" {
		t.Fatalf("body = %q, want ok\\n", body)
	}
}

func TestGetWaitNotFound404(t *testing.T) {
	env := startTestServerDefault(t, config.Config{ApprovalTimeout: time.Second})
	resp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/tx_doesnotexist/wait")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestPostSignReplay409(t *testing.T) {
	env := startTestServerDefault(t, config.Config{ApprovalTimeout: 60 * time.Second})
	body := buildSignBody(t, "deploy", "10.0.0.5")
	postSign(t, env, body)

	conn, err := env.client.shared.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	mac, err := auth.ComputeBodyHMAC(conn, body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, env.ts.URL+"/api/v1/ssh/sign", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Luna-Body-Mac", hex.EncodeToString(mac))

	resp, err := env.client.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("replay status = %d, want 409", resp.StatusCode)
	}
}

func TestApproveIssuesLocalCACert(t *testing.T) {
	env := startTestServer(t, config.Config{ApprovalTimeout: 60 * time.Second}, nil)

	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))
	env.store.Approve(txID, 5*time.Minute, "telegram:1")

	resp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, body = %s", resp.StatusCode, body)
	}
	var out struct {
		SSHCertificate string `json:"ssh_certificate"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.SSHCertificate, "ssh-ed25519-cert-v01@openssh.com") {
		t.Fatalf("cert = %q, want OpenSSH user certificate", out.SSHCertificate)
	}
}

func TestDevBypassIssuesLocalCACert(t *testing.T) {
	env := startTestServer(t, config.Config{
		Env:             "dev",
		ApprovalTimeout: 60 * time.Second,
	}, nil)

	txID := postSign(t, env, buildSignBody(t, "deploy", "10.0.0.5"))

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := env.client.http.Get(env.ts.URL + "/api/v1/ssh/sign/" + txID + "/wait")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode == http.StatusOK {
			var out struct {
				SSHCertificate string `json:"ssh_certificate"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if !strings.Contains(out.SSHCertificate, "ssh-ed25519-cert-v01@openssh.com") {
				t.Fatalf("cert = %q, want OpenSSH user certificate", out.SSHCertificate)
			}
			return
		}
		resp.Body.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("dev auto-approve did not complete")
}
