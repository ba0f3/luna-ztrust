package sign_test

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/sdk"
	"github.com/ba0f3/luna-ztrust/sdk/sign"
)

type tlsConnKey struct{}

func connContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		return context.WithValue(ctx, tlsConnKey{}, tc)
	}
	return ctx
}

func tlsConnFromContext(ctx context.Context) (*tls.Conn, bool) {
	tc, ok := ctx.Value(tlsConnKey{}).(*tls.Conn)
	return tc, ok
}

type mockSignServer struct {
	mu      sync.Mutex
	pending map[string]string // tx_id -> ssh public_key line from POST
}

func newMockSignServer() *mockSignServer {
	return &mockSignServer{
		pending: make(map[string]string),
	}
}

func (m *mockSignServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/capabilities", m.handleCapabilities)
	mux.HandleFunc("POST /api/v1/ssh/sign", m.handleSign)
	mux.HandleFunc("GET /api/v1/ssh/sign/{tx_id}/wait", m.handleWait)
	return mux
}

func (m *mockSignServer) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"signer_mode":         "local-ca",
		"lease_supported":     true,
		"allowed_ttl_seconds": []int{180, 300, 900},
		"sealed":              false,
	})
}

func (m *mockSignServer) handleSign(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	conn, ok := tlsConnFromContext(r.Context())
	if !ok {
		http.Error(w, "tls connection required", http.StatusUnauthorized)
		return
	}
	if err := verifyBodyHMAC(conn, rawBody, r.Header.Get("X-Luna-Body-Mac")); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req sign.Request
	if err := json.Unmarshal(rawBody, &req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	txID := "tx_test01HABCDEF"
	m.mu.Lock()
	m.pending[txID] = req.PublicKey
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"tx_id": txID})
}

func (m *mockSignServer) handleWait(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	txID := r.PathValue("tx_id")
	if txID == "" {
		http.Error(w, "missing tx_id", http.StatusBadRequest)
		return
	}

	m.mu.Lock()
	pubLine, ok := m.pending[txID]
	m.mu.Unlock()
	if !ok || pubLine == "" {
		http.Error(w, "transaction not found", http.StatusNotFound)
		return
	}

	certLine, err := certLineForPublicKey(pubLine)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(sign.WaitResponse{
		SSHCertificate: certLine,
		ExpiresAt:      time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
	})
}

func verifyBodyHMAC(conn *tls.Conn, body []byte, headerHex string) error {
	expected, err := sign.ComputeBodyHMAC(conn, body)
	if err != nil {
		return err
	}
	provided, err := hex.DecodeString(headerHex)
	if err != nil {
		return err
	}
	if len(provided) != len(expected) || subtle.ConstantTimeCompare(provided, expected) != 1 {
		return errInvalidMAC
	}
	return nil
}

var errInvalidMAC = &macError{"invalid body HMAC"}

type macError struct{ msg string }

func (e *macError) Error() string { return e.msg }

func startMockServer(t *testing.T) (*httptest.Server, *tls.Config) {
	t.Helper()
	mock := newMockSignServer()
	serverTLS, clientTLS := loadTestTLSConfigs(t)
	ts := httptest.NewUnstartedServer(mock.handler())
	ts.TLS = serverTLS
	ts.Config.ConnContext = connContext
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, clientTLS
}

func TestRequestCertificateHappyPath(t *testing.T) {
	ts, clientTLS := startMockServer(t)

	c, err := sign.NewClient(sign.Config{
		ProxyURL:   ts.URL,
		TLSCert:    clientTLS.Certificates[0],
		TLSRootCAs: clientTLS.RootCAs,
		Timeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		cert, priv, err := c.RequestCertificate(context.Background(), sign.CertRequest{
			TargetUser: "deploy",
			TargetIP:   "10.0.0.5",
		})
		if err != nil {
			t.Fatalf("RequestCertificate attempt %d: %v", i+1, err)
		}
		if cert == nil {
			t.Fatalf("attempt %d: nil certificate", i+1)
		}
		if len(priv) != ed25519.PrivateKeySize {
			t.Fatalf("attempt %d: private key len = %d", i+1, len(priv))
		}
	}
}

func TestFetchCapabilities(t *testing.T) {
	ts, clientTLS := startMockServer(t)

	c, err := sign.NewClient(sign.Config{
		ProxyURL:   ts.URL,
		TLSCert:    clientTLS.Certificates[0],
		TLSRootCAs: clientTLS.RootCAs,
		Timeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	caps, err := c.FetchCapabilities(context.Background())
	if err != nil {
		t.Fatalf("FetchCapabilities: %v", err)
	}
	if caps.SignerMode != "local-ca" {
		t.Fatalf("signer_mode = %q", caps.SignerMode)
	}
	if !caps.LeaseSupported {
		t.Fatal("expected lease_supported")
	}
	if len(caps.AllowedTTLSeconds) != 3 {
		t.Fatalf("allowed_ttl_seconds = %v", caps.AllowedTTLSeconds)
	}
}

func TestSDKClientFetchCapabilities(t *testing.T) {
	ts, _ := startMockServer(t)

	tlsCert, pool, err := sdk.LoadTLSConfig(
		filepath.Join(testCADir(t), "client.crt"),
		filepath.Join(testCADir(t), "client.key"),
		filepath.Join(testCADir(t), "ca.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}

	client, err := sdk.NewClient(sdk.Config{
		ProxyURL:   ts.URL,
		TLSCert:    tlsCert,
		TLSRootCAs: pool,
		Timeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	caps, err := client.FetchCapabilities(context.Background())
	if err != nil {
		t.Fatalf("FetchCapabilities: %v", err)
	}
	if caps.SignerMode != "local-ca" {
		t.Fatalf("signer_mode = %q", caps.SignerMode)
	}
}

func TestSDKClientRequestCertificate(t *testing.T) {
	ts, clientTLS := startMockServer(t)

	cert, pool, err := sdk.LoadTLSConfig(
		filepath.Join(testCADir(t), "client.crt"),
		filepath.Join(testCADir(t), "client.key"),
		filepath.Join(testCADir(t), "ca.crt"),
	)
	if err != nil {
		t.Fatal(err)
	}
	_ = pool

	client, err := sdk.NewClient(sdk.Config{
		ProxyURL:   ts.URL,
		TLSCert:    cert,
		TLSRootCAs: clientTLS.RootCAs,
		Timeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, priv, err := client.RequestCertificate(context.Background(), sdk.CertRequest{
		TargetUser: "deploy",
		TargetIP:   "10.0.0.5",
	})
	if err != nil {
		t.Fatalf("RequestCertificate: %v", err)
	}
	if got == nil || len(priv) == 0 {
		t.Fatal("expected cert and private key")
	}
}

func TestMockServerRejectsMissingHMAC(t *testing.T) {
	ts, clientTLS := startMockServer(t)

	tr := &http.Transport{
		TLSClientConfig: clientTLS,
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Post(
		ts.URL+"/api/v1/ssh/sign",
		"application/json",
		strings.NewReader(`{"public_key":"x","target_user":"u","target_ip":"1.2.3.4","timestamp":1,"pop_signature":"00"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// Ensure HMAC helper stays aligned with mock verifier.
func TestMockHMACMatchesSignPackage(t *testing.T) {
	body := []byte(`{"target_user":"deploy"}`)
	serverTLS, clientTLS := loadTestTLSConfigs(t)

	var serverConn, clientConn *tls.Conn
	ready := make(chan struct{})

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(ready)
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = serverTLS
	ts.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateActive {
			if tc, ok := c.(*tls.Conn); ok {
				serverConn = tc
			}
		}
	}
	ts.StartTLS()
	defer ts.Close()

	var once sync.Once
	tr := &http.Transport{
		TLSClientConfig: clientTLS,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, clientTLS)
			if err := tc.Handshake(); err != nil {
				raw.Close()
				return nil, err
			}
			once.Do(func() { clientConn = tc })
			return tc, nil
		},
	}
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr}).Get(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	<-ready

	macClient, err := sign.ComputeBodyHMAC(clientConn, body)
	if err != nil {
		t.Fatal(err)
	}
	macServer, err := sign.ComputeBodyHMAC(serverConn, body)
	if err != nil {
		t.Fatal(err)
	}
	if !hmac.Equal(macClient, macServer) {
		t.Fatalf("MAC mismatch client=%x server=%x", macClient, macServer)
	}
}
