package sign_test

import (
	"context"
	"crypto/hmac"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/ba0f3/luna-ztrust/sdk/sign"
)

func TestBodyHMACRoundTrip(t *testing.T) {
	body := []byte(`{"target_user":"u"}`)
	serverTLS, clientTLS := loadTestTLSConfigs(t)

	var (
		serverConn *tls.Conn
		clientConn *tls.Conn
	)
	serverReady := make(chan struct{})

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(serverReady)
		w.WriteHeader(http.StatusOK)
	}))
	ts.TLS = serverTLS.Clone()
	ts.Config.ConnState = func(c net.Conn, state http.ConnState) {
		if state == http.StateActive {
			if tc, ok := c.(*tls.Conn); ok {
				serverConn = tc
			}
		}
	}
	ts.StartTLS()
	defer ts.Close()

	var clientOnce sync.Once
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
			clientOnce.Do(func() { clientConn = tc })
			return tc, nil
		},
	}
	defer tr.CloseIdleConnections()

	resp, err := (&http.Client{Transport: tr}).Get(ts.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	<-serverReady

	if clientConn == nil || serverConn == nil {
		t.Fatal("missing tls connection on client or server")
	}

	macClient, err := sign.ComputeBodyHMAC(clientConn, body)
	if err != nil {
		t.Fatalf("client MAC: %v", err)
	}
	macServer, err := sign.ComputeBodyHMAC(serverConn, body)
	if err != nil {
		t.Fatalf("server MAC: %v", err)
	}
	if !hmac.Equal(macClient, macServer) {
		t.Fatalf("MAC mismatch: client %x server %x", macClient, macServer)
	}

	header := sign.FormatMACHeader(macClient)
	if len(header) != 64 {
		t.Fatalf("header length %d, want 64 hex chars", len(header))
	}
}
