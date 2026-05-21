package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
		ClientAuth:   tls.RequireAndVerifyClientCert,
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

func dialTestTLS(t *testing.T) (clientConn, serverConn *tls.Conn) {
	t.Helper()
	serverTLS, clientTLS := loadTestTLSConfigs(t)

	var (
		serverConnOut *tls.Conn
		clientConnOut *tls.Conn
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
				serverConnOut = tc
			}
		}
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)

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
			clientOnce.Do(func() { clientConnOut = tc })
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

	if clientConnOut == nil || serverConnOut == nil {
		t.Fatal("missing tls connection on client or server")
	}
	return clientConnOut, serverConnOut
}

func signPoP(t *testing.T, sshPub ssh.PublicKey, priv ed25519.PrivateKey, user, ip string, ts int64) string {
	t.Helper()
	msg := []byte(fmt.Sprintf("%s:%s:%d", user, ip, ts))
	sig := ed25519.Sign(priv, msg)
	return hex.EncodeToString(sig)
}

func TestValidateSignRequestRejectsBadHMACBeforePoP(t *testing.T) {
	clientConn, _ := dialTestTLS(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(sshPub))

	now := time.Now()
	ts := now.Unix()
	user, ip := "deploy", "10.0.0.5"
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

	req := &SignRequest{
		PublicKey:    pubLine,
		TargetUser:   user,
		TargetIP:     ip,
		Timestamp:    ts,
		PopSignature: popSig,
		BodyMAC:      "deadbeef",
	}

	replay := NewReplayLRU(60*time.Second, 100)
	err = ValidateSignRequest(clientConn, rawBody, req, now, replay)
	if !errors.Is(err, ErrInvalidHMAC) {
		t.Fatalf("got %v, want ErrInvalidHMAC", err)
	}
}

func TestValidateSignRequestValidRequest(t *testing.T) {
	clientConn, _ := dialTestTLS(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(sshPub))

	now := time.Now()
	ts := now.Unix()
	user, ip := "deploy", "10.0.0.5"
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

	mac, err := computeBodyHMAC(clientConn, rawBody)
	if err != nil {
		t.Fatal(err)
	}

	req := &SignRequest{
		PublicKey:    pubLine,
		TargetUser:   user,
		TargetIP:     ip,
		Timestamp:    ts,
		PopSignature: popSig,
		BodyMAC:      hex.EncodeToString(mac),
	}

	replay := NewReplayLRU(60*time.Second, 100)
	if err := ValidateSignRequest(clientConn, rawBody, req, now, replay); err != nil {
		t.Fatalf("valid request: %v", err)
	}
}
