package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/auth"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/keystore"
	"github.com/ba0f3/luna-ztrust/proxy/internal/mobile"
)

type tlsConnKey struct{}

// NewServer returns an HTTP handler for sign, wait, webhook, and health routes.
// GET /healthz is registered without the mTLS gate: probes may use TLS without a client certificate.
func NewServer(cfg config.Config, ks *keystore.Keystore, pending *keystore.PendingStore, store *approval.Store, replay *auth.ReplayLRU, telegram *approval.Notifier, mob *mobile.Store) http.Handler {
	if pending == nil {
		pending = keystore.NewPendingStore()
	}
	if mob == nil {
		mob = mobile.NewStore()
	}
	s := &server{
		cfg:      cfg,
		keystore: ks,
		pending:  pending,
		store:    store,
		replay:   replay,
		telegram: telegram,
		mobile:   mob,
		push:     mobile.NewPushNotifier(cfg.FCMCredentials),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /api/v1/admin/unseal", s.withAdminMTLS(s.handleUnseal))
	mux.HandleFunc("GET /api/v1/admin/seal-status", s.withAdminMTLS(s.handleSealStatus))
	mux.HandleFunc("GET /api/v1/capabilities", s.withMTLS(s.handleCapabilities))
	mux.HandleFunc("POST /api/v1/ssh/sign", s.withMTLS(s.handleSign))
	mux.HandleFunc("GET /api/v1/ssh/sign/{tx_id}/wait", s.withMTLS(s.handleWait))
	mux.HandleFunc("POST /api/v1/telegram/webhook", s.handleTelegramWebhook)
	mux.HandleFunc("POST /api/v1/mobile/enroll", s.withAdminMTLS(s.handleMobileEnroll))
	mux.HandleFunc("DELETE /api/v1/mobile/devices/{device_id}", s.withAdminMTLS(s.handleMobileDeleteDevice))
	mux.HandleFunc("POST /api/v1/mobile/approve", s.withMTLS(s.handleMobileApprove))
	mux.HandleFunc("POST /api/v1/mobile/keys/pending", s.withMTLS(s.handleMobileKeysPending))
	return mux
}

type server struct {
	cfg      config.Config
	keystore *keystore.Keystore
	store    *approval.Store
	replay   *auth.ReplayLRU
	telegram *approval.Notifier
	mobile   *mobile.Store
	pending  *keystore.PendingStore
	push     mobile.Notifier
}

func (s *server) withMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// handleHealthz is intentionally outside withMTLS so load balancers can probe without a client cert.
func (s *server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

// ConnContext stores the server-side TLS connection for HMAC verification.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		return context.WithValue(ctx, tlsConnKey{}, tc)
	}
	return ctx
}

func tlsConnFromContext(ctx context.Context) (*tls.Conn, bool) {
	tc, ok := ctx.Value(tlsConnKey{}).(*tls.Conn)
	return tc, ok
}

// TLSConfigFromEnv builds a server TLS config from environment (deprecated: use LoadTLSConfig with config.Load).
func TLSConfigFromEnv() (*tls.Config, error) {
	certFile := envOr("LUNA_MTLS_SERVER_CERT", defaultCertPath("server.crt"))
	keyFile := envOr("LUNA_MTLS_SERVER_KEY", defaultCertPath("server.key"))
	caFile := envOr("LUNA_MTLS_CLIENT_CA", defaultCertPath("ca.crt"))
	return LoadTLSConfig(certFile, keyFile, caFile)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func defaultCertPath(name string) string {
	for _, base := range []string{
		"testdata/ca",
		filepath.Join("..", "..", "testdata", "ca"),
	} {
		p := filepath.Join(base, name)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join("testdata", "ca", name)
}

// LoadTLSConfig loads server certificate and client CA for mutual TLS.
func LoadTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read client CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse client CA")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// NewHTTPServer returns an http.Server configured for mTLS API and ConnContext.
func NewHTTPServer(addr string, handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Addr:        addr,
		Handler:     handler,
		TLSConfig:   tlsConfig,
		ReadTimeout: 30 * time.Second,
		ConnContext: ConnContext,
	}
}
