package httpclient_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/cli/httpclient"
)

func TestFetchCA_WritesPEM(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/mtls/ca" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(pem))
	}))
	t.Cleanup(ts.Close)

	dest := filepath.Join(t.TempDir(), "ca.crt")
	path, err := httpclient.FetchCA(context.Background(), ts.URL, dest)
	if err != nil {
		t.Fatal(err)
	}
	if path != dest {
		t.Fatalf("path = %q", path)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != pem {
		t.Fatalf("got %q", raw)
	}
}

func TestFetchCA_RejectsNonPEM(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not a cert"))
	}))
	t.Cleanup(ts.Close)

	_, err := httpclient.FetchCA(context.Background(), ts.URL, filepath.Join(t.TempDir(), "ca.crt"))
	if err == nil {
		t.Fatal("expected error")
	}
}
