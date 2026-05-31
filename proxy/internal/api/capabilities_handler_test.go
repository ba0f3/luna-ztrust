package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/api"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func TestCapabilities_ReturnsSignerModeAndTTLs(t *testing.T) {
	env := startTestServerDefault(t, config.Config{
		SignerMode:        "local-ca",
		AllowedTTLSeconds: []int{180, 300, 900},
	})

	resp, err := env.client.http.Get(env.ts.URL + "/api/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var out struct {
		SignerMode        string `json:"signer_mode"`
		LeaseSupported    bool   `json:"lease_supported"`
		AllowedTTLSeconds []int  `json:"allowed_ttl_seconds"`
		Sealed            bool   `json:"sealed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.SignerMode != "local-ca" {
		t.Fatalf("signer_mode = %q", out.SignerMode)
	}
	if !out.LeaseSupported {
		t.Fatal("expected lease_supported true")
	}
	if len(out.AllowedTTLSeconds) != 3 {
		t.Fatalf("allowed_ttl_seconds = %v", out.AllowedTTLSeconds)
	}
	if out.Sealed {
		t.Fatal("test harness unseals keystore; expected sealed false")
	}
}

func TestCapabilities_LogsSealedAccess(t *testing.T) {
	buf := &bytes.Buffer{}
	defer api.SwapSignLogOut(buf)()

	env := startTestServer(t, config.Config{
		Env:        "production",
		SignerMode: "local-key",
	}, nil)

	resp, err := env.client.http.Get(env.ts.URL + "/api/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var out struct {
		Sealed bool `json:"sealed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if !out.Sealed {
		t.Fatal("expected sealed true in production without key load")
	}

	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("expected access log line")
	}
	var logEntry struct {
		Route         string `json:"route"`
		Outcome       string `json:"outcome"`
		Sealed        bool   `json:"sealed"`
		LoadedSigners int    `json:"loaded_signers"`
		SignerMode    string `json:"signer_mode"`
	}
	if err := json.Unmarshal([]byte(line), &logEntry); err != nil {
		t.Fatalf("log json: %v raw=%q", err, line)
	}
	if logEntry.Route != "capabilities" || logEntry.Outcome != "sealed" || !logEntry.Sealed {
		t.Fatalf("log = %+v", logEntry)
	}
	if logEntry.LoadedSigners != 0 || logEntry.SignerMode != "local-key" {
		t.Fatalf("log = %+v", logEntry)
	}
}
