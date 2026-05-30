package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

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
