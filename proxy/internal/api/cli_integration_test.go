package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestCLIIntegration_FullFlow(t *testing.T) {
	cfg := cliTestServerConfig(t)
	env := startTestServerLocalKeyWithConfig(t, cfg)

	cliClient, deviceID := enrollCLIDevice(t, env, cfg)
	if deviceID == "" {
		t.Fatal("missing device_id from enroll")
	}

	pemBytes := makeEncryptedHostPEM(t)
	resp := postCLIKeysLoad(t, cliClient, env.ts.URL, pemBytes, "integration-host")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("load status %d: %s", resp.StatusCode, b)
	}
	var loadOut struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loadOut); err != nil {
		t.Fatal(err)
	}
	if loadOut.Fingerprint == "" {
		t.Fatal("missing fingerprint")
	}

	found := false
	for _, s := range env.ks.ListSigners() {
		if strings.EqualFold(s.Fingerprint, loadOut.Fingerprint) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ListSigners missing fingerprint %q, have %+v", loadOut.Fingerprint, env.ks.ListSigners())
	}

	capResp, err := env.client.http.Get(env.ts.URL + "/api/v1/capabilities")
	if err != nil {
		t.Fatal(err)
	}
	defer capResp.Body.Close()
	if capResp.StatusCode != http.StatusOK {
		t.Fatalf("capabilities status %d", capResp.StatusCode)
	}
	var caps struct {
		LoadedSigners []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"loaded_signers"`
	}
	if err := json.NewDecoder(capResp.Body).Decode(&caps); err != nil {
		t.Fatal(err)
	}
	foundInCaps := false
	for _, s := range caps.LoadedSigners {
		if strings.EqualFold(s.Fingerprint, loadOut.Fingerprint) {
			foundInCaps = true
			break
		}
	}
	if !foundInCaps {
		t.Fatalf("capabilities missing fingerprint %q, have %+v", loadOut.Fingerprint, caps.LoadedSigners)
	}

	_, adminTLS, _ := loadAdminTLSConfigs(t)
	admin := newMTLSClient(t, env.ts, adminTLS)
	delReq, err := http.NewRequest(http.MethodDelete, env.ts.URL+"/api/v1/cli/devices/"+deviceID, nil)
	if err != nil {
		t.Fatal(err)
	}
	delResp, err := admin.http.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	delResp.Body.Close()
	if delResp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status %d, want 204", delResp.StatusCode)
	}

	retryResp := postCLIKeysLoad(t, cliClient, env.ts.URL, pemBytes, "after-revoke")
	defer retryResp.Body.Close()
	if retryResp.StatusCode != http.StatusForbidden {
		b, _ := io.ReadAll(retryResp.Body)
		t.Fatalf("retry load status %d, want 403: %s", retryResp.StatusCode, b)
	}
}
