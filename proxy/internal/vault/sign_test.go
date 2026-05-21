package vault_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ba0f3/luna-ztrust/proxy/internal/vault"
)

func TestSignSSHKeyPostsToVault(t *testing.T) {
	const wantToken = "test-token"
	var got struct {
		PublicKey       string            `json:"public_key"`
		ValidPrincipals string            `json:"valid_principals"`
		CriticalOptions map[string]string `json:"critical_options"`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/ssh-agent-signer/sign/agent-role" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if got := r.Header.Get("X-Vault-Token"); got != wantToken {
			t.Errorf("X-Vault-Token = %q, want %q", got, wantToken)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]string{
				"signed_key": "ssh-ed25519-cert-v01@openssh.com AAAAsigned",
			},
		})
	}))
	defer srv.Close()

	pubKey := "ssh-ed25519 AAAA... user@host"
	cert, err := vault.SignSSHKey(
		context.Background(),
		vault.SignConfig{VaultAddr: srv.URL},
		wantToken,
		pubKey,
		"deploy",
		"10.0.0.5",
	)
	if err != nil {
		t.Fatalf("SignSSHKey: %v", err)
	}
	if cert != "ssh-ed25519-cert-v01@openssh.com AAAAsigned" {
		t.Fatalf("cert = %q", cert)
	}
	if got.PublicKey != pubKey {
		t.Fatalf("public_key = %q", got.PublicKey)
	}
	if got.ValidPrincipals != "deploy" {
		t.Fatalf("valid_principals = %q", got.ValidPrincipals)
	}
	if got.CriticalOptions["source-address"] != "10.0.0.5" {
		t.Fatalf("source-address = %q", got.CriticalOptions["source-address"])
	}
}

func TestSignSSHKeyCustomSignPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/custom/sign" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]string{"signed_key": "cert"},
		})
	}))
	defer srv.Close()

	cert, err := vault.SignSSHKey(
		context.Background(),
		vault.SignConfig{VaultAddr: srv.URL, SignPath: "/v1/custom/sign"},
		"tok",
		"ssh-ed25519 AAAA",
		"user",
		"1.2.3.4",
	)
	if err != nil {
		t.Fatal(err)
	}
	if cert != "cert" {
		t.Fatalf("cert = %q", cert)
	}
}

func TestSignSSHKeyVaultError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := vault.SignSSHKey(
		context.Background(),
		vault.SignConfig{VaultAddr: srv.URL},
		"tok",
		"key",
		"user",
		"ip",
	)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v, want status 403", err)
	}
}
