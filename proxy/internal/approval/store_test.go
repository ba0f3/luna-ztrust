package approval_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
)

type stubIssuer struct {
	cert string
}

func (s stubIssuer) IssueCert(_ context.Context, req signing.IssueRequest) (signing.IssueResult, error) {
	return signing.IssueResult{
		Certificate: s.cert,
		ExpiresAt:   req.ValidUntil,
	}, nil
}

func TestStoreApproveWakesWaiter(t *testing.T) {
	s := approval.NewStore(60 * time.Second)
	s.SetIssuer(stubIssuer{cert: "certpem"})
	tx, _ := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA", "203.0.113.1", "fp1", "")
	go func() {
		time.Sleep(10 * time.Millisecond)
		s.Approve(tx.ID, time.Minute, "telegram:1")
	}()
	cert, _, _, _, err := s.Wait(context.Background(), tx.ID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if cert != "certpem" {
		t.Fatalf("cert = %q, want certpem", cert)
	}
}

func TestStoreDevBypass(t *testing.T) {
	s := approval.NewStore(60 * time.Second)
	s.SetIssuer(stubIssuer{cert: "ssh-ed25519-cert-v01@openssh.com AAAAutotest"})
	s.SetConfig(config.Config{Env: "dev"})
	tx, ch := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA", "203.0.113.1", "fp1", "")
	select {
	case res := <-ch:
		if res.Err != nil {
			t.Fatalf("dev bypass err: %v", res.Err)
		}
		if !strings.Contains(res.Cert, "cert-v01") {
			t.Fatalf("cert = %q, want SSH certificate", res.Cert)
		}
	case <-time.After(time.Second):
		t.Fatal("dev bypass did not auto-approve")
	}
	if tx.State != approval.StateApproved {
		t.Fatalf("state = %q, want approved", tx.State)
	}
}

func TestStoreLocalKeyRequiresAgentSignData(t *testing.T) {
	s := approval.NewStore(60 * time.Second)
	s.SetConfig(config.Config{SignerMode: approval.SignerModeLocalKey})
	tx, _ := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA", "203.0.113.1", "fp1", "")
	go func() {
		time.Sleep(10 * time.Millisecond)
		s.Approve(tx.ID, time.Minute, "telegram:1")
	}()
	_, _, _, _, err := s.Wait(context.Background(), tx.ID)
	if err != approval.ErrAgentSignData {
		t.Fatalf("err = %v, want ErrAgentSignData", err)
	}
}
