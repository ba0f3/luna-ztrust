package approval_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
	"github.com/ba0f3/luna-ztrust/proxy/internal/signing"
)

type stubIssuer struct {
	cert string
}

type blockingIssuer struct {
	started sync.Once
	start   chan struct{}
	release chan struct{}
}

func (b *blockingIssuer) IssueCert(_ context.Context, req signing.IssueRequest) (signing.IssueResult, error) {
	b.started.Do(func() { close(b.start) })
	<-b.release
	return signing.IssueResult{Certificate: "certpem", ExpiresAt: req.ValidUntil}, nil
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
	tx, _ := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA", "203.0.113.1", "fp1", "", "", approval.ClientMeta{})
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
	tx, ch := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA", "203.0.113.1", "fp1", "", "", approval.ClientMeta{})
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
	tx, _ := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA", "203.0.113.1", "fp1", "", "", approval.ClientMeta{})
	go func() {
		time.Sleep(10 * time.Millisecond)
		s.Approve(tx.ID, time.Minute, "telegram:1")
	}()
	_, _, _, _, err := s.Wait(context.Background(), tx.ID)
	if err != approval.ErrAgentSignData {
		t.Fatalf("err = %v, want ErrAgentSignData", err)
	}
}

func TestStoreDenyCannotOverrideClaimedApproval(t *testing.T) {
	issuer := &blockingIssuer{start: make(chan struct{}), release: make(chan struct{})}
	leases := lease.NewStore()
	s := approval.NewStore(time.Minute)
	s.SetIssuer(issuer)
	s.SetLeases(leases)
	tx, _ := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA", "203.0.113.1", "fp1", "", "", approval.ClientMeta{})

	done := make(chan struct{})
	go func() {
		s.Approve(tx.ID, time.Minute, "telegram:1")
		close(done)
	}()
	<-issuer.start
	s.Deny(tx.ID)
	close(issuer.release)
	<-done

	got := s.Snapshot(tx.ID)
	if got == nil || got.State != approval.StateApproved {
		t.Fatalf("state = %v, want approved", got)
	}
	lookup := lease.NewLookupKey("fp1", "deploy", "10.0.0.1", "203.0.113.1", "")
	if _, ok := leases.FindActive(lookup); !ok {
		t.Fatal("expected lease after committed approval")
	}
}
