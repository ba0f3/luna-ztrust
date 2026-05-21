package approval_test

import (
	"context"
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/approval"
	"github.com/ba0f3/luna-ztrust/proxy/internal/config"
)

func TestStoreApproveWakesWaiter(t *testing.T) {
	s := approval.NewStore(60 * time.Second)
	tx, _ := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA")
	go func() {
		time.Sleep(10 * time.Millisecond)
		s.Approve(tx.ID, "certpem")
	}()
	cert, err := s.Wait(context.Background(), tx.ID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if cert != "certpem" {
		t.Fatalf("cert = %q, want certpem", cert)
	}
}

func TestStoreDevBypass(t *testing.T) {
	s := approval.NewStore(60 * time.Second)
	s.SetConfig(config.Config{Env: "dev"})
	tx, ch := s.Create("deploy", "10.0.0.1", "ssh-ed25519 AAAA")
	select {
	case res := <-ch:
		if res.Err != nil {
			t.Fatalf("dev bypass err: %v", res.Err)
		}
		if res.Cert != "dev-cert" {
			t.Fatalf("cert = %q, want dev-cert", res.Cert)
		}
	case <-time.After(time.Second):
		t.Fatal("dev bypass did not auto-approve")
	}
	if tx.State != approval.StateApproved {
		t.Fatalf("state = %q, want approved", tx.State)
	}
}
