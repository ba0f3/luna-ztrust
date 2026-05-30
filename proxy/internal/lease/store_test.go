package lease_test

import (
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
)

func TestLeaseKey_DifferentApproverSeparate(t *testing.T) {
	s := lease.NewStore()
	lookup := lease.NewLookupKey("fp1", "deploy", "10.0.1.5", "203.0.113.10")
	until := time.Now().Add(5 * time.Minute)

	s.Put(lease.NewFullKey(lookup, "telegram:1"), until)
	_, ok := s.FindActive(lookup)
	if !ok {
		t.Fatal("expected active lease")
	}

	s.Put(lease.NewFullKey(lookup, "telegram:2"), until.Add(time.Minute))
	l, ok := s.FindActive(lookup)
	if !ok {
		t.Fatal("expected lease from second approver")
	}
	if l.Approver != "telegram:2" {
		t.Fatalf("approver = %q", l.Approver)
	}
}

func TestLeaseKey_DeterministicLookup(t *testing.T) {
	k1 := lease.NewLookupKey("fp1", "deploy", "10.0.1.5", "203.0.113.10")
	k2 := lease.NewLookupKey("fp1", "deploy", "10.0.1.5", "203.0.113.99")
	if k1 == k2 {
		t.Fatal("different source IP must not match")
	}
}

func TestFindActive_ExpiredIgnored(t *testing.T) {
	s := lease.NewStore()
	lookup := lease.NewLookupKey("fp1", "deploy", "10.0.1.5", "203.0.113.10")
	s.Put(lease.NewFullKey(lookup, "telegram:1"), time.Now().Add(-time.Second))
	if _, ok := s.FindActive(lookup); ok {
		t.Fatal("expired lease should not match")
	}
}
