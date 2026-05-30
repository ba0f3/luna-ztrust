package lease_test

import (
	"testing"
	"time"

	"github.com/ba0f3/luna-ztrust/proxy/internal/lease"
)

func TestFindActive_UsesLookupIndex(t *testing.T) {
	s := lease.NewStore()
	target := lease.NewLookupKey("fp-target", "deploy", "10.0.0.1", "203.0.113.1", "")
	other := lease.NewLookupKey("fp-other", "root", "10.0.0.2", "203.0.113.2", "")
	until := time.Now().Add(5 * time.Minute)

	for i := 0; i < 200; i++ {
		s.Put(lease.NewFullKey(other, "telegram:noise"), until)
	}
	s.Put(lease.NewFullKey(target, "telegram:1"), until)

	l, ok := s.FindActive(target)
	if !ok || l.Approver != "telegram:1" {
		t.Fatalf("FindActive = %+v ok=%v", l, ok)
	}
}
