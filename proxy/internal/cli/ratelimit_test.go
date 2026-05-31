package cli

import (
	"testing"
	"time"
)

func TestLoadRateLimiter_TryRecordSuccess(t *testing.T) {
	l := NewLoadRateLimiter()
	const id = "cli_test"
	for i := 0; i < loadRateLimitCount; i++ {
		if !l.TryRecordSuccess(id) {
			t.Fatalf("TryRecordSuccess %d: expected true", i+1)
		}
	}
	if l.TryRecordSuccess(id) {
		t.Fatal("11th TryRecordSuccess should be false before window elapses")
	}
}

func TestLoadRateLimiter_ForgetClearsHistory(t *testing.T) {
	l := NewLoadRateLimiter()
	const id = "cli_forget"
	for i := 0; i < loadRateLimitCount; i++ {
		if !l.TryRecordSuccess(id) {
			t.Fatalf("TryRecordSuccess %d: expected true", i+1)
		}
	}
	if l.TryRecordSuccess(id) {
		t.Fatal("expected at limit before Forget")
	}
	l.Forget(id)
	if !l.TryRecordSuccess(id) {
		t.Fatal("expected TryRecordSuccess after Forget")
	}
}

func TestLoadRateLimiter_PrunesOldEvents(t *testing.T) {
	l := NewLoadRateLimiter()
	const id = "cli_prune"
	old := time.Now().Add(-2 * loadRateLimitWindow)
	l.loads[id] = []time.Time{old, old, old, old, old, old, old, old, old, old}
	if !l.TryRecordSuccess(id) {
		t.Fatal("stale events should not count against limit")
	}
}

func TestLoadRateLimiter_AllowedMatchesTryRecordSuccess(t *testing.T) {
	l := NewLoadRateLimiter()
	const id = "cli_allowed"
	if !l.Allowed(id) {
		t.Fatal("empty limiter should allow")
	}
	if !l.TryRecordSuccess(id) {
		t.Fatal("record")
	}
	if !l.Allowed(id) {
		t.Fatal("still under limit")
	}
}
