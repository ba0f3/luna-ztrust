package cli

import (
	"testing"
	"time"
)

func TestLoadRateLimiter_AllowsUpToTenPerHour(t *testing.T) {
	l := NewLoadRateLimiter()
	const id = "cli_test"
	for i := 0; i < loadRateLimitCount; i++ {
		if !l.Allow(id) {
			t.Fatalf("Allow %d: expected true", i+1)
		}
		l.RecordSuccess(id)
	}
	if l.Allow(id) {
		t.Fatal("11th Allow should be false before window elapses")
	}
}

func TestLoadRateLimiter_PrunesOldEvents(t *testing.T) {
	l := NewLoadRateLimiter()
	const id = "cli_prune"
	old := time.Now().Add(-2 * loadRateLimitWindow)
	l.loads[id] = []time.Time{old, old, old, old, old, old, old, old, old, old}
	if !l.Allow(id) {
		t.Fatal("stale events should not count against limit")
	}
}
