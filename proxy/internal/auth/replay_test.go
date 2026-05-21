package auth

import (
	"testing"
	"time"
)

func TestReplayLRURejectsDuplicate(t *testing.T) {
	lru := NewReplayLRU(60*time.Second, 100)
	k := []byte("body1")
	if !lru.AddIfNew(k) {
		t.Fatal("first should be new")
	}
	if lru.AddIfNew(k) {
		t.Fatal("duplicate should be rejected")
	}
}

func TestTimestampWindow(t *testing.T) {
	now := time.Now().Unix()
	if err := ValidateTimestamp(now, 30); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTimestamp(now-31, 30); err == nil {
		t.Fatal("want expired")
	}
}
