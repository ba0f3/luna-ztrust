package auth

import (
	"container/list"
	"errors"
	"sync"
	"time"
)

// ErrTimestampOutsideWindow is returned when a request timestamp is outside the allowed window.
var ErrTimestampOutsideWindow = errors.New("timestamp outside allowed window")

// ReplayLRU tracks recently seen request body hashes and rejects duplicates within TTL.
type ReplayLRU struct {
	ttl   time.Duration
	max   int
	mu    sync.Mutex
	// ⚡ Bolt: Use fixed size array for map keys to avoid string allocation.
	byKey map[[32]byte]*list.Element
	order *list.List
}

type replayEntry struct {
	key       [32]byte
	expiresAt time.Time
}

// NewReplayLRU returns a replay cache with the given entry TTL and maximum size.
func NewReplayLRU(ttl time.Duration, max int) *ReplayLRU {
	return &ReplayLRU{
		ttl:   ttl,
		max:   max,
		byKey: make(map[[32]byte]*list.Element),
		order: list.New(),
	}
}

// AddIfNew records key if it has not been seen within TTL. Returns true when key is new.
func (r *ReplayLRU) AddIfNew(key [32]byte) bool {
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()

	r.evictExpired(now)

	if el, ok := r.byKey[key]; ok {
		ent := el.Value.(*replayEntry)
		if now.Before(ent.expiresAt) {
			return false
		}
		r.order.Remove(el)
		delete(r.byKey, key)
	}

	ent := &replayEntry{
		key:       key,
		expiresAt: now.Add(r.ttl),
	}
	el := r.order.PushFront(ent)
	r.byKey[key] = el

	for r.order.Len() > r.max {
		back := r.order.Back()
		if back == nil {
			break
		}
		old := back.Value.(*replayEntry)
		r.order.Remove(back)
		delete(r.byKey, old.key)
	}

	return true
}

func (r *ReplayLRU) evictExpired(now time.Time) {
	for el := r.order.Back(); el != nil; {
		ent := el.Value.(*replayEntry)
		if now.Before(ent.expiresAt) {
			break
		}
		prev := el.Prev()
		r.order.Remove(el)
		delete(r.byKey, ent.key)
		el = prev
	}
}

// ValidateTimestamp checks that ts is within ±windowSec of the current time.
func ValidateTimestamp(ts int64, windowSec int) error {
	return ValidateTimestampAt(ts, time.Now(), windowSec)
}
