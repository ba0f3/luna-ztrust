package lease

import (
	"strings"
	"sync"
	"time"
)

// ActiveLease is a non-expired session lease from an OOB approval.
type ActiveLease struct {
	Approver  string
	ExpiresAt time.Time
}

// Store holds in-memory session leases.
type Store struct {
	mu     sync.RWMutex
	leases map[string]ActiveLease
}

// NewStore creates an empty lease store.
func NewStore() *Store {
	return &Store{leases: make(map[string]ActiveLease)}
}

// Put records a lease until expiresAt.
func (s *Store) Put(key FullKey, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases[key.String()] = ActiveLease{
		Approver:  key.Approver,
		ExpiresAt: expiresAt,
	}
}

// FindActive returns the longest-lived active lease matching lookup (any approver).
func (s *Store) FindActive(lookup LookupKey) (ActiveLease, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now()
	prefix := lookup.lookupString() + "|"
	var best *ActiveLease
	for k, l := range s.leases {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		if now.After(l.ExpiresAt) {
			continue
		}
		if best == nil || l.ExpiresAt.After(best.ExpiresAt) {
			cp := l
			best = &cp
		}
	}
	if best == nil {
		return ActiveLease{}, false
	}
	return *best, true
}

// Remaining returns time until lease expiry.
func (l ActiveLease) Remaining() time.Duration {
	d := time.Until(l.ExpiresAt)
	if d < 0 {
		return 0
	}
	return d
}
