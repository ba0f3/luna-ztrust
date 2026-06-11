package lease

import (
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
	mu       sync.RWMutex
	leases   map[FullKey]ActiveLease
	byLookup map[LookupKey]map[FullKey]struct{} // lookup key -> full lease keys
}

// NewStore creates an empty lease store with periodic expiry cleanup.
func NewStore() *Store {
	s := &Store{
		leases:   make(map[FullKey]ActiveLease),
		byLookup: make(map[LookupKey]map[FullKey]struct{}),
	}
	go s.purgeLoop()
	return s
}

func (s *Store) purgeLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.purgeExpired()
	}
}

func (s *Store) purgeExpired() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for full, l := range s.leases {
		if now.After(l.ExpiresAt) {
			s.deleteLocked(full)
		}
	}
}

func (s *Store) deleteLocked(full FullKey) {
	delete(s.leases, full)
	if bucket, ok := s.byLookup[full.LookupKey]; ok {
		delete(bucket, full)
		if len(bucket) == 0 {
			delete(s.byLookup, full.LookupKey)
		}
	}
}

// Put records a lease until expiresAt.
func (s *Store) Put(key FullKey, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases[key] = ActiveLease{
		Approver:  key.Approver,
		ExpiresAt: expiresAt,
	}
	if s.byLookup[key.LookupKey] == nil {
		s.byLookup[key.LookupKey] = make(map[FullKey]struct{})
	}
	s.byLookup[key.LookupKey][key] = struct{}{}
}

// FindActive returns the longest-lived active lease matching lookup (any approver).
func (s *Store) FindActive(lookup LookupKey) (ActiveLease, bool) {
	s.mu.RLock()
	candidates := s.byLookup[lookup]
	now := time.Now()

	// ⚡ Bolt: Avoid pointer indirection tracking 'best' to eliminate heap allocations per lookup cycle.
	var best ActiveLease
	found := false
	for full := range candidates {
		l, ok := s.leases[full]
		if !ok || now.After(l.ExpiresAt) {
			continue
		}
		if !found || l.ExpiresAt.After(best.ExpiresAt) {
			best = l
			found = true
		}
	}
	s.mu.RUnlock()
	return best, found
}

// Remaining returns time until lease expiry.
func (l ActiveLease) Remaining() time.Duration {
	d := time.Until(l.ExpiresAt)
	if d < 0 {
		return 0
	}
	return d
}
