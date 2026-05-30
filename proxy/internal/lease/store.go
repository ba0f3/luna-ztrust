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
	mu       sync.RWMutex
	leases   map[string]ActiveLease
	byLookup map[string]map[string]struct{} // lookup key -> full lease keys
}

// NewStore creates an empty lease store with periodic expiry cleanup.
func NewStore() *Store {
	s := &Store{
		leases:   make(map[string]ActiveLease),
		byLookup: make(map[string]map[string]struct{}),
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

func (s *Store) deleteLocked(full string) {
	delete(s.leases, full)
	if bucket, ok := s.byLookup[lookupFromFullKey(full)]; ok {
		delete(bucket, full)
		if len(bucket) == 0 {
			delete(s.byLookup, lookupFromFullKey(full))
		}
	}
}

func lookupFromFullKey(full string) string {
	if i := strings.LastIndex(full, "|"); i >= 0 {
		return full[:i]
	}
	return full
}

// Put records a lease until expiresAt.
func (s *Store) Put(key FullKey, expiresAt time.Time) {
	full := key.String()
	lookup := key.LookupKey.lookupString()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leases[full] = ActiveLease{
		Approver:  key.Approver,
		ExpiresAt: expiresAt,
	}
	if s.byLookup[lookup] == nil {
		s.byLookup[lookup] = make(map[string]struct{})
	}
	s.byLookup[lookup][full] = struct{}{}
}

// FindActive returns the longest-lived active lease matching lookup (any approver).
func (s *Store) FindActive(lookup LookupKey) (ActiveLease, bool) {
	lookupStr := lookup.lookupString()
	s.mu.RLock()
	candidates := s.byLookup[lookupStr]
	now := time.Now()
	var best *ActiveLease
	for full := range candidates {
		l, ok := s.leases[full]
		if !ok || now.After(l.ExpiresAt) {
			continue
		}
		if best == nil || l.ExpiresAt.After(best.ExpiresAt) {
			cp := l
			best = &cp
		}
	}
	s.mu.RUnlock()
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
