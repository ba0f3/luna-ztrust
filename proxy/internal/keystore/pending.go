package keystore

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	ErrPendingNotFound = errors.New("pending key not found")
	ErrPendingFull     = errors.New("pending key queue full")
)

const (
	defaultPendingTTL     = 15 * time.Minute
	maxPendingGlobal      = 32
	maxPendingPerDevice   = 4
)

// PendingKey is an encrypted key blob awaiting operator confirm.
type PendingKey struct {
	ID        string
	DeviceID  string
	Label     string
	Comment   string
	Blob      []byte
	ExpiresAt time.Time
}

// PendingStore holds mobile-uploaded key blobs in memory.
type PendingStore struct {
	mu      sync.Mutex
	entries map[string]*PendingKey
	byDev   map[string]int
}

// NewPendingStore returns an empty pending queue.
func NewPendingStore() *PendingStore {
	return &PendingStore{
		entries: make(map[string]*PendingKey),
		byDev:   make(map[string]int),
	}
}

// Add stores a pending blob; returns pending id.
func (s *PendingStore) Add(deviceID, label, comment string, blob []byte) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.entries) >= maxPendingGlobal {
		return "", ErrPendingFull
	}
	if s.byDev[deviceID] >= maxPendingPerDevice {
		return "", ErrPendingFull
	}
	id := "pend_" + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	s.entries[id] = &PendingKey{
		ID:        id,
		DeviceID:  deviceID,
		Label:     label,
		Comment:   comment,
		Blob:      append([]byte(nil), blob...),
		ExpiresAt: time.Now().Add(defaultPendingTTL),
	}
	s.byDev[deviceID]++
	return id, nil
}

// Get returns a pending entry if not expired.
func (s *PendingStore) Get(id string) (*PendingKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	p, ok := s.entries[id]
	if !ok {
		return nil, ErrPendingNotFound
	}
	return p, nil
}

// Delete removes a pending entry.
func (s *PendingStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.entries[id]
	if !ok {
		return ErrPendingNotFound
	}
	delete(s.entries, id)
	if s.byDev[p.DeviceID] > 0 {
		s.byDev[p.DeviceID]--
	}
	return nil
}

// List returns non-expired pending entries.
func (s *PendingStore) List() []PendingKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	out := make([]PendingKey, 0, len(s.entries))
	for _, p := range s.entries {
		out = append(out, *p)
	}
	return out
}

// Count returns the number of pending entries.
func (s *PendingStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	return len(s.entries)
}

func (s *PendingStore) purgeExpiredLocked() {
	now := time.Now()
	for id, p := range s.entries {
		if now.After(p.ExpiresAt) {
			delete(s.entries, id)
			if s.byDev[p.DeviceID] > 0 {
				s.byDev[p.DeviceID]--
			}
		}
	}
}
