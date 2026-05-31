package cli

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	ErrNotFound            = errors.New("device not found")
	ErrEmptyLabel          = errors.New("device label required")
	ErrDuplicateFingerprint = errors.New("certificate fingerprint already enrolled")
)

// Device is an enrolled CLI operator client.
type Device struct {
	ID              string
	Label           string
	CertFingerprint string
	EnrolledAt      time.Time
}

// Store holds enrolled CLI devices in memory.
type Store struct {
	mu      sync.RWMutex
	devices map[string]*Device
}

// NewStore returns an empty CLI device registry.
func NewStore() *Store {
	return &Store{devices: make(map[string]*Device)}
}

// Enroll registers a device and returns its server-assigned ID.
func (s *Store) Enroll(label, certFingerprint string) (*Device, error) {
	if label == "" {
		return nil, ErrEmptyLabel
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.CertFingerprint == certFingerprint {
			return nil, ErrDuplicateFingerprint
		}
	}
	id := "cli_" + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	dev := &Device{
		ID:              id,
		Label:           label,
		CertFingerprint: certFingerprint,
		EnrolledAt:      time.Now().UTC(),
	}
	s.devices[id] = dev
	return dev, nil
}

// GetByFingerprint returns a device matching the certificate fingerprint.
func (s *Store) GetByFingerprint(fp string) (*Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, d := range s.devices {
		if d.CertFingerprint == fp {
			return d, true
		}
	}
	return nil, false
}

// List returns all enrolled devices.
func (s *Store) List() []*Device {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d)
	}
	return out
}

// Delete removes a device.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; !ok {
		return ErrNotFound
	}
	delete(s.devices, id)
	return nil
}
