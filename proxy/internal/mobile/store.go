package mobile

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

var (
	ErrNotFound   = errors.New("device not found")
	ErrInvalidKey = errors.New("invalid device public key")
	ErrEmptyLabel = errors.New("device label required")
)

// Device is an enrolled mobile approver.
type Device struct {
	ID         string
	Label      string
	PubKey     ed25519.PublicKey
	EnrolledAt time.Time
}

// Store holds enrolled devices in memory.
type Store struct {
	mu      sync.RWMutex
	devices map[string]*Device
}

// NewStore returns an empty device registry.
func NewStore() *Store {
	return &Store{devices: make(map[string]*Device)}
}

// Enroll registers a device and returns its server-assigned ID.
func (s *Store) Enroll(label, devicePubKeyB64 string) (*Device, error) {
	if label == "" {
		return nil, ErrEmptyLabel
	}
	raw, err := base64.StdEncoding.DecodeString(devicePubKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	id := "dev_" + ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
	dev := &Device{
		ID:         id,
		Label:      label,
		PubKey:     ed25519.PublicKey(raw),
		EnrolledAt: time.Now().UTC(),
	}
	s.mu.Lock()
	s.devices[id] = dev
	s.mu.Unlock()
	return dev, nil
}

// Get returns a device by ID.
func (s *Store) Get(id string) (*Device, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	dev, ok := s.devices[id]
	return dev, ok
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
