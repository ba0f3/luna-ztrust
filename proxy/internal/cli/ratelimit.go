package cli

import (
	"sync"
	"time"
)

const (
	loadRateLimitCount  = 10
	loadRateLimitWindow = time.Hour
)

// LoadRateLimiter limits successful remote key loads per enrolled device.
type LoadRateLimiter struct {
	mu    sync.Mutex
	loads map[string][]time.Time
}

// NewLoadRateLimiter returns a limiter allowing loadRateLimitCount successes per hour per device.
func NewLoadRateLimiter() *LoadRateLimiter {
	return &LoadRateLimiter{loads: make(map[string][]time.Time)}
}

// Allowed reports whether deviceID is under the success limit (read-only).
func (l *LoadRateLimiter) Allowed(deviceID string) bool {
	if deviceID == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	times := l.pruneLocked(deviceID, time.Now().Add(-loadRateLimitWindow))
	return len(times) < loadRateLimitCount
}

// TryRecordSuccess atomically records a successful load if under the hourly limit.
func (l *LoadRateLimiter) TryRecordSuccess(deviceID string) bool {
	if deviceID == "" {
		return false
	}
	now := time.Now()
	cutoff := now.Add(-loadRateLimitWindow)

	l.mu.Lock()
	defer l.mu.Unlock()

	times := l.pruneLocked(deviceID, cutoff)
	if len(times) >= loadRateLimitCount {
		return false
	}
	l.loads[deviceID] = append(times, now)
	return true
}

func (l *LoadRateLimiter) pruneLocked(deviceID string, cutoff time.Time) []time.Time {
	times := l.loads[deviceID]
	n := 0
	for _, ts := range times {
		if ts.After(cutoff) {
			times[n] = ts
			n++
		}
	}
	times = times[:n]
	if len(times) == 0 {
		delete(l.loads, deviceID)
	} else {
		l.loads[deviceID] = times
	}
	return times
}

// Forget removes rate-limit history for deviceID (e.g. after device revocation).
func (l *LoadRateLimiter) Forget(deviceID string) {
	if deviceID == "" {
		return
	}
	l.mu.Lock()
	delete(l.loads, deviceID)
	l.mu.Unlock()
}
