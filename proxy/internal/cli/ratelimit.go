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

// Allow reports whether another successful load is permitted for deviceID.
func (l *LoadRateLimiter) Allow(deviceID string) bool {
	if deviceID == "" {
		return false
	}
	now := time.Now()
	cutoff := now.Add(-loadRateLimitWindow)

	l.mu.Lock()
	defer l.mu.Unlock()

	times := l.pruneLocked(deviceID, cutoff)
	return len(times) < loadRateLimitCount
}

// RecordSuccess records a completed load for deviceID.
func (l *LoadRateLimiter) RecordSuccess(deviceID string) {
	if deviceID == "" {
		return
	}
	now := time.Now()
	cutoff := now.Add(-loadRateLimitWindow)

	l.mu.Lock()
	defer l.mu.Unlock()

	times := l.pruneLocked(deviceID, cutoff)
	times = append(times, now)
	l.loads[deviceID] = times
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
