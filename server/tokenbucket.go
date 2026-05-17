package server

import (
	"math"
	"sync"
	"time"
)

// TokenBucket per-IP. Burst capacity = burst; refill at refillPerSecond.
// State map capped at maxIPs (LRU-ish — simple sweep on overflow).
type TokenBucket struct {
	burst           float64
	refillPerSecond float64
	maxIPs          int

	mu    sync.Mutex
	state map[string]*tbEntry
}

type tbEntry struct {
	tokens float64
	last   time.Time
}

// NewTokenBucket constructs a bucket. refillPerSecond may be < 1 (e.g.
// 30/min = 0.5/sec). burst is the maximum tokens accumulable.
func NewTokenBucket(burst int, refillPerSecond float64, maxIPs int) *TokenBucket {
	if maxIPs <= 0 {
		maxIPs = 10000
	}
	return &TokenBucket{
		burst:           float64(burst),
		refillPerSecond: refillPerSecond,
		maxIPs:          maxIPs,
		state:           make(map[string]*tbEntry, maxIPs),
	}
}

// Allow checks and consumes one token. Returns (allowed, remaining, retryAfter).
func (tb *TokenBucket) Allow(ip string) (bool, int, time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	e, exists := tb.state[ip]
	if !exists {
		if len(tb.state) >= tb.maxIPs {
			tb.evictOne(now)
		}
		e = &tbEntry{tokens: tb.burst, last: now}
		tb.state[ip] = e
	} else {
		// Refill
		elapsed := now.Sub(e.last).Seconds()
		e.tokens = math.Min(tb.burst, e.tokens+elapsed*tb.refillPerSecond)
		e.last = now
	}
	if e.tokens >= 1 {
		e.tokens--
		return true, int(math.Floor(e.tokens)), 0
	}
	// Time until 1 token available
	deficit := 1.0 - e.tokens
	retry := time.Duration(deficit/tb.refillPerSecond*float64(time.Second.Nanoseconds())) * time.Nanosecond
	if retry < 0 {
		retry = time.Second
	}
	return false, 0, retry
}

// Size returns current state map size.
func (tb *TokenBucket) Size() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return len(tb.state)
}

// evictOne removes the oldest entry. Called under lock when len>=maxIPs.
func (tb *TokenBucket) evictOne(now time.Time) {
	var oldestKey string
	var oldestT time.Time
	first := true
	for k, e := range tb.state {
		if first || e.last.Before(oldestT) {
			oldestKey = k
			oldestT = e.last
			first = false
		}
	}
	delete(tb.state, oldestKey)
}

// Cleanup removes entries idle longer than window. Called periodically.
func (tb *TokenBucket) Cleanup(idle time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	for k, e := range tb.state {
		if now.Sub(e.last) > idle {
			delete(tb.state, k)
		}
	}
}
