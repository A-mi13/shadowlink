package server

import (
	"math"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

// tbIdleTTL mirrors the historical Cleanup(10*time.Minute) idle window so the
// expirable LRU drops idle entries automatically. HIGH-2.
const tbIdleTTL = 10 * time.Minute

// TokenBucket per-IP. Burst capacity = burst; refill at refillPerSecond.
// State is held in an expirable LRU capped at maxIPs so eviction beyond
// capacity is O(1) (least-recently-used drop) instead of an O(N) scan. HIGH-2.
type TokenBucket struct {
	burst           float64
	refillPerSecond float64
	maxIPs          int

	mu    sync.Mutex
	state *lru.LRU[string, *tbEntry]
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
		// No eviction callback needed — entries hold no external resource.
		state: lru.NewLRU[string, *tbEntry](maxIPs, nil, tbIdleTTL),
	}
}

// Allow checks and consumes one token. O(1): LRU Get/Add handle eviction; no
// scan. Returns (allowed, remaining, retryAfter). HIGH-2.
func (tb *TokenBucket) Allow(ip string) (bool, int, time.Duration) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	e, exists := tb.state.Get(ip) // refreshes recency on hit
	if !exists {
		e = &tbEntry{tokens: tb.burst, last: now}
		tb.state.Add(ip, e) // O(1); evicts LRU if over capacity
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

// Size returns current state size.
func (tb *TokenBucket) Size() int {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.state.Len()
}

// Cleanup is retained for API compatibility. The expirable LRU evicts idle
// entries on access automatically (TTL=tbIdleTTL); an explicit periodic sweep
// is no longer required. The idle parameter is ignored. HIGH-2.
func (tb *TokenBucket) Cleanup(idle time.Duration) {
	// no-op: expirable LRU handles idle eviction. Kept so RateLimiters.Cleanup
	// compiles unchanged.
	_ = idle
}
