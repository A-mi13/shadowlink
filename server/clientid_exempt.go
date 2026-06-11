package server

import (
	"math"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
)

// ClientIDExemption tracks recently-seen authenticated client IDs and
// optionally allows them to bypass the per-IP rate-limit bucket on handshake POSTs.
// A separate soft-limit counter caps total handshake rate per clientID.
type ClientIDExemption struct {
	cache      *lru.LRU[string, struct{}]
	ttl        time.Duration
	softLimit  int
	softWindow time.Duration
	// dataBytesPerSec is the generous per-clientID data-path byte/sec ceiling
	// (burst = 1s worth). <=0 disables it (unlimited). HIGH-3.
	dataBytesPerSec float64

	mu        sync.Mutex
	soft      map[string]*softCounter
	byteState map[string]*byteBucket
}

type softCounter struct {
	count    int
	winStart time.Time
}

type byteBucket struct {
	avail float64
	last  time.Time
}

// NewClientIDExemption builds the cache.
//
//	capacity   — max distinct clientIDs (LRU eviction beyond)
//	ttl        — exemption TTL per clientID
//	softLimit  — max requests per clientID per softWindow before AllowExempted=false.
//	             softLimit <= 0 disables the soft cap (unlimited).
//	softWindow — sliding window for soft-limit
//	dataBytesPerSec — generous high-water bytes/sec ceiling for the data path
//	             per clientID (see AllowExemptedBytes). <=0 disables (unlimited). HIGH-3.
func NewClientIDExemption(capacity int, ttl time.Duration, softLimit int, softWindow time.Duration, dataBytesPerSec float64) *ClientIDExemption {
	e := &ClientIDExemption{
		ttl:             ttl,
		softLimit:       softLimit,
		softWindow:      softWindow,
		soft:            make(map[string]*softCounter, capacity),
		dataBytesPerSec: dataBytesPerSec,
		byteState:       make(map[string]*byteBucket, capacity),
	}
	e.cache = lru.NewLRU(capacity, func(key string, _ struct{}) {
		e.mu.Lock()
		delete(e.soft, key)
		delete(e.byteState, key)
		e.mu.Unlock()
	}, ttl)
	return e
}

// MarkSeen records a successful handshake. Subsequent IsExempt calls return true
// until TTL expiry or LRU eviction.
func (e *ClientIDExemption) MarkSeen(clientID []byte) {
	if len(clientID) == 0 {
		return
	}
	e.cache.Add(string(clientID), struct{}{})
}

// IsExempt returns whether clientID is currently a recognized cached entity.
// Note: looking up the entry counts as recent use — this refreshes the LRU
// recency rank but does NOT extend the TTL.
func (e *ClientIDExemption) IsExempt(clientID []byte) bool {
	if len(clientID) == 0 {
		return false
	}
	_, ok := e.cache.Get(string(clientID))
	return ok
}

// AllowExempted is called for an exempt clientID's rate-limit decision.
// Increments the soft-counter; returns false once softLimit hit within softWindow.
// If softLimit <= 0, always returns true (unlimited).
func (e *ClientIDExemption) AllowExempted(clientID []byte) bool {
	if len(clientID) == 0 {
		return false
	}
	if e.softLimit <= 0 {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	key := string(clientID)
	c, ok := e.soft[key]
	if !ok || now.Sub(c.winStart) > e.softWindow {
		c = &softCounter{count: 0, winStart: now}
		e.soft[key] = c
	}
	if c.count >= e.softLimit {
		return false
	}
	c.count++
	return true
}

// AllowExemptedBytes applies the generous per-clientID byte/sec ceiling on the
// data path. Burst capacity = dataBytesPerSec (1s worth). Returns true if the
// n bytes fit in the budget; false once a single identity exceeds the ceiling.
// dataBytesPerSec<=0 → always true (unlimited). Kept separate from the
// request-count AllowExempted so it does not throttle VPN payload throughput.
// HIGH-3.
func (e *ClientIDExemption) AllowExemptedBytes(clientID []byte, n int) bool {
	if e.dataBytesPerSec <= 0 {
		return true
	}
	if len(clientID) == 0 {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	key := string(clientID)
	b, ok := e.byteState[key]
	if !ok {
		b = &byteBucket{avail: e.dataBytesPerSec, last: now}
		e.byteState[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		b.avail = math.Min(e.dataBytesPerSec, b.avail+elapsed*e.dataBytesPerSec)
		b.last = now
	}
	if b.avail >= float64(n) {
		b.avail -= float64(n)
		return true
	}
	return false
}

// Size — current LRU cache size.
func (e *ClientIDExemption) Size() int {
	return e.cache.Len()
}
