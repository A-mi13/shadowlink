package core

import (
	"container/list"
	"sync"
	"time"
)

// ReplayCache tracks recently-seen handshake (clientID, timestamp) pairs to
// block replay attacks within the timestamp validity window.
//
// Replay-detection model (A1-M1 fix, 2026-04-26):
//   - Sliding-window approach. Per clientID we store the last-accepted timestamp.
//     On Accept(clientID, ts) we reject if the previous timestamp for this
//     clientID is within `window` seconds of `ts` regardless of bucket boundaries.
//     The original bucket-arithmetic scheme had a boundary-replay loophole
//     (record at bucket_end - 1, replay at bucket_end + 1: different keys,
//     replay accepted). The sliding-window check has no such loophole.
//
// Background eviction (A3-S-MED-2 fix, 2026-04-26):
//   - A goroutine wakes every evictInterval and deletes entries whose timestamp
//     is more than `window` seconds behind "now" — i.e. fully past the
//     protection window. This bounds memory even when traffic is sparse and
//     Accept is rarely called (the previous design only evicted on capacity
//     overflow). Stop() halts the goroutine; idempotent.
type ReplayCache struct {
	mu         sync.Mutex
	maxSize    int
	windowSecs int64
	order      *list.List // oldest first; entries hold clientID and ts
	index      map[string]*list.Element

	// Background eviction state.
	stopCh    chan struct{}
	stopOnce  sync.Once
	evictTick time.Duration

	// nowFn returns current unix-seconds; tests can override via newReplayCacheForTest.
	nowFn func() int64
	// onTick fires once after every background eviction pass. Test hook only.
	onTick func()
}

// replayEntry is a single accepted (clientID, ts) record.
type replayEntry struct {
	clientID string
	ts       int64
}

// defaultEvictInterval controls how often the background goroutine runs when
// the caller doesn't specify one. Picked to be one tenth of the default
// 5-minute window; eviction lag of ~30s on stale entries is fine.
const defaultEvictInterval = 30 * time.Second

// NewReplayCache creates a cache capped at maxSize entries with the given
// replay-protection window. A background goroutine prunes stale entries every
// defaultEvictInterval; call Stop to release it.
func NewReplayCache(maxSize int, window time.Duration) *ReplayCache {
	return NewReplayCacheWithOptions(maxSize, window, defaultEvictInterval)
}

// NewReplayCacheWithOptions allows callers/tests to tune eviction cadence.
// Passing evictInterval <= 0 disables the background goroutine entirely.
func NewReplayCacheWithOptions(maxSize int, window, evictInterval time.Duration) *ReplayCache {
	if maxSize <= 0 {
		maxSize = 10000
	}
	if window <= 0 {
		window = 5 * time.Minute
	}
	w := int64(window.Seconds())
	if w < 1 {
		w = 1 // sub-second windows clamp to 1s due to ts second-granularity
	}
	c := &ReplayCache{
		maxSize:    maxSize,
		windowSecs: w,
		order:      list.New(),
		index:      make(map[string]*list.Element),
		stopCh:     make(chan struct{}),
		evictTick:  evictInterval,
		nowFn:      func() int64 { return time.Now().Unix() },
	}
	if evictInterval > 0 {
		go c.evictLoop()
	}
	return c
}

// newReplayCacheForTest is a test-only constructor that injects a tick
// observer so eviction-loop tests don't have to scrape internal state.
func newReplayCacheForTest(maxSize int, window, evictInterval time.Duration, onTick func()) *ReplayCache {
	c := NewReplayCacheWithOptions(maxSize, window, 0) // start without goroutine
	c.evictTick = evictInterval
	c.onTick = onTick
	if evictInterval > 0 {
		go c.evictLoop()
	}
	return c
}

// Accept returns true if the (clientID, ts) pair is NEW within the protection
// window. Returns false if the same clientID was already accepted within
// `window` seconds of `ts` (replay).
//
// Sliding-window semantics: the absolute difference |ts - prev_ts| must be
// >= windowSecs for an Accept to succeed. This catches boundary-straddling
// replays that the previous bucket-arithmetic scheme silently accepted.
//
// On accept, the entry's timestamp is refreshed and the entry moves to the
// back of the FIFO order list (treated as fresh for capacity eviction).
// When at capacity the oldest entries are evicted FIFO.
func (c *ReplayCache) Accept(clientID []byte, ts int64) bool {
	if c.windowSecs == 0 {
		return true
	}
	key := string(clientID)

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.index[key]; ok {
		ent := el.Value.(*replayEntry)
		diff := ts - ent.ts
		if diff < 0 {
			diff = -diff
		}
		if diff < c.windowSecs {
			return false // replay within window
		}
		// Out-of-window legitimate re-use: refresh ts and reorder for FIFO.
		ent.ts = ts
		c.order.MoveToBack(el)
		return true
	}

	// Capacity eviction (FIFO oldest-first).
	for c.order.Len() >= c.maxSize {
		front := c.order.Front()
		if front == nil {
			break
		}
		old := c.order.Remove(front).(*replayEntry)
		delete(c.index, old.clientID)
	}

	ent := &replayEntry{clientID: key, ts: ts}
	el := c.order.PushBack(ent)
	c.index[key] = el
	return true
}

// Stop halts the background eviction goroutine. Idempotent.
func (c *ReplayCache) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

// size returns the current number of stored entries (test helper).
func (c *ReplayCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// evictLoop runs in its own goroutine; periodically prunes entries whose
// timestamp is fully past the replay-protection window.
func (c *ReplayCache) evictLoop() {
	t := time.NewTicker(c.evictTick)
	defer t.Stop()
	for {
		select {
		case <-c.stopCh:
			return
		case <-t.C:
			c.evictExpired()
			if c.onTick != nil {
				c.onTick()
			}
		}
	}
}

// evictExpired removes entries whose timestamp is more than windowSecs behind
// "now" — fully past the replay-protection window.
func (c *ReplayCache) evictExpired() {
	now := c.nowFn()
	threshold := now - c.windowSecs

	c.mu.Lock()
	defer c.mu.Unlock()

	for {
		front := c.order.Front()
		if front == nil {
			return
		}
		ent := front.Value.(*replayEntry)
		if ent.ts > threshold {
			return // remaining entries are within window (FIFO)
		}
		c.order.Remove(front)
		delete(c.index, ent.clientID)
	}
}
