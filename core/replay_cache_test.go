package core

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestReplayCache_RejectsDuplicateWithinWindow(t *testing.T) {
	c := NewReplayCache(100, 5*time.Minute)
	key := []byte("client-id-123")
	ts := int64(1000000)

	if !c.Accept(key, ts) {
		t.Fatal("first Accept should succeed")
	}
	if c.Accept(key, ts) {
		t.Error("duplicate within same bucket should be rejected")
	}
}

func TestReplayCache_AcceptsDifferentBucket(t *testing.T) {
	c := NewReplayCache(100, 5*time.Minute)
	key := []byte("client-id-123")

	if !c.Accept(key, 1000000) {
		t.Fatal("first bucket Accept")
	}
	// Advance past the 5-min window (300s buckets) — different bucket
	if !c.Accept(key, 1000000+301) {
		t.Error("different time bucket should Accept")
	}
}

func TestReplayCache_EvictsOldestWhenFull(t *testing.T) {
	c := NewReplayCache(2, 5*time.Minute)
	c.Accept([]byte("a"), 1)
	c.Accept([]byte("b"), 2)
	c.Accept([]byte("c"), 3) // evicts "a"

	if !c.Accept([]byte("a"), 1) {
		t.Error("evicted entry should Accept again")
	}
}

func TestReplayCache_DifferentClientIDs(t *testing.T) {
	c := NewReplayCache(100, 5*time.Minute)
	ts := int64(1000000)

	if !c.Accept([]byte("client-a"), ts) {
		t.Fatal("first client")
	}
	if !c.Accept([]byte("client-b"), ts) {
		t.Error("different client same ts should pass")
	}
}

// TestReplayCache_BoundaryReplay_Detected verifies that a replay of a handshake
// whose timestamp lies within the protection window is rejected even if the
// original landed near the end of the previous bucket and the replay lands at
// the start of the current bucket. Without sliding-window detection (A1-M1),
// the "bucket /" arithmetic key would let an attacker bypass the cache simply
// by waiting until the next 5-minute bucket boundary.
func TestReplayCache_BoundaryReplay_Detected(t *testing.T) {
	const window = 5 * time.Minute
	c := NewReplayCache(100, window)
	key := []byte("client-id-boundary")

	// First handshake is recorded near the END of bucket B (1 second before
	// the boundary) — bucket = 1.
	bucketSecs := int64(window.Seconds())
	tsEndOfBucket := bucketSecs*2 - 1 // last second inside bucket #1
	if !c.Accept(key, tsEndOfBucket) {
		t.Fatal("first Accept should succeed")
	}

	// Replay arrives 1 second later — same handshake content, but timestamp
	// now sits at the START of bucket #2. With pure ts/bucketSz keying the
	// keys differ and the replay would be silently accepted.
	tsStartNextBucket := bucketSecs * 2 // first second of bucket #2
	if c.Accept(key, tsStartNextBucket) {
		t.Error("boundary replay within window must be rejected")
	}

	// Replay further inside the window also stays rejected.
	if c.Accept(key, bucketSecs*2+30) {
		t.Error("replay 30s into next bucket but inside window must stay rejected")
	}

	// But a fresh handshake clearly outside the window passes.
	if !c.Accept(key, tsEndOfBucket+bucketSecs+10) {
		t.Error("handshake fully past replay window should be accepted")
	}
}

// TestReplayCache_BackgroundEviction_RemovesOldEntries verifies that a
// background goroutine prunes entries whose buckets are completely past the
// replay window without requiring callers to call Accept on a fresh entry to
// trigger eviction. (A3-S-MED-2 fix.)
func TestReplayCache_BackgroundEviction_RemovesOldEntries(t *testing.T) {
	// Tiny window + frequent eviction tick so the test runs fast.
	c := NewReplayCacheWithOptions(100, 100*time.Millisecond, 20*time.Millisecond)
	defer c.Stop()

	now := time.Now().Unix()
	c.Accept([]byte("a"), now-10) // far in the past, stale
	c.Accept([]byte("b"), now-10)

	if c.size() != 2 {
		t.Fatalf("expected 2 entries, got %d", c.size())
	}

	// Wait long enough for the background ticker to run a few times.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if c.size() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if got := c.size(); got != 0 {
		t.Errorf("background eviction should have purged old entries, still have %d", got)
	}
}

// TestReplayCache_Stop_IsIdempotent verifies repeated Stop calls don't panic
// or close an already-closed channel.
func TestReplayCache_Stop_IsIdempotent(t *testing.T) {
	c := NewReplayCacheWithOptions(10, time.Second, 10*time.Millisecond)
	c.Stop()
	c.Stop() // must not panic
}

// TestReplayCache_Stop_HaltsBackgroundGoroutine verifies the eviction goroutine
// exits after Stop. Race-detector friendly: only checks call count.
func TestReplayCache_Stop_HaltsBackgroundGoroutine(t *testing.T) {
	var ticks atomic.Int64
	c := newReplayCacheForTest(10, time.Second, 5*time.Millisecond, func() { ticks.Add(1) })
	time.Sleep(40 * time.Millisecond)
	before := ticks.Load()
	if before == 0 {
		t.Fatalf("background ticker should have ticked at least once, got %d", before)
	}
	c.Stop()
	time.Sleep(40 * time.Millisecond)
	after := ticks.Load()
	// Allow at most 1 in-flight tick after Stop (race on the ticker channel).
	if after-before > 1 {
		t.Errorf("background ticker still running after Stop: before=%d after=%d", before, after)
	}
}
