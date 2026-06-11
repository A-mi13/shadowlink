package server

import (
	"sync"
	"testing"
	"time"
)

func TestTokenBucket_Burst(t *testing.T) {
	tb := NewTokenBucket(5, 1.0 /* 1 token/sec */, 100)
	for i := 0; i < 5; i++ {
		ok, _, _ := tb.Allow("1.1.1.1")
		if !ok {
			t.Fatalf("burst slot %d should allow", i)
		}
	}
	ok, remaining, retry := tb.Allow("1.1.1.1")
	if ok {
		t.Fatal("6th request inside burst window should reject")
	}
	if remaining != 0 {
		t.Errorf("remaining = %d, want 0", remaining)
	}
	if retry <= 0 || retry > time.Second*2 {
		t.Errorf("retry-after = %v, want ~1s", retry)
	}
}

func TestTokenBucket_Refill(t *testing.T) {
	tb := NewTokenBucket(2, 10.0 /* 10 tokens/sec */, 100)
	// Drain
	tb.Allow("2.2.2.2")
	tb.Allow("2.2.2.2")
	if ok, _, _ := tb.Allow("2.2.2.2"); ok {
		t.Fatal("should be empty")
	}
	time.Sleep(150 * time.Millisecond) // 1.5 token refill
	if ok, _, _ := tb.Allow("2.2.2.2"); !ok {
		t.Fatal("after 150ms should have refilled 1 token")
	}
}

func TestTokenBucket_PerIPIsolation(t *testing.T) {
	tb := NewTokenBucket(1, 0.01, 100)
	if ok, _, _ := tb.Allow("3.3.3.3"); !ok {
		t.Fatal()
	}
	if ok, _, _ := tb.Allow("4.4.4.4"); !ok {
		t.Fatal("different IP should have own bucket")
	}
	if ok, _, _ := tb.Allow("3.3.3.3"); ok {
		t.Fatal("first IP should be drained")
	}
}

func TestTokenBucket_MaxIPsCap(t *testing.T) {
	tb := NewTokenBucket(1, 0.01, 3)
	for i := 0; i < 5; i++ {
		ip := []byte{byte(i), 0, 0, 1}
		_, _, _ = tb.Allow(string(ip))
	}
	if got := tb.Size(); got > 3 {
		t.Errorf("Size = %d, exceeds maxIPs=3", got)
	}
}

// HIGH-2: eviction must be O(1) (LRU drop), not an O(N) full scan. We assert
// behaviourally that under heavy distinct-IP churn the map stays capped AND the
// most-recently-used entry survives while the oldest is evicted.
func TestTokenBucket_LRUEvictsOldest(t *testing.T) {
	tb := NewTokenBucket(1, 0.0001 /* effectively no refill */, 2)
	// Drain "a" and "b".
	if ok, _, _ := tb.Allow("a"); !ok {
		t.Fatal("a first allow")
	}
	if ok, _, _ := tb.Allow("b"); !ok {
		t.Fatal("b first allow")
	}
	// Touch "a" so it becomes most-recently-used (and stays drained).
	tb.Allow("a")
	// Insert "c" → capacity 2 exceeded → LRU ("b") evicted, "a" survives.
	if ok, _, _ := tb.Allow("c"); !ok {
		t.Fatal("c is new, full bucket → allowed")
	}
	if got := tb.Size(); got > 2 {
		t.Fatalf("Size=%d exceeds cap 2", got)
	}
	// "a" survived as drained → next allow rejected.
	if ok, _, _ := tb.Allow("a"); ok {
		t.Fatal("a should still be drained (survived eviction)")
	}
	// "b" was evicted → fresh full bucket → allowed.
	if ok, _, _ := tb.Allow("b"); !ok {
		t.Fatal("b was evicted, should be fresh")
	}
}

func TestTokenBucket_ConcurrentSafe(t *testing.T) {
	tb := NewTokenBucket(1000, 1000, 100)
	var wg sync.WaitGroup
	for g := 0; g < 50; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				_, _, _ = tb.Allow("5.5.5.5")
			}
		}()
	}
	wg.Wait()
	// no race detector triggers; deterministic outcome not asserted
}
