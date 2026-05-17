package socks5

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
)

// TestCoalesceMetrics_SingleCallerOneGroup drives a single Acquire and
// verifies exactly one Group + one Grouped tick — the bare-minimum case
// where a CONNECT opens a fresh window with no joiners.
func TestCoalesceMetrics_SingleCallerOneGroup(t *testing.T) {
	beforeGroup := client.SOCKS5CoalesceGrouped.Load()
	beforeGroups := client.SOCKS5CoalesceGroups.Load()
	t.Cleanup(func() {
		client.SOCKS5CoalesceGrouped.Store(beforeGroup)
		client.SOCKS5CoalesceGroups.Store(beforeGroups)
	})

	pool := &fakePool{}
	cd := NewCoalescingDispatcher(pool, 30*time.Millisecond, 4)
	if _, err := cd.Acquire(context.Background()); err != nil {
		t.Fatalf("Acquire: %v", err)
	}

	if got := client.SOCKS5CoalesceGroups.Load() - beforeGroups; got != 1 {
		t.Errorf("Groups delta = %d, want 1", got)
	}
	if got := client.SOCKS5CoalesceGrouped.Load() - beforeGroup; got != 1 {
		t.Errorf("Grouped delta = %d, want 1", got)
	}
}

// TestCoalesceMetrics_BurstSharesOneGroup fires N concurrent Acquires
// inside the same window and asserts the group counter ticks exactly
// once while Grouped ticks N times. This is the cold-start signal the
// metric was added for.
//
// Determinism: a sync barrier (`startWG.Wait` + `close(start)`) holds all
// N goroutines until every one is parked at the barrier; then they all
// race into Acquire together. Combined with a 1s window (~10000× the
// scheduler's per-goroutine overhead) this guarantees all N appends
// land before `time.AfterFunc(window, flush)` fires, so groups == 1.
// The dispatcher's flush goroutine receives the burst and the test
// completes once the timer expires.
func TestCoalesceMetrics_BurstSharesOneGroup(t *testing.T) {
	beforeGroup := client.SOCKS5CoalesceGrouped.Load()
	beforeGroups := client.SOCKS5CoalesceGroups.Load()
	t.Cleanup(func() {
		client.SOCKS5CoalesceGrouped.Store(beforeGroup)
		client.SOCKS5CoalesceGroups.Store(beforeGroups)
	})

	pool := &fakePool{}
	cd := NewCoalescingDispatcher(pool, 1*time.Second, 4)

	const N = 6
	var startWG sync.WaitGroup
	startWG.Add(N)
	var doneWG sync.WaitGroup
	doneWG.Add(N)
	start := make(chan struct{})

	for range N {
		go func() {
			defer doneWG.Done()
			startWG.Done()
			<-start
			_, _ = cd.Acquire(context.Background())
		}()
	}

	startWG.Wait()
	close(start)
	doneWG.Wait()

	if got := client.SOCKS5CoalesceGrouped.Load() - beforeGroup; got != int64(N) {
		t.Errorf("Grouped delta = %d, want %d", got, N)
	}
	if got := client.SOCKS5CoalesceGroups.Load() - beforeGroups; got != 1 {
		t.Errorf("Groups delta = %d, want 1 (single burst, deterministic via barrier)", got)
	}
}
