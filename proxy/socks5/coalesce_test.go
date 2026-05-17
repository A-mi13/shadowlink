package socks5

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakePool implements PoolAcquirer for tests
type fakePool struct {
	mu    sync.Mutex
	calls int
	delay time.Duration
}

func (f *fakePool) Acquire(ctx context.Context) (any, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return struct{}{}, nil
}

// closableConn implements io.Closer for ctx-cancel close-fallback test.
type closableConn struct {
	closed atomic.Bool
}

func (c *closableConn) Close() error {
	c.closed.Store(true)
	return nil
}

// ctxIgnoringPool simulates a real pool that allocates a slot without
// checking ctx (a worst-case for the close-fallback path).
type ctxIgnoringPool struct {
	mu    sync.Mutex
	conns []*closableConn
	delay time.Duration
}

func (f *ctxIgnoringPool) Acquire(ctx context.Context) (any, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	c := &closableConn{}
	f.mu.Lock()
	f.conns = append(f.conns, c)
	f.mu.Unlock()
	return c, nil
}

func TestCoalesce_SmallBurstGroups(t *testing.T) {
	pool := &fakePool{}
	cd := NewCoalescingDispatcher(pool, 50*time.Millisecond, 4)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cd.Acquire(context.Background())
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)
	pool.mu.Lock()
	calls := pool.calls
	pool.mu.Unlock()
	if calls != 5 {
		t.Errorf("expected 5 underlying Acquires, got %d", calls)
	}
	if elapsed < 50*time.Millisecond {
		t.Errorf("expected at least 50ms wall (debounce window), got %v", elapsed)
	}
}

func TestCoalesce_SemaphoreLimitsParallel(t *testing.T) {
	pool := &fakePool{delay: 100 * time.Millisecond}
	// 20ms window keeps all 4 callers in the same flush batch even on a
	// loaded Windows scheduler (1ms was technically enough but fragile —
	// a 1ms hiccup would split the batch and let half the requests run
	// in a second flush, throwing off the elapsed-time floor below).
	cd := NewCoalescingDispatcher(pool, 20*time.Millisecond, 2) // max 2 in-flight
	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cd.Acquire(context.Background())
		}()
	}
	wg.Wait()
	// 4 requests × 100ms each, max 2 parallel → ≥ 200ms
	if time.Since(start) < 180*time.Millisecond {
		t.Errorf("semaphore not limiting concurrency, elapsed=%v", time.Since(start))
	}
}

// TestCoalesce_CallerCancelClosesConn covers the slot-leak guard: a
// pool that ignores ctx and allocates a conn AFTER the caller cancels
// must have that conn closed by the dispatcher (not silently dropped).
// Without the io.Closer fallback in flush(), a real WSReadyPool slot
// would leak permanently each time a SOCKS5 client cancels mid-window —
// a real risk under reconnect cascade (Tier S R.1 scenario).
func TestCoalesce_CallerCancelClosesConn(t *testing.T) {
	pool := &ctxIgnoringPool{delay: 30 * time.Millisecond}
	cd := NewCoalescingDispatcher(pool, 5*time.Millisecond, 4)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = cd.Acquire(ctx)
	}()

	// Wait for window to fire (~5ms) and pool.Acquire to start its sleep.
	time.Sleep(15 * time.Millisecond)
	cancel()
	<-done // caller exits with ctx.Err()

	// Wait for pool to finish its delay + dispatch goroutine to hit the
	// close-fallback branch.
	time.Sleep(80 * time.Millisecond)

	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.conns) != 1 {
		t.Fatalf("expected ctx-ignoring pool to allocate 1 conn, got %d", len(pool.conns))
	}
	if !pool.conns[0].closed.Load() {
		t.Errorf("conn allocated after caller cancel must be closed by dispatcher (slot-leak guard regressed)")
	}
}
