//go:build linux

// Race tests skip on Windows (no gcc). Run on Linux CI with `go test -race`.

package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPoolSend_ConcurrentActiveCounterBalance is the A1-L4 race test.
//
// AUDIT FINDING (A1-L4): Pool.Send incremented `p.active` on acquire and
// decremented inline after Close. If SendChunk panicked (or the goroutine was
// otherwise terminated mid-send), the counter would leak — Pool.MaxConns gate
// would falsely report saturation.
//
// Fix: defer atomic.AddInt32(&p.active, -1) only after successful getConn.
//
// This test spawns 100 goroutines concurrently sending into a pool. Each
// goroutine performs ~10 send-and-close cycles. After all goroutines complete,
// active-counter MUST return to 0. Run under `-race` to additionally catch any
// data race on the counter (none expected — atomic).
func TestPoolSend_ConcurrentActiveCounterBalance(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinConns = 2
	config.MaxConns = 32 // generous to avoid getConn blocking
	config.PreopenSize = 4

	pool := NewPool(config, mockDialer([]byte("ok")))
	defer pool.Close()

	// Let preopen fill a bit.
	time.Sleep(50 * time.Millisecond)

	const goroutines = 100
	const sendsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < sendsPerGoroutine; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_, err := pool.Send(ctx, []byte("data"))
				cancel()
				if err != nil {
					// Acceptable under load (max-conns transient saturation),
					// but counter MUST still balance.
					t.Logf("goroutine %d send %d: %v", 0, j, err)
				}
			}
		}()
	}
	wg.Wait()

	// Allow async cleanup to settle (Close on ready-conns happens via preopenLoop).
	time.Sleep(50 * time.Millisecond)

	// Active counter MUST return to 0. Any leak indicates an unbalanced
	// increment/decrement under concurrency — A1-L4 regression.
	if active := atomic.LoadInt32(&pool.active); active != 0 {
		t.Errorf("active counter leaked: got %d, want 0 (A1-L4 regression)", active)
	}
}

// panicConn is a PoolConn whose SendChunk panics — simulating a buggy
// transport implementation. The pool's active-counter must still balance
// because we deferred the decrement on acquire.
type panicConn struct{}

func (panicConn) SendChunk(_ context.Context, _ []byte) ([]byte, error) {
	panic("simulated transport panic")
}
func (panicConn) Close() error { return nil }

// TestPoolSend_ActiveCounterBalancesOnPanic asserts that even when SendChunk
// panics, the active counter is correctly decremented via defer (the A1-L4 fix).
func TestPoolSend_ActiveCounterBalancesOnPanic(t *testing.T) {
	config := DefaultPoolConfig()
	config.MinConns = 1
	config.MaxConns = 4

	dialer := func(ctx context.Context) (PoolConn, error) {
		return panicConn{}, nil
	}
	pool := NewPool(config, dialer)
	defer pool.Close()

	// Allow preopen to populate.
	time.Sleep(50 * time.Millisecond)

	// Trigger a panicking Send and recover it.
	func() {
		defer func() { _ = recover() }()
		_, _ = pool.Send(context.Background(), []byte("data"))
	}()

	// Settle.
	time.Sleep(20 * time.Millisecond)

	if active := atomic.LoadInt32(&pool.active); active != 0 {
		t.Errorf("active counter leaked after panic: got %d, want 0 (A1-L4 regression)", active)
	}
}
