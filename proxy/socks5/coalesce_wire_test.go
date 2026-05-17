package socks5

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSocks5CoalesceEnabled_DefaultOn — env unset → coalesce ON.
func TestSocks5CoalesceEnabled_DefaultOn(t *testing.T) {
	t.Setenv("SHADOWLINK_SOCKS5_COALESCE", "")
	if !socks5CoalesceEnabled() {
		t.Fatal("default behavior must be coalesce ON")
	}
}

// TestSocks5CoalesceEnabled_OptOutValues — only the documented strings disable.
func TestSocks5CoalesceEnabled_OptOutValues(t *testing.T) {
	optOut := []string{"0", "false", "no", "off", "FALSE", "Off", "  no  ", "OFF"}
	for _, v := range optOut {
		t.Run("optout="+v, func(t *testing.T) {
			t.Setenv("SHADOWLINK_SOCKS5_COALESCE", v)
			if socks5CoalesceEnabled() {
				t.Errorf("value %q must opt out (return false)", v)
			}
		})
	}
}

// TestSocks5CoalesceEnabled_NoiseStaysOn — anything else keeps default-on.
func TestSocks5CoalesceEnabled_NoiseStaysOn(t *testing.T) {
	for _, v := range []string{"1", "true", "yes", "on", "garbage", "ON", " 1 "} {
		t.Run("on="+v, func(t *testing.T) {
			t.Setenv("SHADOWLINK_SOCKS5_COALESCE", v)
			if !socks5CoalesceEnabled() {
				t.Errorf("value %q must keep coalesce ON", v)
			}
		})
	}
}

// countingPool is a PoolAcquirer that records concurrent in-flight calls,
// used to prove the dispatcher is shared across goroutines (a per-call
// dispatcher would let all callers run in parallel without coalescing).
type countingPool struct {
	mu       sync.Mutex
	calls    int
	maxInFlt int32
	curInFlt int32
	delay    time.Duration
}

func (p *countingPool) Acquire(ctx context.Context) (any, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	cur := atomic.AddInt32(&p.curInFlt, 1)
	defer atomic.AddInt32(&p.curInFlt, -1)
	for {
		max := atomic.LoadInt32(&p.maxInFlt)
		if cur <= max || atomic.CompareAndSwapInt32(&p.maxInFlt, max, cur) {
			break
		}
	}
	time.Sleep(p.delay)
	return struct{}{}, nil
}

// TestCoalesceDispatcher_SharedAcrossCallers — when a single dispatcher
// fronts a pool, concurrent Acquires within the window are gated by the
// semaphore (max 2 in-flight). This is the property that makes wiring
// the dispatcher onto PerStreamWSConfig (instead of per-CONNECT) correct.
func TestCoalesceDispatcher_SharedAcrossCallers(t *testing.T) {
	pool := &countingPool{delay: 50 * time.Millisecond}
	dispatch := NewCoalescingDispatcher(pool, 20*time.Millisecond, 2)

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = dispatch.Acquire(context.Background())
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&pool.maxInFlt); got > 2 {
		t.Errorf("shared dispatcher must cap concurrency at 2; saw %d in-flight", got)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if pool.calls != 6 {
		t.Errorf("expected 6 underlying Acquires (one per caller), got %d", pool.calls)
	}
}
