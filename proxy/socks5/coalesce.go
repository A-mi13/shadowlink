package socks5

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/client"
)

// PoolAcquirer abstracts the slot acquisition so tests can stub it.
// Real wiring uses *client.WSReadyPool.
type PoolAcquirer interface {
	Acquire(ctx context.Context) (any, error)
}

// CoalescingDispatcher debounces a flurry of Acquires within a window so
// the underlying pool isn't hammered with concurrent demand. The actual
// upgrade rate is also capped via the in-flight semaphore.
//
// Semantics: when a CONNECT arrives, the dispatcher starts a window timer
// (if not running). All CONNECTs arriving inside the window queue. When
// the window expires the queue flushes — each call invokes the underlying
// Acquire, gated by the semaphore (max N in-flight). Wall-clock cost per
// CONNECT is window_size + acquire_latency.
//
// Cancellation: each pending request keeps a reference to its caller's
// context. flush() passes that context into pool.Acquire so a cancelled
// caller propagates the cancel down (a respecting pool returns early
// without allocating a slot). Belt-and-suspenders: if pool.Acquire ignores
// the ctx and returns a live conn AFTER the caller bailed, the dispatch
// goroutine type-asserts the conn to io.Closer and closes it — without
// this, the slot would leak from the underlying WSReadyPool every time a
// SOCKS5 caller cancels mid-window (real risk under reconnect cascade).
type CoalescingDispatcher struct {
	pool   PoolAcquirer
	window time.Duration
	sem    chan struct{}

	mu      sync.Mutex
	pending []pendingReq
	timer   *time.Timer
}

type dispatchResult struct {
	conn any
	err  error
}

// pendingReq tracks one queued Acquire — its result channel and the
// caller's context. The ctx travels with the request so flush() can
// (a) propagate cancel into pool.Acquire and (b) detect a departed
// caller in the result-delivery select.
type pendingReq struct {
	ch  chan dispatchResult
	ctx context.Context
}

// NewCoalescingDispatcher constructs a dispatcher with given window and
// max in-flight Acquires.
func NewCoalescingDispatcher(pool PoolAcquirer, window time.Duration, maxParallel int) *CoalescingDispatcher {
	if maxParallel <= 0 {
		maxParallel = 2
	}
	return &CoalescingDispatcher{
		pool:   pool,
		window: window,
		sem:    make(chan struct{}, maxParallel),
	}
}

// Acquire enqueues for the next flush. Unbuffered ch is intentional: it
// forces the dispatch goroutine's send to block until the caller reads,
// so a caller that exits via ctx.Done() leaves the send unmatched and the
// goroutine's select falls through to the close-conn branch.
func (cd *CoalescingDispatcher) Acquire(ctx context.Context) (any, error) {
	ch := make(chan dispatchResult)
	cd.mu.Lock()
	cd.pending = append(cd.pending, pendingReq{ch: ch, ctx: ctx})
	newGroup := cd.timer == nil
	if newGroup {
		cd.timer = time.AfterFunc(cd.window, cd.flush)
	}
	cd.mu.Unlock()

	// Task D5 (cold-start metrics): every CONNECT that lands in a window
	// counts as Grouped (including the first caller that opened it); the
	// window itself counts as exactly one Group. Ratio
	// (Grouped - Groups) / Grouped is the fraction of CONNECTs that
	// benefited from batching. Counters live in the client/ package so the
	// /metrics text exporter sees them via WritePromMetrics.
	client.IncSOCKS5CoalesceGrouped(1)
	if newGroup {
		client.IncSOCKS5CoalesceGroups()
	}

	select {
	case res := <-ch:
		return res.conn, res.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (cd *CoalescingDispatcher) flush() {
	cd.mu.Lock()
	pending := cd.pending
	cd.pending = nil
	cd.timer = nil
	cd.mu.Unlock()

	for _, p := range pending {
		p := p
		go func() {
			// Honor caller's ctx while waiting for a semaphore slot. Without
			// this escape, a flurry of cancelled requests would queue behind
			// in-flight pool.Acquire calls and only unblock once those return.
			// Under reconnect cascade (the exact failure mode this dispatcher
			// targets) the wait would extend by O(WS upgrade latency). The
			// caller in Acquire() has already exited via ctx.Done(), so no
			// result needs to be delivered and no slot was acquired.
			select {
			case cd.sem <- struct{}{}:
			case <-p.ctx.Done():
				return
			}
			defer func() { <-cd.sem }()
			conn, err := cd.pool.Acquire(p.ctx)
			select {
			case p.ch <- dispatchResult{conn: conn, err: err}:
				// delivered to caller
			case <-p.ctx.Done():
				// Caller cancelled before we could deliver. Release the
				// conn so it doesn't leak from the underlying pool.
				if c, ok := conn.(io.Closer); ok {
					_ = c.Close()
				}
			}
		}()
	}
}
