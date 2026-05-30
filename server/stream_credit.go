package server

import "sync"

// stream_credit.go — server-side per-stream send credit (Bug #8). The WS
// per-stream relay goroutine calls waitForCredit BEFORE reading the target
// (websocket.go), so a stream with no credit simply doesn't read — the target
// TCP socket applies its own backpressure. Credit is replenished by
// handleWindowUpdate when the client confirms consumption. Blocking happens
// ONLY in the per-stream relay goroutine, never in the session reader-loop
// (invariant I2) — so there is no head-of-line blocking across streams.
type streamCredit struct {
	mu        sync.Mutex
	cond      *sync.Cond
	available int64
	closed    bool
}

func newStreamCredit(window int64) *streamCredit {
	c := &streamCredit{available: window}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// waitForCredit blocks until available > 0, then returns it; or returns -1 if
// the stream/session was closed (caller exits the relay). done is the session
// done channel — the caller arranges wake() to be called when done fires
// (sync.Cond cannot select on a channel).
func (c *streamCredit) waitForCredit(done <-chan struct{}) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	for c.available <= 0 && !c.closed {
		// Check done before blocking.
		select {
		case <-done:
			return -1
		default:
		}
		c.cond.Wait()
		// After wakeup: re-check done (covers wake() call after close(doneCh)).
		select {
		case <-done:
			return -1
		default:
		}
		if c.closed {
			return -1
		}
	}
	if c.closed {
		return -1
	}
	return c.available
}

// consume decrements available by n (after enqueueing n bytes to the client).
func (c *streamCredit) consume(n int) {
	c.mu.Lock()
	c.available -= int64(n)
	c.mu.Unlock()
}

// add replenishes credit by delta, clamped at 2*window, and wakes the waiter.
func (c *streamCredit) add(delta uint32, window int64) {
	c.mu.Lock()
	c.available += int64(delta)
	if capLimit := 2 * window; c.available > capLimit {
		c.available = capLimit
	}
	c.cond.Signal()
	c.mu.Unlock()
}

// close marks the credit closed and wakes any waiter. Signal under mu so the
// waiter sees closed (no lost wakeup — M4).
func (c *streamCredit) close() {
	c.mu.Lock()
	c.closed = true
	c.cond.Signal()
	c.mu.Unlock()
}

// wake nudges the waiter to re-check (used on session done). Safe to call
// repeatedly.
func (c *streamCredit) wake() {
	c.mu.Lock()
	c.cond.Signal()
	c.mu.Unlock()
}

// snapshot returns current available (test/diagnostic helper).
func (c *streamCredit) snapshot() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.available
}
