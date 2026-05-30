package client

import (
	"sync/atomic"
	"time"

	"math/rand/v2"

	"github.com/nixavpn/shadowlink/core"
)

// stream_flow.go — client-side per-stream flow control (Bug #8). The downlink
// relay goroutine calls OnStreamConsumed after each successful conn.Write into
// the app (memConn) — it ONLY does an atomic add and NEVER sends or blocks
// (invariant I3). A separate per-client credit sender (added in a later task)
// drains pendingDelta into WINDOW_UPDATE frames non-blockingly.

// streamFlowState accumulates bytes the app has consumed but not yet credited
// back to the server via WINDOW_UPDATE.
type streamFlowState struct {
	pendingDelta atomic.Uint64 // bytes consumed since last WINDOW_UPDATE sent
	window       uint64        // negotiated effective window (read-only)
	lastSentNs   atomic.Int64  // unix-nano of last successful WINDOW_UPDATE (watchdog)
}

const (
	creditSenderInterval = 8 * time.Millisecond // tick cadence (cheap)
	creditWatchdogNs     = int64(200 * time.Millisecond)
)

// startCreditSender launches the single per-client credit-sender goroutine.
// It scans Client.streamFlow each tick and emits WINDOW_UPDATE for any stream
// whose pendingDelta crossed the (jittered 40-60%) threshold, or whose tail has
// been waiting longer than the watchdog window. Idempotent via flowStop.
func (c *Client) startCreditSender() {
	if !c.flowControlEnabled {
		return
	}
	c.streamMu.Lock()
	if c.flowStop != nil {
		c.streamMu.Unlock()
		return
	}
	c.flowStop = make(chan struct{})
	stop := c.flowStop
	c.streamMu.Unlock()

	go func() {
		t := time.NewTicker(creditSenderInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				ratio := 0.4 + rand.Float64()*0.2 // jitter 40-60% (§16)
				c.creditSenderTick(ratio)
			}
		}
	}()
}

// stopCreditSender stops the credit-sender goroutine. Idempotent.
func (c *Client) stopCreditSender() {
	c.streamMu.Lock()
	if c.flowStop != nil {
		close(c.flowStop)
		c.flowStop = nil
	}
	c.streamMu.Unlock()
}

// creditSenderTick scans all streams once. thresholdRatio is the fraction of
// the window that must accumulate before a WINDOW_UPDATE is emitted (the
// watchdog overrides it for stale tails). Pure given flowSendForTest.
func (c *Client) creditSenderTick(thresholdRatio float64) {
	c.streamMu.Lock()
	type item struct {
		id uint16
		st *streamFlowState
	}
	items := make([]item, 0, len(c.streamFlow))
	for id, st := range c.streamFlow {
		items = append(items, item{id, st})
	}
	c.streamMu.Unlock()

	nowNs := time.Now().UnixNano()
	for _, it := range items {
		d := it.st.pendingDelta.Load()
		if d == 0 {
			continue
		}
		threshold := uint64(float64(it.st.window) * thresholdRatio)
		// Watchdog fires only after at least one successful send (lastSentNs != 0);
		// this prevents new streams (lastSentNs=0) from triggering a watchdog-send
		// even when d < threshold (would break TestCreditSender_BelowThresholdNoSend).
		lastNs := it.st.lastSentNs.Load()
		stale := lastNs != 0 && nowNs-lastNs >= creditWatchdogNs
		if d < threshold && !stale {
			continue
		}
		// Take the current delta atomically; only zero it if the send succeeds.
		if it.st.pendingDelta.CompareAndSwap(d, 0) {
			if c.sendWindowUpdate(it.id, uint32(d)) {
				it.st.lastSentNs.Store(nowNs)
				Stats.FlowWindowUpdatesSent.Add(1)
			} else {
				it.st.pendingDelta.Add(d) // give back (additive, race-safe)
				Stats.FlowWindowUpdateDropped.Add(1)
			}
		}
		// CAS failure → OnStreamConsumed added concurrently; next tick handles it.
	}
}

// NOTE: c.flowTransport must be assigned BEFORE startCreditSender launches the
// sender goroutine (happens-before via goroutine start) and not mutated after —
// so this lock-free read is race-free. Wiring (later task) must honor this.

// sendWindowUpdate builds and non-blockingly sends a WINDOW_UPDATE for streamID.
// Returns true if enqueued. Uses the test seam when set.
func (c *Client) sendWindowUpdate(streamID uint16, delta uint32) bool {
	if c.flowSendForTest != nil {
		return c.flowSendForTest(streamID, delta)
	}
	if c.flowTransport == nil {
		return false
	}
	session := StreamSession(c.flowTransport, c, streamID)
	if session == nil {
		return false
	}
	chunk := core.NewWindowUpdateChunk(session.ID, session.NextSeqNum(), streamID, delta)
	enc, err := session.EncryptChunk(chunk)
	if err != nil {
		return false
	}
	return TryStreamWriteControl(c.flowTransport, streamID, enc)
}

// OnStreamConsumed records that n bytes were delivered to the app for streamID.
// Add-only: never blocks, never sends (I3). No-op if flow control is disabled
// or the stream has no flow state.
func (c *Client) OnStreamConsumed(streamID uint16, n int) {
	if !c.flowControlEnabled || n <= 0 {
		return
	}
	c.streamMu.Lock()
	st := c.streamFlow[streamID]
	c.streamMu.Unlock()
	if st == nil {
		return
	}
	st.pendingDelta.Add(uint64(n))
}
