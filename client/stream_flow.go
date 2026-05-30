package client

import "sync/atomic"

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
