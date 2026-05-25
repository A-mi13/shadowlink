# Stream Buffer Overflow Aggregation + Drain Spam Reduction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace 100+ per-event WARN "stream buffer full, data dropped" with one centralized aggregated WARN/INFO pair per stream + surface drain storm-brake counter in health snapshot (downgrade per-event INFO to DEBUG).

**Architecture:** P0 — move overflow detection from per-call WARN at `client.RouteToStream` to per-stream `streamOverflowState` map keyed by stream ID, flushed at `UnregisterStream`. Covers all code paths uniformly (WS pool reader, Split, ready pool, ServerClose). P1 — `Info` → `Debug` for storm-brake per-event logs, add `drainDeferrals1m atomic.Int32` (same pattern as existing `rotations1m`) + surface `deferred_drains_total` + `deferred_drains_1m` in `WS pool health` snapshot.

**Tech Stack:** Go 1.x, `log/slog`, `sync.Mutex`, `sync/atomic`, `testing` stdlib.

**Spec:** `docs/superpowers/specs/2026-05-23-stream-buffer-and-drain-log-fixes-design.md`

---

## File structure

| File | Action | Responsibility |
|---|---|---|
| `shadowlink/client/stream_overflow.go` | CREATE | Per-stream overflow state struct + recordBufferOverflow + flushBufferOverflow |
| `shadowlink/client/client.go` | MODIFY | `RouteToStream` calls `recordBufferOverflow` instead of inline `slog.Warn`. `UnregisterStream` calls `flushBufferOverflow` after delete. Add field `streamOverflow map[uint16]*streamOverflowState` + `streamOverflowMu sync.Mutex`. |
| `shadowlink/client/stats.go` | MODIFY | Add `StreamBufferOverflowsTotal atomic.Uint64` + metrics-dump entry |
| `shadowlink/proxy/socks5/tcp.go` | MODIFY | Remove `slog.Info("downlink post-error drain", ...)` log (drain loop body itself stays — it still drains channel to unblock producers) |
| `shadowlink/client/ws_pool_drain.go` | MODIFY | `Info` → `Debug` for "drain deferred" logs (lines 265-271, 286-293). Add `p.bumpDrainDeferrals1m()` calls right after `Stats.DrainStormBrakeEngagedTotal.Add(1)` (2 sites). |
| `shadowlink/client/ws_pool.go` | MODIFY | Add `drainDeferrals1m atomic.Int32` field. Add `bumpDrainDeferrals1m` method (clone of `bumpRotations1m`). Surface `deferred_drains_total` + `deferred_drains_1m` in `emitHealthSummary`. |
| `shadowlink/client/stream_overflow_test.go` | CREATE | 5 TDD tests for P0 |
| `shadowlink/client/ws_pool_drain_logging_test.go` | CREATE | 4 TDD tests for P1 |

---

## P0: Centralized Stream Buffer Overflow Aggregation

### Task 1: Add `StreamBufferOverflowsTotal` stats counter

**Files:**
- Modify: `shadowlink/client/stats.go` (struct ~line 235, metrics-dump ~line 588)

- [ ] **Step 1: Add counter to Stats struct**

In `shadowlink/client/stats.go`, find the block declaring `DrainStormBrakeEngagedTotal atomic.Uint64` (~line 235). Add immediately after it:

```go
	// StreamBufferOverflowsTotal — cumulative count of frames dropped at
	// client.RouteToStream when the per-stream buffered channel (cap 512)
	// is full. Counter increments once per dropped frame, surfaced at
	// stream UnregisterStream as an aggregated INFO log. Non-zero rate
	// indicates SOCKS consumer death races (most often local app closing
	// TCP early) — see spec 2026-05-23.
	StreamBufferOverflowsTotal atomic.Uint64
```

- [ ] **Step 2: Add metrics-dump entry**

In `shadowlink/client/stats.go`, find the block that outputs `shadowlink_slot_drain_storm_brake_engaged_total` (~line 588). Add immediately after that block (after the `Fprintf` for `shadowlink_slot_drain_force_evicted_total`):

```go
	fmt.Fprintf(w, "# HELP shadowlink_stream_buffer_overflows_total Frames dropped at RouteToStream because the per-stream buffered channel was full (consumer dead/slow)\n")
	fmt.Fprintf(w, "# TYPE shadowlink_stream_buffer_overflows_total counter\n")
	fmt.Fprintf(w, "shadowlink_stream_buffer_overflows_total %d\n", Stats.StreamBufferOverflowsTotal.Load())
```

- [ ] **Step 3: Compile check**

Run: `cd D:/NIXAVPN/shadowlink && go build ./...`
Expected: no errors.

---

### Task 2: Create `streamOverflow` state + helpers

**Files:**
- Create: `shadowlink/client/stream_overflow.go`

- [ ] **Step 1: Write the file**

Create `D:/NIXAVPN/shadowlink/client/stream_overflow.go`:

```go
package client

import (
	"log/slog"
	"time"
)

// streamOverflowState aggregates per-stream RouteToStream channel-full
// drops so we emit two logs per stream (one WARN on first drop, one INFO
// on stream end with totals) instead of N WARNs per drop event.
//
// Triggered by: SOCKS consumer death races, ServerClose mid-stream,
// per-stream WS path teardown — all paths funnel through RouteToStream's
// `select case ch <- data: default` fallthrough.
//
// Design: spec 2026-05-23.
type streamOverflowState struct {
	firstAt      time.Time
	lastAt       time.Time
	drops        uint32
	droppedBytes uint64
}

// recordBufferOverflow registers a single drop event for the given stream.
// Caller must hold no Client locks (function acquires streamOverflowMu).
//
// On the FIRST drop for a stream a WARN is emitted; subsequent drops are
// silently counted. The aggregate is flushed at flushBufferOverflow time
// (called from UnregisterStream).
func (c *Client) recordBufferOverflow(streamID uint16, dataSize int) {
	now := time.Now()
	c.streamOverflowMu.Lock()
	st, exists := c.streamOverflow[streamID]
	if !exists {
		if c.streamOverflow == nil {
			c.streamOverflow = make(map[uint16]*streamOverflowState)
		}
		st = &streamOverflowState{firstAt: now}
		c.streamOverflow[streamID] = st
	}
	st.lastAt = now
	st.drops++
	st.droppedBytes += uint64(dataSize)
	c.streamOverflowMu.Unlock()
	Stats.StreamBufferOverflowsTotal.Add(1)
	if !exists {
		slog.Warn("stream buffer overflow started",
			"stream_id", streamID, "data_size", dataSize)
	}
}

// flushBufferOverflow emits the aggregated INFO log for a stream if any
// drops were recorded and clears state. Safe to call for streams with
// no overflow (no-op in that case). Called from UnregisterStream.
func (c *Client) flushBufferOverflow(streamID uint16) {
	c.streamOverflowMu.Lock()
	st, has := c.streamOverflow[streamID]
	if has {
		delete(c.streamOverflow, streamID)
	}
	c.streamOverflowMu.Unlock()
	if !has {
		return
	}
	slog.Info("stream buffer overflow ended",
		"stream_id", streamID,
		"drops", st.drops,
		"dropped_bytes", st.droppedBytes,
		"duration", st.lastAt.Sub(st.firstAt))
}
```

- [ ] **Step 2: Compile check**

Run: `cd D:/NIXAVPN/shadowlink && go build ./...`
Expected: error about `streamOverflow` / `streamOverflowMu` not being a field of `Client` — that's expected; we add it in Task 3.

---

### Task 3: Add `streamOverflow` fields to `Client` + wire calls

**Files:**
- Modify: `shadowlink/client/client.go` (struct ~line 139, RouteToStream ~line 909, UnregisterStream ~line 695)

- [ ] **Step 1: Add fields to Client struct**

In `shadowlink/client/client.go`, find:

```go
	streamChans   map[uint16]chan []byte // StreamID → incoming data from server
	streamMu      sync.Mutex
```

Add immediately below `streamMu`:

```go
	// streamOverflow tracks per-stream RouteToStream drops so we emit a
	// single aggregated INFO at UnregisterStream instead of N WARNs per
	// drop. See spec 2026-05-23.
	streamOverflow   map[uint16]*streamOverflowState
	streamOverflowMu sync.Mutex
```

- [ ] **Step 2: Replace inline slog.Warn in RouteToStream**

In `shadowlink/client/client.go`, find `RouteToStream` (~line 907):

```go
// RouteToStream delivers data to a registered stream's channel.
// MED-5 fix: logs warning on buffer full instead of silent drop.
func (c *Client) RouteToStream(streamID uint16, data []byte) {
	c.streamMu.Lock()
	ch := c.streamChans[streamID]
	c.streamMu.Unlock()
	if ch != nil {
		select {
		case ch <- data:
		default:
			slog.Warn("stream buffer full, data dropped", "stream_id", streamID, "bytes", len(data))
		}
	}
}
```

Replace with:

```go
// RouteToStream delivers data to a registered stream's channel.
// On buffer-full it records an overflow event; aggregated WARN/INFO
// pair is emitted by recordBufferOverflow/flushBufferOverflow rather
// than a WARN per dropped frame. See spec 2026-05-23.
func (c *Client) RouteToStream(streamID uint16, data []byte) {
	c.streamMu.Lock()
	ch := c.streamChans[streamID]
	c.streamMu.Unlock()
	if ch != nil {
		select {
		case ch <- data:
		default:
			c.recordBufferOverflow(streamID, len(data))
		}
	}
}
```

- [ ] **Step 3: Call flushBufferOverflow in UnregisterStream**

In `shadowlink/client/client.go`, find `UnregisterStream` (~line 695):

```go
// UnregisterStream removes a stream channel.
func (c *Client) UnregisterStream(streamID uint16) {
	c.streamMu.Lock()
	defer c.streamMu.Unlock()
	delete(c.streamChans, streamID)
}
```

Replace with:

```go
// UnregisterStream removes a stream channel and flushes any
// per-stream buffer-overflow state (aggregated INFO if non-empty).
func (c *Client) UnregisterStream(streamID uint16) {
	c.streamMu.Lock()
	delete(c.streamChans, streamID)
	c.streamMu.Unlock()
	c.flushBufferOverflow(streamID)
}
```

- [ ] **Step 4: Compile check**

Run: `cd D:/NIXAVPN/shadowlink && go build ./...`
Expected: no errors.

---

### Task 4: Write TDD tests for stream overflow

**Files:**
- Create: `shadowlink/client/stream_overflow_test.go`

- [ ] **Step 1: Write failing tests**

Create `D:/NIXAVPN/shadowlink/client/stream_overflow_test.go`:

```go
package client

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// captureSlog redirects the default slog logger to an in-memory buffer
// and returns a cleanup func + the buffer. Caller asserts on buffer
// contents to verify log emissions.
func captureSlog(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// newTestClient returns a minimal Client suitable for stream-overflow
// tests. Does NOT establish a network session — only the bits exercised
// by RegisterStream/RouteToStream/UnregisterStream are initialized.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	return &Client{
		ctx:    context.Background(),
		cancel: func() {},
	}
}

func TestStreamBufferOverflow_SingleStreamMultipleDrops(t *testing.T) {
	buf := captureSlog(t, slog.LevelInfo)
	c := newTestClient(t)
	startBaseline := Stats.StreamBufferOverflowsTotal.Load()

	const sid uint16 = 7777
	ch, err := c.RegisterStream(sid)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	_ = ch // consumer never reads; channel cap = 512

	// First 512 sends fill the buffer; further sends drop.
	for i := 0; i < 512; i++ {
		c.RouteToStream(sid, []byte{0xAB})
	}
	// 200 guaranteed drops.
	for i := 0; i < 200; i++ {
		c.RouteToStream(sid, []byte{0xCD, 0xEF}) // 2 bytes each
	}

	// Before Unregister: exactly ONE WARN "started", zero INFO "ended".
	warnCount := strings.Count(buf.String(), `msg="stream buffer overflow started"`)
	if warnCount != 1 {
		t.Errorf("expected 1 WARN 'started', got %d. Log:\n%s", warnCount, buf.String())
	}
	if c := strings.Count(buf.String(), `msg="stream buffer overflow ended"`); c != 0 {
		t.Errorf("expected 0 INFO 'ended' before Unregister, got %d", c)
	}

	c.UnregisterStream(sid)

	// After Unregister: exactly ONE INFO "ended".
	endedCount := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCount != 1 {
		t.Errorf("expected 1 INFO 'ended', got %d. Log:\n%s", endedCount, buf.String())
	}
	// Counter incremented exactly 200 (drops; first 512 fit in buffer).
	delta := Stats.StreamBufferOverflowsTotal.Load() - startBaseline
	if delta != 200 {
		t.Errorf("StreamBufferOverflowsTotal delta = %d, want 200", delta)
	}
}

func TestStreamBufferOverflow_NoOverflowNoLog(t *testing.T) {
	buf := captureSlog(t, slog.LevelInfo)
	c := newTestClient(t)

	const sid uint16 = 8888
	ch, err := c.RegisterStream(sid)
	if err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}
	// Active consumer drains.
	done := make(chan struct{})
	go func() {
		for range ch {
		}
		close(done)
	}()

	for i := 0; i < 100; i++ {
		c.RouteToStream(sid, []byte{0x01})
	}
	c.UnregisterStream(sid)
	// Close channel so consumer exits.
	close(ch)
	<-done

	if got := buf.String(); strings.Contains(got, "stream buffer overflow") {
		t.Errorf("unexpected overflow log emitted on healthy stream:\n%s", got)
	}
}

func TestStreamBufferOverflow_ConcurrentProducersSingleStart(t *testing.T) {
	buf := captureSlog(t, slog.LevelInfo)
	c := newTestClient(t)
	startBaseline := Stats.StreamBufferOverflowsTotal.Load()

	const sid uint16 = 9999
	const producers = 5
	const sendsPerProducer = 300

	if _, err := c.RegisterStream(sid); err != nil {
		t.Fatalf("RegisterStream: %v", err)
	}

	var wg sync.WaitGroup
	var startSignal atomic.Bool
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !startSignal.Load() {
			}
			for i := 0; i < sendsPerProducer; i++ {
				c.RouteToStream(sid, []byte{0xFF})
			}
		}()
	}
	startSignal.Store(true)
	wg.Wait()

	// Exactly ONE "started" log despite concurrent producers (mutex
	// serializes the first-drop detection).
	startedCount := strings.Count(buf.String(), `msg="stream buffer overflow started"`)
	if startedCount != 1 {
		t.Errorf("expected 1 WARN 'started' under concurrent producers, got %d", startedCount)
	}

	c.UnregisterStream(sid)
	endedCount := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCount != 1 {
		t.Errorf("expected 1 INFO 'ended', got %d", endedCount)
	}
	// 5*300 = 1500 sends; first 512 land in buffer, remaining 988 dropped.
	delta := Stats.StreamBufferOverflowsTotal.Load() - startBaseline
	if delta != 988 {
		t.Errorf("StreamBufferOverflowsTotal delta = %d, want 988", delta)
	}
}

func TestStreamBufferOverflow_CumulativeStatCounter(t *testing.T) {
	captureSlog(t, slog.LevelInfo)
	c := newTestClient(t)
	startBaseline := Stats.StreamBufferOverflowsTotal.Load()

	// Stream A: 30 drops.
	const sidA uint16 = 1001
	if _, err := c.RegisterStream(sidA); err != nil {
		t.Fatalf("RegisterStream A: %v", err)
	}
	for i := 0; i < 512+30; i++ {
		c.RouteToStream(sidA, []byte{0x01})
	}
	c.UnregisterStream(sidA)

	// Stream B: 50 drops.
	const sidB uint16 = 1002
	if _, err := c.RegisterStream(sidB); err != nil {
		t.Fatalf("RegisterStream B: %v", err)
	}
	for i := 0; i < 512+50; i++ {
		c.RouteToStream(sidB, []byte{0x02})
	}
	c.UnregisterStream(sidB)

	delta := Stats.StreamBufferOverflowsTotal.Load() - startBaseline
	if delta != 80 {
		t.Errorf("cumulative StreamBufferOverflowsTotal delta = %d, want 80", delta)
	}
}

func TestStreamBufferOverflow_UnregisterClearsState(t *testing.T) {
	buf := captureSlog(t, slog.LevelInfo)
	c := newTestClient(t)

	const sid uint16 = 4242
	// First lifecycle with overflow.
	if _, err := c.RegisterStream(sid); err != nil {
		t.Fatalf("RegisterStream 1: %v", err)
	}
	for i := 0; i < 512+10; i++ {
		c.RouteToStream(sid, []byte{0x00})
	}
	c.UnregisterStream(sid)

	endedCountAfterFirst := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCountAfterFirst != 1 {
		t.Fatalf("expected 1 INFO 'ended' after first lifecycle, got %d", endedCountAfterFirst)
	}

	// Second lifecycle without overflow — state must have been cleared.
	if _, err := c.RegisterStream(sid); err != nil {
		t.Fatalf("RegisterStream 2: %v", err)
	}
	c.UnregisterStream(sid)

	endedCountAfterSecond := strings.Count(buf.String(), `msg="stream buffer overflow ended"`)
	if endedCountAfterSecond != endedCountAfterFirst {
		t.Errorf("unexpected 'ended' on second lifecycle (cleared state should suppress); count went from %d to %d",
			endedCountAfterFirst, endedCountAfterSecond)
	}
}
```

- [ ] **Step 2: Run tests — expect PASS (implementation already done in Tasks 2-3)**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestStreamBufferOverflow -v`
Expected: 5 PASS.

If failures: read output carefully, identify root cause (likely test logic, not impl, since impl is straightforward). Do NOT modify impl unless the failure is reproducible against the spec.

---

### Task 5: Remove duplicate post-error drain log in tcp.go

**Files:**
- Modify: `shadowlink/proxy/socks5/tcp.go` (~lines 685-707)

- [ ] **Step 1: Remove the redundant INFO**

In `shadowlink/proxy/socks5/tcp.go`, find the block (~line 685):

```go
				if _, err := conn.Write(data); err != nil {
					slog.Warn("downlink write error", "dest", destAddr, "stream", streamID, "err", err)
					// Consumer (local SOCKS5 client) is gone. The uplink
					// goroutine still sits in its 15s grace before
					// canceling ctx2, during which the WS demux keeps
					// pushing frames into incomingCh. Without an active
					// reader on this end, the chan buffer (cap 512) fills
					// and every subsequent RouteToStream pushes a WARN
					// "stream buffer full, data dropped". Drain quietly
					// until ctx2 is done — frames meant for a dead
					// consumer are unrecoverable, so a single info-level
					// summary at end is the honest signal. 2026-05-22
					// canary observed 13 WARN drops on stream=2418 in
					// this exact race; the fix collapses them.
					droppedFrames := 0
					droppedBytes := 0
					for {
						select {
						case d, ok := <-incomingCh:
							if !ok {
								return
							}
							droppedFrames++
							droppedBytes += len(d)
						case <-ctx2.Done():
							if droppedFrames > 0 {
								slog.Info("downlink post-error drain",
									"dest", destAddr, "stream", streamID,
									"dropped_frames", droppedFrames,
									"dropped_bytes", droppedBytes)
							}
							return
						}
					}
				}
```

Replace with:

```go
				if _, err := conn.Write(data); err != nil {
					slog.Warn("downlink write error", "dest", destAddr, "stream", streamID, "err", err)
					// Consumer (local SOCKS5 client) is gone. The uplink
					// goroutine still sits in its 15s grace before
					// canceling ctx2, during which the WS demux keeps
					// pushing frames into incomingCh. Without an active
					// reader the chan buffer (cap 512) fills and
					// RouteToStream starts recording per-stream overflow
					// (logged once aggregated at UnregisterStream, spec
					// 2026-05-23). Here we just keep reading so the demux
					// is not blocked on a full channel.
					for {
						select {
						case _, ok := <-incomingCh:
							if !ok {
								return
							}
						case <-ctx2.Done():
							return
						}
					}
				}
```

- [ ] **Step 2: Compile + run all proxy/socks5 tests**

Run: `cd D:/NIXAVPN/shadowlink && go build ./... && go test ./proxy/socks5/...`
Expected: PASS.

---

## P1: Storm-Brake Counter in Health Snapshot + DEBUG downgrade

### Task 6: Add `drainDeferrals1m` to WSPoolTransport

**Files:**
- Modify: `shadowlink/client/ws_pool.go` (struct ~line 875, method block ~line 2520-2535)

- [ ] **Step 1: Add field to struct**

In `shadowlink/client/ws_pool.go`, find the `rotations1m` field declaration (~line 875):

```go
	rotations1m atomic.Int32
```

Add immediately after it:

```go
	// drainDeferrals1m — count of storm-brake drain deferrals in the
	// last 60s (mirror of rotations1m). Surfaced in `WS pool health`
	// snapshot so per-event INFO ("drain deferred") can be downgraded
	// to DEBUG without losing operational visibility. Cumulative total
	// lives in Stats.DrainStormBrakeEngagedTotal. Spec 2026-05-23.
	drainDeferrals1m atomic.Int32
```

- [ ] **Step 2: Add bump method**

In `shadowlink/client/ws_pool.go`, find `bumpRotations1m` (~line 2524). Add immediately after its closing brace:

```go
// bumpDrainDeferrals1m mirrors bumpRotations1m for storm-brake drain
// deferrals. Lock-free Int32 Add with a 60s decay goroutine that
// exits cleanly on pool ctx cancel. Spec 2026-05-23.
func (p *WSPoolTransport) bumpDrainDeferrals1m() {
	p.drainDeferrals1m.Add(1)
	go func() {
		timer := time.NewTimer(60 * time.Second)
		defer timer.Stop()
		select {
		case <-p.ctx.Done():
		case <-timer.C:
			p.drainDeferrals1m.Add(-1)
		}
	}()
}
```

- [ ] **Step 3: Surface counters in emitHealthSummary**

In `shadowlink/client/ws_pool.go`, find the `p.log.Info("WS pool health", ...)` call (~line 1266). Add two fields between `"inflight_drains", p.inflightDrains.Load(),` and `"uptime", uptime,`:

```go
		"deferred_drains_total", Stats.DrainStormBrakeEngagedTotal.Load(),
		"deferred_drains_1m", p.drainDeferrals1m.Load(),
```

- [ ] **Step 4: Compile check**

Run: `cd D:/NIXAVPN/shadowlink && go build ./...`
Expected: no errors.

---

### Task 7: Wire bump + downgrade per-event logs in ws_pool_drain.go

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go` (~lines 263-271, 279-293)

- [ ] **Step 1: Downgrade inflight-cap log + add bump**

In `shadowlink/client/ws_pool_drain.go`, find the inflight-cap block (~line 263):

```go
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		p.log.Info("WS pool slot drain deferred (inflight cap)",
			"slot", oldIdx, "reason", reason,
			"inflight", inflight,
			"max_concurrent", p.maxConcurrentDrains())
		// Storm-brake-only deferral — fast retry.
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}
```

Replace with:

```go
	if int(inflight) > p.maxConcurrentDrains() {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// Per-event DEBUG: aggregated counter surfaces in 'WS pool
		// health' snapshot every ~5s (deferred_drains_1m /
		// deferred_drains_total). Spec 2026-05-23.
		p.log.Debug("WS pool slot drain deferred (inflight cap)",
			"slot", oldIdx, "reason", reason,
			"inflight", inflight,
			"max_concurrent", p.maxConcurrentDrains())
		// Storm-brake-only deferral — fast retry.
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(drainStormBrakeBackoff).UnixNano())
		return
	}
```

- [ ] **Step 2: Downgrade capacity-floor log + add bump**

In the same file, find the capacity-floor block (~line 279):

```go
	if ready < floor {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		// Catastrophic state (less than half pool ready) → longer backoff
		// so reconnectLoop has time to heal capacity (spec §2.1.1).
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		p.log.Info("WS pool slot drain deferred (capacity floor)",
			"slot", oldIdx, "reason", reason,
			"ready_capacity", ready,
			"floor", floor,
			"backoff", backoff)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}
```

Replace with:

```go
	if ready < floor {
		Stats.DrainStormBrakeEngagedTotal.Add(1)
		p.bumpDrainDeferrals1m()
		// Catastrophic state (less than half pool ready) → longer backoff
		// so reconnectLoop has time to heal capacity (spec §2.1.1).
		backoff := drainStormBrakeBackoff
		if ready < p.poolSize/2 {
			backoff = drainCatastrophicBackoff
		}
		// Per-event DEBUG: aggregated counter in 'WS pool health'.
		// Spec 2026-05-23.
		p.log.Debug("WS pool slot drain deferred (capacity floor)",
			"slot", oldIdx, "reason", reason,
			"ready_capacity", ready,
			"floor", floor,
			"backoff", backoff)
		oldSlot.nextDrainAttemptNs.Store(time.Now().Add(backoff).UnixNano())
		return
	}
```

- [ ] **Step 3: Compile check**

Run: `cd D:/NIXAVPN/shadowlink && go build ./...`
Expected: no errors.

- [ ] **Step 4: Verify existing drain tests still pass**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestDrain -v -count=1`
Expected: existing drain tests PASS. (Some tests assert on Stats.DrainStormBrakeEngagedTotal increments — those still pass since we did NOT touch counter increments.)

---

### Task 8: Write TDD tests for drain-deferred logging

**Files:**
- Create: `shadowlink/client/ws_pool_drain_logging_test.go`

- [ ] **Step 1: Inspect existing drain test scaffolding**

Run: `grep -n "func TestDrain.*Deferred\|setupTestPool\|makeTestPool" D:/NIXAVPN/shadowlink/client/ws_pool_drain_test.go | head -20`

Goal: identify the existing helper that constructs a `*WSPoolTransport` for tests (so the new test file reuses it rather than reinventing).

- [ ] **Step 2: Write failing tests**

Create `D:/NIXAVPN/shadowlink/client/ws_pool_drain_logging_test.go`:

```go
package client

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

// captureSlogForDrain mirrors captureSlog (in stream_overflow_test.go)
// but accepts an explicit level so callers can choose Info-only (asserts
// "no debug visible") vs Debug (asserts "debug visible at debug level").
func captureSlogForDrain(t *testing.T, level slog.Level) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	handler := slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})
	prev := slog.Default()
	slog.SetDefault(slog.New(handler))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

// TestDrainDeferred_LogLevelDebug verifies that drain-deferred storm-brake
// emissions are at DEBUG level (no spam at default INFO level).
//
// We invoke startDrain on a pool configured so the inflight cap is
// immediately exceeded, then assert the log buffer at LevelInfo does NOT
// contain the deferred message, but at LevelDebug it DOES.
func TestDrainDeferred_LogLevelDebug(t *testing.T) {
	// First sub-run: capture at Info — message must be absent.
	t.Run("info_level_silent", func(t *testing.T) {
		buf := captureSlogForDrain(t, slog.LevelInfo)
		triggerStormBrakeInflightCap(t)
		if strings.Contains(buf.String(), "drain deferred (inflight cap)") {
			t.Errorf("INFO-level capture should NOT contain drain deferred:\n%s", buf.String())
		}
	})
	// Second sub-run: capture at Debug — message must appear.
	t.Run("debug_level_visible", func(t *testing.T) {
		buf := captureSlogForDrain(t, slog.LevelDebug)
		triggerStormBrakeInflightCap(t)
		if !strings.Contains(buf.String(), "drain deferred (inflight cap)") {
			t.Errorf("DEBUG-level capture SHOULD contain drain deferred:\n%s", buf.String())
		}
	})
}

// TestDrainDeferred_CounterIncrement verifies the cumulative stat
// counter increments per deferral (unchanged behaviour).
func TestDrainDeferred_CounterIncrement(t *testing.T) {
	captureSlogForDrain(t, slog.LevelDebug) // silence noise; not asserted here
	before := Stats.DrainStormBrakeEngagedTotal.Load()
	const n = 5
	for i := 0; i < n; i++ {
		triggerStormBrakeInflightCap(t)
	}
	got := Stats.DrainStormBrakeEngagedTotal.Load() - before
	if got != n {
		t.Errorf("DrainStormBrakeEngagedTotal delta = %d, want %d", got, n)
	}
}

// TestDrainDeferred_BumpRollingCounter verifies bumpDrainDeferrals1m
// is called per deferral (drainDeferrals1m increases).
func TestDrainDeferred_BumpRollingCounter(t *testing.T) {
	captureSlogForDrain(t, slog.LevelDebug)
	p := makeStormBrakeTestPool(t)
	before := p.drainDeferrals1m.Load()
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)
	got := p.drainDeferrals1m.Load() - before
	if got != 2 {
		t.Errorf("drainDeferrals1m delta = %d, want 2", got)
	}
}

// TestHealthSnapshot_SurfacesDeferredCounters verifies emitHealthSummary
// emits both deferred_drains_total and deferred_drains_1m fields.
func TestHealthSnapshot_SurfacesDeferredCounters(t *testing.T) {
	buf := captureSlogForDrain(t, slog.LevelInfo)
	p := makeStormBrakeTestPool(t)
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)
	triggerStormBrakeInflightCapOn(t, p)

	p.emitHealthSummary()

	out := buf.String()
	if !strings.Contains(out, "deferred_drains_total=") {
		t.Errorf("health snapshot missing deferred_drains_total:\n%s", out)
	}
	if !strings.Contains(out, "deferred_drains_1m=") {
		t.Errorf("health snapshot missing deferred_drains_1m:\n%s", out)
	}
}
```

> **Note for implementer:** Helpers `triggerStormBrakeInflightCap`, `triggerStormBrakeInflightCapOn`, `makeStormBrakeTestPool` are NOT yet defined. In Step 3 you inspect `ws_pool_drain_test.go` for existing helpers (look for setup patterns like `newPoolForTest`, `inflightDrains.Store(...)`) and either reuse or write thin wrappers in this same `ws_pool_drain_logging_test.go` file. The wrapper should: (a) build a minimal `*WSPoolTransport` with poolSize=8, (b) artificially set `p.inflightDrains` above `maxConcurrentDrains()` (e.g., Store(20)), (c) call `p.startDrain(c, 0, "age")` (or whatever the entry point is — confirmed via test file inspection in Step 1). If `startDrain` requires a fully-wired `*Client` and slots that's too heavy, alternative: directly test the storm-brake gate by extracting it to a callable method, OR by setting state and calling `p.startDrain(...)` with a stub Client that has `ctx` populated. Do whichever the existing tests already do — DO NOT invent new mocking patterns.

- [ ] **Step 3: Add helpers based on existing patterns**

Open `D:/NIXAVPN/shadowlink/client/ws_pool_drain_test.go` and find an existing test that successfully triggers storm-brake deferral (search for `DrainStormBrakeEngagedTotal` — line 1400 area was shown to hold one). Copy its setup pattern into a small helper section at the bottom of `ws_pool_drain_logging_test.go`:

```go
// makeStormBrakeTestPool returns a pool wired enough to call startDrain
// and have it land in the storm-brake gate. Reuses the same construction
// pattern as the existing TestDrain* tests in ws_pool_drain_test.go.
func makeStormBrakeTestPool(t *testing.T) *WSPoolTransport {
	t.Helper()
	// TODO[implementer]: copy from ws_pool_drain_test.go around the
	// DrainStormBrakeEngagedTotal assertion (~line 1400). The
	// canonical pattern there is the minimal valid scaffold.
	t.Fatal("not implemented — fill from existing test setup")
	return nil
}

func triggerStormBrakeInflightCap(t *testing.T) {
	t.Helper()
	triggerStormBrakeInflightCapOn(t, makeStormBrakeTestPool(t))
}

func triggerStormBrakeInflightCapOn(t *testing.T, p *WSPoolTransport) {
	t.Helper()
	// Force inflight above cap then call the drain entry point.
	// TODO[implementer]: confirm exact entry point — likely
	// p.startDrain(p.cl, 0, "age") with inflightDrains.Store(>cap)
	// pre-set.
	t.Fatal("not implemented — fill from existing test setup")
}
```

Then DO fill in the helpers based on the existing test. **This is the implementer's job in Task 8 — do NOT proceed with `t.Fatal` placeholders to commit.**

- [ ] **Step 4: Run tests — expect PASS**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run "TestDrainDeferred|TestHealthSnapshot_SurfacesDeferredCounters" -v -count=1`
Expected: 4 PASS.

If failures: re-examine assertions against actual log output. A common gotcha — `slog.NewTextHandler` writes `key=value`, so `"deferred_drains_total="` substring match works regardless of value.

---

## Final integration

### Task 9: Full test suite + format check

- [ ] **Step 1: Run full shadowlink test suite**

Run: `cd D:/NIXAVPN/shadowlink && go test ./... -count=1`
Expected: ALL PASS. No regressions in existing tests.

If any failures: do NOT mass-ignore. Investigate each — most likely an existing test asserted on the old log format or counter snapshot. Fix the test if it asserted on something we intentionally changed (per spec acceptance criteria). DO NOT change implementation behavior to match an old test.

- [ ] **Step 2: gofmt**

Run: `cd D:/NIXAVPN/shadowlink && gofmt -w . && git diff --stat`
Expected: no diff (code already formatted) OR small whitespace diff.

---

### Task 10: Rebuild Windows client binary

**Files:**
- Output: `D:/NIXAVPN/bin/nixavpn-client-graceful-drain.exe`

- [ ] **Step 1: Locate build target**

Run: `ls D:/NIXAVPN/shadowlink/cmd/ 2>/dev/null`

Expected to see a directory like `client` or similar that builds the main client binary. Confirm with `cat D:/NIXAVPN/shadowlink/cmd/<dir>/main.go | head -5`.

- [ ] **Step 2: Build (native Windows since user runs on Win)**

Run from D:/NIXAVPN/shadowlink (native build, since shell is git-bash on Windows and target is Windows binary):

```bash
cd D:/NIXAVPN/shadowlink && go build -o D:/NIXAVPN/bin/nixavpn-client-graceful-drain.exe ./cmd/<the-client-dir>
```

(Replace `<the-client-dir>` with whatever Step 1 revealed.)

Expected: command completes silently; `nixavpn-client-graceful-drain.exe` updated with current mtime.

- [ ] **Step 3: Sanity check binary**

Run: `ls -la D:/NIXAVPN/bin/nixavpn-client-graceful-drain.exe`
Expected: mtime is "now" (within a few seconds).

Run: `D:/NIXAVPN/bin/nixavpn-client-graceful-drain.exe --help 2>&1 | head -10`
Expected: usage output, no panic / link error.

- [ ] **Step 4: Rebuild any other affected binaries**

Check what else lives in `D:/NIXAVPN/shadowlink/cmd/`. If there are server binaries (e.g., shadowlink-server, shadowlink-metrics-dump) that share the client package, rebuild them too:

```bash
cd D:/NIXAVPN/shadowlink && go build -o D:/NIXAVPN/bin/shadowlink-server-linux ./cmd/<server-dir>
cd D:/NIXAVPN/shadowlink && go build -o D:/NIXAVPN/bin/shadowlink-metrics-dump-linux ./cmd/<metrics-dump-dir>
```

(Note: these are Linux binaries — if cross-compiling from Windows needed: `GOOS=linux GOARCH=amd64 go build ...`.)

If those binaries do NOT import the changed package (client), skip rebuild for them.

---

## Self-review checklist

After all tasks: verify against spec acceptance criteria.

- [ ] All 5 stream-overflow tests PASS
- [ ] All 4 drain-logging tests PASS
- [ ] `go test ./...` in shadowlink fully PASS
- [ ] No raw `slog.Warn("stream buffer full, data dropped"` left in repo (`grep -r 'stream buffer full' shadowlink/` should be empty or only test fixtures)
- [ ] No `Info` log for drain-deferred at runtime (grep `'drain deferred'` in `ws_pool_drain.go` shows only `Debug`)
- [ ] Health snapshot emit includes new fields (grep `'deferred_drains_total'` in `ws_pool.go` non-empty)
- [ ] `nixavpn-client-graceful-drain.exe` rebuilt with new mtime
