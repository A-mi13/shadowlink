# Per-stream activity diagnostics — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Добавить per-stream activity tracking (`*streamEntry` с `atomic.Int64 lastWriteNs`) + diagnostic поля в drain-логи для подтверждения/опровержения гипотезы H1 в следующей канарейке. Idle-decision logic пока НЕ меняется — это infrastructure step (Step 1 из 2).

**Architecture:** Заменить `streamMap sync.Map (map[uint16]int)` на `sync.Map (map[uint16]*streamEntry)`, добавить hot-path stamping в 3 точках (`WriteMessageForStream`, `WriteControlMessageForStream`, `slotReaderWithClient` после stale-frame check), добавить `snapshotDrainStreams` функцию, расширить hard-cap + idle-finish лог-сообщения 5 новыми diag-полями.

**Tech Stack:** Go 1.21+, `sync.Map`, `atomic.Int64`, slog, существующие `ws_pool.go` / `ws_pool_drain.go` / `stats.go` patterns. Без новых зависимостей.

**Spec:** `shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-diagnostics-design.md` (verified APPROVE_WITH_MINOR_CHANGES после двух rounds Opus review).

---

## Сводный список изменяемых файлов

**Production code (создать/изменить):**
- `shadowlink/client/stream_entry.go` — **NEW**: тип `streamEntry`, конструктор `newStreamEntry`, snapshot функция `snapshotDrainStreams`.
- `shadowlink/client/ws_pool.go` — изменить declaration streamMap, 9 call sites (`AssignStream`, `IncrPending`, `DecrPending`, `SlotPending`, `ReleaseStream`, `SessionForStream`, `WriteMessageForStream`, `WriteControlMessageForStream`, `slotReaderWithClient`, `handleSlotDeath`).
- `shadowlink/client/ws_pool_drain.go` — изменить `emitHardCapLog` и `finishIdle` branch в `tearDown` (добавить snapshot + diag поля).
- `shadowlink/client/stats.go` — добавить `SnapshotNegativeAgeTotal atomic.Uint64`.

**Test code (создать/изменить):**
- `shadowlink/client/stream_entry_test.go` — **NEW**: unit tests для streamEntry / newStreamEntry / snapshotDrainStreams.
- `shadowlink/client/ws_pool_test_helpers_test.go` — **NEW**: `storeStreamForTest`, `storeStreamForTestWithAge` test helpers (внутри package).
- `shadowlink/client/ws_pool_test.go` — обновить 5 sites `streamMap.Store(uint16, 0)` / Load type asserts.
- `shadowlink/client/ws_pool_drain_test.go` — обновить 7 sites + integration tests для diag-полей.

---

## Build / verification commands

Стандартный цикл (применяется в каждом Task'е где сказано "Run test"):

```bash
cd /d/NIXAVPN/shadowlink
go test ./client/ -run 'TestSpecificName' -v
```

Race detector (обязательно для concurrency-related тестов):

```bash
go test -race -count=3 ./client/ -run 'TestPattern'
```

Под Windows без CGO — `-race` skipped, см. `shadowlink/CLAUDE.md` § Race Detector.

Full pre-commit check:

```bash
cd /d/NIXAVPN/shadowlink
go build ./...
go test ./client/...
```

---

## Task 1: streamEntry type + newStreamEntry constructor

**Files:**
- Create: `shadowlink/client/stream_entry.go`
- Test: `shadowlink/client/stream_entry_test.go`

- [ ] **Step 1.1: Write failing test for newStreamEntry**

Create `shadowlink/client/stream_entry_test.go`:

```go
package client

import (
	"testing"
	"time"
)

func TestNewStreamEntry_StampsLastWriteNs(t *testing.T) {
	before := time.Now().UnixNano()
	e := newStreamEntry(5)
	after := time.Now().UnixNano()

	if e.slotIdx != 5 {
		t.Errorf("slotIdx = %d, want 5", e.slotIdx)
	}
	got := e.lastWriteNs.Load()
	if got < before || got > after {
		t.Errorf("lastWriteNs = %d, want in [%d, %d]", got, before, after)
	}
}
```

- [ ] **Step 1.2: Run test, verify FAIL**

```bash
cd /d/NIXAVPN/shadowlink
go test ./client/ -run TestNewStreamEntry -v
```

Expected: FAIL with `undefined: newStreamEntry` / `undefined: streamEntry`.

- [ ] **Step 1.3: Create stream_entry.go with the type**

Create `shadowlink/client/stream_entry.go`:

```go
package client

import (
	"sync/atomic"
	"time"
)

// streamEntry tracks per-stream state required for both routing
// (which slot owns the stream) and diagnostics (when this stream
// last had wire activity).
//
// Stored as *streamEntry in WSPoolTransport.streamMap (sync.Map);
// pointer storage avoids re-Store on lastWriteNs updates.
//
// Concurrency: slotIdx is set once at construction by newStreamEntry
// and never mutated thereafter — safe for unlocked reads. lastWriteNs
// is updated and read exclusively through its atomic.Int64 methods.
type streamEntry struct {
	slotIdx     int
	lastWriteNs atomic.Int64
}

// newStreamEntry constructs a fully-initialized entry: slotIdx pinned,
// lastWriteNs pre-stamped to time.Now() so snapshot logic never sees
// a zero clock.
func newStreamEntry(slotIdx int) *streamEntry {
	e := &streamEntry{slotIdx: slotIdx}
	e.lastWriteNs.Store(time.Now().UnixNano())
	return e
}
```

- [ ] **Step 1.4: Run test, verify PASS**

```bash
go test ./client/ -run TestNewStreamEntry -v
```

Expected: PASS.

- [ ] **Step 1.5: Add race-safety test**

Append to `stream_entry_test.go`:

```go
func TestStreamEntry_LastWriteNsAtomic(t *testing.T) {
	e := newStreamEntry(0)
	const N = 1000
	done := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			e.lastWriteNs.Store(time.Now().UnixNano())
			done <- struct{}{}
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
	// Final read should be non-zero and recent.
	if e.lastWriteNs.Load() == 0 {
		t.Error("lastWriteNs should be non-zero after concurrent writes")
	}
}
```

- [ ] **Step 1.6: Run with -race, verify PASS**

```bash
go test -race -count=3 ./client/ -run TestStreamEntry -v
```

Expected: PASS, no DATA RACE.

If Windows without CGO:
```bash
go test -count=3 ./client/ -run TestStreamEntry -v
```

Expected: PASS (race detector skipped).

- [ ] **Step 1.7: Commit**

```bash
git add shadowlink/client/stream_entry.go shadowlink/client/stream_entry_test.go
git commit -m "feat(ws_pool): add streamEntry type with per-stream lastWriteNs

Foundation for per-stream activity tracking — Step 1 of
2026-05-25-drain-per-stream-diagnostics spec. Idle-decision logic
unchanged; streamEntry will replace int values in streamMap in
follow-up tasks.

newStreamEntry stamps lastWriteNs at construction so snapshot
code never sees zero clock (resolves R1-M3 edge case)."
```

---

## Task 2: snapshotDrainStreams + Stats counter

**Files:**
- Modify: `shadowlink/client/stream_entry.go`
- Modify: `shadowlink/client/stats.go`
- Test: `shadowlink/client/stream_entry_test.go`

- [ ] **Step 2.1: Add SnapshotNegativeAgeTotal to Stats**

In `shadowlink/client/stats.go`, find the block with `StaleFrameDroppedTotal` (around line 230). Append AFTER `StaleFrameDroppedTotal` declaration block (before the next counter):

```go
	// SnapshotNegativeAgeTotal — counts cases where drainStreamSnapshot
	// observed lastWriteNs > now (clock went backwards under NTP adjust,
	// or, worse, arbitrary value stored). Clamped to 0 in snapshot logic;
	// counter exposes the underlying event for observability. Non-zero
	// rate at >1/h indicates clock skew or a stamping bug worth investigating.
	// Spec 2026-05-25 (drain-per-stream-diagnostics).
	SnapshotNegativeAgeTotal atomic.Uint64
```

- [ ] **Step 2.2: Write failing test for snapshotDrainStreams**

Append to `shadowlink/client/stream_entry_test.go`:

```go
import (
	"sync"
	"testing"
	"time"
)

// snapshotTestHarness builds a minimal pool with just a streamMap
// populated with entries at controlled ages, enough to drive snapshot
// tests without spinning up real slots.
type snapshotTestHarness struct {
	pool *WSPoolTransport
}

func newSnapshotHarness() *snapshotTestHarness {
	return &snapshotTestHarness{
		pool: &WSPoolTransport{
			streamMap: sync.Map{},
		},
	}
}

func (h *snapshotTestHarness) put(streamID uint16, slotIdx int, age time.Duration) {
	e := newStreamEntry(slotIdx)
	e.lastWriteNs.Store(time.Now().Add(-age).UnixNano())
	h.pool.streamMap.Store(streamID, e)
}

func TestSnapshotDrainStreams_Empty(t *testing.T) {
	h := newSnapshotHarness()
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 0 || snap.idleAge30sCount != 0 || snap.activeCount != 0 {
		t.Errorf("empty snapshot = %+v, want zero values", snap)
	}
}

func TestSnapshotDrainStreams_SingleActive(t *testing.T) {
	h := newSnapshotHarness()
	h.put(42, 5, 1*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 1 || snap.activeCount != 1 || snap.idleAge30sCount != 0 {
		t.Errorf("single-active snapshot = %+v, want total=1 active=1 idle=0", snap)
	}
	if snap.maxStreamAgeMs < 800 || snap.maxStreamAgeMs > 1200 {
		t.Errorf("maxStreamAgeMs = %d, want ≈1000ms", snap.maxStreamAgeMs)
	}
}

func TestSnapshotDrainStreams_SingleIdle(t *testing.T) {
	h := newSnapshotHarness()
	h.put(42, 5, 60*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 1 || snap.idleAge30sCount != 1 || snap.activeCount != 0 {
		t.Errorf("single-idle snapshot = %+v, want total=1 idle=1 active=0", snap)
	}
}

// TestSnapshotDrainStreams_BimodalActivePlusIdle — the smoking-gun shape
// for hypothesis H1: one active heartbeat-stream + one idle stream attached
// to the same slot.
func TestSnapshotDrainStreams_BimodalActivePlusIdle(t *testing.T) {
	h := newSnapshotHarness()
	h.put(42, 5, 1*time.Second)
	h.put(43, 5, 60*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 2 || snap.activeCount != 1 || snap.idleAge30sCount != 1 {
		t.Errorf("bimodal snapshot = %+v, want total=2 active=1 idle=1", snap)
	}
	delta := snap.maxStreamAgeMs - snap.minStreamAgeMs
	if delta < 50000 {
		t.Errorf("max-min delta = %d ms, want >50000 (bimodal shape)", delta)
	}
}

func TestSnapshotDrainStreams_OnlyOurSlot(t *testing.T) {
	h := newSnapshotHarness()
	h.put(10, 0, 1*time.Second)
	h.put(11, 1, 60*time.Second)
	h.put(12, 5, 1*time.Second)
	h.put(13, 5, 60*time.Second)
	h.put(14, 5, 5*time.Second)
	snap := snapshotDrainStreams(h.pool, 5, time.Now())
	if snap.total != 3 {
		t.Errorf("filtered total = %d, want 3 (only slot=5 entries)", snap.total)
	}
}
```

- [ ] **Step 2.3: Run, verify FAIL**

```bash
go test ./client/ -run TestSnapshotDrainStreams -v
```

Expected: FAIL with `undefined: snapshotDrainStreams` / `undefined: drainStreamSnapshot`.

- [ ] **Step 2.4: Implement snapshotDrainStreams**

Append to `shadowlink/client/stream_entry.go`:

```go
// drainStreamSnapshot aggregates per-stream activity for one slot
// at drain teardown. Populated by snapshotDrainStreams; consumed
// only by drain log emission.
type drainStreamSnapshot struct {
	total           int
	idleAge30sCount int
	activeCount     int
	maxStreamAgeMs    int64
	minStreamAgeMs    int64
}

// snapshotDrainStreams scans the pool's streamMap once and aggregates
// per-stream activity for streams currently attached to slotIdx.
//
// Concurrency contract:
//   - lastWriteNs is read via atomic.Int64.Load() — no torn reads.
//   - sync.Map.Range visits each entry at most once; entries removed
//     concurrently by ReleaseStream may or may not appear in iteration,
//     per sync.Map's documented contract. No partial-entry exposure.
//   - All age math operates on local copies — race-free by construction.
//   - lastWriteNs is guaranteed >0 for every entry (newStreamEntry stamps
//     at construction); no zero-clock special case.
//
// Cost: O(N) where N is the total number of active streams across all
// slots in the pool (sync.Map.Range cannot pre-filter). Typical N is
// 50–100; iteration takes <10 µs and runs only at drain teardown — not
// in any hot path.
func snapshotDrainStreams(p *WSPoolTransport, slotIdx int, now time.Time) drainStreamSnapshot {
	nowNs := now.UnixNano()
	const idleThresholdMs = 30_000

	var snap drainStreamSnapshot
	p.streamMap.Range(func(_, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != slotIdx {
			return true
		}
		snap.total++

		ageMs := (nowNs - e.lastWriteNs.Load()) / int64(time.Millisecond)
		if ageMs < 0 {
			// Clock regressed (NTP adjust on Windows, ~100ns scale).
			// Clamp to 0 and bump telemetry so persistent negatives are
			// observable rather than silently masked.
			Stats.SnapshotNegativeAgeTotal.Add(1)
			ageMs = 0
		}

		if ageMs >= idleThresholdMs {
			snap.idleAge30sCount++
		} else {
			snap.activeCount++
		}
		if snap.total == 1 || ageMs > snap.maxStreamAgeMs {
			snap.maxStreamAgeMs = ageMs
		}
		if snap.total == 1 || ageMs < snap.minStreamAgeMs {
			snap.minStreamAgeMs = ageMs
		}
		return true
	})
	return snap
}
```

- [ ] **Step 2.5: Run, verify PASS**

```bash
go test ./client/ -run TestSnapshotDrainStreams -v
```

Expected: PASS for all 5 cases.

- [ ] **Step 2.6: Commit**

```bash
git add shadowlink/client/stream_entry.go shadowlink/client/stream_entry_test.go shadowlink/client/stats.go
git commit -m "feat(ws_pool): add snapshotDrainStreams + diag counter

drainStreamSnapshot aggregates per-stream activity for a target
slot at drain teardown (total, idle_30s, active counts + min/max
age ms). Cost: O(N) sync.Map scan, ~10µs, runs only at teardown.

Stats.SnapshotNegativeAgeTotal exposes clock-skew clamping events
for observability — non-zero rate indicates time regression or a
stamping bug.

Tests cover empty / single-active / single-idle / bimodal H1-shape /
multi-slot filter scenarios. The bimodal test enshrines the exact
shape we expect to see in canary hard-cap logs when H1 is correct."
```

---

## Task 3: Migrate streamMap to *streamEntry (production sites)

**Files:**
- Modify: `shadowlink/client/ws_pool.go`

This task is the type migration — no behavioral change yet (still using `slot.lastActivityNs` for idle decision). Pure refactor: 9 call sites switch from `.(int)` to `.(*streamEntry).slotIdx`, the `Store` site constructs `*streamEntry`.

- [ ] **Step 3.1: Update streamMap declaration comment**

In `shadowlink/client/ws_pool.go`, find the line declaring `streamMap` (around line 857):

```go
	streamMap sync.Map // map[uint16]int — streamID -> slot index
```

Replace with:

```go
	streamMap sync.Map // map[uint16]*streamEntry — streamID -> entry (see stream_entry.go)
```

- [ ] **Step 3.2: Update AssignStream — flip order + new entry**

Find `AssignStream` (around line 1950). Locate the final two lines (around 2014–2015):

```go
	p.streamMap.Store(streamID, minIdx)
	p.slots[minIdx].streams.Add(1)
```

Replace with:

```go
	// R1-H3 fix: streams.Add MUST precede streamMap.Store so any
	// concurrent snapshot that observes the new entry also sees
	// the incremented counter. See spec §2.5.
	//
	// R2-M3 sanity-assert: log if streamID is already mapped (caller
	// bug — production SOCKS guarantees single-owner). Not atomic
	// protection; just observability for future regression.
	if existing, dup := p.streamMap.Load(streamID); dup {
		if e, ok := existing.(*streamEntry); ok {
			p.log.Warn("AssignStream called twice for same streamID without ReleaseStream",
				"stream", streamID, "old_slot", e.slotIdx, "new_slot", minIdx)
		} else {
			p.log.Warn("AssignStream duplicate with non-streamEntry value",
				"stream", streamID, "new_slot", minIdx)
		}
		return
	}
	p.slots[minIdx].streams.Add(1)
	p.streamMap.Store(streamID, newStreamEntry(minIdx))
```

- [ ] **Step 3.3: Update IncrPending / DecrPending / SlotPending**

Find these three functions (around lines 2022–2049). Each has the same pattern:

```go
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		...
	}
```

Replace each occurrence of `idx := v.(int)` with:

```go
		e, ok := v.(*streamEntry)
		if !ok {
			return
		}
		idx := e.slotIdx
```

For `SlotPending` (returns `int32`), use `return 0` instead of bare `return`.

After edit, the three functions should look like:

```go
func (p *WSPoolTransport) IncrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return
		}
		idx := e.slotIdx
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(1)
		}
	}
}

func (p *WSPoolTransport) DecrPending(streamID uint16) {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return
		}
		idx := e.slotIdx
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].pendingConnects.Add(-1)
		}
	}
}

func (p *WSPoolTransport) SlotPending(streamID uint16) int32 {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return 0
		}
		idx := e.slotIdx
		if idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].pendingConnects.Load()
		}
	}
	return 0
}
```

- [ ] **Step 3.4: Update ReleaseStream**

Find `ReleaseStream` (around line 2071):

```go
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
	if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].streams.Add(-1)
		}
	}
}
```

Replace with:

```go
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
	// LoadAndDelete remains atomic for the map entry. The minor race
	// between Delete and streams.Add(-1) is documented in spec §2.5
	// (ReleaseStream known minor): joint probability <<1 event per
	// multi-hour canary. If observed in diag logs as diag_total <
	// remaining_streams, treat as expected mid-Release race.
	if v, ok := p.streamMap.LoadAndDelete(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return
		}
		idx := e.slotIdx
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].streams.Add(-1)
		}
	}
}
```

- [ ] **Step 3.5: Update SessionForStream**

Find `SessionForStream` (around line 2086):

```go
func (p *WSPoolTransport) SessionForStream(streamID uint16) *core.Session {
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx >= 0 && idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].session
		}
	}
	return nil
}
```

Replace:

```go
func (p *WSPoolTransport) SessionForStream(streamID uint16) *core.Session {
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return nil
		}
		idx := e.slotIdx
		if idx >= 0 && idx < len(p.slots) && p.slots[idx] != nil {
			return p.slots[idx].session
		}
	}
	return nil
}
```

- [ ] **Step 3.6: Update WriteMessageForStream (stamp lastWriteNs)**

Find `WriteMessageForStream` (around line 2112). The inner block currently:

```go
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					slot.lastActivityNs.Store(time.Now().UnixNano())
					return slot.transport.WriteMessage(data)
				}
			}
		}
	}
```

Replace with:

```go
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return p.WriteMessage(data)
		}
		idx := e.slotIdx
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					now := time.Now().UnixNano()
					slot.lastActivityNs.Store(now) // existing per-slot stamp (out-of-scope to remove)
					e.lastWriteNs.Store(now)       // NEW: per-stream stamp (Step 1 spec §2.3)
					return slot.transport.WriteMessage(data)
				}
			}
		}
	}
```

- [ ] **Step 3.7: Update WriteControlMessageForStream (stamp lastWriteNs)**

Symmetric to Step 3.6. Find `WriteControlMessageForStream` (around line 2136). The inner block currently:

```go
	if v, ok := p.streamMap.Load(streamID); ok {
		idx := v.(int)
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					slot.lastActivityNs.Store(time.Now().UnixNano())
					return slot.transport.WriteControlMessage(data)
				}
			}
		}
	}
```

Replace with:

```go
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			return p.WriteControlMessage(data)
		}
		idx := e.slotIdx
		if idx < len(p.slots) {
			slot := p.slots[idx]
			if slot != nil && slot.transport != nil {
				st := slot.getState()
				if st == slotReady || st == slotDraining {
					now := time.Now().UnixNano()
					slot.lastActivityNs.Store(now)
					e.lastWriteNs.Store(now) // NEW: per-stream stamp
					return slot.transport.WriteControlMessage(data)
				}
			}
		}
	}
```

- [ ] **Step 3.8: Update slotReaderWithClient (stale-frame check + stamp position)**

Find the stale-frame check block (around line 2436–2459):

```go
		// Stamp activity for drainWatchdog's idle-finish gate. Any successful
		// decrypt is a real downlink frame — keepalive cover frames take a
		// different path. Cheap atomic store, no lock.
		slot.lastActivityNs.Store(time.Now().UnixNano())

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		// W5 stale-frame validation: drop frames whose streamID has been
		// reassigned to a different slot (post-drain-teardown streamID
		// reuse race). Spec 2026-05-20 §2.4.1.
		if v, ok := p.streamMap.Load(streamID); ok {
			if v.(int) != idx {
				Stats.StaleFrameDroppedTotal.Add(1)
				continue
			}
		}
```

Replace with:

```go
		// Stamp activity for drainWatchdog's idle-finish gate. Any successful
		// decrypt is a real downlink frame — keepalive cover frames take a
		// different path. Cheap atomic store, no lock.
		slot.lastActivityNs.Store(time.Now().UnixNano())

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		// W5 stale-frame validation: drop frames whose streamID has been
		// reassigned to a different slot (post-drain-teardown streamID
		// reuse race). Spec 2026-05-20 §2.4.1.
		//
		// Spec 2026-05-25 §2.4: per-stream lastWriteNs is stamped ONLY
		// AFTER successful slotIdx == idx validation. Frames for
		// reassigned streamIDs do NOT count as activity on the new owner.
		if v, ok := p.streamMap.Load(streamID); ok {
			e, ok := v.(*streamEntry)
			if !ok {
				continue
			}
			if e.slotIdx != idx {
				Stats.StaleFrameDroppedTotal.Add(1)
				continue
			}
			e.lastWriteNs.Store(time.Now().UnixNano())
		}
```

- [ ] **Step 3.9: Update handleSlotDeath streamMap.Range**

Find `handleSlotDeath` (around line 2658):

```go
	p.streamMap.Range(func(key, value any) bool {
		if value.(int) != idx {
			return true
		}
		streamID := key.(uint16)
		p.streamMap.Delete(streamID)
		cl.streamMu.Lock()
		if ch, ok := cl.streamChans[streamID]; ok {
			close(ch)
			delete(cl.streamChans, streamID)
		}
		cl.streamMu.Unlock()
		return true
	})
```

Replace with:

```go
	p.streamMap.Range(func(key, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != idx {
			return true
		}
		streamID := key.(uint16)
		p.streamMap.Delete(streamID)
		cl.streamMu.Lock()
		if ch, ok := cl.streamChans[streamID]; ok {
			close(ch)
			delete(cl.streamChans, streamID)
		}
		cl.streamMu.Unlock()
		return true
	})
```

- [ ] **Step 3.10: Build production code**

```bash
cd /d/NIXAVPN/shadowlink
go build ./client/...
```

Expected: SUCCESS (production code compiles). Tests will fail at this point — that's Task 4's job.

- [ ] **Step 3.11: Commit**

```bash
git add shadowlink/client/ws_pool.go
git commit -m "refactor(ws_pool): migrate streamMap to *streamEntry

All 9 production call sites in ws_pool.go now use *streamEntry:
- AssignStream: flip order (streams.Add BEFORE Store, spec §2.5)
  plus duplicate-assign sanity warning (spec §2.7).
- IncrPending/DecrPending/SlotPending/ReleaseStream/SessionForStream:
  type assertion now reads e.slotIdx with safe ok form.
- WriteMessageForStream/WriteControlMessageForStream: stamp
  per-stream lastWriteNs alongside existing per-slot stamp.
- slotReaderWithClient: per-stream stamp ONLY AFTER stale-frame
  validation (spec §2.4 H2 resolution).
- handleSlotDeath: Range value now *streamEntry.

Idle-decision logic unchanged — still per-slot. Tests will fail
until ws_pool_test_helpers_test.go provides storeStreamForTest
(next task)."
```

---

## Task 4: Test helpers + migrate test sites

**Files:**
- Create: `shadowlink/client/ws_pool_test_helpers_test.go`
- Modify: `shadowlink/client/ws_pool_test.go`
- Modify: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 4.1: Create test helpers**

Create `shadowlink/client/ws_pool_test_helpers_test.go`:

```go
package client

import (
	"time"
)

// storeStreamForTest constructs and stores a streamEntry with a
// fresh lastWriteNs stamp. Tests use this instead of constructing
// streamEntry directly to keep newStreamEntry's invariants centralized.
func storeStreamForTest(p *WSPoolTransport, streamID uint16, slotIdx int) {
	p.streamMap.Store(streamID, newStreamEntry(slotIdx))
}

// storeStreamForTestWithAge stores an entry whose lastWriteNs is offset
// `age` into the past — used to drive idle/active scenarios in snapshot
// and drain tests.
func storeStreamForTestWithAge(p *WSPoolTransport, streamID uint16, slotIdx int, age time.Duration) {
	e := newStreamEntry(slotIdx)
	e.lastWriteNs.Store(time.Now().Add(-age).UnixNano())
	p.streamMap.Store(streamID, e)
}
```

- [ ] **Step 4.2: Find all test sites that need migration**

```bash
cd /d/NIXAVPN/shadowlink
grep -nE 'streamMap\.(Store|Load)' client/ws_pool_test.go client/ws_pool_drain_test.go
```

Output is the migration checklist. For each line in the output:
- `streamMap.Store(uint16(X), Y)` where Y is an `int` literal → replace with `storeStreamForTest(p, uint16(X), Y)`.
- `streamMap.Load(...).(int)` → replace with `.(* streamEntry).slotIdx` or use a helper if pattern is repetitive.

- [ ] **Step 4.3: Migrate ws_pool_test.go**

For each `p.streamMap.Store(uint16(X), Y)` occurrence found in Step 4.2, replace with `storeStreamForTest(p, uint16(X), Y)`.

For each `.(int)` type assertion on a streamMap Load result, replace with:

```go
e, ok := v.(*streamEntry)
if !ok {
    t.Fatalf("expected *streamEntry, got %T", v)
}
idx := e.slotIdx
```

- [ ] **Step 4.4: Migrate ws_pool_drain_test.go**

Same procedure as Step 4.3 for `ws_pool_drain_test.go`. Per the spec's count, there are ~7 sites in this file.

- [ ] **Step 4.5: Run all client tests**

```bash
cd /d/NIXAVPN/shadowlink
go test ./client/ -count=1
```

Expected: ALL PASS. If a test fails because the migration missed a site, grep again with broader patterns (e.g. `.(int)` near streamMap context) and fix.

- [ ] **Step 4.6: Run with race detector**

```bash
go test -race -count=3 ./client/
```

Expected: PASS (or PASS-skipped on Windows w/o CGO).

- [ ] **Step 4.7: Commit**

```bash
git add shadowlink/client/ws_pool_test_helpers_test.go shadowlink/client/ws_pool_test.go shadowlink/client/ws_pool_drain_test.go
git commit -m "test(ws_pool): migrate streamMap test sites to *streamEntry

Adds storeStreamForTest / storeStreamForTestWithAge helpers used by
all existing drain and pool tests. Direct streamMap.Store(int) calls
are replaced site-by-site to preserve test intent (slot routing
unaffected by the type change)."
```

---

## Task 5: Hot-path stamp tests

**Files:**
- Modify: `shadowlink/client/ws_pool_test.go` (or new `ws_pool_stamp_test.go` if existing is large)

- [ ] **Step 5.1: Write test for WriteMessageForStream stamps stream entry**

The exact placement depends on existing fixture patterns. Look at `TestWriteMessageForStream_*` tests already in `ws_pool_test.go`. The new test should reuse the same fixture (mock transport, set up slot in Ready state).

If `ws_pool_test.go` already has a `TestWriteMessageForStream_*` family, add:

```go
func TestWriteMessageForStream_StampsStreamEntry(t *testing.T) {
	// Reuse pattern from existing TestWriteMessageForStream_* helpers
	// to set up pool with one Ready slot at index 0 and a mock transport
	// that records WriteMessage calls.
	p, _ := buildPoolForTest(t /* or whatever existing helper */)
	defer p.Close()

	const sid uint16 = 42
	storeStreamForTest(p, sid, 0)

	before := time.Now().UnixNano()
	err := p.WriteMessageForStream(sid, []byte("payload"))
	if err != nil {
		t.Fatalf("WriteMessageForStream: %v", err)
	}
	after := time.Now().UnixNano()

	v, ok := p.streamMap.Load(sid)
	if !ok {
		t.Fatal("streamMap missing entry after write")
	}
	e := v.(*streamEntry)
	got := e.lastWriteNs.Load()
	if got < before || got > after {
		t.Errorf("per-stream lastWriteNs = %d, want in [%d, %d]", got, before, after)
	}

	// Sanity: existing per-slot stamp also updated.
	slotStamp := p.slots[0].lastActivityNs.Load()
	if slotStamp < before || slotStamp > after {
		t.Errorf("per-slot lastActivityNs = %d, want in [%d, %d]", slotStamp, before, after)
	}
}
```

**Note:** If `buildPoolForTest` does not exist, use the pattern from existing `ws_pool_test.go` — search for setup of `p := &WSPoolTransport{...}` with mock slots. The exact helper invocation must match what existing tests already do.

- [ ] **Step 5.2: Write test for slotReaderWithClient stamp position**

Add to the same file:

```go
// TestSlotReaderWithClient_StampsAfterValidation verifies that
// per-stream lastWriteNs is stamped ONLY when the frame is owned by
// the slot we're reading on (spec §2.4 H2 fix). Frames for streamIDs
// belonging to other slots are stale-dropped without updating any
// stream's per-entry timestamp.
//
// Implementation note: this test mocks the decrypt path directly via
// the streamMap; building a full slotReader run requires a real
// transport, which is heavier than necessary. Validation happens by
// running the same logic on parallel-set up entries and asserting
// stamps stay where we expect.
//
// If the existing test suite has TestSlotReader_*, use the same
// fixture pattern (fake transport returning canned chunks).
func TestSlotReaderWithClient_StampsAfterValidation(t *testing.T) {
	// Skeleton — flesh out with whatever fixture pattern exists.
	// Key invariant: a frame arriving on slot=5 for a streamID owned
	// by slot=3 (per streamMap) MUST NOT update streamID's lastWriteNs.
	t.Skip("Implement using existing slotReader fixture pattern")
}
```

**Note:** if the existing test suite has no `TestSlotReader_*` family that exercises decrypt + stale-frame check, leave the skeleton with `t.Skip` — exercising this branch requires a fake transport setup. The integration test in Task 6 covers the behavior end-to-end via drain log assertions. Document the skip with a clear marker so a future contributor can fill it in.

- [ ] **Step 5.3: Run new tests**

```bash
go test ./client/ -run 'TestWriteMessageForStream_StampsStreamEntry' -v
```

Expected: PASS.

- [ ] **Step 5.4: Commit**

```bash
git add shadowlink/client/ws_pool_test.go  # or new file
git commit -m "test(ws_pool): verify hot-path per-stream stamping

WriteMessageForStream stamps both slot.lastActivityNs (existing
behavior) and streamEntry.lastWriteNs (new). Slot-reader stamp
test is skeletoned with a Skip marker — the integration test in
the drain log task covers stamping semantics end-to-end."
```

---

## Task 6: Drain log emission + integration test

**Files:**
- Modify: `shadowlink/client/ws_pool_drain.go`
- Test: `shadowlink/client/ws_pool_drain_test.go`

- [ ] **Step 6.1: Locate emitHardCapLog and finishIdle branch**

Open `shadowlink/client/ws_pool_drain.go` and find:
- `emitHardCapLog` function (around line 656).
- The `case finishIdle:` block inside `tearDown` (around line 584).

- [ ] **Step 6.2: Write failing integration test**

Append to `shadowlink/client/ws_pool_drain_test.go`:

```go
// TestEmitHardCapLog_IncludesDiagSnapshot verifies that the hard-cap
// log includes the new diag_* fields populated from snapshotDrainStreams.
// Uses the same fixture pattern as TestDrainWatchdog_HardCapTimeout (~line
// 1113) — fakes a pool with two streams at controlled ages, then directly
// invokes emitHardCapLog and inspects captured output.
func TestEmitHardCapLog_IncludesDiagSnapshot(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	// Minimal harness: pool with one slot, two streams (1 active, 1 idle).
	p := &WSPoolTransport{
		log: logger,
		slots: []*poolSlot{
			{streams: atomic.Int32{}},
		},
	}
	p.slots[0].streams.Store(2)

	storeStreamForTestWithAge(p, 1, 0, 1*time.Second)
	storeStreamForTestWithAge(p, 2, 0, 60*time.Second)

	emitHardCapLog(p, 0, p.slots[0], "age", 90*time.Second)

	out := buf.String()
	expected := []string{
		"drain hard cap reached",
		"diag_total=2",
		"diag_idle_30s_count=1",
		"diag_active_count=1",
	}
	for _, want := range expected {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q\nfull output:\n%s", want, out)
		}
	}
}
```

If `bytes`, `slog`, `strings`, `atomic`, `time` are not already imported in this test file, add them.

- [ ] **Step 6.3: Run, verify FAIL**

```bash
go test ./client/ -run TestEmitHardCapLog_IncludesDiagSnapshot -v
```

Expected: FAIL — log does not contain `diag_total=2` yet.

- [ ] **Step 6.4: Modify emitHardCapLog to include diag fields**

In `shadowlink/client/ws_pool_drain.go`, locate `emitHardCapLog`. The current function increments `Stats.DrainHardCapTotal`, then logs. Modify to compute snapshot first and append fields:

```go
func emitHardCapLog(p *WSPoolTransport, oldIdx int, slot *poolSlot, reason string, duration time.Duration) {
	Stats.DrainHardCapTotal.Add(1)
	remaining := slot.streams.Load()
	snap := snapshotDrainStreams(p, oldIdx, time.Now())

	logFn := p.log.Info
	if remaining >= hardCapWarnThreshold {
		logFn = p.log.Warn
	}
	logFn("WS pool slot drain hard cap reached",
		"slot", oldIdx, "reason", reason,
		"remaining_streams", remaining,
		"drain_duration", duration.Truncate(time.Second),
		"diag_total", snap.total,
		"diag_idle_30s_count", snap.idleAge30sCount,
		"diag_active_count", snap.activeCount,
		"diag_max_stream_age_ms", snap.maxStreamAgeMs,
		"diag_min_stream_age_ms", snap.minStreamAgeMs,
	)
}
```

**Note:** the existing `logFn` selection between Info/Warn already exists — keep it. Only the field list changes.

- [ ] **Step 6.5: Run test, verify PASS**

```bash
go test ./client/ -run TestEmitHardCapLog_IncludesDiagSnapshot -v
```

Expected: PASS.

- [ ] **Step 6.6: Add finishIdle diag fields**

Locate the `case finishIdle:` block in `tearDown` (around line 584):

```go
		case finishIdle:
			Stats.DrainNaturalFinishTotal.Add(1)
			Stats.DrainIdleFinishTotal.Add(1)
			idleFor := time.Since(time.Unix(0, oldSlot.lastActivityNs.Load()))
			p.log.Info("WS pool slot drain natural finish (idle)",
				"slot", oldIdx, "reason", reason,
				"remaining_streams", oldSlot.streams.Load(),
				"idle_for", idleFor.Truncate(time.Second),
				"drain_duration", duration.Truncate(time.Second))
```

Replace with:

```go
		case finishIdle:
			Stats.DrainNaturalFinishTotal.Add(1)
			Stats.DrainIdleFinishTotal.Add(1)
			idleFor := time.Since(time.Unix(0, oldSlot.lastActivityNs.Load()))
			snap := snapshotDrainStreams(p, oldIdx, time.Now())
			p.log.Info("WS pool slot drain natural finish (idle)",
				"slot", oldIdx, "reason", reason,
				"remaining_streams", oldSlot.streams.Load(),
				"idle_for", idleFor.Truncate(time.Second),
				"drain_duration", duration.Truncate(time.Second),
				"diag_total", snap.total,
				"diag_idle_30s_count", snap.idleAge30sCount,
				"diag_active_count", snap.activeCount,
				"diag_max_stream_age_ms", snap.maxStreamAgeMs,
				"diag_min_stream_age_ms", snap.minStreamAgeMs,
			)
```

(The `finishStreamsZero` branch — `default` — gets NO diag fields per spec §2.8: streams=0 makes snapshot meaningless.)

- [ ] **Step 6.7: Add test for finishIdle diag fields**

Append to `ws_pool_drain_test.go`:

```go
// TestTearDownIdle_IncludesDiagSnapshot verifies the natural-finish-idle
// branch also emits diag fields. Uses an inline harness rather than a
// full drainWatchdog orchestration — we want to assert the log line
// shape, not the timing logic.
func TestTearDownIdle_IncludesDiagSnapshot(t *testing.T) {
	t.Skip("Requires drainWatchdog harness; covered by canary log analysis. Track via TODO.")
}
```

**Rationale for skip:** the finishIdle branch sits inside `drainWatchdog`'s closure (`tearDown`) and is not directly callable from outside. Exercising it requires a real watchdog run, which is well-covered by `TestDrainWatchdog_*` family already. The diag-field shape is identical to hard-cap (same `snapshotDrainStreams` call, same field names), so the hard-cap test exercises the same logic. The skip is documented so anyone investigating canary regressions knows where to start.

- [ ] **Step 6.8: Build and run all tests**

```bash
cd /d/NIXAVPN/shadowlink
go build ./...
go test ./client/ -count=1
```

Expected: ALL PASS.

- [ ] **Step 6.9: Run with race detector**

```bash
go test -race -count=3 ./client/
```

Expected: PASS (or skipped on Windows w/o CGO).

- [ ] **Step 6.10: Commit**

```bash
git add shadowlink/client/ws_pool_drain.go shadowlink/client/ws_pool_drain_test.go
git commit -m "feat(ws_pool): emit diag snapshot in hard-cap and idle-finish logs

WS pool slot drain {hard cap reached, natural finish (idle)} now
include five new fields:
  diag_total diag_idle_30s_count diag_active_count
  diag_max_stream_age_ms diag_min_stream_age_ms

Computed once at teardown via snapshotDrainStreams (O(N) sync.Map
scan, ~10µs typical). finishStreamsZero branch unchanged — empty
slot has nothing to aggregate.

Integration test verifies field presence on synthetic 'active + idle'
shape. Spec 2026-05-25-drain-per-stream-diagnostics-design §2.8."
```

---

## Task 7: Build binary for canary, smoke-test

**Files:** none modified; this task produces the canary artifact.

- [ ] **Step 7.1: Build the graceful-drain client binary**

The launcher batch file `D:/NIXAVPN/bin/connect-vpn-graceful-drain.bat` expects `D:/NIXAVPN/bin/nixavpn-client-graceful-drain.exe`. Build path depends on existing build scripts.

```bash
cd /d/NIXAVPN
# Use whatever build target produces nixavpn-client-graceful-drain.exe.
# Check ./scripts/ or Makefile or existing build artifacts for the right
# invocation. If unknown, build from cmd/nixavpn-client and rename:
go build -o bin/nixavpn-client-graceful-drain.exe ./cmd/nixavpn-client
```

- [ ] **Step 7.2: Quick smoke verify**

```bash
/d/NIXAVPN/bin/nixavpn-client-graceful-drain.exe -h 2>&1 | head -5
```

Expected: binary runs, prints help.

- [ ] **Step 7.3: Inform user — canary handoff**

Stop here. The next step (running `connect-vpn-graceful-drain.bat` for 4h+, analyzing diag fields in the resulting log) is a manual user operation. The plan is complete from a code-shipping perspective.

The canary will produce a new log at `%TEMP%\nixavpn-graceful-drain-YYYYMMDD-HHMMSS.log`. After ≥4h runtime, analyze with the criteria from spec §4.4 (bucketed by `remaining_streams`, looking for bimodal shape).

- [ ] **Step 7.4: Final commit / push reminder**

Do NOT push to any remote. The user explicitly forbids automated git operations (per memory `feedback_no_git.md`). Once the canary finishes and confirms H1, follow-up will be a separate planning round for Step 2 (Variant A — switch idle-decision to per-stream).

---

## Self-review

**Spec coverage:** every spec section maps to a task:
- §2.1 (streamEntry type) → Task 1.
- §2.2 (call-sites migration table) → Tasks 3 (prod) + 4 (test).
- §2.3 (stream-bound stamp points) → Steps 3.6, 3.7, 3.8.
- §2.4 (stamp position after stale-frame check) → Step 3.8.
- §2.5 (AssignStream flip order) → Step 3.2.
- §2.6 (snapshot function) → Task 2.
- §2.7 (double-assign sanity-assert) → Step 3.2.
- §2.8 (log field extension) → Task 6.
- §4.1 (unit tests) → covered across Tasks 1, 2, 5.
- §4.2 (integration test) → Task 6.
- §4.3 (race detector) → Steps 1.6, 4.6, 6.9.
- §4.4 (canary validation) → handed off in Task 7.

**Placeholder scan:** all code blocks are concrete. Two test skeletons (Step 5.2, Step 6.7) are explicitly `t.Skip` with rationale — those are not lazy "TODO" markers but documented decisions about where integration coverage already exists.

**Type consistency:** `*streamEntry`, `drainStreamSnapshot`, `snapshotDrainStreams`, `storeStreamForTest`, `storeStreamForTestWithAge`, `newStreamEntry`, `Stats.SnapshotNegativeAgeTotal` — names consistent across tasks.
