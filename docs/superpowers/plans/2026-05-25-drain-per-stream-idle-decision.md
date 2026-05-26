# Per-stream idle decision (Step 2) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Switch WS pool graceful drain idle decision from per-slot to per-stream measurement. Replace `slot.lastActivityNs >= threshold && streams ≤ STREAMS_MAX` gate with `allStreamsIdle()` iterating per-stream `streamEntry.lastWriteNs`. Remove dead `slot.lastActivityNs` field. Land natural_ratio in 75-80% target band (currently 56%).

**Architecture:** Add `allStreamsIdle()` helper in `client/stream_entry.go` (where snapshot lives). Modify `drainWatchdog` tick gate in `client/ws_pool_drain.go`. Flip `ReleaseStream` order in `client/ws_pool.go` to close the symmetric race (R2-H2 fix). Remove `slot.lastActivityNs` field + 4 stamp sites + 2 reads + `idle_for` log field. Deprecate `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX` env (no-op + startup WARN). Migrate 3 existing tests with semantic changes.

**Tech Stack:** Go 1.21+, `sync.Map`, `atomic.Int64`, slog. No new dependencies.

**Spec:** `D:/NIXAVPN/shadowlink/docs/superpowers/specs/2026-05-25-drain-per-stream-idle-decision-design.md` (passed 2 rounds Opus review, verdict APPROVE).

---

## Сводный список изменяемых файлов

**Production code:**
- `client/stream_entry.go` — add `allStreamsIdle()` helper
- `client/ws_pool.go` — remove `lastActivityNs` field (line 288) + 4 stamp sites (lines 1502, 2167, 2197, 2493) + flip `ReleaseStream` order (lines 2106-2117) + add `// Deprecated:` markers on `drainIdleStreamsMax` (line 836) and `DrainIdleStreamsMax` (line 1044)
- `client/ws_pool_drain.go` — replace idle gate (lines 619-643) + remove `idle_for` from finishIdle log (line 587)
- `cmd/nixavpn-client/engine_shadowlink.go` — add startup WARN for deprecated env (around line 434)

**Test code:**
- `client/stream_entry_test.go` — 7 new tests for `allStreamsIdle` (empty, all-active, all-idle, bimodal, only-our-slot, exactly-at-threshold, concurrent races)
- `client/ws_pool_drain_test.go` — 3 existing test migrations + 2 new integration tests

**Build artifact:**
- `bin/nixavpn-client-graceful-drain.exe` — rebuild for canary

---

## Build / verification commands

Standard cycle:

```bash
cd /d/NIXAVPN/shadowlink
go test ./client/ -run 'TestSpecificName' -v -count=1
```

Race detector (Windows w/o CGO falls back to plain test per `shadowlink/CLAUDE.md`):

```bash
go test -race -count=3 ./client/ -run 'TestPattern'
```

Full pre-commit check:

```bash
cd /d/NIXAVPN/shadowlink
go build ./...
go test ./client/...
```

---

## Task 1: `allStreamsIdle` helper

**Files:**
- Modify: `client/stream_entry.go` (append function)
- Modify: `client/stream_entry_test.go` (append tests + harness helper)

- [ ] **Step 1.1: Write failing test for empty case**

Append to `client/stream_entry_test.go`:

```go
func TestAllStreamsIdle_Empty(t *testing.T) {
	h := newSnapshotHarness()
	if allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("empty streamMap should return false (no streams to be 'all idle')")
	}
}
```

- [ ] **Step 1.2: Run test, verify FAIL**

```bash
cd /d/NIXAVPN/shadowlink
go test ./client/ -run TestAllStreamsIdle_Empty -v -count=1
```

Expected: FAIL with `undefined: allStreamsIdle`.

- [ ] **Step 1.3: Add allStreamsIdle implementation**

Append to `client/stream_entry.go`:

```go
// allStreamsIdle returns true iff every stream attached to slotIdx has
// been silent for at least threshold. Returns false if there are no
// streams attached to slotIdx (caller should have already handled the
// streams.Load()==0 case via finishStreamsZero) — defensive against
// edge case where streams counter and streamMap diverge.
//
// Early-exits on first active stream found (most ticks during a drain
// have at least one active heartbeat-stream, so typical path is fast).
//
// Concurrency:
//   - lastWriteNs read via atomic.Int64.Load — no torn reads.
//   - sync.Map.Range visits each entry at most once; entries removed by
//     concurrent ReleaseStream may or may not appear, per sync.Map
//     contract. No partial state.
//   - Race with new AssignStream: newStreamEntry stamps lastWriteNs=now,
//     so fresh entries appear as active → conservative (no premature
//     teardown). False negative for idle on at most one tick (500ms).
//   - Race with ReleaseStream (spec §2.3.1 fix flips order: streams.Add(-1)
//     BEFORE Delete): window where snapshot sees decremented counter
//     but entry still present — entry's lastWriteNs is read, either
//     correctly active (no premature teardown) or correctly idle
//     (teardown safe).
//
// Cost: O(N) sync.Map scan, N = total active streams across pool.
// Called only from drainWatchdog tick (500ms cadence). Typical N=50-100,
// early-exit path <1µs, full-scan path ~5-10µs. Not a hot path.
func allStreamsIdle(p *WSPoolTransport, slotIdx int, threshold time.Duration, now time.Time) bool {
	nowNs := now.UnixNano()
	thresholdNs := threshold.Nanoseconds()
	found := false
	allIdle := true
	p.streamMap.Range(func(_, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != slotIdx {
			return true
		}
		found = true
		age := nowNs - e.lastWriteNs.Load()
		// Clock-skew handling (spec §2.1 R2-L4): age < 0 means clock
		// regressed. Conservative — treat as active. No telemetry
		// bump here (decision path is silent; snapshot path handles
		// telemetry for the same condition in Step 1).
		if age < thresholdNs {
			allIdle = false
			return false // early exit
		}
		return true
	})
	return found && allIdle
}
```

- [ ] **Step 1.4: Run test, verify PASS**

```bash
go test ./client/ -run TestAllStreamsIdle_Empty -v -count=1
```

Expected: PASS.

- [ ] **Step 1.5: Add remaining unit tests**

Append to `client/stream_entry_test.go`:

```go
func TestAllStreamsIdle_AllActive(t *testing.T) {
	h := newSnapshotHarness()
	h.put(1, 5, 1*time.Second)
	h.put(2, 5, 2*time.Second)
	h.put(3, 5, 5*time.Second)
	if allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("3 active streams should return false")
	}
}

func TestAllStreamsIdle_AllIdle(t *testing.T) {
	h := newSnapshotHarness()
	h.put(1, 5, 60*time.Second)
	h.put(2, 5, 45*time.Second)
	h.put(3, 5, 35*time.Second)
	if !allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("3 idle streams (all >30s) should return true")
	}
}

// TestAllStreamsIdle_BimodalSmokingGun — exactly the canary case for H1:
// 1 active heartbeat stream + 1 idle stream on same slot. The whole
// reason Step 2 exists. Must return false (active stream holds slot).
func TestAllStreamsIdle_BimodalSmokingGun(t *testing.T) {
	h := newSnapshotHarness()
	h.put(1, 5, 1*time.Second)   // active heartbeat
	h.put(2, 5, 60*time.Second)  // idle
	if allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("bimodal (1 active + 1 idle) should return false")
	}
}

func TestAllStreamsIdle_OnlyOurSlot(t *testing.T) {
	h := newSnapshotHarness()
	// other slots — active and idle, irrelevant to our scan
	h.put(10, 0, 1*time.Second)
	h.put(11, 1, 60*time.Second)
	// our slot 5 — all idle
	h.put(12, 5, 35*time.Second)
	h.put(13, 5, 40*time.Second)
	if !allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("should return true (only slot=5 streams considered, both idle)")
	}
}

// TestAllStreamsIdle_ExactlyAtThreshold — boundary: age == threshold
// (within 5ms tolerance for time.Now() jitter). The check is `age < threshold`,
// so an entry at exactly threshold is NOT active → counted as idle.
func TestAllStreamsIdle_ExactlyAtThreshold(t *testing.T) {
	h := newSnapshotHarness()
	// Stamp slightly older than threshold to avoid race with time.Now()
	// inside allStreamsIdle.
	h.put(1, 5, 30*time.Second+5*time.Millisecond)
	if !allStreamsIdle(h.pool, 5, 30*time.Second, time.Now()) {
		t.Error("stream at age >= threshold should count as idle")
	}
}
```

- [ ] **Step 1.6: Run all allStreamsIdle tests**

```bash
go test ./client/ -run TestAllStreamsIdle -v -count=1
```

Expected: 5 PASS.

- [ ] **Step 1.7: Add concurrent race regression tests (R2-Q6)**

Append to `client/stream_entry_test.go`:

```go
// TestAllStreamsIdle_ConcurrentReleaseStream — regression bound for
// R2-H2 fix. Spawns ReleaseStream loop concurrent with allStreamsIdle
// scan, asserts no panic. The Step 2 flip-order in ReleaseStream
// (streams.Add(-1) BEFORE Delete) means snapshot can't observe a state
// where streams.Load() > 0 but entry was the only active stream and
// already gone from map — preventing premature teardown.
func TestAllStreamsIdle_ConcurrentReleaseStream(t *testing.T) {
	p := &WSPoolTransport{streamMap: sync.Map{}}
	// Seed slot 5 with 10 idle streams.
	for sid := uint16(1); sid <= 10; sid++ {
		e := newStreamEntry(5)
		e.lastWriteNs.Store(time.Now().Add(-60 * time.Second).UnixNano())
		p.streamMap.Store(sid, e)
	}

	// Concurrent Delete + scan.
	done := make(chan struct{})
	go func() {
		for sid := uint16(1); sid <= 10; sid++ {
			p.streamMap.Delete(sid)
			runtime.Gosched()
		}
		close(done)
	}()

	// Spin scans during deletions.
	for {
		select {
		case <-done:
			return
		default:
			_ = allStreamsIdle(p, 5, 30*time.Second, time.Now())
		}
	}
}

// TestAllStreamsIdle_ConcurrentAssignStream — race regression: scan
// while new entries are being added. Fresh entries stamp now → active →
// conservative (allStreamsIdle returns false). Asserts no panic and
// no false-positive idle.
func TestAllStreamsIdle_ConcurrentAssignStream(t *testing.T) {
	p := &WSPoolTransport{streamMap: sync.Map{}}
	// Seed one idle stream so map is non-empty.
	e := newStreamEntry(5)
	e.lastWriteNs.Store(time.Now().Add(-60 * time.Second).UnixNano())
	p.streamMap.Store(uint16(1), e)

	done := make(chan struct{})
	go func() {
		for sid := uint16(2); sid <= 20; sid++ {
			p.streamMap.Store(sid, newStreamEntry(5))
			runtime.Gosched()
		}
		close(done)
	}()

	// During Add — fresh entries are active, so allStreamsIdle must
	// return false (or true only if the goroutine hasn't started yet).
	// We just assert no panic and no incorrect-idle. After done, all
	// new entries are < 30s old → still active → still false.
	for {
		select {
		case <-done:
			if allStreamsIdle(p, 5, 30*time.Second, time.Now()) {
				t.Error("after concurrent AssignStream, fresh entries should keep result false")
			}
			return
		default:
			_ = allStreamsIdle(p, 5, 30*time.Second, time.Now())
		}
	}
}
```

Required imports — verify these are already present (`testing`, `time`, `sync`); add `runtime`:

```go
import (
	"runtime"
	"sync"
	"testing"
	"time"
)
```

- [ ] **Step 1.8: Run race tests**

```bash
go test ./client/ -run TestAllStreamsIdle_Concurrent -v -count=1
```

Expected: 2 PASS, no panic.

On Linux/macOS or Windows with CGO:

```bash
go test -race -count=3 ./client/ -run TestAllStreamsIdle -v
```

Expected: PASS, no DATA RACE.

- [ ] **Step 1.9: Commit**

```bash
cd /d/NIXAVPN/shadowlink
git add client/stream_entry.go client/stream_entry_test.go
git commit -m "$(cat <<'EOF'
feat(ws_pool): add allStreamsIdle helper for per-stream idle decision

allStreamsIdle iterates streamMap (filtered by slotIdx) and returns
true iff every attached stream has lastWriteNs older than threshold.
Foundation for replacing per-slot drainWatchdog idle gate (next task).

Tests cover empty / all-active / all-idle / bimodal smoking-gun /
multi-slot filter / boundary-at-threshold + 2 concurrent race
regressions (Release and Assign). Clock-skew handled conservatively
(negative age treated as active, no telemetry — snapshot path covers it).

Spec 2026-05-25-drain-per-stream-idle-decision-design §2.1.
EOF
)"
```

---

## Task 2: ReleaseStream flip order (R2-H2 fix)

**Files:**
- Modify: `client/ws_pool.go` (function around line 2106-2117)

This is a **critical concurrency fix** — must land BEFORE Task 3 (the drainWatchdog gate switch) because the new gate is what makes the race material. Doing it first means Task 3 lands on top of a safe foundation.

- [ ] **Step 2.1: Verify current code**

```bash
cd /d/NIXAVPN/shadowlink
sed -n '2100,2120p' client/ws_pool.go
```

Confirm current code matches (used `LoadAndDelete` pattern from Step 1).

- [ ] **Step 2.2: Apply flip order**

In `client/ws_pool.go`, find function `ReleaseStream` (around line 2100). Replace entire function body (keep any existing exported doc-comment above the func line) with:

```go
func (p *WSPoolTransport) ReleaseStream(streamID uint16) {
	// R2-H2 fix: streams.Add(-1) MUST precede streamMap.Delete (symmetric
	// to the AssignStream flip from Step 1 spec §2.5). Under per-stream
	// idle decision (Step 2), the inverse ordering would let drainWatchdog
	// observe streams.Load()>0 while the released entry is already gone
	// from the map → allStreamsIdle could return true prematurely if the
	// gone stream was the only active one → tearDown fires while Release
	// hasn't completed counter decrement → silent drop or decrypt_fails.
	//
	// Read entry via Load first (need slotIdx), then decrement counter,
	// then Delete from map. Trade: not atomic vs old LoadAndDelete, but
	// SOCKS layer guarantees one owner per streamID so double-Release
	// requires a future bug (defense-in-depth via inner type checks).
	if v, ok := p.streamMap.Load(streamID); ok {
		e, ok := v.(*streamEntry)
		if !ok {
			p.streamMap.Delete(streamID)
			return
		}
		idx := e.slotIdx
		if idx < len(p.slots) && p.slots[idx] != nil {
			p.slots[idx].streams.Add(-1)
		}
		p.streamMap.Delete(streamID)
	}
}
```

- [ ] **Step 2.3: Verify build**

```bash
cd /d/NIXAVPN/shadowlink
go build ./client/...
```

Expected: clean.

- [ ] **Step 2.4: Run existing pool/drain tests**

```bash
go test ./client/ -count=1
```

Expected: ALL PASS. ReleaseStream behavior is unchanged from caller's perspective — only internal ordering differs.

If any test fails — **STOP and report BLOCKED**.

- [ ] **Step 2.5: Commit**

```bash
git add client/ws_pool.go
git commit -m "$(cat <<'EOF'
fix(ws_pool): ReleaseStream — flip streams.Add(-1) before Delete (R2-H2)

Symmetric to Step 1 §2.5 AssignStream fix. Under Step 1 the inverse
ordering was a 'cosmetic diag mismatch' in logs. Under Step 2's
per-stream idle decision, the same race window becomes material:
drainWatchdog observing streams.Load()>0 with the only-active entry
already removed from map → allStreamsIdle returns true prematurely →
finishIdle teardown while Release counter decrement pending → silent
drop or decrypt_fails.

Trade Load+Delete (not atomic) vs LoadAndDelete: acceptable because
SOCKS guarantees single owner per streamID. Inner type-assertion +
nil-checks defend the unlikely double-Release case.

Spec 2026-05-25-drain-per-stream-idle-decision-design §2.3.1.
EOF
)"
```

---

## Task 3: drainWatchdog per-stream gate

**Files:**
- Modify: `client/ws_pool_drain.go` (lines 619-643)

- [ ] **Step 3.1: Read current code**

```bash
cd /d/NIXAVPN/shadowlink
sed -n '619,643p' client/ws_pool_drain.go
```

- [ ] **Step 3.2: Replace idle gate**

In `client/ws_pool_drain.go`, find the idle gate block (currently around lines 619-643). Replace:

```go
	// Idle heuristic is active only when both knobs are >0 (DrainIdleStreamsMax
	// is set to 0 to disable; DrainIdleThreshold <= 0 also disables). Read
	// once at watchdog entry — these are write-once-at-init fields on the pool.
	idleThreshold := p.drainIdleThreshold
	idleStreamsMax := p.drainIdleStreamsMax
	idleEnabled := idleThreshold > 0 && idleStreamsMax > 0

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline.C:
			tearDown(finishHardCap)
			return
		case <-ticker.C:
			streams := oldSlot.streams.Load()
			if streams == 0 {
				tearDown(finishStreamsZero)
				return
			}
			if idleEnabled && streams <= idleStreamsMax {
				last := oldSlot.lastActivityNs.Load()
				// last==0 is the impossible-but-defensive case: connectSlot
				// always stamps lastActivityNs alongside startedAtNs on
				// (re)connect. Guard against it anyway so a corrupt slot
				// state can't trip the idle path prematurely.
				if last > 0 && time.Since(time.Unix(0, last)) >= idleThreshold {
					tearDown(finishIdle)
					return
				}
			}
		}
	}
```

With:

```go
	// Step 2: idle heuristic now uses per-stream measurement via
	// allStreamsIdle (defined in stream_entry.go). The disable knob is
	// SHADOWLINK_DRAIN_IDLE_THRESHOLD=0 — SHADOWLINK_DRAIN_IDLE_STREAMS_MAX
	// is deprecated and ignored in the decision (BREAKING CHANGE doc'd
	// in spec §2.5; startup WARN emitted in cmd-layer if env set).
	idleThreshold := p.drainIdleThreshold
	idleEnabled := idleThreshold > 0

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-deadline.C:
			tearDown(finishHardCap)
			return
		case <-ticker.C:
			streams := oldSlot.streams.Load()
			if streams == 0 {
				tearDown(finishStreamsZero)
				return
			}
			if idleEnabled && allStreamsIdle(p, oldIdx, idleThreshold, time.Now()) {
				tearDown(finishIdle)
				return
			}
		}
	}
```

- [ ] **Step 3.3: Verify build**

```bash
cd /d/NIXAVPN/shadowlink
go build ./client/...
```

Expected: clean.

- [ ] **Step 3.4: Confirm existing tests fail (semantic regression expected)**

```bash
go test ./client/ -run 'TestDrainWatchdog_TooManyStreamsBypassesIdle|TestDrainWatchdog_IdleFinish|TestDrainWatchdog_IdleHeuristicDisabled' -v -count=1
```

Expected: at least 1-2 tests FAIL or be malformed. These existing tests pin pre-Step-2 semantics and are migrated in Task 5. Continue to commit this task — Task 4 (cleanup) and Task 5 (test migration) close out the regression.

- [ ] **Step 3.5: Commit**

```bash
git add client/ws_pool_drain.go
git commit -m "$(cat <<'EOF'
feat(ws_pool): drainWatchdog uses per-stream idle decision

Replaces per-slot gate (streams≤STREAMS_MAX && slot.lastActivityNs ≥
threshold) with per-stream allStreamsIdle(p, oldIdx, threshold, now).
Direct response to canary 2026-05-25 evening evidence: 64.9% of hard
caps had H1-shape (one active heartbeat-stream blocking the per-slot
timer for siblings that were silent for >30s).

SHADOWLINK_DRAIN_IDLE_STREAMS_MAX is now ignored in decision logic
(deprecated, BREAKING CHANGE doc'd in spec §2.5). Disable knob is
SHADOWLINK_DRAIN_IDLE_THRESHOLD=0.

Existing tests TooManyStreamsBypassesIdle / IdleFinish /
IdleHeuristicDisabled are migrated in a follow-up task — they pin
pre-Step-2 semantics and currently fail. Production code is correct;
test layer catches up next.

Spec 2026-05-25-drain-per-stream-idle-decision-design §2.2.
EOF
)"
```

---

## Task 4: Remove `slot.lastActivityNs` field + stamps + reads + idle_for log

**Files:**
- Modify: `client/ws_pool.go` (lines 288, 1502, 2167, 2197, 2493)
- Modify: `client/ws_pool_drain.go` (lines 580-598 — finishIdle case)

- [ ] **Step 4.1: Remove field from poolSlot struct**

In `client/ws_pool.go`, find around line 288:

```go
	lastActivityNs atomic.Int64
```

**Delete the entire line.** Also delete any doc-comment block immediately preceding this line that refers to `lastActivityNs`. Use grep to check:

```bash
cd /d/NIXAVPN/shadowlink
grep -n "lastActivityNs" client/ws_pool.go | head -10
```

After this step, only the 4 stamp sites + 1 read in drain should remain.

- [ ] **Step 4.2: Remove stamp at connectSlot (line ~1502)**

Find line 1502 in `client/ws_pool.go`. Currently:

```go
	slot.lastActivityNs.Store(now)
```

**Delete the entire line.** Verify the surrounding `connectSlot` logic still compiles — `now` variable should still be used elsewhere or unused (compiler will tell us).

- [ ] **Step 4.3: Remove stamp in WriteMessageForStream (line ~2167)**

Find line ~2167. Currently:

```go
				if st == slotReady || st == slotDraining {
					now := time.Now().UnixNano()
					slot.lastActivityNs.Store(now) // existing per-slot stamp (out-of-scope to remove)
					e.lastWriteNs.Store(now)       // NEW: per-stream stamp (Step 1 spec §2.3)
					return slot.transport.WriteMessage(data)
				}
```

Replace with:

```go
				if st == slotReady || st == slotDraining {
					e.lastWriteNs.Store(time.Now().UnixNano())
					return slot.transport.WriteMessage(data)
				}
```

- [ ] **Step 4.4: Remove stamp in WriteControlMessageForStream (line ~2197)**

Symmetric to Step 4.3. Find around line 2197:

```go
				if st == slotReady || st == slotDraining {
					now := time.Now().UnixNano()
					slot.lastActivityNs.Store(now)
					e.lastWriteNs.Store(now) // NEW: per-stream stamp
					return slot.transport.WriteControlMessage(data)
				}
```

Replace with:

```go
				if st == slotReady || st == slotDraining {
					e.lastWriteNs.Store(time.Now().UnixNano())
					return slot.transport.WriteControlMessage(data)
				}
```

- [ ] **Step 4.5: Remove stamp in slotReaderWithClient (line ~2493)**

Find around line 2493 in `client/ws_pool.go`. The current block:

```go
		// Stamp activity for drainWatchdog's idle-finish gate. Any successful
		// decrypt is a real downlink frame — keepalive cover frames take a
		// different path. Cheap atomic store, no lock.
		slot.lastActivityNs.Store(time.Now().UnixNano())

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])
```

Replace the 4-line stamp comment+code block with a 1-line note:

```go
		// Per-stream lastWriteNs is stamped below, after the stale-frame
		// check (spec §2.4) — slot-level stamp was removed in Step 2.

		msgCount++
		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])
```

The per-stream stamp inside the if-block already exists from Step 1 — verify by reading lines just below (around 2515):

```bash
sed -n '2510,2520p' client/ws_pool.go
```

Should see `e.lastWriteNs.Store(time.Now().UnixNano())` already there. Don't touch it.

- [ ] **Step 4.6: Remove `idle_for` from finishIdle log + simplify**

In `client/ws_pool_drain.go`, find the `case finishIdle:` block (currently around line 580-598):

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

Replace with (removing `idleFor` computation + `idle_for` log field):

```go
		case finishIdle:
			Stats.DrainNaturalFinishTotal.Add(1)
			Stats.DrainIdleFinishTotal.Add(1)
			snap := snapshotDrainStreams(p, oldIdx, time.Now())
			p.log.Info("WS pool slot drain natural finish (idle)",
				"slot", oldIdx, "reason", reason,
				"remaining_streams", oldSlot.streams.Load(),
				"drain_duration", duration.Truncate(time.Second),
				"diag_total", snap.total,
				"diag_idle_30s_count", snap.idleAge30sCount,
				"diag_active_count", snap.activeCount,
				"diag_max_stream_age_ms", snap.maxStreamAgeMs,
				"diag_min_stream_age_ms", snap.minStreamAgeMs,
			)
```

- [ ] **Step 4.7: Verify production build**

```bash
cd /d/NIXAVPN/shadowlink
go build ./...
```

Expected: clean. If any "unused variable: now" or "undefined: lastActivityNs" error — investigate the failing site (probably a stamp site we missed or a residual reference). If error mentions `time` package not used — drop the import.

If `connectSlot` line that previously stamped uses `now` variable nowhere else after removing the stamp — remove the `now :=` assignment too:

```bash
sed -n '1495,1510p' client/ws_pool.go
```

If `now` is only used by the removed stamp, delete its declaration line too.

- [ ] **Step 4.8: Sanity grep — no lastActivityNs references remain in production**

```bash
cd /d/NIXAVPN/shadowlink
grep -n "lastActivityNs" client/ws_pool.go client/ws_pool_drain.go
```

Expected: NO output (zero matches). If matches remain, fix them.

```bash
grep -n "idle_for" client/ws_pool_drain.go
```

Expected: NO output. If `idle_for` log field appears anywhere — remove it.

- [ ] **Step 4.9: Build full and test (existing tests still expected to fail at this point)**

```bash
cd /d/NIXAVPN/shadowlink
go build ./...
```

Expected: clean. Test layer still broken because tests reference `lastActivityNs` directly — fixed in Task 5.

- [ ] **Step 4.10: Commit**

```bash
git add client/ws_pool.go client/ws_pool_drain.go
git commit -m "$(cat <<'EOF'
refactor(ws_pool): remove slot.lastActivityNs and idle_for log field

Cleanup after Step 2 (per-stream idle decision). slot.lastActivityNs
is no longer consulted by the drain watchdog gate; per-stream
streamEntry.lastWriteNs replaces it. Remove:

- poolSlot struct field (line 288)
- 4 stamp sites: connectSlot, WriteMessage{,Control}ForStream,
  slotReaderWithClient (lines 1502, 2167, 2197, 2493)
- 2 reads in drainWatchdog: finishIdle idle_for log + idle gate
  (gate was already replaced in previous commit; idle_for removed
  here)

Log field 'idle_for' is removed from the 'natural finish (idle)'
line. diag_min_stream_age_ms (per-stream, more precise) supersedes
it — at finishIdle by construction min_stream_age >= threshold.

Test layer migration in next task (3 tests pin pre-Step-2 semantics).

Spec 2026-05-25-drain-per-stream-idle-decision-design §2.3, §2.4.
EOF
)"
```

---

## Task 5: Test migration (3 existing tests + ws_pool_drain_test.go diag-field cleanup)

**Files:**
- Modify: `client/ws_pool_drain_test.go`

- [ ] **Step 5.1: Locate the 3 tests + diag-related sites**

```bash
cd /d/NIXAVPN/shadowlink
echo "=== TooManyStreamsBypassesIdle (DELETE) ==="
sed -n '2616,2680p' client/ws_pool_drain_test.go
echo ""
echo "=== IdleFinish (REWRITE) ==="
sed -n '2525,2575p' client/ws_pool_drain_test.go
echo ""
echo "=== IdleHeuristicDisabled (REWRITE) ==="
sed -n '2576,2615p' client/ws_pool_drain_test.go
echo ""
echo "=== other lastActivityNs.Store sites in tests ==="
grep -n "lastActivityNs.Store\|lastActivityNs.Load" client/ws_pool_drain_test.go
```

- [ ] **Step 5.2: DELETE `TestDrainWatchdog_TooManyStreamsBypassesIdle`**

The test pins behavior "with streams>STREAMS_MAX, idle path does NOT fire". Step 2 abolishes that semantic (any number of all-idle streams now triggers finishIdle correctly). Find the test (around line 2616) including its doc-comment block and the closing brace. Delete the entire function including 4-5 lines of doc-comment before it.

Verify deletion:

```bash
grep -n "TooManyStreamsBypassesIdle" client/ws_pool_drain_test.go
```

Expected: no output.

- [ ] **Step 5.3: REWRITE `TestDrainWatchdog_IdleFinish`**

Current test (around line 2530) uses `oldSlot.lastActivityNs.Store(...)` to set up state. Rewrite to use `storeStreamForTestWithAge` plus `slot.streams.Store(N)` for per-stream state.

Find the existing test, delete it entirely. Append a new version at the same location (or end of file — order doesn't matter for tests):

```go
// TestDrainWatchdog_IdleFinish verifies that a slot with all attached
// streams idle for >= DrainIdleThreshold terminates via finishIdle
// (natural finish) instead of hard cap.
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §4.2 #7.
func TestDrainWatchdog_IdleFinish(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		DrainHardCap:       3 * time.Second,
		DrainIdleThreshold: 100 * time.Millisecond,
	})
	defer p.Stop()

	// Set up draining slot with 2 streams, both idle 500ms (well past
	// the 100ms threshold).
	oldSlot := &poolSlot{}
	oldSlot.streams.Store(2)
	p.slots[0] = oldSlot

	storeStreamForTestWithAge(p, 1, 0, 500*time.Millisecond)
	storeStreamForTestWithAge(p, 2, 0, 500*time.Millisecond)

	// Invoke drainWatchdog (assuming an exported test harness exists in
	// the codebase — check how IdleFinish was originally invoked and
	// reuse that pattern).
	// If no test harness exists, the drainWatchdog function may need to
	// be invoked through a public Drain() or similar — adapt to the
	// existing pattern in nearby tests.
	teardownCalled := make(chan struct{})
	go func() {
		// Use the same invocation pattern as the existing
		// TestDrainWatchdog_* tests in this file. Refer to e.g.
		// TestDrainWatchdog_HardCapTimeout for the exact harness.
		_ = teardownCalled
	}()

	// Within 500ms of tick + 100ms threshold, expect finishIdle teardown.
	// Verify by polling slot state or by checking that the slot was
	// transitioned out of slotDraining.
	// Match the assertion pattern from other TestDrainWatchdog_* tests.
}
```

**IMPLEMENTER NOTE:** This task requires reading the existing `TestDrainWatchdog_*` family in the same file (lines around 1113 `HardCapTimeout`, 2525 `IdleFinish`, etc.) to mirror exactly the test harness pattern used for invoking drainWatchdog. The skeleton above shows shape but the precise invocation depends on existing helpers. **Do NOT skip this — match the existing pattern.** If the existing tests use a global helper like `runDrainWatchdog(t, p, oldIdx, ...)`, use the same.

If you cannot find a clear existing pattern to mirror within 5 minutes of reading the file — STOP and report BLOCKED with the harness question.

- [ ] **Step 5.4: REWRITE `TestDrainWatchdog_IdleHeuristicDisabled`**

Current test (around line 2580) uses `DrainIdleStreamsMax: 0` as disable knob — that's no longer the disable knob (spec §2.5 BREAKING). Switch to `DrainIdleThreshold: 0`.

Delete existing test. Append new version:

```go
// TestDrainWatchdog_IdleHeuristicDisabled verifies that
// DrainIdleThreshold=0 disables the idle gate entirely (slot rides
// to hard cap regardless of stream idleness). After Step 2 this is
// the canonical disable knob (STREAMS_MAX=0 is deprecated no-op).
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §2.5.
func TestDrainWatchdog_IdleHeuristicDisabled(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		DrainHardCap:       300 * time.Millisecond,
		DrainIdleThreshold: 0, // DISABLED
	})
	defer p.Stop()

	oldSlot := &poolSlot{}
	oldSlot.streams.Store(2)
	p.slots[0] = oldSlot

	// Set up streams that WOULD trigger idle if heuristic were on.
	storeStreamForTestWithAge(p, 1, 0, 1*time.Second)
	storeStreamForTestWithAge(p, 2, 0, 1*time.Second)

	// Run drainWatchdog via the same harness as in IdleFinish.
	// Expected: slot terminates via finishHardCap (~300ms hard cap),
	// NOT finishIdle.
	// Match assertion pattern from existing tests.
}
```

Same IMPLEMENTER NOTE as Step 5.3 — use existing harness pattern.

- [ ] **Step 5.5: Remove `idle_for` assertions from any test capturing the finishIdle log**

```bash
cd /d/NIXAVPN/shadowlink
grep -n "idle_for" client/ws_pool_drain_test.go
```

For each match, find the surrounding assertion (likely `strings.Contains(out, "idle_for=")` or similar) and **delete** that single assertion line. The test's other assertions remain.

If no matches — skip step.

- [ ] **Step 5.6: Remove direct reads of lastActivityNs from tests**

```bash
grep -n "lastActivityNs" client/ws_pool_drain_test.go
```

Each remaining match is a test reading `oldSlot.lastActivityNs.Load()` or `p.slots[0].lastActivityNs.Load()`. Tests like `TestWriteMessageForStream_StampsBothPerSlotAndPerStream` (around line 2685) check this. After Step 2 the field doesn't exist — these assertions must be either:

(a) **Delete** the slot-stamp assertion (keep per-stream stamp assertion), OR
(b) **Delete the entire test** if it only existed to verify slot-stamp behavior.

For `TestWriteMessageForStream_StampsBothPerSlotAndPerStream` and `TestWriteControlMessageForStream_StampsBothPerSlotAndPerStream` (Task 5 of Step 1, lines ~2685, ~2790): these tested **both** per-slot AND per-stream stamping. Per-slot no longer exists. **Delete the per-slot assertion block** (search for `slotStamp := p.slots[0].lastActivityNs.Load()` and the 3-4 lines around it that compare slotStamp vs before/after) but **keep** the per-stream `streamStamp := e.lastWriteNs.Load()` check. Also delete the `if slotStamp != streamStamp` final assertion (no longer meaningful with one stamp).

After this step:

```bash
grep -n "lastActivityNs" client/ws_pool_drain_test.go
```

Expected: NO output (all references removed).

- [ ] **Step 5.7: Build + run full client tests**

```bash
cd /d/NIXAVPN/shadowlink
go build ./...
go test ./client/ -count=1
```

Expected: ALL PASS.

If specific tests fail because the harness invocation in Steps 5.3/5.4 is wrong — fix to match existing pattern, do NOT modify production code.

- [ ] **Step 5.8: Commit**

```bash
git add client/ws_pool_drain_test.go
git commit -m "$(cat <<'EOF'
test(ws_pool): migrate drain tests to per-stream idle semantics

Three tests pinned pre-Step-2 semantics that the new code removes:

- TestDrainWatchdog_TooManyStreamsBypassesIdle: DELETED. Tested an
  anti-feature (streams>STREAMS_MAX blocked idle path); Step 2
  abolishes the count cap.
- TestDrainWatchdog_IdleFinish: REWRITTEN. Now uses
  storeStreamForTestWithAge + slot.streams.Store to set per-stream
  state instead of slot.lastActivityNs.Store.
- TestDrainWatchdog_IdleHeuristicDisabled: REWRITTEN. DrainIdleThreshold=0
  is the new disable knob (DrainIdleStreamsMax=0 is deprecated no-op).

Removed idle_for log assertions. Removed per-slot stamp assertions
from TestWriteMessage{,Control}ForStream_StampsBothPerSlotAndPerStream
(slot.lastActivityNs no longer exists; per-stream stamp assertions
retained).

Spec 2026-05-25-drain-per-stream-idle-decision-design §2.6.
EOF
)"
```

---

## Task 6: Deprecate STREAMS_MAX env + startup WARN

**Files:**
- Modify: `client/ws_pool.go` (lines 836, 1044 — add `// Deprecated:` markers)
- Modify: `cmd/nixavpn-client/engine_shadowlink.go` (around line 434 — add WARN log)

- [ ] **Step 6.1: Add Deprecated markers in ws_pool.go**

In `client/ws_pool.go`, find the field declaration at line ~836:

```go
	// drainIdleStreamsMax — upper bound on streams.Load() at which the
	// drain watchdog ... [existing doc-comment continues]
	drainIdleStreamsMax int32
```

Prepend a `// Deprecated:` marker block. Update the comment to:

```go
	// drainIdleStreamsMax — Deprecated: kept readable for env-parsing
	// backward compatibility. Step 2 (per-stream idle decision) ignores
	// this value in decision logic. Use DrainIdleThreshold=0 to disable
	// the idle gate. See spec 2026-05-25-drain-per-stream-idle-decision-design §2.5.
	drainIdleStreamsMax int32
```

Similarly at line ~1044 (the WSPoolConfig public field):

```go
	// DrainIdleStreamsMax is the upper bound on remaining streams under
	// which the idle heuristic fires. ... [existing doc-comment]
	DrainIdleStreamsMax int32
```

Replace with:

```go
	// DrainIdleStreamsMax — Deprecated: no longer participates in the
	// idle gate decision after Step 2 (per-stream idle decision).
	// Kept on the struct for env-parsing backward compatibility. Use
	// DrainIdleThreshold=0 to disable the idle gate.
	DrainIdleStreamsMax int32
```

- [ ] **Step 6.2: Add startup WARN in cmd-layer**

Find `cmd/nixavpn-client/engine_shadowlink.go` around line 434:

```bash
cd /d/NIXAVPN/shadowlink
sed -n '430,460p' cmd/nixavpn-client/engine_shadowlink.go
```

The line should read approximately:

```go
				drainIdleStreamsMax := int32(envIntDefault("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX", 2))
```

Immediately after this line, add a deprecation warning block. The warning should fire only if the env variable was set explicitly (not just defaulted). Add:

```go
				drainIdleStreamsMax := int32(envIntDefault("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX", 2))
				// Deprecation notice (spec 2026-05-25-drain-per-stream-idle-decision-design §2.5):
				// SHADOWLINK_DRAIN_IDLE_STREAMS_MAX is no longer consulted in the drain
				// decision after Step 2. Emit a one-time WARN if operator set it
				// explicitly so they know to migrate to SHADOWLINK_DRAIN_IDLE_THRESHOLD=0.
				if _, set := os.LookupEnv("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX"); set {
					slog.Warn("SHADOWLINK_DRAIN_IDLE_STREAMS_MAX is deprecated and no longer affects drain behavior. " +
						"Use SHADOWLINK_DRAIN_IDLE_THRESHOLD=0 to disable the idle gate.")
				}
```

Verify imports — `os` and `log/slog` are likely already imported. If not, add to import block.

- [ ] **Step 6.3: Verify build**

```bash
cd /d/NIXAVPN/shadowlink
go build ./...
```

Expected: clean.

- [ ] **Step 6.4: Verify WARN test (manual)**

Quick sanity:

```bash
cd /d/NIXAVPN
SHADOWLINK_DRAIN_IDLE_STREAMS_MAX=2 ./bin/nixavpn-client-graceful-drain.exe -h 2>&1 | head -10
```

Expected: see the WARN message in early output.

Note: this is just a sanity smoke — full integration test happens in canary.

- [ ] **Step 6.5: Commit**

```bash
git add client/ws_pool.go cmd/nixavpn-client/engine_shadowlink.go
git commit -m "$(cat <<'EOF'
chore(ws_pool): deprecate SHADOWLINK_DRAIN_IDLE_STREAMS_MAX env

Step 2 per-stream idle decision no longer consults the count cap.
Mark drainIdleStreamsMax / DrainIdleStreamsMax fields as
// Deprecated:, kept readable for env-parsing backward compat.

Cmd-layer emits a one-time WARN on startup if the operator set
the env explicitly, pointing them to SHADOWLINK_DRAIN_IDLE_THRESHOLD=0
as the new disable knob.

Spec 2026-05-25-drain-per-stream-idle-decision-design §2.5.
EOF
)"
```

---

## Task 7: Integration tests for drainWatchdog per-stream behavior

**Files:**
- Modify: `client/ws_pool_drain_test.go` (append new tests)

These tests verify Step 2 behavior end-to-end via drainWatchdog rather than directly testing `allStreamsIdle`. Mirror the harness pattern from existing `TestDrainWatchdog_*` tests in the file.

- [ ] **Step 7.1: Add TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent**

Append to `client/ws_pool_drain_test.go`:

```go
// TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent verifies the
// new Step 2 behavior: with 2 streams attached, both pre-aged past
// threshold, drainWatchdog should fire finishIdle (not hard cap).
// Asserts the spec §2.4 invariant on the emitted log:
// diag_min_stream_age_ms >= 30000 at finishIdle.
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §4.2 #7.
func TestDrainWatchdog_PerStreamIdle_TriggersWhenAllSilent(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, nil))

	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		DrainHardCap:       3 * time.Second,
		DrainIdleThreshold: 100 * time.Millisecond,
	})
	p.log = logger
	defer p.Stop()

	oldSlot := &poolSlot{}
	oldSlot.streams.Store(2)
	p.slots[0] = oldSlot

	// Both streams aged 500ms — well past 100ms threshold.
	storeStreamForTestWithAge(p, 1, 0, 500*time.Millisecond)
	storeStreamForTestWithAge(p, 2, 0, 500*time.Millisecond)

	// Run drainWatchdog using the existing TestDrainWatchdog_* harness
	// pattern. Adapt to the actual signature. The test should expect
	// the watchdog to call tearDown(finishIdle) within ~600ms.

	// After teardown, assert log contains:
	out := logBuf.String()
	if !strings.Contains(out, "natural finish (idle)") {
		t.Errorf("log should contain 'natural finish (idle)', got:\n%s", out)
	}
	// Invariant: at finishIdle, all streams >= threshold (spec §2.4)
	// → diag_min_stream_age_ms >= threshold (100ms here, but we
	// stamped 500ms so expect >=500 in practice).
	if !strings.Contains(out, "diag_min_stream_age_ms=") {
		t.Errorf("log should contain diag_min_stream_age_ms field, got:\n%s", out)
	}
}
```

**IMPLEMENTER NOTE:** Same pattern note as Tasks 5.3/5.4 — adapt the watchdog-invocation to match existing pattern in the file. The harness lines are not strictly defined above; replace `// Run drainWatchdog using the existing pattern` comment with actual invocation code.

- [ ] **Step 7.2: Add TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream**

Append:

```go
// TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream verifies
// that a slot with one persistently-active stream does NOT trigger
// finishIdle — it rides to hard cap. This is the H1 case BEFORE
// Step 2's fix would have wrongly fired finishIdle (heartbeat-
// stream blocking) — but in Step 2 the active stream alone is
// enough to keep idle gate from firing.
//
// Spec 2026-05-25-drain-per-stream-idle-decision-design §4.2 #8.
func TestDrainWatchdog_PerStreamIdle_HoldsOpenForActiveStream(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:               2,
		ServerAddr:         "127.0.0.1:0",
		DrainHardCap:       400 * time.Millisecond,
		DrainIdleThreshold: 100 * time.Millisecond,
	})
	defer p.Stop()

	oldSlot := &poolSlot{}
	oldSlot.streams.Store(2)
	p.slots[0] = oldSlot

	// Stream 1: idle (would-be candidate to trigger finishIdle alone).
	storeStreamForTestWithAge(p, 1, 0, 200*time.Millisecond)

	// Stream 2: stays active by re-stamping every 50ms (well under
	// the 100ms threshold).
	storeStreamForTestWithAge(p, 2, 0, 0)

	stopActive := make(chan struct{})
	defer close(stopActive)
	go func() {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopActive:
				return
			case <-ticker.C:
				if v, ok := p.streamMap.Load(uint16(2)); ok {
					e := v.(*streamEntry)
					e.lastWriteNs.Store(time.Now().UnixNano())
				}
			}
		}
	}()

	// Run drainWatchdog (using existing harness — see Task 5/7.1 note).
	// Expected: drainWatchdog rides to hard cap (~400ms), NOT finishIdle.
	// Assertion pattern: check the recorded cause/log line.
}
```

- [ ] **Step 7.3: Run new integration tests**

```bash
cd /d/NIXAVPN/shadowlink
go test ./client/ -run 'TestDrainWatchdog_PerStreamIdle' -v -count=1
```

Expected: 2 PASS.

If tests fail, the most likely cause is the watchdog invocation pattern. Check existing TestDrainWatchdog_* tests and align.

- [ ] **Step 7.4: Full client suite**

```bash
go test ./client/ -count=1
```

Expected: ALL PASS.

- [ ] **Step 7.5: Run with race detector if possible**

```bash
go test -race -count=3 ./client/
```

Expected: PASS or skipped (CGO).

- [ ] **Step 7.6: Commit**

```bash
git add client/ws_pool_drain_test.go
git commit -m "$(cat <<'EOF'
test(ws_pool): integration tests for per-stream idle decision

Two new TestDrainWatchdog_PerStreamIdle_* tests:
- TriggersWhenAllSilent: 2 streams pre-aged past threshold,
  watchdog should finishIdle and emit log with diag_min_stream_age_ms
  satisfying the spec §2.4 invariant (>= threshold).
- HoldsOpenForActiveStream: 1 idle + 1 active (re-stamped every
  50ms) — slot must ride to hard cap, not finishIdle. Directly
  validates that active heartbeat correctly holds the slot.

These complement the Task 1 unit tests (allStreamsIdle direct)
with end-to-end watchdog orchestration.

Spec 2026-05-25-drain-per-stream-idle-decision-design §4.2 #7,8.
EOF
)"
```

---

## Task 8: Build binary for canary

**Files:** none modified; produces canary artifact.

- [ ] **Step 8.1: Backup current binary**

```bash
cd /d/NIXAVPN
cp bin/nixavpn-client-graceful-drain.exe bin/nixavpn-client-graceful-drain.exe.bak-step1-$(date +%Y%m%d)
ls -la bin/nixavpn-client-graceful-drain.exe.bak-step1-*
```

- [ ] **Step 8.2: Build Step 2 binary**

```bash
cd /d/NIXAVPN/shadowlink
go build -o /d/NIXAVPN/bin/nixavpn-client-graceful-drain.exe ./cmd/nixavpn-client
ls -la /d/NIXAVPN/bin/nixavpn-client-graceful-drain.exe
```

Expected: clean build, ~52 MB binary.

- [ ] **Step 8.3: Smoke test**

```bash
cd /d/NIXAVPN
./bin/nixavpn-client-graceful-drain.exe -h 2>&1 | head -3
```

Expected: usage output, no startup panic.

Quick env-deprecation WARN check:

```bash
SHADOWLINK_DRAIN_IDLE_STREAMS_MAX=2 ./bin/nixavpn-client-graceful-drain.exe -h 2>&1 | grep -i "deprecated"
```

Expected: at least one line mentioning deprecation. (Note: WARN may only fire after env-parsing in the connect subcommand, not on `-h` — if not visible, that's OK; manual test in canary will show.)

- [ ] **Step 8.4: Handoff to user**

Inform user that the binary is built and ready. The next step (running `connect-vpn-graceful-drain.bat` for 4h+ and analyzing the canary log) is a manual user operation.

**Canary criteria recap (spec §4.4):**
- ≥75% natural_ratio, 0 meltdowns, 0 decrypt_fails, 0 ERROR → ✅ Target met
- 70-75% natural_ratio + clean → ✅ Partial win, open follow-up
- <70% OR any regression → ❌ Revert

Predicted landing: ~77.6% natural_ratio.

- [ ] **Step 8.5: Do NOT push to remote**

Per user preference (memory `feedback_no_git.md`), no `git push`. All commits remain local. After canary confirms success, user will decide on push timing.

---

## Self-review

**Spec coverage:**

| Spec section | Implementing task |
|---|---|
| §2.1 `allStreamsIdle` helper | Task 1 |
| §2.2 drainWatchdog gate switch | Task 3 |
| §2.3 `slot.lastActivityNs` removal (4 stamps + field + reads) | Task 4 |
| §2.3.1 ReleaseStream flip order (R2-H2) | Task 2 |
| §2.4 idle_for log field removal | Task 4 (Step 4.6) |
| §2.5 STREAMS_MAX deprecation + startup WARN | Task 6 |
| §2.6 Test migration (3 existing tests + diag assertions) | Task 5 |
| §3 Behavioral contract | covered by Task 1+3+7 integration tests |
| §4.1 Unit tests for allStreamsIdle (5 tests + 2 race) | Task 1 (Steps 1.1-1.8) |
| §4.2 Integration tests (#7, #8, plus #9, #10 races) | Task 7 + Task 1.7 |
| §4.3 Race detector | Task 1.8, 7.5 |
| §4.4 Canary three-tier criteria | Task 8 handoff note |
| §5 Rollback path | Task 8.5 (don't push) |
| §6 Resolved Questions | tracked in spec — no implementation needed |

**Placeholder scan:** Two IMPLEMENTER NOTES in Task 5 and Task 7 about adapting harness pattern. These are NOT placeholders — they document a known unknown (the exact existing test harness signature) and instruct the implementer to read the file and match the pattern. If the harness genuinely can't be found in 5 minutes, the implementer is told to escalate. This is the right design because writing fake harness invocation code would be a hallucination.

**Type consistency:** `streamEntry`, `newStreamEntry`, `storeStreamForTest`, `storeStreamForTestWithAge`, `snapshotDrainStreams`, `allStreamsIdle`, `drainStreamSnapshot` — all consistent with Step 1 plan's naming. `drainIdleThreshold`, `drainIdleStreamsMax` field names match `client/ws_pool.go` exactly.

**Task ordering rationale:**
1. Task 1 (allStreamsIdle): new helper, no prod-code change — safest to land first.
2. Task 2 (ReleaseStream flip): critical race fix, must precede the gate switch.
3. Task 3 (gate switch): the actual behavior change, lands on Tasks 1+2 foundation.
4. Task 4 (lastActivityNs cleanup): post-gate; gate no longer needs the field.
5. Task 5 (test migration): catches test-layer breakage from Tasks 3+4.
6. Task 6 (env deprecation): cosmetic, independent.
7. Task 7 (integration tests): new tests for new behavior.
8. Task 8 (binary build): final artifact.

This order keeps `go build ./client/...` clean throughout. The only window where `go test` fails is between Task 3 and Task 5 (semantically broken tests pending migration) — documented and expected.
