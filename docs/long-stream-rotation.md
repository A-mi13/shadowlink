# WS-Pool Long-Stream Rotation Issue Analysis

**Date:** 2026-05-29  
**Problem:** Large file downloads (>500MB, >50s) break due to WS slot rotation hard cap (90s drain timeout).  
**Symptom:** `downlink cancelled` + `"WS pool slot drain hard cap reached remaining_streams=N"`

## Issue Summary

When a large file downloads on a single WS slot for >50-90 seconds:
1. Slot byte budget burns up (~0.16s at 50 MB/s for 8MB budget)
2. `byteBudgetMinRotationInterval` floor (10s) prevents cascading rotations
3. Slot enters graceful drain (`slotDraining` state) via `startDrain()`
4. Drain watchdog waits for streams to finish (timeout: `drainHardCap = 90s`)
5. If download still in-flight after 90s → hard cap fires → stream forced closed

**Root cause:** Stream is **architecturally pinned to its slot** via per-slot crypto session.

## Key Architectural Findings

### 1. Stream-Slot Binding (Hard Coupling)

**Files:** ws_pool.go:2028-2114, ws_pool.go:2241-2260

- **AssignStream()** assigns stream to a single slot index (line 2110)
- **Lifetime:** Pinned for entire stream lifetime via `streamMap` entry
- **Data routing:** All frames route via `WriteMessageForStream()` (line 2241-2260)
- **Session binding:** Each slot has unique `core.Session` with own crypto keys
- **Why no migration?** Server-side session is per-slot. Frame from different session → decryption failure

### 2. Byte Budget & Rotation Cadence

**File:** ws_pool.go:493-594, ws_pool.go:2518-2555

| Parameter | Value | Effect |
|-----------|-------|--------|
| **effectiveMaxBytesForSlot()** | base + (idx × base / poolSize) | Slot 0→8MB, Slot 7→15MB for 8MB base |
| **Jitter sample** | once per (re)connect | Budget frozen for slot lifetime |
| **Min floor** | `byteBudgetMinRotationInterval = 10s` (line 560) | Prevents rotation < 10s after ready |
| **Download speed** | 50 MB/s | Burns 8MB budget in 0.16s, but min floor delays rotation to 10s |

### 3. Drain Hard Cap & Graceful Drain

**File:** ws_pool_drain.go

| Component | Value | Location |
|-----------|-------|----------|
| **drainHardCap** | 90 seconds (default) | Line 1108-1110 in NewWSPoolTransport |
| **Watchdog polling** | 500 ms ticks | Line 12: drainPollInterval |
| **Graceful drain** | slotReady → startDrain CAS to slotDraining → wait streams==0 OR hard cap | Lines 352-487 (startDrain), 557-643 (drainWatchdog) |
| **Natural finish paths** | streams==0 OR allStreamsIdle (30s) OR hard cap (90s) | Lines 574-614 tearDown closure |

State machine:
```
slotReady → startDrain() CAS→ slotDraining
  + connectReserveSlot(newIdx) spawned
  + drainWatchdog(oldIdx) spawned
  → polls streams.Load():
    - == 0? → tearDown(finishStreamsZero)
    - all idle >30s? → tearDown(finishIdle)
    - hard cap (90s)? → tearDown(finishHardCap) ← PROBLEM
  → handleSlotDeath closes all streams via close(streamChans)
```

### 4. Stream Lifetime During Drain

**File:** ws_pool.go:2227-2288, stream_entry.go:96-145

- **WriteMessageForStream:** During drain accepts both `slotReady || slotDraining` (line 2251-2252)
- **allStreamsIdle:** Checks every stream's `lastWriteNs` against threshold
- **Hard cap kill:** `handleSlotDeath` closes streamChans for all streams on slot (line 2817)

Problem: Download stream gets killed by hard cap after 90s even if still in-flight.

### 5. Active-Stream Deferral (Incomplete)

**File:** ws_pool.go:2612-2726, line 461

- **slotRotationGraceWithActiveStreams = 30 seconds** (line 461)
- **maybeRotateSlot:** Defers rotation up to 30s if active streams found
- **Grace expiry:** After 30s → **force-rotate anyway** (line 2716-2722, call fireRotation())
- Problem: Grace window only 30s. Force-rotate happens even with activeStreams > 0.

## Solution Options

### Option A: RECOMMENDED - Block Byte-Budget Drain for Active Streams

Do NOT initiate byte-budget drain if `slot.streams.Load() > 0`. Wait for streams to clear.

**Pros:**
- Simplest: no protocol changes
- Stream continues on original slot (no session migration risk)
- Respects stream lifetime for large downloads

**Cons:**
- Byte-budget rotation blocked on slots with any active stream
- Slot with persistent SOCKS stream pins past both byte AND age thresholds
- Fingerprint anti-TSPU weaker if slots never rotate due to persistent streams

**Implementation:**
```go
// In maybeRotateSlot (ws_pool.go:2646), before fireRotation:
if slot.streams.Load() > 0 {
    if deferredAt == 0 {
        slot.rotationDeferredNs.Store(nowNs)
    }
    return false  // never rotate byte-budget on active streams
}
```

### Option B: Increase Drain Hard Cap for High-Download Activity

Dynamically raise `drainHardCap` (e.g., to 5 min) when slot has recent high-throughput.

**Pros:**
- Existing graceful-drain works unchanged
- Gives long downloads >90s to complete naturally
- Anti-TSPU rotation still happens (delayed)

**Cons:**
- TSPU's ML window might still catch during grace period
- Hard to tune: too low → breaks; too high → defeats anti-TSPU

### Option C: NOT RECOMMENDED - Migrate Stream to New Slot

Requires server-side protocol change ("session reassign" control message). High complexity, high risk of decryption failures.

### Option D: Exclude Large Downloads from Byte-Budget Rotation

Track per-stream download size; skip byte-budget rotation if stream has downloaded >threshold.

**Cons:**
- Adds per-stream state
- Still subject to age-based force-rotate (2×maxSlotAge emergency eviction)

## RECOMMENDED: Hybrid Solution (Option A + B)

**Tier 1 (Default):**
- Do NOT initiate byte-budget rotation if `activeStreams > 0`
- Continue age-based rotation on idle slots (rotationWatchdog)
- Grace window still applies, but NO force-rotate when activeStreams > 0

**Tier 2 (Optional):**
- If byte-budget defer persists past threshold (60s), emit WARN log
- Surfaces long-lived SOCKS streams blocking rotation

**Tier 3 (Fallback):**
- Rely on age-based rotation (rotationWatchdog) for slots with persistent streams
- maxSlotAge triggers independently of byte-budget

## Code Locations (Key References)

- **Byte budget rotation:** ws_pool.go:518-555, reader check line 2532
- **Graceful drain:** ws_pool_drain.go:337-487 (startDrain), 557-643 (drainWatchdog)
- **Active-stream grace:** ws_pool.go:456-461 (constant), 2612-2726 (logic)
- **Stream binding:** ws_pool.go:2028-2114 (AssignStream), 2241-2260 (WriteMessageForStream)
- **Hard cap logging:** ws_pool_drain.go:655-673 (emitHardCapLog)
- **Stream idle check:** stream_entry.go:96-145 (allStreamsIdle)

## Implementation Checklist

**Phase 1: Option A (Block Byte-Budget Drain for Active Streams)**
- [ ] Modify `maybeRotateSlot()` to check `activeStreams == 0` before `fireRotation()`
- [ ] Update deferral log message
- [ ] Add test: `TestMaybeRotateSlot_DefersIndefinitelyWithActiveStreams`

**Phase 2: Option B (Extended Hard Cap for High-Throughput)**
- [ ] In `drainWatchdog()`, compute `effectiveHardCap` based on `oldSlot.downBytes`
- [ ] Threshold: >100 MB → cap = 5 min; else default 90s
- [ ] Add metric: `shadowlink_drain_hard_cap_extended_total`
- [ ] Add test: `TestDrainWatchdog_ExtendedCapForHighThroughput`

## Conclusion

Architecture blocks transparent stream migration (per-slot session keys).  
Recommended: Do NOT rotate byte-budget-triggered drains when streams active (Option A) + extend hard cap for high-throughput slots (Option B).  
This preserves stream integrity, respects download completion, and keeps anti-TSPU rotation mostly working via age-based triggers.
