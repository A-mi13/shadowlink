# Bug #6 Design: Graceful Byte-Budget Deferral for Active Streams

**Status:** Design (not implemented)  
**Date:** 2026-05-29

## Executive Summary

**Problem:** Large file downloads (>90s) break when hard cap fires.  
**Root cause:** Stream pinned to slot; cannot migrate.  
**Solution:** Do NOT rotate byte-budget while streams actively downloading.  
**Risk:** ACCEPTABLE. Age-rotation + hard-cap provide backstops.

## 1. Detection: Active Downloads

Use existing `allStreamsIdle(threshold)` from `stream_entry.go:96-145`.

Before byte-budget `startDrain()` at `ws_pool.go:2532`:

```go
if !allStreamsIdle(p, idx, p.drainIdleThreshold, time.Now()) {
    // Streams downloading; defer rotation
    if slot.rotationDeferredNs.Load() == 0 {
        slot.rotationDeferredNs.Store(time.Now().UnixNano())
    }
    continue
}
```

## 2. Changes Required

Must add same check to BOTH rotation paths:
- `ws_pool.go:1300` (age rotation)
- `ws_pool.go:2532` (byte-budget rotation)

Both must defer when `!allStreamsIdle()`.

## 3. Anti-TSPU Risk

**Acceptable because:**
1. Age rotation (2min) still fires independently
2. Hard cap (90s) limits drain time
3. Real downloads work on long TCPs in production
4. Browser mimicry (Chrome_133) helps credibility

**Trade-off:** Passive TSPU freeze (maybe never happens) > active stream kill (guaranteed).

## 4. Deadlock Risk

**None.** Slots stay `slotReady`, no state trap.  
`readyCapacity()` unaffected (all stay ready).

## 5. Expected Behavior

Large file download (100s):

```
t=10s:  "rotation deferred (active streams)" reason=byte_budget
t=10-100s: [no rotation logs]
t=100s: [stream ends] → rotation resumes or age-rotation fires
```

vs without fix: hard cap at t~90s kills stream.

## 6. Edge Cases

- **Persistent stream (video):** Age rotation fires at 2min, drains with hard cap (90s). OK.
- **Heartbeat-only:** Idle streams allow rotation. OK.
- **Mixed (active + idle):** Active blocks rotation. OK.

## 7. Implementation

Add idle check before `startDrain()` in:
1. `ws_pool.go:1300` (age path)
2. `ws_pool.go:2532` (byte-budget path)

Code scope: ~10 LOC, 2 locations.

Add metrics:
- `shadowlink_byte_budget_rotation_deferred_total`
- `shadowlink_byte_budget_deferral_duration_seconds`

## 8. Recommendation

**PROCEED.** Simple, safe, effective. Preserves anti-TSPU via age-rotation.

