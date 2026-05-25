# Final Holistic Review — WS Pool Uniform Cells Refactor
**Date:** 2026-05-20
**Reviewer:** Claude Sonnet 4.6
**Verdict:** APPROVED with MINOR
**Counts:** Critical: 0 / Warning: 2 / Suggestion: 1

---

## Critical Issues

None.

---

## WARNING — W1: `connectSlot` overwrites `p.slots[idx]` unconditionally under `reserveMu` AFTER `claimFreeSlot` already installed a placeholder

**Location:** `ws_pool.go:1280-1282` (`connectSlot` body)

**Issue:**
`connectSlot` always does:
```go
p.reserveMu.Lock()
p.slots[idx] = slot  // brand new *poolSlot
p.reserveMu.Unlock()
```
This overwrites whatever is currently in `p.slots[idx]`. In the reserve path (`connectReserveSlot`), `claimFreeSlot` already installed a placeholder `*poolSlot` at `newIdx` with state `slotConnecting`. So `connectSlot`'s write clobbers the placeholder with a fresh `*poolSlot` — this is fine and intended.

**However:** In `reconnectLoop`, `connectSlot(p.ctx, idx)` is called AFTER the recycle guard passes. The guard checks `p.slots[idx] != nil && getState() != slotDead`. But `connectSlot` immediately overwrites `p.slots[idx]` with a brand-new struct regardless. This means there is a window between the recycle guard read (under `reserveMu`) and the `connectSlot` write (also under `reserveMu`) where nothing bad happens — the `reserveMu` serializes both, so no race. This is actually OK.

**But note a subtler issue:** `connectSlot` is shared between `reconnectLoop` (primary idx) and `connectReserveSlot` (drain replacement idx). In the reconnect path, `connectSlot` writes a brand-new `*poolSlot` into `p.slots[idx]`, which means the slot pointer seen by `drainWatchdog` (still holding `oldSlot` from `startDrain`) becomes stale. `drainWatchdog` operates on `oldSlot` directly (captured reference), not through `p.slots[oldIdx]`, so this is safe. Confirmed: `drainWatchdog` takes `oldSlot *poolSlot` as a parameter.

**Verdict:** Benign. No action required, but worth a comment on `connectSlot` noting it always re-installs a fresh struct regardless of what was there.

---

## WARNING — W2: `handleSlotDeath` stream teardown holds `cl.streamMu` per-stream inside `streamMap.Range`

**Location:** `ws_pool.go:2470-2483`

**Issue:**
```go
p.streamMap.Range(func(key, value any) bool {
    ...
    p.streamMap.Delete(streamID)
    cl.streamMu.Lock()          // lock acquired per-iteration
    if ch, ok := cl.streamChans[streamID]; ok {
        close(ch)
        delete(cl.streamChans, streamID)
    }
    cl.streamMu.Unlock()
    return true
})
```

`cl.streamMu` is acquired and released on every iteration of the Range. Any goroutine that holds `cl.streamMu` and then tries to call into anything that needs `p.streamMap` internally (e.g. `ReleaseStream`, `SessionForStream`) will not deadlock because `sync.Map` is lock-free and `streamMu` only guards `streamChans`. However, `cl.streamMu` is a `sync.Mutex` (not `sync.RWMutex`), meaning every in-flight SOCKS5 stream trying to get/release a channel will contend on `streamMu` for every stream being torn down.

**In practice:** a slot death with N active streams = N serial acquisitions of `streamMu`. At current pool sizes (≤16 slots, ≤`maxConns` streams per slot, typically single digits), this is negligible.

**Concern for the future:** If `maxConns` grows significantly, or if this code path is called under high fanout, the per-stream lock acquisition becomes a serialization bottleneck during teardown cascades.

**Recommendation:** Low urgency for current scale. Document the per-stream lock pattern or consider batch-building a local slice of channels under one `streamMu` lock and then ranging the slice to close — but don't do it now unless the scale warrants it.

---

## SUGGESTION — S1: `connectReserveSlot` failure guard comment should mention the invariant explicitly

**Location:** `ws_pool.go:187-196`

```go
if err != nil {
    p.reserveMu.Lock()
    if p.slots[newIdx] != nil && p.slots[newIdx].getState() != slotReady {
        p.slots[newIdx] = nil
    }
    p.reserveMu.Unlock()
    ...
}
```

The guard `!= slotReady` was chosen instead of the spec's `== slotConnecting` because `connectSlot` on failure always transitions to `slotDead` (verified: every error path in `connectSlot` calls `slot.setState(slotDead)` before returning — lines 1287, 1293, 1299, 1317, 1331, 1351). The guard therefore matches either `slotConnecting` (placeholder only, handshake not started) or `slotDead` (handshake started and failed) — both should free the cell. `slotReady` is excluded correctly because it would mean another goroutine already succeeded in connecting the slot.

The invariant `connectSlot never returns err=nil with state != slotReady AND never returns err!=nil with state == slotReady` is load-bearing here but not documented inline.

**Recommendation:** Add a one-line comment: `// connectSlot only returns nil on setState(slotReady); any error leaves state == slotDead.`

---

## Key Findings Summary

### inflightDrains lifecycle — CLEAN

`startDrain` does `Add(1)` first, then immediately registers `defer Add(-1)` while `committed=false`. If gates 4-6 reject the drain, `committed` stays false and the defer subtracts. If gate 7+ clears, `committed=true` prevents the defer and drainWatchdog takes ownership via its own `defer Add(-1)`. Panic between `Add(1)` and the defer registration is not possible in Go (defer is registered at the statement, not lazily). The cycle is clean.

### connectSlot slotReady + error invariant — CONFIRMED SAFE

Reading `connectSlot` end-to-end: `slotReady` is set exactly once at line 1396, which is the last statement before `return nil`. Every prior error return path explicitly sets `slotDead` (lines 1287, 1293, 1299, 1317, 1331, 1351). There is no code path that sets `slotReady` and then returns an error. The `connectReserveSlot` guard `getState() != slotReady` is therefore correct: it will never incorrectly nil a successfully-connected slot.

### reconnectLoop recycle guard — CLEAN

Guard fires under `reserveMu`. Observed state: non-nil AND non-slotDead → a drain claimed this cell → bail. The only way the guard fires incorrectly would be if the cell transitioned slotDead→slotConnecting concurrently, but `connectSlot` writes a fresh `*poolSlot` (not state transitions on the existing one), and it does so under `reserveMu`, so the guard read and the new pointer write are serialized. No stuck loop possible.

### handleSlotDeath uniform teardown — CLEAN

`streamMap.Delete` before `close(ch)` is the correct order. `ReleaseStream` uses `LoadAndDelete`; if it races with `handleSlotDeath.Delete`, one of them wins. If `ReleaseStream` wins first, the channel is already deleted from the map, `handleSlotDeath`'s Range callback skips `close(ch)` (the `ok` check). `streams.Store(0)` after the Range is correct — even if `ReleaseStream.Add(-1)` ran concurrently and decremented to -1, `Store(0)` overwrites to the canonical terminal state. No underflow risk that's observable.

### drainWatchdog ctx.Done path — NOTE

On `<-p.ctx.Done()`, the watchdog returns without calling `tearDown`. This means:
1. `inflightDrains.Add(-1)` runs via the top-of-function defer. ✓
2. The draining slot is **not** torn down. It stays in `slotDraining` permanently.

This is acceptable because `ctx.Done` fires only during `WSPoolTransport.Close()`, which immediately closes all transport connections and the pool is being shut down. The slot's transport.Close() in the main Close() loop handles any remaining connections. This is intentional and correct for shutdown semantics.

### for-range iteration expansion — CLEAN

All 4 iteration sites now use `range p.slots`. On 16 cells (2× poolSize=8), this adds 8 extra nil/state checks per sweep vs the old `[0, poolSize)` range. At 16 entries and 5s tick frequency, the overhead is sub-microsecond.

### emitHealthSummary dead counter — CLEAN

`dead == slotDead` (literal state), not nil-primary. `rate_limited_recent` reads `lastDeathNs` regardless of current state — a recovered slot can still increment this counter. This is legacy behavior and not a regression.

---

## Test Coverage Assessment

The submitted acceptance checks (paired-arithmetic grep, p.poolSize review, full suite pass, go vet clean) are sufficient for the scope of this refactor. The key behavioral contracts (inflightDrains lifecycle, storm brake gates, drainWatchdog) are covered by the existing test suite per the context provided. No additional tests recommended at this time.
