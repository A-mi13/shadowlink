# Stream-Counter Leak Fix — Design (2026-06-01)

**Goal:** Stop `poolSlot.streams` from drifting upward under load (observed
active_streams=1397 vs physical max 80), which makes the pool believe it is
saturated and falsely reject new SOCKS5 CONNECTs under a burst — the
user-visible "обрывы / невозможно работать".

**Root cause (proven, see docs/sl-counter-leak-rootcause-v2.md):**
`rebindStreamToSlot` (migrate_watchdog.go:331/337) mutates the per-slot stream
counter BY INDEX — `p.slots[targetIdx].streams.Add(1)` then
`p.slots[srcIdx].streams.Add(-1)`. Under a burst of close-1006 slot deaths,
`connectSlot` replaces the object at `srcIdx` with a fresh
`&poolSlot{streams:0}` BETWEEN the inc and the dec. The dec then lands on the
NEW (zeroed) object — missing its intended target — while the inc stays stranded
on the live `targetIdx` object with no pairing dec. Summed across live objects
in `emitHealthSummary` (ws_pool.go:1744), the stranded incs accumulate. Both
`migrateStream` (preemptive) and `resumeStreamOnDeath` (per-stream, per slot
death) call rebind, so frequent close-1006 multiplies the drift.

A single `AssignStream`/`ReleaseStream` pair does NOT drift — both touch the same
`idx`. The drift is born ONLY where inc and dec target TWO different indices
(rebind) and one index's object can be swapped mid-operation.

**Architecture:** Make every counter mutation address a CAPTURED `*poolSlot`
pointer (read once), not a re-indexed `p.slots[idx]`. A captured pointer that is
no longer the current occupant of its index is a DEAD object — its counter is
irrelevant (the replacement starts at 0), so mutating it is harmless to the live
sum AND keeps inc/dec paired on the same object. We additionally guard rebind so
it only adjusts counters for slots that are still the live occupant, and clamp
the counter at a floor of 0 as defense-in-depth.

**Tech Stack:** Go 1.25, `shadowlink/client`. No wire change.

---

## The invariant

> `slot.streams` == number of live `streamMap` entries whose `slotIdx` resolves
> to THIS `*poolSlot` object (not merely this index).

Index-addressed mutation violates it because an index can be re-occupied by a
new object mid-flight. Pointer-addressed mutation preserves it: inc and dec on a
captured pointer always hit the same object; if that object has been retired
(replaced in `p.slots`), its counter no longer feeds the health sum, so a
stranded inc on it is inert.

## Fixes

### F1 — rebindStreamToSlot: capture pointers, verify liveness (PRIMARY)

`migrate_watchdog.go` `rebindStreamToSlot(streamID, targetIdx)`:

Current (buggy):
```go
if targetIdx >= 0 && targetIdx < len(p.slots) && p.slots[targetIdx] != nil {
    p.slots[targetIdx].streams.Add(1)   // inc by index
}
p.streamMap.Store(streamID, newStreamEntry(targetIdx))
if srcIdx >= 0 && srcIdx < len(p.slots) && p.slots[srcIdx] != nil {
    p.slots[srcIdx].streams.Add(-1)      // dec by index — object may have swapped
}
```

Fixed: capture BOTH pointers up front under `reserveMu` (the same lock
`connectSlot` holds when it swaps `p.slots[idx]`), so the capture is coherent
with slot replacement. Then mutate the captured pointers. A capture that is nil
(no current occupant) is skipped. The dec is applied to the pointer the inc-side
of the stream's PREVIOUS life used — but since we transfer in one critical
section, src and target are both "as of now", and any later swap of either index
cannot retro-actively split this pair.

```go
p.reserveMu.Lock()
var srcSlot, dstSlot *poolSlot
if targetIdx >= 0 && targetIdx < len(p.slots) {
    dstSlot = p.slots[targetIdx]
}
if srcIdx >= 0 && srcIdx < len(p.slots) {
    srcSlot = p.slots[srcIdx]
}
p.reserveMu.Unlock()

if dstSlot != nil {
    dstSlot.streams.Add(1)
}
p.streamMap.Store(streamID, newStreamEntry(targetIdx))
if srcSlot != nil {
    decStreamsFloor(srcSlot) // Add(-1) but never below 0
}
```

The ordering (inc target → Store entry → dec src) is preserved from the original
(no transient under-count on target). The change is ONLY that src/target are
captured pointers, and the dec is floor-clamped.

### F2 — decStreamsFloor helper (defense-in-depth)

A small helper that decrements but never drives the counter negative:
```go
// decStreamsFloor decrements s.streams by one but never below zero. A negative
// counter (from a historical mismatched dec) would otherwise corrupt
// AssignStream's load-balancing picker and the health sum. CAS loop keeps it
// race-safe against concurrent Add.
func decStreamsFloor(s *poolSlot) {
    for {
        cur := s.streams.Load()
        if cur <= 0 {
            return
        }
        if s.streams.CompareAndSwap(cur, cur-1) {
            return
        }
    }
}
```
Used in `ReleaseStream`, `rebindStreamToSlot` src-dec, and
`resumeStreamOnDeath`'s rebind path. NOT a substitute for F1 — it bounds the
symptom; F1 removes the cause.

### F3 — ReleaseStream: capture pointer (consistency)

`ReleaseStream` (ws_pool.go:2603) already reads `idx := e.slotIdx` then
`p.slots[idx].streams.Add(-1)`. If the slot at idx was replaced between
AssignStream and Release, this dec lands on the new object (drives it toward
negative). Switch to: capture `slot := p.slots[idx]` once (under reserveMu) and
`decStreamsFloor(slot)`. Floor clamp absorbs the residual case where the inc
went to a now-retired object.

### F4 — NextStreamID: check both stream maps (secondary leak, H3')

`client.go` `NextStreamID` (~719) checks uniqueness only against `streamChans`.
In migration mode streams also register in `streamFramesChans`
(RegisterStreamSeq). A reused ID collides; AssignStream's dup-guard then
`return`s without inc, and the two colliding streams' lifecycles leave an
orphaned count. Fix: `NextStreamID` must consider BOTH maps when picking a free
ID. One-line-ish: extend the in-use check.

## File Structure

- **Modify** `shadowlink/client/migrate_watchdog.go` — `rebindStreamToSlot`
  (F1) + use `decStreamsFloor`.
- **Modify** `shadowlink/client/ws_pool.go` — add `decStreamsFloor` (F2);
  `ReleaseStream` capture + floor (F3). `handleSlotDeath` `Store(0)` is KEPT (it
  zeroes a slot that is about to be replaced anyway; with F1/F3 it is no longer
  load-bearing for correctness, only a tidy reset) — but add a comment that the
  real invariant now lives in pointer-addressed mutation.
- **Modify** `shadowlink/client/client.go` — `NextStreamID` both-maps (F4).
- **Test** `shadowlink/client/stream_counter_leak_test.go` (new).

## Testing strategy (TDD)

1. **TestRebind_CounterPairedOnCapturedPointer** — set up src slot with a stream
   (streams=1), target slot (streams=0). Call rebindStreamToSlot. Assert
   src.streams==0, target.streams==1, sum unchanged. (green even today)
2. **TestRebind_SrcReplacedMidFlight_NoDrift** — THE regression. Simulate the
   race: src slot object O1 (streams=1), then between capture and dec, replace
   p.slots[srcIdx] with a fresh O2 (streams=0). Assert: after rebind, the LIVE
   sum across p.slots did NOT increase (the stranded inc is on O1 which we either
   correctly dec'd via captured pointer, or O1 is retired and inert). target
   gets +1, and the net live-sum delta is 0, not +1. This test FAILS on current
   code (drift +1), passes after F1.
3. **TestDecStreamsFloor_NeverNegative** — counter at 0, decStreamsFloor → stays
   0. Counter at 2 → 1.
4. **TestReleaseStream_AfterSlotReplaced_NoNegative** — assign stream to slot,
   replace the object at its idx, ReleaseStream → new object not driven negative.
5. **TestNextStreamID_SkipsIDInFramesChans** — register an ID only in
   streamFramesChans; NextStreamID must not return it (F4).
6. **Burst invariant test** — N goroutines doing AssignStream/migrate/Release
   while M goroutines do handleSlotDeath+connectSlot replacement on the same
   indices; after quiescence assert `sum(slots[i].streams) == live entry count`
   and no negative counters. Run under `-race` (on pl1 Linux).

Each: red→green. Existing migration tests
(TestHandleSlotDeath_Resumes*, TestEmergencyEvict_*) must stay green — rebind's
external contract (entry re-pointed, counter transferred) is unchanged; only the
addressing is hardened.

## Race / concurrency

- `rebindStreamToSlot` capture under `reserveMu` matches `connectSlot`'s write
  lock — capture is coherent with slot replacement.
- `decStreamsFloor` CAS-loop is safe against concurrent `Add`/`Add`.
- Must pass `go test -race -count=3 ./client/` on pl1 (Windows dev lacks gcc).

## Why not "fence AssignStream with CAS-recheck" or "reserveMu in AssignStream"

- CAS-recheck narrows but does not close the window (per investigator), and the
  drift is in rebind, not Assign — fencing Assign treats the wrong site.
- `reserveMu` on AssignStream is the hot path under burst — lock contention
  exactly when load peaks. F1 fixes the actual cause (rebind index-addressing)
  without touching the hot path.

## Out of scope

- Pool headroom / max-conns tuning.
- The emergency-evict-migrate feature (2026-06-01) is correct and unaffected;
  this fix hardens the shared rebind primitive it relies on, making it MORE
  correct under burst.
