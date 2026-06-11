# Impl Block E — Centralize `p.slots[]` access (audit H1 / H-C1 + M1 + M4 + L3)

Date: 2026-06-11
Files: `client/ws_pool.go`, `client/ws_pool_drain.go`, `client/migrate_watchdog.go`,
`client/migrate_send.go`, new `client/ws_pool_slots_access_test.go`.

## Chosen variant: (а) — centralized accessors `slotAt(idx)` + `snapshotSlots()`

The audit recommended (б) `[]atomic.Pointer[poolSlot]` as the cleanest fix. I evaluated it
concretely and chose **(а)** for this codebase. Rationale:

1. **Test-surface blast radius.** Changing the field type to `[]atomic.Pointer[poolSlot]`
   breaks every test that does `make([]*poolSlot, n)` / `p.slots[i] = &poolSlot{...}` directly.
   `grep` counts **496 references across 14 test files** (`may_audit_p2`, `migrate_resume`,
   `migrate_send`, `migrate_watchdog`, `pool_capacity_dip`, `ratelimit_sentinel`,
   `sticky_stream`, `stream_counter_leak`, `ws_pool_drain_logging`, `ws_pool_drain`,
   `ws_pool_emergency_migrate`, `ws_pool_fin`, `ws_pool_sticky_timeout`, `ws_pool`). Rewriting
   all of them mechanically against `Load()`/`Store()` on bug-laden lifecycle code (history of
   Bug#6–#10) is high-risk churn for a fix that is supposed to be purely mechanical.

2. **(а) fully removes the "sometimes locked" ambiguity too.** The audit's objection to (а) was
   that the lock stays "sometimes" held. That is only true of a half-applied (а). Applied
   completely — *every* single-cell read goes through `slotAt` (takes `reserveMu`), *every*
   iteration goes through `snapshotSlots` (copies under `reserveMu`), and the lifecycle writers
   keep their existing `reserveMu` critical sections — the discipline becomes **total and
   unambiguous: "every `p.slots` cell access, read or write, holds `reserveMu`."** No exceptions
   remain. That is race-free under the Go memory model exactly like (б), at ~10× less change
   surface and zero test-type churn.

3. **Continuity with the existing fix.** The maintainers already introduced `snapshotSlots()`
   and the under-lock pointer-capture in `ReleaseStream`/`rebindStreamToSlot` (2026-06-01). (а)
   *finishes that same design* rather than replacing it with a different mechanism.

`reserveMu` remains the only lock; it still serializes the multi-cell claim scans
(`claimFreeSlot`, `connectReserveSlot` free, `startDrain` reserve install) which need an atomic
find-nil-and-claim — exactly the case the audit said the lock should still cover under (б).

### New helpers (ws_pool.go, next to `snapshotSlots`)

- `slotAt(idx) *poolSlot` — single-cell read under `reserveMu`; nil for empty/out-of-range.
- `storeSlot(idx, slot)` — single-cell write under `reserveMu`; out-of-range no-op. (Used by the
  test seam and as the canonical writer counterpart; production lifecycle writers keep their
  bespoke critical sections because they couple the cell write with adjacent locked reads —
  recycle guard, claim scan.)

## Sites converted to safe access (H1 / H-C1 / L3)

Single-cell reads → `slotAt(idx)` (10):
`slotReaderWithClient`, `handleSlotDeath`, `IncrPending`, `DecrPending`, `SlotPending`,
`SessionForStream`, `WriteMessageForStream`, `WriteControlMessageForStream`,
`TryWriteControlMessageForStream`, `ReleaseStream` (replaced the inline lock/capture),
plus `legacyRotateOneSlot`, `startDrain` (oldSlot), `slotForMigrate` (migrate_send.go).

Iteration loops → `snapshotSlots()` (12):
`readyCapacity`, `poolStateCounts`, `emitHealthSummary`, `sendKeepaliveToAllSlots`,
`countDeadSlots`, `rotateMinLoadedSlot` pick, `AssignStream` (all 3 passes on one snapshot),
`AllSlotsAtMaxPending`, `WriteMessage`, `WriteControlMessage`, `spawnMissingReaders`,
Close (FIN loop + teardown loop), `HealthySlots`.

Evict scans (ws_pool_drain.go, L3) → `snapshotSlots()` with captured winner pointer:
`tryForceEvictIdleSlot`, `tryEmergencyEvictMinStreamsSlot` (now captures the scored `*poolSlot`
from the snapshot instead of re-reading `p.slots[bestIdx]` live afterward).

migrate_watchdog.go: `selectYoungTargetSlot` → `snapshotSlots()`.

**Total: ~25 read/iteration sites centralized.** All remaining direct `p.slots[idx]` accesses
are inside `reserveMu` critical sections (lifecycle writers): `connectSlot` install, reconnect
recycle guard, `handleSlotDeath` nil-write, `claimFreeSlot`, `connectReserveSlot` free,
`rebindStreamToSlot` capture, and the two helpers themselves. Verified via grep that no
unguarded `.slots[` read remains in non-test files.

## M1 — AssignStream inc-by-index → captured pointer  ✅

`AssignStream` now picks on a single `snapshotSlots()` and, before the increment, re-captures the
live `*poolSlot` at `minIdx` via `slotAt` and increments on the captured pointer (skips the inc if
the cell was niled by a racing teardown, letting the paired `ReleaseStream` floor-clamp absorb the
asymmetry). This pairs the inc with the same kind of under-lock capture `ReleaseStream` uses for the
dec, closing the "fresh zeroed object" drift window the old by-index inc admitted. The `Trace` call
was updated to use the captured pointer.

## M4 — legacyRotateOneSlot generation bump before Close  ✅

Added `slot.generation.Add(1)` immediately before `slot.transport.Close()` in
`legacyRotateOneSlot`'s `reconnect:` block, mirroring `drainWatchdog.tearDown` and
`tryForceEvictIdleSlot`. The stale reader now exits silently via `shouldExitReader` (gen
mismatch) instead of feeding a false `deathCauseNatural` meltdown signal for a rotation we
initiated. The read at the top of `legacyRotateOneSlot` was also moved to `slotAt`.

NOTE: M4 also appears under Block G (#7). It is implemented here (Block E is first/sequential).
Block G should treat the legacy-rotate generation part as already done.

## L3 — evict functions unguarded reads  ✅

Folded into H1: both evict scans now iterate `snapshotSlots()`; `handleSlotDeath` (called from
the evict path) reads via `slotAt`. No separate change needed.

## Tests

New file `client/ws_pool_slots_access_test.go`:
- `TestSlotAt_ReturnsCellUnderLock`, `TestStoreSlot_NilsAndInstalls` — helper contract incl.
  out-of-range safety.
- `TestSlotsAccess_NoRaceUnderConcurrentLifecycle` — concurrent install/teardown writers vs
  `slotAt`/`readyCapacity`/`snapshotSlots` readers. On amd64 without `-race` it asserts no
  panic/corruption; under `go test -race` on Linux/CI it is the decisive guard that no
  unguarded cell access remains.
- `TestLegacyRotateOneSlot_BumpsGenerationBeforeClose` — M4 regression: a probe transport
  records `slot.generation` at `Close()` time and asserts it already advanced past the
  pre-rotation value.

## Verification

- `go build ./...` — **OK** (clean).
- `go vet ./client/...` — **OK** (clean).
- `go test ./client/...` — **OK** (48–52s; full client suite green, incl. counter-leak, sticky,
  emergency-migrate, drain, capacity-dip, migrate, force-evict generation).
- `go test ./core/... ./proxy/...` — **OK**.
- New tests pass with `-count=2` (no flakiness on the touched set).

## Remaining for Linux/CI (-race)

`-race` cannot run on this Windows host (no gcc). The conversion is reasoned to be race-free by
construction (uniform "every cell access under reserveMu"). On Linux/CI run:
`go test -race -count=3 ./client/` — focus on `TestSlotsAccess_NoRaceUnderConcurrentLifecycle`
and the drain/migrate/keepalive suites. Expect the ~15 `-race` sites the audit flagged to be
silenced.

## Risks

1. **Read latency under contention.** `slotAt`/`snapshotSlots` now take `reserveMu` on hot read
   paths (`WriteMessageForStream`, `slotForMigrate`, keepalive sweep). Critical sections are a
   single pointer load / O(2·poolSize) copy and `reserveMu` is otherwise held only for the tiny
   claim/install windows, so contention should be negligible — but a canary should confirm no
   throughput regression on heavy-stream sessions.
2. **AssignStream snapshot staleness.** All three picking passes now run on one snapshot taken at
   entry; a slot that becomes ready between entry and pick is not chosen until the next assign.
   This is strictly more consistent than the old live-indexed multi-pass, but is a behavioral
   nuance worth noting if assign-latency canaries shift.
3. **M1 skip-on-nil.** If the picked cell is niled by a racing teardown between pick and capture,
   AssignStream now skips the inc but still publishes the streamMap entry (relies on
   ReleaseStream's floor-clamp). This matches prior floor-clamp intent but is a new code path;
   covered structurally by existing counter-leak tests staying green.
