# Emergency-Eviction Stream Migration — Design (2026-06-01)

**Goal:** When the WS-pool tier-2 emergency eviction must reclaim a busy cell under
capacity pressure, migrate that cell's active streams onto live slots BEFORE
tearing the cell down — instead of killing them. Closes the last residual
stream-loss path observed in the Bug#9 4h canary (6 streams = 0.075% over 4h,
all via `emergency-evicted slot with active streams`).

**Architecture:** Reuse the existing Bug#9 preemptive migration primitive
(`migrateStream`) at the emergency-eviction site. The cell is first transitioned
out of service (CAS slotReady→slotDraining) so AssignStream stops landing new
streams on it and `selectYoungTargetSlot` cannot pick it as a target; then each
active stream is migrated synchronously under a single bounded deadline; then the
cell is torn down via the existing `handleSlotDeath` path. Streams that cannot be
migrated (no younger target, or ack timeout) die with the cell — exactly today's
behavior, so worst-case is never worse than the status quo. Eviction ALWAYS
completes (the cell is always reclaimed), preserving the tier-2 anti-deadlock
contract.

**Tech Stack:** Go 1.25, `shadowlink/client` package. No wire-format change — uses
the already-deployed MIGRATE control frame. No new env flag (rides
`SHADOWLINK_GRACEFUL_DRAIN` + `MigrateCapable()`).

---

## Background — the residual path

`startDrain` (ws_pool_drain.go:432-464), when `claimFreeSlot()` returns -1
(slice full), runs a two-tier eviction:

- **Tier 1** `tryForceEvictIdleSlot` — evicts an idle (`streams==0`) cell. No
  stream loss. Unchanged by this design.
- **Tier 2** `tryEmergencyEvictMinStreamsSlot` — only when the drain target is
  over-aged (`drainTargetOverAged`, 2× maxSlotAge). Picks the slotReady cell
  with the LOWEST active stream count and **immediately** calls
  `handleSlotDeath(deathCauseDrainTeardown)`, which closes every stream's
  streamChan → those SOCKS5 flows break.

The migration machinery that prevents exactly this kind of loss
(`migrateStream`, `selectYoungTargetSlot`, `rebindStreamToSlot`,
`sendMigrate`) already exists and is field-proven (canary #2: migrate_ok=8764,
bad_proof=0). Tier 2 simply never calls it.

## Design decisions (resolved with user 2026-06-01)

1. **Synchronous migrate-then-kill** (not deferred-to-tick). `startDrain`
   already runs tier-1/tier-2 synchronously inside its own flow; injecting
   migration there keeps the existing "eviction happens now OR is deferred via a
   gate" invariant. A deferred variant would add a new "marked-but-alive" cell
   state and hold capacity pressure ~5s longer. **Bounded** so startDrain never
   stalls: the whole victim-migration runs under a single
   `emergencyEvictMigrateBudget` deadline (NOT an unbounded per-stream ack sum).

2. **Unmigratable streams die with the cell** (no victim-cancel/retry-other).
   Tier 2 fires precisely under capacity dearth (no free cell). "Could not
   migrate" almost always means `selectYoungTargetSlot` found no younger slot —
   i.e. the same dearth. Cancelling the victim and hunting another would risk
   evicting NOTHING in dense load and re-freeze rotation (the 2026-05-20 bug
   tier-2 fixed). So: migrate what we can within budget, reclaim the cell
   unconditionally. Worst case = today's behavior exactly. Capacity-floor gate
   already guards against catastrophic pool starvation upstream.

## Migration primitive reuse — correctness notes

`migrateStream(streamID)` (migrate_watchdog.go:224) is the reused unit. Its
contract makes it safe to call from the eviction site:

- **Single-winner CAS** on `e.migrating` — if the preemptive watchdog already
  armed a move for this stream, the emergency call stands down (no double
  MIGRATE / double counter-transfer).
- **Graceful degradation** — on no-target / FAIL / timeout the stream is left on
  its current slot; the subsequent `handleSlotDeath` then breaks it (= today).
- **Counter transfer** — `rebindStreamToSlot` moves `poolSlot.streams` from the
  victim to the target with the inc-target→store→dec-source ordering, so the
  victim's count reaches 0 as streams leave.

**Ordering requirement — mark victim draining BEFORE migrating its streams:**

`tryEmergencyEvictMinStreamsSlot` currently selects `bestIdx`, THEN
`tryMarkDraining()`. We keep that order, but must perform the per-stream
migration AFTER the CAS to slotDraining and BEFORE `handleSlotDeath`:

- After CAS the victim is `slotDraining`. `selectYoungTargetSlot` only returns
  `slotReady` slots, so the victim can never be chosen as its own streams'
  migration target (no self-migrate, no wasted rebind churn).
- After CAS, `AssignStream` (which filters on `slotReady`) stops landing NEW
  streams on the victim — the set of streams to migrate is now stable (modulo
  streams releasing concurrently, which migrateStream's Load-miss handles).
- `slotForMigrate` accepts `slotReady` OR `slotDraining` TARGETS, but we never
  target the victim (it's excluded by selectYoungTargetSlot's slotReady filter),
  so the draining victim being a valid *source* is fine.

## File Structure

- **Modify:** `shadowlink/client/ws_pool_drain.go`
  - New const `emergencyEvictMigrateBudget` (bounded total deadline).
  - New method `migrateVictimStreams(cl, victimIdx) (migrated, total int)` —
    snapshots the victim's active streamIDs, migrates each via the existing
    `migrateStream`, under the shared budget, returns counts for the log line.
  - Edit `tryEmergencyEvictMinStreamsSlot`: after `tryMarkDraining()` succeeds
    and before `generation.Add(1)`/`handleSlotDeath`, call
    `migrateVictimStreams` when `MigrateCapable()`. Enrich the existing Warn log
    with `migrated`/`killed` counts.
  - New counters wired in stats.go (below).
- **Modify:** `shadowlink/client/stats.go`
  - `EmergencyEvictMigratedTotal` (streams saved by the preemptive pre-eviction
    migration). Prometheus exposition mirroring `DrainForceEvictedActiveTotal`.
  - **No `killed` counter.** (Revised after opus review, finding 2c.) The streams
    the preemptive pass does NOT move are not "killed" — they fall through to
    `handleSlotDeath`, which (when migration is negotiated) attempts a grace
    RESUME-on-death for each, counted by the existing
    `MigrateResumeOnDeathOK/Fail`. A separate `killed` counter would
    double-count streams the teardown's RESUME still rescues. The eviction log
    line instead reports `remaining` (streams handed to teardown) for
    observability without inventing a misleading counter.
- **Test:** `shadowlink/client/ws_pool_drain_test.go` (extend existing
  emergency-evict test cluster).

## Behavioral contract

```
tryEmergencyEvictMinStreamsSlot(cl, skipIdx):
  pick bestIdx = slotReady cell (≠skipIdx) with min streams.Load()   # unchanged
  if none: return false                                              # unchanged
  victim = slots[bestIdx]
  if !victim.tryMarkDraining(): return false                         # unchanged (lost race)
  streamsAtEvict = victim.streams.Load()                             # for logging

  migrated, total := 0, 0
  if MigrateCapable():
      migrated, total = migrateVictimStreams(cl, bestIdx)            # NEW: bounded
  killed := victim.streams.Load()                                    # whatever did NOT migrate

  EmergencyEvictMigratedTotal += migrated
  EmergencyEvictKilledTotal   += killed
  log.Warn("emergency-evicted slot with active streams",
           evicted_slot=bestIdx, for_drain_of=skipIdx,
           streams_at_evict=streamsAtEvict, migrated=migrated, killed=killed)

  victim.generation.Add(1)                                           # unchanged
  handleSlotDeath(cl, bestIdx, deathCauseDrainTeardown)              # unchanged
  return true                                                        # eviction ALWAYS completes
```

`migrateVictimStreams(cl, victimIdx)`:
```
deadline = now + emergencyEvictMigrateBudget
snapshot victimIDs = [streamID for entry in streamMap where entry.slotIdx == victimIdx]
total = len(victimIDs)
migrated = 0
for sid in victimIDs:
    if now > deadline: break          # bounded — do not stall startDrain
    before = streamMap.Load(sid).slotIdx
    migrateStream(sid)                # reuse: CAS-guarded, soft-degrade, counter-transfer
    after = streamMap.Load(sid)
    if after present AND after.slotIdx != victimIdx AND after.slotIdx != before:
        migrated++                    # rebind moved it off the victim
return migrated, total
```

Counting note: `migrated` is derived from the binding actually leaving the
victim (post-condition of a successful `rebindStreamToSlot`), not from
`migrateStream`'s internal result — `migrateStream` has no return value and may
stand down on the single-winner CAS (already-migrating by the watchdog), in
which case the stream still legitimately left the victim and should count as
saved. `killed` is read as `victim.streams.Load()` AFTER the loop — the exact
residual the upcoming `handleSlotDeath` will break.

## Why no env flag

The behavior is strictly an improvement on an existing, default-on path
(`SHADOWLINK_GRACEFUL_DRAIN` ON since 2026-05-20) and is further gated by
`MigrateCapable()` (negotiated + hysteresis-healthy). If migration is
unavailable, `migrateVictimStreams` is skipped and behavior is identical to
today. No new opt-out surface needed; emergency disable of the whole feature is
already `SHADOWLINK_GRACEFUL_DRAIN=0`, and migration disable is the existing
hysteresis / non-negotiated path.

## Constants

```go
// emergencyEvictMigrateBudget bounds the TOTAL time spent migrating a victim's
// streams before its forced teardown, so startDrain (which runs this
// synchronously) never stalls the rotation watchdog. One migrateAckTimeout
// worth of budget covers the common 1-3 streams/victim; streams not moved
// within it die with the cell (= pre-2026-06-01 behavior).
const emergencyEvictMigrateBudget = migrateAckTimeout
```

(`migrateAckTimeout` is the existing per-MIGRATE ack window; one budget unit lets
the typical low-stream victim — tier-2 picks the MIN-streams cell — clear within
a single round-trip window while strictly bounding the worst case.)

## Testing strategy (TDD)

Extend the emergency-evict test cluster in `ws_pool_drain_test.go`. All use the
existing `migrateSendHook` to intercept MIGRATE sends (no real wire).

1. **TestEmergencyEvict_MigratesActiveStreamsBeforeKill** — victim with 2 active
   streams, ≥1 younger slotReady target available, `migrateSendHook` returns OK.
   Assert: both streams' streamMap bindings moved OFF the victim;
   `EmergencyEvictMigratedTotal += 2`; `EmergencyEvictKilledTotal += 0`; victim
   torn down (slots[bestIdx] nil); `DrainForceEvictedActiveTotal += 1`.

2. **TestEmergencyEvict_KillsUnmigratableStreams** — victim with active streams
   but NO younger target slot (all others draining/dead). Assert: streams NOT
   moved; `EmergencyEvictMigratedTotal += 0`;
   `EmergencyEvictKilledTotal += streamsAtEvict`; victim STILL torn down
   (eviction completes); return true.

3. **TestEmergencyEvict_PartialMigrationUnderBudget** — hook delays one stream
   past the budget (or returns timeout for one, OK for the other). Assert:
   migrated count == streams that actually left victim; killed == residual;
   eviction completes.

4. **TestEmergencyEvict_SkippedWhenMigrationIncapable** — `MigrateCapable()`
   false (not negotiated). Assert: no migration attempted; behavior identical to
   pre-change (all streams killed, counters Migrated+=0 Killed+=streamsAtEvict),
   eviction completes. Guards the no-flag fallback.

5. **TestEmergencyEvict_VictimMarkedDrainingBeforeMigration** — assert the
   victim is in slotDraining when `migrateSendHook` fires (capture victim state
   inside the hook), proving selectYoungTargetSlot can't pick it as a self-target
   and AssignStream is fenced off.

Each test follows red→green: write the assertion against the new
method/counters first, run to see it fail (method undefined / counter zero),
implement minimal, verify green. Existing emergency-evict tests
(`TestStartDrain_EmergencyEvictsMinStreamsWhenOverAged`,
`_DoesNotEmergencyEvictWhenTargetYoung`) must stay green — they use no younger
target / non-over-aged target, so migration is a no-op or not reached.

## Race / concurrency

- Runs inside `startDrain`, same goroutine that already mutates pool slots under
  the established drain contract. `migrateStream` is the same primitive the
  watchdog calls concurrently; its single-winner CAS resolves a watchdog-vs-
  emergency overlap on the same stream (one wins, the other stands down).
- `migrateVictimStreams` only READS the streamMap to snapshot IDs and re-reads
  bindings for counting; it mutates nothing the migrate primitive doesn't
  already own.
- Must pass `go test -race -count=3 ./client/` on Linux (Windows dev has no
  gcc — race run happens on pl1, per existing Bug#9 workflow).

## Relationship to RESUME-on-death (opus review finding 2c)

`handleSlotDeath(deathCauseDrainTeardown)` ALREADY attempts a grace RESUME for
each surviving stream when migration is negotiated. So why a separate preemptive
pass here? Because the two operate at different moments:

- **Preemptive MIGRATE (this design)** runs while the victim is `slotDraining`
  but its TCP is still UP — the stream moves cleanly, before any Close, with no
  dependency on the server's orphan grace window.
- **RESUME-on-death** runs AFTER `transport.Close()` — reactive, relying on the
  server having held the relay in its orphan window.

The preemptive pass is strictly better for streams that have a younger slot to
move onto NOW (eliminates the close→RESUME gap). Whatever it cannot move falls
through to RESUME-on-death — so the two compose, they do not conflict, and we do
NOT emit a `killed` counter that would double-count RESUME-rescued streams.

## Worst-case stall (opus review finding 3)

`migrateVictimStreams` runs synchronously inside `startDrain`. Each
`migrateStream` may block on its `sendMigrate` ack window
(`migrateAckTimeout`). The budget is checked BETWEEN streams, so a victim with N
streams and a silent server stalls at most ONE `migrateAckTimeout` (the first
stream's block) before the next `time.Now().After(deadline)` check breaks the
loop. So worst-case added latency to `startDrain` ≈ 1× `migrateAckTimeout`,
independent of N. Acceptable: it is bounded, happens only on the rare over-aged
emergency path, and the alternative (killing the streams immediately) is the
pre-2026-06-01 behavior we are improving on.

## Out of scope

- Raising pool headroom (alive 11-15 vs size 8) — separate tuning lever, not
  this fix. This design eliminates the loss at the eviction site itself, which
  is the architecturally correct place regardless of headroom.
- Tier-1 (idle eviction) — already lossless, untouched.
