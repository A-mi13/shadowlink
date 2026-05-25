# WS Pool — Uniform Cells Architecture (W1 fix)

**Date:** 2026-05-20
**Status:** Design — supersedes pairing rules in
`2026-05-19-ws-pool-graceful-drain-design.md`
**Trigger:** canary 2026-05-19 (`SHADOWLINK_GRACEFUL_DRAIN=1`, 23 min)
showed 326 deferred drains after the first 2 succeeded — storm brake stuck
on `non_ready_slots=2` due to broken `i+poolSize` pairing assumption.

## 1. Problem statement

The 2026-05-19 graceful-drain design introduced a `2*poolSize` slice with
`[0, poolSize)` "primary" and `[poolSize, 2*poolSize)` "reserve" ranges.
It then introduced two contradictory rules:

- **§Reserve slot promotion to primary (line 101):** "primary and reserve
  cells circulate". After teardown, the freed cell can host any role.
- **§Fix C3 (line 481-499) / `countNonReadySlots`:** "matching reserve
  cell = `i + p.poolSize`". Storm brake assumes fixed pairing.

`claimFreeReserveSlot()` follows the **first** rule (first-nil scan in
the reserve range — no pairing constraint). `countNonReadySlots()`,
`rotationWatchdogSweep`, `sendKeepaliveToAllSlots`, `rotateMinLoadedSlot`,
`StartReader`, `emitHealthSummary` follow the **second** rule (paired
indexing or `[0, poolSize)` iteration).

When canary drained primary[6]→reserve[8] and primary[2]→reserve[9],
the result was:

| Cell | State |
|---|---|
| slots[0..1,3..5,7] (primary) | slotReady |
| **slots[2,6]** (primary) | **nil** |
| **slots[8,9]** (reserve) | **slotReady** |
| slots[10..15] (reserve) | nil |

`countNonReadySlots()` for slots[2]: probes `slots[2+8] = slots[10] = nil`,
slots[10] is not slotReady → counts slots[2] as a capacity gap. Same
for slots[6] → slots[14]. **n=2 forever**, storm brake threshold=2 →
every subsequent drain attempt deferred.

The bug is not in `countNonReadySlots()` alone — it is the **pairing
assumption** spread across 9 distinct sites in `ws_pool.go` + the spec
itself. Point-fixing `countNonReadySlots()` leaves 8 other sites with
the same broken assumption (`StartReader` won't restart reserve readers
after engine reset, `rotateMinLoadedSlot` won't anti-FP rotate cells that
were once reserves, `sendKeepaliveToAllSlots` won't keepalive reserve
cells acting as primaries, etc.).

## 2. Architectural decision: uniform cells

**All `2*poolSize` cells are equivalent.** No primary/reserve
distinction. The slice is just a "slot table" with `2*poolSize` capacity.

Each cell has its own lifecycle (`slotReady`/`slotDraining`/`slotConnecting`/
`slotDead` or `nil`). No cell is "more primary" than another. Index
position is purely an addressing key for `streamMap`; it carries no
behavioral meaning.

### 2.1 Capacity, not gap-counting

Storm brake switches from "count non-ready" to "count ready capacity":

```
readyCapacity := <number of slotReady cells across the whole slice>
floor := poolSize - maxConcurrentDrains
if readyCapacity < floor {
    defer drain  // would drop capacity below safe floor
}
```

**`maxConcurrentDrains` is derived, not literal.** The default formula:

```
maxConcurrentDrains := max(1, ceil(poolSize * rotationStormBrakeFraction))
```

where `rotationStormBrakeFraction = 0.25` (unchanged from existing code,
ws_pool.go:485). Construction-time invariant:
`maxConcurrentDrains < poolSize` AND `floor >= ceil(poolSize/2)`. For
`poolSize=8`: floor = 6 (75%). For `poolSize=4`: floor = 3 (75%). For
`poolSize=2`: floor = 1 (50% — minimum allowed by invariant). The literal
constant `2` from the old `rotationStormBrakeThreshold()` is replaced by
the formula — keeping the same numeric value at `poolSize=8` but scaling
honestly at smaller pool sizes.

No more `i + poolSize` arithmetic anywhere.

#### 2.1.0 TOCTOU — atomic gate via `inflightDrains` counter (W3)

The simple read-check-act in `startDrain` (`readyCapacity` → compare →
`tryMarkDraining`) is racy: 3 concurrent drain triggers (age + byte +
anti-FP) can all read `readyCapacity = floor`, all pass the check, all
CAS-succeed — momentarily dropping capacity below floor by N drains.

Fix: maintain `p.inflightDrains atomic.Int32`. `startDrain` does:

```
inflight := p.inflightDrains.Add(1)
defer func() { if !committed { p.inflightDrains.Add(-1) } }()
if int(inflight) > maxConcurrentDrains {
    // Lost the race — back out.
    return /* deferred */
}
// ... existing readyCapacity check + tryMarkDraining ...
committed = true  // hand-off counter ownership to drainWatchdog
```

`drainWatchdog` MUST guarantee `inflightDrains.Add(-1)` on **every** exit
path. Implementation uses `defer p.inflightDrains.Add(-1)` at the top
of `drainWatchdog` so context-cancel, panic, natural finish, and hard
cap all decrement exactly once (NEW-1). This gives a hard upper bound
on concurrent drains independent of the capacity check — no TOCTOU
window AND no counter leak across abnormal exits.

`readyCapacity` check is kept as a SECONDARY gate (catches catastrophic
state where many natural failures depressed capacity below floor without
inflating `inflightDrains`).

#### 2.1.1 Bootstrap exemption — surviving catastrophic capacity loss

If the initial `Connect()` fan-out has multiple failures (3+ slots fail
to handshake), `readyCapacity` can stay below `floor` for the entire
session — reconnectLoop is the only recovery path, and the storm brake
must NOT block reconnects (it doesn't — reconnects are driven by
`handleSlotDeath`, not `startDrain`). But it WILL block all drains
indefinitely, including age-driven drains that would have happened in
healthy state.

Rule: when storm brake defers a drain AND `readyCapacity < poolSize/2`
(catastrophic state — pool is more than half dead), set the slot's
`nextDrainAttemptNs` to `now + 5 * drainRevertBackoff` (150s) instead of
`now + drainRevertBackoff` (30s). This avoids tight retry loops in
catastrophic state while still allowing healthy state to react to a
freed cell within one watchdog tick (5s).

`Stats.DrainStormBrakeEngagedTotal` counter (S6) is incremented on every
deferral so the canary can quantify the engagement rate.

### 2.2 Free-cell scan

`claimFreeSlot()` (renamed from `claimFreeReserveSlot()`) scans the
**entire** slice (from index 0) for the first nil cell. Once a primary
cell becomes nil post-teardown, it is immediately a candidate for the
next drain's replacement, exactly as the spec line 101 intended. The
slice no longer "swiss-cheeses" — torn-down cells are recyclable.

#### 2.2.1 Locking semantics — invariant unchanged

`claimFreeSlot` MUST hold `reserveMu` for the entire scan + placeholder
install. The widening from `[poolSize, 2*poolSize)` to `[0, 2*poolSize)`
does **not** weaken the existing invariant: every write to `p.slots[i]`
is under `reserveMu`. Writers under that lock today:

- `connectSlot` install (ws_pool.go:1306-1308) — when bringing up any
  slot (initial fan-out OR drain replacement).
- `handleSlotDeath/drainTeardown` nil-write (ws_pool.go:2538-2540).
- `claimFreeSlot` placeholder install (this function).
- **NEW: `reconnectLoop` install (W7 fix).** `reconnectLoop` calls
  `connectSlot` which already takes `reserveMu` — but it does NOT check
  the cell's pre-install state. After this design, post-teardown cells
  are recyclable. If a drain has installed a fresh slot at idx 3 (via
  `claimFreeSlot` + `connectReserveSlot`) while a stale `reconnectLoop(3)`
  goroutine from a much earlier death is still running, the
  `reconnectLoop` install would silently overwrite. Mitigation:
  `reconnectLoop` MUST verify `p.slots[idx] == nil` under `reserveMu`
  before calling `connectSlot`. If the cell is non-nil (recycled by a
  drain), `reconnectLoop` exits cleanly with no install. See §2.3.1.

`claimFreeSlot` returns -1 if no nil cell exists in the whole slice
(swiss-cheese with all 2*poolSize cells in non-nil states). Caller
(`startDrain`) treats -1 as "defer drain with revert backoff" exactly
as today.

#### 2.2.2 reconnectLoop recycle guard

`reconnectLoop(idx)` runs in background after `deathCauseNatural`. By
the time backoff + meltdown-cooldown clear, the cell at `idx` may have
been recycled by a drain (this is the whole point of "cells circulate").
Implementation:

```
p.reserveMu.Lock()
if p.slots[idx] != nil {
    p.reserveMu.Unlock()
    p.log.Info("WS pool reconnect short-circuited — cell recycled by drain",
        "slot", idx)
    return
}
p.reserveMu.Unlock()
// connectSlot reacquires reserveMu for its own install
err := p.connectSlot(p.ctx, idx)
```

The TOCTOU window (lock release → connectSlot lock reacquire) is
acceptable because `claimFreeSlot` also takes the same lock — if it
claims `idx` in the window, `connectSlot` will overwrite its placeholder.
Both paths end in a valid `slotConnecting` cell; the difference is
which goroutine "owns" the slot afterwards. The drain-driven path is
preferable (it has a `connectReserveSlot` follow-up that handles the
reader); the `reconnectLoop` path is a fallback. To avoid the silent
overwrite, the guard above resolves it on the `reconnectLoop` side.

#### 2.2.3 Slice-full eviction policy (long-running session deadlock fix)

The 5h+ canary on 2026-05-20 (2.96 GB downlink + 0.79 GB uplink over
log `nixavpn-graceful-drain-20260520-110323.log`) exposed an
architectural deadlock that uniform cells alone do not resolve: after
the first 23 minutes the pool reached `alive=16 dead=0 empty=0` (every
cell in `p.slots` occupied by a live slot) and stayed there for 5+
hours. During that window `claimFreeSlot` returned -1 on every drain
attempt → 9410 `"WS pool drain skipped — no free cell"` warnings, 0
successful drains, 0 natural finishes. Pool stayed functional (101+
active streams, 0 meltdowns, 0 decrypt_fails) but the
anti-fingerprinting / anti-TSPU goal was not met — slot TLS
fingerprints stayed stable for the full session.

**Circular dependency** (verified in code at `ws_pool_drain.go:28-40`
+ `ws_pool.go:2539`):

1. `claimFreeSlot()` scans for the first nil cell. With every cell
   non-nil → returns -1.
2. The only path that nils a cell is
   `handleSlotDeath(deathCauseDrainTeardown)`.
3. `deathCauseDrainTeardown` fires only from `drainWatchdog`.
4. `drainWatchdog` runs only after `startDrain` cleared gate 7
   (claimFreeSlot ≥ 0).
5. Therefore: if all 16 cells stay alive (no reader error → no
   `deathCauseNatural` → no `reconnectLoop` "ageing"), age-rotation
   is locked forever.

Stable network in quiet hours keeps every reader healthy, so the
chain never restarts on its own.

**Fix**: when `claimFreeSlot() == -1`, scan `p.slots` for an idle
`slotReady` cell (`streams.Load() == 0`) and force-tear it down via
`handleSlotDeath(deathCauseDrainTeardown)`. Then re-call
`claimFreeSlot`, which now finds the freed cell and the drain
proceeds normally.

```
newIdx := p.claimFreeSlot()
if newIdx < 0 {
    if p.tryForceEvictIdleSlot(cl, oldIdx) {
        Stats.DrainForceEvictedTotal.Add(1)
        newIdx = p.claimFreeSlot()
    }
}
if newIdx < 0 {
    // fall through to defer-with-revert
    ...
}
```

**Two-tier eviction policy (canary 2026-05-20 #174716 update).**

The first canary of the slice-full eviction fix (run 174716, 2h 6m)
exposed a flaw in the "typical avg ~2 streams/slot leaves several
idle" assumption: under real production load (speedtest + YouTube)
the active-stream distribution was 20-94 streams across 16 cells,
**always ≥1 stream/cell**. The idle-only tier never found a
candidate; `force_evicted_total=0` and the deadlock persisted
(3192 "no free cell" warnings over 1h 51m). Plain idle-only is
insufficient under dense load.

The eviction policy therefore has **two tiers**:

**Tier 1 — idle-only (always tried first).**
Scan for a `slotReady` cell with `streams.Load() == 0`. If found,
CAS to slotDraining, recheck streams (race vs AssignStream),
bump generation, tear down. Counter:
`DrainForceEvictedTotal` (`shadowlink_slot_drain_force_evicted_total`).

This tier is the preferred path. It costs zero user-visible
disruption. In quiet hours (avg ~1 stream/slot, several cells
idle) tier 1 carries the entire eviction load.

**Tier 2 — emergency min-streams (gated on drain-target age).**
If tier 1 fails AND the drain target's slot age exceeds
`emergencyEvictAgeMultiplier × maxSlotAge` (currently 2× = ~4 min
at default 2-min maxSlotAge), scan for the `slotReady` cell with
the lowest `streams.Load()` (minimizes collateral damage) and
evict it even if `streams > 0`. Counter:
`DrainForceEvictedActiveTotal`
(`shadowlink_slot_drain_force_evicted_active_total`).

Tier 2 explicitly accepts killing user-visible streams. The
rationale: at the 2× threshold the drain target has been waiting
through two full rotation periods. Continued delay leaves the
underlying TLS fingerprint stable for 4+ minutes — the lower
bound of the TSPU ML classifier observation window for active
fingerprint correlation. **Anti-fingerprint correctness is a
continuous, hard requirement; one TCP-stream-level reconnect on
the SOCKS5 client is a soft, recoverable UX cost.** The tradeoff
explicitly favors the security goal under sustained dense load.

**Threshold tuning.** 2× was chosen because the canary 174716 logs
show drain targets reaching ages of 4-6 min during the stuck
window. A 2× threshold (=4 min) catches that regime promptly
without firing during normal staggered rotation (where ages stay
well under 1× maxSlotAge by design — see slotStaggerOffset).
3× and 5× were considered and rejected as too lax — they would
allow up to 10 min of stable fingerprint, well inside the TSPU
window.

**No env flag.** Tier 2 is unconditionally on alongside Tier 1.
The full mechanism is governed by `SHADOWLINK_GRACEFUL_DRAIN`;
opt-out routes back through legacy hard-rotation which has its
own (less graceful) stream-killing semantics. A separate flag
for tier 2 was considered and rejected: anti-fingerprint
correctness must not be partially toggleable.

**Min-streams victim selection.** Among non-target slotReady
cells, tier 2 picks the one with smallest `streams.Load()`.
Deterministic — first cell in slice order wins ties. Single
O(2*poolSize) scan; no additional lock pressure since the
selection is one read pass + one CAS.

**Tier 1 vs 2 ordering rationale.** Even when the target is
over-aged, tier 1 (idle) is tried first because idle costs zero
streams. The tier 2 trigger is "no idle exists", not "target
over-aged" alone; the age gate only authorizes the kill, it
does not override the preference for zero-disruption when
available.

**Fallback when every cell is busy.** If no idle cell exists, fall
through to the existing defer-with-revert path:

- CAS the oldSlot state back to `slotReady`.
- Set `oldSlot.nextDrainAttemptNs = now + drainRevertBackoff`.
- Drop the inflight counter (deferred function handles this).
- Caller (the watchdog sweep) retries on the next tick.

This degrades gracefully: rotation pauses for ~30s under peak load,
but no streams are killed. When load shifts (typically within
minutes) the next sweep finds an idle cell and rotation resumes.
Killing a busy slot to "make rotation move" was considered and
rejected — anti-fingerprinting is a continuous-improvement goal, not
a hard deadline; an interrupted flow is a worse user outcome than a
delayed rotation.

**Race vs AssignStream.** `AssignStream` does not take `reserveMu`
— it filters on `slotReady` then calls `streams.Add(1)` unlocked.
A naive evictor that reads `streams.Load() == 0` under `reserveMu`,
releases the lock, then tears down can still kill an active stream
that landed in the unlock-window. Mitigation:

1. CAS `slotReady → slotDraining` first. After the CAS,
   `AssignStream`'s next picker pass excludes this slot
   (`getState() != slotReady` filter on line 1833 of `ws_pool.go`).
2. Re-load `streams.Load()` after the CAS. The Go memory model
   guarantees that any `streams.Add(1)` ordered before the CAS
   (via the AssignStream picker observing slotReady) is visible
   here. If we see non-zero, revert the slot to `slotReady`
   (CAS back) and continue scanning for another candidate. Do
   not evict.

This double-check closes the window without forcing AssignStream's
hot path under a lock. The cost is one extra atomic load per
eviction attempt; the revert path is rare (only triggers under
true contention).

**Generation bump before teardown.** `tryForceEvictIdleSlot` calls
`victim.generation.Add(1)` immediately before `handleSlotDeath`,
matching the contract in `drainWatchdog.tearDown`. Without the
bump, when `handleSlotDeath` closes the victim's transport, the
slotReader observes the read error as "natural" — inflating
`Stats.ReaderExits` and `Stats.IncFrameAnomaly(...)` counters with
false-positive death attributions (lines 2226 + 2235 of
`ws_pool.go`). The generation bump trips `shouldExitReader` so
the reader exits silently.

**Counter wiring.** `Stats.DrainForceEvictedTotal` (new in §4.3) is
incremented exactly once per successful eviction. A non-zero rate
in field telemetry is the expected steady state during long-running
sessions and is the signal that the deadlock fix is doing its job;
a zero rate over a 2h+ session with `alive=16` means either no
rotation was attempted (suspicious) or the pool never got fully
populated. The matching Prometheus line is
`shadowlink_slot_drain_force_evicted_total`.

**Counter relationship.** `DrainForceEvictedTotal` is bounded above
by `DrainStartedTotal`: every successful eviction is followed by a
successful drain start. In steady state the ratio is typically
≤ 1 (most drains find a free cell organically; only the
slice-full minority needs eviction).

### 2.3 All iterations use `range p.slots`

The 4 sites that iterate `[0, poolSize)` become unified loops over the
whole slice:

| Site | Before | After |
|---|---|---|
| `rotationWatchdogSweep` | `[0, poolSize)` | `range p.slots`, skip nil/non-Ready |
| `sendKeepaliveToAllSlots` | `[0, poolSize)` | `range p.slots`, skip nil/non-Ready |
| `rotateMinLoadedSlot` | `[0, poolSize)` | `range p.slots`, pick min-loaded Ready |
| `StartReader` (re-entry) | `[0, poolSize)` | `range p.slots`, start reader if none |

`Connect()` initial fan-out **stays** at `[0, poolSize)`. This is NOT
an asymmetry in the uniform-cells model — it is the initial fan-out
target. Justification:

1. **Stagger math.** `staggerDelay` (300ms) × `poolSize` (8) = 2.4s
   total bring-up under viaCF mode. Fanning out 16 cells would double
   this to 4.8s, slowing first-stream-ready time without compensating
   benefit. The extra 8 cells exist as drain replacement capacity, not
   initial capacity.
2. **No race with drain.** At `Connect()` time no drain has fired (the
   first watchdog tick is `MaxSlotAge` minutes in the future), so
   `claimFreeSlot` cannot race with the fan-out — there are no
   in-flight drains during initial bring-up.
3. **Reconnect race covered by §2.2.2.** If an initial `connectSlot(3)`
   fails, `reconnectLoop(3)` runs. If by then a drain has recycled
   cell 3, the recycle guard in §2.2.2 short-circuits the reconnect.
   No silent overwrite.

The `Connect()` fan-out is the **one** justified `[0, poolSize)` use
remaining post-refactor (acceptance #2 whitelist).

### 2.4 emitHealthSummary

Becomes uniform: counts by state across the whole slice. Removes the
`if i < p.poolSize { dead++ }` branch for nil cells. New schema:

- `alive` = count of slotReady cells (was: primary or reserve in Ready).
- `dead` = count of slotDead cells (no longer includes nil cells).
- `empty` = count of nil cells (NEW field).
- `connecting`, `draining` — unchanged.

`alive + dead + empty + connecting + draining == 2*poolSize` (invariant).

Old ops dashboards using `dead` to track "nil primaries" need migration;
the field now means literally `slotDead`. Empty cells (just-freed) are
not failures.

### 2.4.1 Slot reader frame validation (W5)

After drainTeardown the streamMap entries for the torn slot are deleted
(handleSlotDeath:2490). The freed streamIDs may be reassigned to new
streams on a different slot. A late inbound frame from the torn slot's
transport (already-buffered bytes after `transport.Close()`) could reach
`slotReaderWithClient` and try to look up the streamID — finding the
NEW mapping → routing the frame to a wrong-session stream.

Rule: `slotReaderWithClient` MUST validate that the streamMap lookup
for an incoming frame returns its OWN idx before dispatching. If not
(different idx), drop the frame silently and continue. Pseudocode:

```
if mappedIdx, ok := p.streamMap.Load(streamID); ok {
    if mappedIdx.(int) != idx {
        // Stale frame from a torn-down slot reaching us late. Drop.
        Stats.StaleFrameDroppedTotal.Add(1)
        continue
    }
    // ... dispatch as today ...
}
```

Counter `shadowlink_stale_frame_dropped_total` for ops visibility — a
non-zero rate indicates teardown-then-reuse churn (expected at low
rates during heavy rotation; sustained high rate is a bug).

### 2.4.2 Storm-brake revert backoff (W6)

Current `drainRevertBackoff = 30s`. When storm brake defers, the slot's
`nextDrainAttemptNs` is set 30s into the future. If 6 cells defer
simultaneously and only 2 can drain at a time, cells 3-6 wait 30s before
their next eligibility check — meanwhile their `MaxSlotAge` (~2 min)
keeps ticking, pushing them past the TSPU kill window the drain was
supposed to beat.

Fix: split the backoff into two cases.

- **Storm-brake-only deferral** (`readyCapacity >= poolSize/2`): use
  `drainStormBrakeBackoff = rotationWatchdogInterval` (one watchdog tick;
  currently 5s — `drainStormBrakeBackoff` is DERIVED from the watchdog
  interval, NOT a magic literal, so any future tuning of the sweep
  cadence keeps backoff aligned). Cheap to re-check on the next sweep —
  `readyCapacity()` is an O(2*poolSize) integer compare.
- **Catastrophic deferral** (`readyCapacity < poolSize/2`): use
  `5 * drainRevertBackoff = 150s` per §2.1.1. Avoid tight retry loops
  while reconnectLoop heals capacity.

`drainRevertBackoff = 30s` is retained for the OTHER case where it
still applies: `claimFreeSlot` returns -1 (no free cell, even though
capacity check passed) — that genuinely needs longer backoff because
the slice is full and only natural teardowns will free space.

### 2.5 SessionForStream fallback

Currently restricted to `[0, poolSize)`. The new design **removes the
fallback entirely** — return nil if `streamMap[streamID]` is not present
or the mapped cell is nil/non-Ready.

**Caller-side audit (confirmed nil-safe):**

| Site | Behavior on nil | Conclusion |
|---|---|---|
| `client.go:710` (CloseStream) | session ignored; defer ReleaseStream still fires | safe |
| `proxy/socks5/tcp.go:495` | `if session == nil { conn.Write(ReplyConnRefused); return }` | safe |
| `proxy/socks5/tcp.go:531` | `if session == nil { conn.Write(ReplyConnRefused); return }` | safe |
| `proxy/socks5/tcp.go:565` | `if session == nil { return }` | safe |

The fallback existed for a hypothetical race window that doesn't actually
exist (every legitimate caller already nil-guards). Removal is safe and
correct architecturally — the server's per-slot crypto keying means the
fallback would have produced silent decrypt failures, not graceful
behavior. Audit listed this as B10/INFO; closing alongside the main
refactor because the new "uniform cells" framing makes the
`[0, poolSize)` restriction nonsensical anyway.

## 3. The streamChans-on-drain-teardown question

The 2026-05-19 spec contained a second internal contradiction:

- §`deathCauseDrainTeardown` (line 305-316): "do NOT close streamChans —
  transport.Close gives network EOF".
- §Race conditions fix #4 (line 357-361): "drainTeardown simplifies:
  close streamChans like deathCauseNatural".

**Current production code follows the FIRST** (ws_pool.go:2491:
`if cause != deathCauseDrainTeardown { close(ch) }`). The
`TestHandleSlotDeath_DrainTeardownDoesNotCloseStreamChans` regression
test correctly asserts this not-closed behavior.

**Architectural decision: CHANGE the behavior — close streamChans on
drainTeardown.** This is a deliberate behavior shift, not a test fix.
The test must be inverted; production code must be updated.

Reasons:
1. **Determinism.** `close(ch)` is synchronous and observable
   immediately by every reader. `transport.Close()` → network EOF is
   asynchronous — depends on whether a stream goroutine is currently
   in `ReadMessage()` vs busy elsewhere. A reader stuck in
   `decoder.Decode()` on bytes already buffered would NOT see EOF
   until those bytes drained, which can be 100+ ms.
2. **drainTeardown happens only after either (a) all streams self-
   completed (natural finish, streamChans already empty/closed)** or
   **(b) hard cap fired with remaining streams (6 streams in canary)**.
   In case (a) close is a no-op. In case (b) the streams have ALREADY
   exceeded their natural lifetime by the drain hard cap (90s) — they
   are stalled, and the only honest signal we can give SOCKS5 layer is
   "your stream is gone, retry". Network EOF would deliver the same
   message but later and racier.
3. **HTTP/2 GOAWAY semantics**: in real HTTP/2, GOAWAY allows in-flight
   streams to finish. Our equivalent of "allow to finish" is the
   `drainHardCap` polling window — after that, streams that did NOT
   finish are explicitly killed. Closing streamChans is the explicit
   kill. The `transport.Close()` network-EOF route is the implicit
   kill, with worse observability and no determinism.

Implementation:
- `handleSlotDeath` `streamMap.Range` loop: close streamChans for
  drainTeardown the same way it does for natural/preemptive — remove the
  `if cause != deathCauseDrainTeardown` exclusion entirely.
  **Order is load-bearing:** `streamMap.Delete(streamID)` MUST run
  BEFORE `close(ch)`. The no-underflow invariant (next §) relies on
  `ReleaseStream`'s `LoadAndDelete` seeing `ok=false` for any stream
  whose mapping has already been deleted. Reversing this order opens a
  window where a late `ReleaseStream` decrements counts that
  `streams.Store(0)` is about to zero — underflow returns. Pin via the
  test `TestHandleSlotDeath_NoUnderflowOnLateRelease`.
- `slot.streams.Store(0)` AFTER the close loop, also for drainTeardown.
  **Underflow analysis:** `ReleaseStream` uses `streamMap.LoadAndDelete`
  (ws_pool.go:1961) — atomic. The handleSlotDeath loop calls
  `streamMap.Delete(streamID)` BEFORE `close(ch)`. After that, any
  late `ReleaseStream` call for the same streamID will see `ok=false`
  from LoadAndDelete and become a no-op — never reach
  `streams.Add(-1)`. So `streams.Store(0)` cannot underflow. The
  warning comment at ws_pool.go:2502-2506 is obsolete (it predates the
  `LoadAndDelete` semantics).
- Update `TestHandleSlotDeath_DrainTeardownDoesNotCloseStreamChans` to
  invert the assertion: assert that streamChans **are** closed. Rename
  to `TestHandleSlotDeath_DrainTeardownClosesStreamChans`.
- Add `TestHandleSlotDeath_NoUnderflowOnLateRelease` — fire drainTeardown
  with 5 streams assigned, then call `ReleaseStream` for all 5 after
  teardown completes. Assert `slot.streams.Load() == 0` (not -5).

## 4. Tests to rewrite

The audit listed 6 tests using paired layouts that silently pass. Each
is rewritten to use an **un-paired** layout that exercises the bug:

| Test | Old layout | New layout |
|---|---|---|
| `TestCountNonReadySlots_IgnoresEmptyReserve` | primary[0] draining + reserve[4] connecting (parity 0↔4) | Rewritten as `TestReadyCapacity_CountsAllReady`: primary[6] ready + reserve[9] ready (no pairing). Asserts capacity=2. |
| `TestStartDrain_StormBrakeSingleDrain` | primary[0] + reserve[8] | primary[6] + reserve[9] (canary scenario) |
| `TestStartDrain_StormBrakeTwoConcurrentEngages` | primary[0,1] + reserve[8,9] | primary[6,2] + reserve[8,9] (exact canary scenario) |
| `TestClaimFreeReserveSlot_PrefersFirstNil` | first claim → idx=4 | Add post-teardown claim: after slots[3]=nil from teardown, next claim must return idx=3 (any-cell scan) |
| `TestHandleSlotDeath_DrainTeardownClearsCell` | teardown primary[0], assert nil | Keep, plus add follow-up claim returning idx=0 |
| `TestDrainWatchdog_NaturalFinish` | unchanged | unchanged (not pairing-dependent) |

Plus new tests:

- `TestCanaryScenario_MismatchedPairs`: exact canary state (primary[6,2]
  nil, reserve[8,9] ready, all other primaries ready). Assert
  `readyCapacity=8`, storm brake disengaged, next drain proceeds.
- `TestRecycle_AfterAllReservesOccupied` (was `TestSwissCheeseRecovery`,
  fixed off-by-one — see W4): drain 8 cells in sequence so all 8 reserve
  slots are occupied AND all 8 primary cells are nil. Then drain the 9th
  → claim MUST land in `[0, poolSize)`, recycling a primary cell that
  has been teardown'd. With only 4 drains the test was permissive (any
  nil reserve still satisfies first-nil scan).
- `TestStartDrain_InflightCounterCaps`: fire 4 concurrent
  `startDrain(idx)` for distinct idx with `maxConcurrentDrains=2`.
  Assert exactly 2 transition to `slotDraining`, 2 are deferred.
- `TestStartDrain_BootstrapBackoff`: simulate `readyCapacity = poolSize/2 - 1`
  (catastrophic). Call `startDrain` → assert deferral set
  `nextDrainAttemptNs ≈ now + 5*drainRevertBackoff` (not 1×).
- `TestReconnectLoop_RecycleGuard`: pre-set `p.slots[3]` to a
  `slotReady` cell. Call `reconnectLoop(3)`. Assert short-circuit log,
  no overwrite of the existing cell.
- `TestStreamIDReuse_RejectStaleFrames`: assign stream A on slot 5,
  teardown slot 5 (drain), assign stream B on slot 7 with same
  streamID. Inject a stale frame buffered "from" slot 5's transport.
  Assert frame is dropped, not decrypted with slot 7's session.

## 4.1 State invariant (S1)

At any moment, across the full slice of `2*poolSize` cells:

```
slotReady + slotDraining + slotConnecting + slotDead + nilCells == 2*poolSize
```

Helper functions all derive from this single set of counts. Storm brake
uses `slotReady` (= `readyCapacity`). emitHealthSummary uses all five.
No function should derive cell states by indexing — only by iterating
the slice and counting.

## 4.2 connectReserveSlot failure path (S5)

If `connectReserveSlot` fails its handshake at `newIdx`, the placeholder
`*poolSlot` (slotConnecting) at that index stays until `reconnectLoop`
eventually replaces it. While `reconnectLoop` runs (potentially minutes
with meltdown cooldown), `claimFreeSlot` will NOT see this cell as nil
— capacity loss the spec was trying to avoid.

Fix: on `connectSlot` failure inside `connectReserveSlot`, drop the
placeholder back to `nil` under `reserveMu` so a fresh drain can reuse
the cell immediately. The `reconnectLoop` recycle guard (§2.2.2) will
short-circuit if a drain has already taken over by the time it runs.

```go
if err := p.connectSlot(p.ctx, newIdx); err != nil {
    p.reserveMu.Lock()
    if p.slots[newIdx] != nil && p.slots[newIdx].getState() == slotConnecting {
        p.slots[newIdx] = nil  // free for next claim
    }
    p.reserveMu.Unlock()
    p.log.Warn("WS pool reserve slot connect failed — placeholder freed",
        "slot", newIdx, "for_drain_of", oldIdx, "err", err)
    go p.reconnectLoop(newIdx)
    return
}
```

The state check (`slotConnecting`) avoids stomping on a state another
goroutine may have transitioned the placeholder into.

## 4.3 New counters (S6)

| Counter | Increment site | Purpose |
|---|---|---|
| `shadowlink_drain_storm_brake_engaged_total` | `startDrain` brake-engage branch | Canary metric — was 326 in baseline |
| `shadowlink_stale_frame_dropped_total` | `slotReaderWithClient` mismatched-idx branch | W5 visibility |
| `shadowlink_drain_inflight` (gauge) | `inflightDrains` atomic exported as Prom gauge | TOCTOU verification |
| `shadowlink_slot_drain_force_evicted_total` | `startDrain` slice-full eviction branch (§2.2.3, tier 1) | Long-running session deadlock fix — non-zero is healthy on 2h+ sessions |
| `shadowlink_slot_drain_force_evicted_active_total` | `startDrain` slice-full eviction branch (§2.2.3, tier 2) | Emergency eviction under dense load — non-zero means we sacrificed active streams to preserve anti-fingerprint rotation |

All exposed via existing `client/stats.go` hand-rolled exporter (project
does not use `prometheus/client_golang`).

## 5. Files touched

| File | Change |
|---|---|
| `client/ws_pool.go` | `countNonReadySlots` → `readyCapacity` (sign inverted, semantics changed). 4 iteration sites updated to `range p.slots`. `emitHealthSummary` schema change. `SessionForStream` fallback removed. `handleSlotDeath` drainTeardown closes streamChans. |
| `client/ws_pool_drain.go` | `claimFreeReserveSlot` → `claimFreeSlot`, scans whole slice. `startDrain` calls `readyCapacity` and inverts the comparison. |
| `client/ws_pool_test.go` | Update tests using `countNonReadySlots`. |
| `client/ws_pool_drain_test.go` | Rewrite the 6 listed tests + add 2 new canary-replay tests. Invert streamChans-close assertion. |
| `client/stats.go` | Add `EmptySlots` gauge field (optional, for ops). |
| `docs/superpowers/specs/2026-05-19-ws-pool-graceful-drain-design.md` | Mark §Fix C3 and §Reserve slot promotion contradiction RESOLVED in favor of uniform-cells. |
| `CLAUDE.md` (root + shadowlink/) | Update graceful-drain row if needed. |

## 6. Acceptance criteria

After the fix and the canary rerun:

1. **No paired indexing remains.** `grep -rn "i + p.poolSize\|i - p.poolSize\|i+poolSize\|i-poolSize"` in `client/` returns 0 hits.
2. **`p.poolSize` boundary usage is justified.** `grep -n "p.poolSize" client/ws_pool.go client/ws_pool_drain.go` is manually reviewed. Every remaining hit must fall into one of the allowed categories: `Connect()` initial fan-out (explicit primary range bring-up), `rotationStormBrakeFraction` derivation, `len(p.slots) = 2*p.poolSize` allocation, comparing capacity to `floor = p.poolSize - maxConcurrentDrains`. Any other use is a regression of pairing logic.
3. **Tests:** all `client/...` tests pass. The 6 rewritten tests use un-paired layouts. New tests added: `TestCanaryScenario_MismatchedPairs`, `TestRecycle_AfterAllReservesOccupied`, `TestStartDrain_InflightCounterCaps`, `TestStartDrain_BootstrapBackoff`, `TestReconnectLoop_RecycleGuard`, `TestStreamIDReuse_RejectStaleFrames`, `TestHandleSlotDeath_NoUnderflowOnLateRelease`.
4. **Canary rerun** (`SHADOWLINK_GRACEFUL_DRAIN=1`, `hard_cap=90s`, 20+ min): natural finish ratio **>30%** (was 0/2), storm brake engagements **<50** total (was 326), `readyCapacity >= floor` consistently after multiple drains.
5. **Baseline bug stays gone**: no "WS Pool: все reader'ы вышли" in the canary log (already true in 2026-05-19 canary).
6. `go vet ./...` clean. `go test ./client/...` 29s suite passes (or less).
7. **streamChans behavior is uniform across all death causes** — verified by `TestHandleSlotDeath_AllCausesCloseStreamChans` (new test that asserts close behavior is identical for natural, preemptive, drainTeardown).
8. **Dashboards updated:** `emitHealthSummary` schema change reflected in ops dashboards. Old `dead` field semantics (counted nil primaries) replaced by literal `slotDead` count; new `empty` field tracks nil cells. CLAUDE.md row for `SHADOWLINK_GRACEFUL_DRAIN` updated if needed.
9. **Snapshot-inconsistency window doc-updated:** `readyCapacity` doc-comment notes that the lock-free read window grew from `poolSize` to `2*poolSize` cells but the brake remains self-correcting on the next watchdog tick. No correctness regression vs current code.
10. **No `inflightDrains` underflow:** `Stats.DrainInflight` (atomic) at session end equals 0. (Verified by canary log final stats line.)

## 7. Rollback

The feature stays behind `SHADOWLINK_GRACEFUL_DRAIN=1` (off by default).
If the canary rerun shows worse behavior than 2026-05-19, user runs the
plain `connect-vpn.bat` (no env flag) and gets legacy hard-rotation. No
production user is affected — only the dev's own machine.

If we want a more granular kill switch, env flag
`SHADOWLINK_GRACEFUL_DRAIN_PAIRING=1` can re-enable the old paired
logic. **Not recommending** — the new design is strictly cleaner; if
the canary reveals a different bug we should fix it, not toggle back.

## 8. Out of scope (Phase 4 — deferred)

- Removing legacy paths (`fireRotation`, `maybeRotateSlot`,
  `legacyRotateOneSlot`, `slotRotationGraceWithActiveStreams`, the env
  flag itself).
- Refactoring `slot.index` field — currently used in a few logs, can
  stay for now (just a string in log key/value).
- Renaming `WSPoolTransport.poolSize` (still meaningful as "initial
  active slot count" / "rotation budget anchor").

These are 1-2 commits of textual cleanup with no runtime change. Doing
them in the same PR risks merge conflicts with concurrent work; defer
to a dedicated Phase 4 plan after this lands and the canary is green.
