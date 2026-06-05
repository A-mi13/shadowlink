# Pool Capacity-Dip Fix — Design (2026-06-01)

**Goal:** Eliminate the user-visible freeze (agent "Precipitating 1m22s") caused by
a transient collapse of live pool capacity under a cascade of routine TSPU
age-cuts. Streams do not drop (migration works, ch_closed=0), but a quiet
long-lived stream's downlink can stall ~10-22s while its slot reconnects.

**Root cause (proven, docs/sl-burst2-freeze-analysis.md + pl1 metrics):**
1. TSPU cuts bare-origin direct-TCP by age → `close 1006` every 15-20s across the
   8 slots (each matures ~100-190s).
2. Every cut is handled as `deathCauseNatural` → `reconnectLoop` with
   `slotBackoffDuration(0)` = **5-10s** before the slot comes back, AND it feeds
   the meltdown detector (`recordSlotDeath`) as if it were a failure.
3. Under the cascade, multiple slots sit in 5-10s reconnect simultaneously (logged:
   3 reconnecting + 1 draining + 1 dead at once, ~50-60 active streams) → live
   capacity dips → quiet streams' downlink freezes for the reconnect window.
4. Aggravator: `close 1006` death is `deathCauseNatural`, which SKIPS the session
   FIN (transport already dead) → server accumulates ghost sessions
   (active_clients=18 after the client disconnected) → server drifts toward
   rate-limit (rate_limited_recent=1 seen) → reconnect throttled → dip deepens.

> **REVISED 2026-06-01 after opus spec-review (docs/sl-capacity-dip-spec-review.md).**
> Lever 2 (FIN-via-sibling) is CRYPTO-IMPOSSIBLE and DROPPED — each slot is a
> separate AES-GCM session, SessionID lives INSIDE the encrypted AEAD plaintext,
> so a FIN for slot A's session sent over slot B is decrypted with B's key →
> gcm.Open fails → frame dropped. The server frees a session by the WS
> connection's BOUND session.ID, not by chunk.SessionID; there is no on-wire
> session addressing. Ghost-session cleanup moves SERVER-SIDE (sweep attached
> sessions whose WS reader exited / idled — infra exists: CleanupNewbornOrphans +
> AttachedAt). Lever 4 (headroom) reduced to a capacity-dip COUNTER only; the
> mechanism is deferred (it duplicates rotationWatchdog). FINAL SCOPE:
> **Lever 1 (fast reconnect) + Lever 3 (no false meltdown) + server ghost-sweep +
> canary counters + regression tests.** Levers 1+3 are the client fix for the
> proven freeze root; the server sweep closes the ghost leak that the client
> cannot. The sections below are kept for context; the FIN-via-sibling text in
> Lever 2 is superseded by the server-sweep section at the end.

**Architecture — one root distinction drives all fixes:** introduce a new death
cause `deathCauseAgeCut` for the EXPECTED TSPU age-cut (a mature slot closing
1006), distinct from `deathCauseNatural` (a genuine unexpected failure on a young
slot). The age-cut is a routine, anticipated lifecycle event in direct mode — not
a fault. From this single classification, all three levers follow:

- **Lever 1 (backoff):** age-cut reconnect uses a near-zero delay (small jitter
  only), NOT the 5-10s exponential. Exponential stays for genuine connect
  failures (the `attempt>0` retry ladder is untouched).
- **Lever 2 (FIN / ghost):** even on a transport-dead age-cut, send the session
  FIN over a LIVE sibling slot so the server releases the session immediately
  (the server keys sessions per-client, FIN carries the slot's session id) —
  killing the ghost accumulation at the source.
- **Lever 3 (no false meltdown):** age-cut does NOT call `recordSlotDeath`, so a
  steady cascade of routine cuts never trips the meltdown cooldown (which would
  PAUSE all reconnects and deepen the dip — the opposite of what we want).

Plus **headroom (Lever 4):** keep more live slots than strictly needed so a
cascade can't bare the pool. Implemented as a preemptive reconnect bias, not a
larger steady poolSize (avoids extra origin handshake load): when a slot is
age-cut, its replacement is already prioritized.

**Tech Stack:** Go 1.25, `shadowlink/client`. No wire change (FIN frame already
exists; we only change WHEN/HOW it is sent).

---

## Distinguishing age-cut from genuine failure

In the slot reader (ws_pool.go:3037-3054), a terminal read error is already
classified via `classifyWSReadError(err)`. An age-cut has a recognizable
signature:
- error is `close 1006` (abnormal closure / unexpected EOF), AND
- `slot_age_ms` is in the mature band (>= a threshold near maxSlotAge, e.g.
  >= 60s — well past warm-up, consistent with TSPU age-based cutting).

A young slot dying with 1006 (age < threshold) is NOT an age-cut — it is a
genuine early failure and stays `deathCauseNatural` (keeps meltdown feeding +
exponential backoff, the correct conservative behavior for real instability).

New helper `isAgeCut(err, slotAgeMs)`:
```go
// isAgeCut reports whether a terminal reader error on a slot of the given age
// is the EXPECTED TSPU age-cut (a mature bare-origin direct-TCP closed 1006 by
// the middlebox) rather than a genuine failure. Age-cuts are routine in direct
// mode and must reconnect fast without feeding the meltdown detector.
func isAgeCut(err error, slotAgeMs int64) bool {
    if slotAgeMs < ageCutMinAgeMs { // young death = real failure, be conservative
        return false
    }
    return isClose1006(err) // classifyWSReadError == "close_other"/1006 family
}
```
`ageCutMinAgeMs` = 60_000 (60s). Rationale: warm-up + any genuine early
instability shows well under 60s; TSPU cuts observed at 100-190s. 60s floor keeps
the fast path conservative (only clearly-mature cuts qualify).

## Death-cause plumbing

Add `deathCauseAgeCut` to the `slotDeathCause` enum. In the reader's terminal
branch (ws_pool.go:3054):
```go
cause := deathCauseNatural
if isAgeCut(err, time.Since(slotStart).Milliseconds()) {
    cause = deathCauseAgeCut
}
p.handleSlotDeath(cl, idx, cause)
```

In `handleSlotDeath`'s dispatch switch, add the age-cut case:
```go
case deathCauseAgeCut:
    // Expected TSPU age-cut — routine in direct mode. Reconnect FAST (no
    // exponential, no meltdown feed) so the cascade of mature-slot cuts does
    // not bare the pool. The FIN was already attempted via the live-sibling
    // path in the cleanup section above.
    go p.reconnectLoopFast(idx)
```
`deathCauseNatural` / `deathCausePreemptiveRotation` / `deathCauseDrainTeardown`
branches are UNCHANGED.

## Lever 1 — fast reconnect

`reconnectLoopFast(idx)` is `reconnectLoop` with a near-zero initial delay:
attempt 0 sleeps `ageCutReconnectJitter` (e.g. U(0, 800ms) — small spread to
avoid a synchronized JA4 handshake burst when several mature slots cut close in
time, reusing the existing anti-thunder-herd rationale), NOT
`slotBackoffDuration(0)`'s 5-10s. If attempt 0's connect FAILS (genuine origin
problem), it falls into the SAME exponential ladder as `reconnectLoop` from
attempt 1 — so a real outage still backs off properly. Implementation: thread a
`fastFirstAttempt bool` into the existing reconnect loop body rather than
duplicating it (DRY), or factor the loop to take an initial-delay function.

The rate-limit handling (ErrRateLimited → cooldown) is preserved — a fast
reconnect that hits a server rate-limit still honors the cooldown.

## Lever 2 — FIN over a live sibling (ghost-session kill)

Today `handleSlotDeath` sends FIN only when `cause != deathCauseNatural` AND uses
the dying slot's own (dead) transport. For age-cut, the dying transport is dead,
but a LIVE sibling slot's transport can carry the FIN (the server releases a
session by id, not by which socket delivers the FIN).

Add `sendSessionFINViaSibling(deadSlot)`: pick any `slotReady` sibling, encrypt a
session-FIN for `deadSlot.session` under the SIBLING's session, enqueue on the
sibling's transport. Best-effort (no live sibling → skip; server idle-sweeper is
the backstop). Call it for `deathCauseAgeCut` AND `deathCauseNatural` (both leave
a ghost today). This is the architectural close of the ghost-session leak from
the client side.

```go
// in handleSlotDeath, replacing the `if cause != deathCauseNatural` FIN block:
switch cause {
case deathCausePreemptiveRotation, deathCauseDrainTeardown:
    p.sendSlotSessionFIN(slot) // live transport, existing path
case deathCauseAgeCut, deathCauseNatural:
    p.sendSessionFINViaSibling(slot) // dead transport — route via a live peer
}
```

## Lever 3 — no false meltdown on age-cut

`recordSlotDeath()` is called only in the `deathCauseNatural` branch — the new
`deathCauseAgeCut` branch does NOT call it. So a steady cascade of routine cuts
never advances the meltdown counter, never triggers the cooldown that pauses
reconnects. Genuine failures (young-slot natural death) still feed it.

## Lever 4 — headroom (preemptive replacement)

The existing `rotationWatchdog` already drains slots preemptively before the
age-cut (graceful drain). The capacity dip happens when an age-cut BEATS the
preemptive drain (slot cut at 100-190s before the watchdog rotated it). Tighten
the preemptive rotation threshold so slots rotate BEFORE the TSPU cut window with
more margin: lower the effective `maxSlotAge` rotation trigger relative to the
observed ~100s cut floor, so the graceful (lossless, migrating) drain wins the
race against the lossy age-cut more often. This is a tuning of the EXISTING
migration watchdog, gated by data — set the rotation bias so p95 of slots rotate
gracefully before 90s.

Concretely: `maxSlotAge` default for direct mode is already below the cut window;
add a `capacityFloorReplacement` — when an age-cut fires and it would drop
readyCapacity below a floor, spawn the replacement reconnect with TOP priority
(fast path, already covered by Lever 1) AND log a capacity-dip counter so the
canary can measure residual dips.

## File Structure

- **Modify** `shadowlink/client/ws_pool.go`:
  - `slotDeathCause` enum + doc (add `deathCauseAgeCut`).
  - `isAgeCut` + `isClose1006` helpers + `ageCutMinAgeMs` const.
  - reader terminal branch: classify cause.
  - `handleSlotDeath`: age-cut dispatch + FIN-via-sibling switch.
  - `reconnectLoopFast` (or `reconnectLoop` refactor with initial-delay param).
  - `sendSessionFINViaSibling`.
  - capacity-dip counter in stats.
- **Modify** `shadowlink/client/stats.go`: `AgeCutReconnectsTotal`,
  `CapacityDipTotal`, `GhostFINViaSiblingTotal` counters + exposition.
- **Test** `shadowlink/client/pool_capacity_dip_test.go` (new).

## Constants

```go
const (
    ageCutMinAgeMs        = 60_000          // slot must be >=60s old for a 1006 to count as a TSPU age-cut
    ageCutReconnectJitter = 800 * time.Millisecond // U(0,800ms) spread on fast reconnect (anti thunder-herd)
)
```

## Testing strategy (TDD)

1. **TestIsAgeCut_MatureClose1006** — close 1006 at age 120s → true; at age 20s →
   false; non-1006 error at age 120s → false.
2. **TestAgeCut_FastReconnect_NoExponential** — inject a mature close-1006 death;
   assert the reconnect uses the fast path (delay <= ageCutReconnectJitter, NOT
   5-10s). Use the existing `setSlotBackoffDurationForTest` seam to detect the
   path NOT taken, and a fast-path seam to confirm the path taken.
3. **TestAgeCut_NoMeltdownFeed** — N age-cuts in a row → meltdown counter
   unchanged; N young-slot natural deaths → meltdown counter advances.
4. **TestAgeCut_SendsFINViaSibling** — slot dies age-cut with a live sibling;
   assert a session-FIN for the dead slot's session was enqueued on the sibling's
   transport (hook the sibling transport's control-write). No live sibling →
   no panic, no send.
5. **TestNaturalDeath_StillExponentialAndMeltdown** — young-slot 1006 / non-1006
   error → deathCauseNatural path intact (meltdown feeds, exponential backoff).
6. **TestCapacityDip_Counter** — simulate a cascade that drops readyCapacity
   below floor → CapacityDipTotal increments (observability for the canary).
7. **Concurrent/race** — cascade of age-cuts + reconnects + migration under
   `-race -count=3` on pl1: assert no negative counters, no deadlock, FIN-via-
   sibling doesn't race the sibling's own death.

Existing reconnect/drain/migration tests must stay green — natural/rotation/
teardown causes are unchanged; age-cut is a NEW branch.

## Race / concurrency

- `sendSessionFINViaSibling` reads sibling slot under `reserveMu` (sibling may be
  dying concurrently), enqueues via the sibling transport's non-blocking
  TryWriteControlMessage (never blocks handleSlotDeath).
- `reconnectLoopFast` reuses `reconnectLoop`'s recycle-guard + ctx-cancel.
- Must pass `go test -race -count=3 ./client/` on pl1.

## Why this is the architectural close (not a patch)

The freeze, the ghost sessions, and the false-meltdown risk are THREE symptoms of
ONE missing distinction: the client treated a routine, expected TSPU age-cut as a
genuine network failure. Modeling the age-cut as its own lifecycle event — fast
reconnect, no meltdown, FIN-via-sibling — removes the dip at its source and closes
the ghost leak, instead of tuning timeouts around the symptom. Headroom is the
belt-and-suspenders measure with a counter so the next canary proves residual
dips are gone.

## Server ghost-sweep (REPLACES Lever 2 — closes the ghost leak)

Client cannot FIN a TSPU-cut session (transport dead, no on-wire session
addressing). So the server reclaims it: when a slot's WS reader goroutine exits
(the server observes the same close 1006 / io_timeout / peer_eof — metrics show
ws_reader_exit_io_timeout=933, peer_eof=669), the bound session must be released
promptly instead of lingering to its idle timeout (the source of active_clients=18
ghosts).

Mechanism: on WS reader exit (server/websocket.go), mark the bound session for
expedited cleanup — reuse the existing idle/orphan sweep (`CleanupNewbornOrphans`
+ `AttachedAt`) by treating "attached session whose only/last WS reader exited"
as eligible for a short grace (a few seconds, enough to allow a RESUME/MIGRATE to
re-adopt the relay — must NOT evict a session a stream is migrating onto). Tie
into the existing orphan-relay grace window (8s) so we never reclaim a session
mid-migration. Counter: `ghost_session_swept_total`.

Constraint: the sweep MUST coexist with Bug#9 migration — a session whose WS
dropped but whose relay is in the orphan window (a stream is RESUMING onto a live
slot) must survive until the grace expires. Gate the sweep on "no active orphan
relay for this session AND reader exited > grace".

## Out of scope

- Lever 4 headroom MECHANISM (only the capacity-dip counter ships now; the
  rotation-threshold tuning is a separate data-driven canary iteration — it
  overlaps rotationWatchdog and needs field data to set safely).
- Lever 2 FIN-via-sibling (crypto-impossible — see revision note at top).
- CF mode (this is direct-mode TSPU behavior).
