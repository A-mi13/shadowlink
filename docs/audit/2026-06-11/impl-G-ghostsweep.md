# Impl-G — Ghost-sweep TOCTOU fix (HIGH-4 / H-S3)

**Date:** 2026-06-11
**Finding:** agent3-server-dataplane.md HIGH-4 — `CleanupDetachedGhosts` can delete a
session in the instant a pool reconnect re-attaches (TOCTOU).
**Files:** `core/session.go`, `server/websocket.go`, `core/session_ghost_sweep_test.go`.
**Scope note:** M4 (`legacyRotateOneSlot` generation bump) was already handled by block E.
`ws_pool.go` intentionally NOT touched.

---

## The race (as reported)

- Sweep Phase 1 collects a candidate while it observes `WSAttached==false`
  (gate eligible). Sweep Phase 2 re-reads `DetachedAt` under `sm.mu`.
- A concurrent reconnect (websocket.go) did, in order:
  `WSAttached.CompareAndSwap(false,true)` (~188) THEN `DetachedAt.Store(0)` (~197).
- Window: between the CAS-win and the bare `DetachedAt.Store(0)`, the sweep
  takes `sm.mu`, re-reads `DetachedAt` (still non-zero), passes the stale-check,
  and `delete`s the session out from under the just-attached live transport.
  Transport now serves a session the manager no longer knows →
  DecryptChunkSafe/findSessionByHint miss → forced full re-handshake mid-traffic.

Root cause: the **attach commit** (clearing `DetachedAt`, gated by the
`WSAttached` latch on the server `Tunnel`) and the **sweep delete** (map
`delete` under `sm.mu`) lived behind *different* synchronization. A bare atomic
`Store` on `Session.DetachedAt` is not mutually exclusive with the sweep's
lock-held re-read+delete, so atomics alone cannot close a cross-variable race.

---

## Chosen fix — variant (в) made authoritative: clear `DetachedAt` under `sm.mu`

The audit offered (а) reorder, (б) re-check WSAttached under `sm.mu`, (в) clear
`DetachedAt` inside the CAS-win block. I implemented **a hardened form of (в)**:

**`core.SessionManager.ReattachClearDetached(id) bool`** — clears `DetachedAt`
**while holding `sm.mu`**, the *same* lock `CleanupDetachedGhosts` Phase 2 holds
across its existence-check → `DetachedAt`-read → `delete` critical section. This
makes attach-commit and sweep-delete **mutually exclusive on one lock**, the
only construct that actually closes a cross-variable race:

- If the reconnect's lock-held clear runs first → the sweep's lock-held
  `DetachedAt` re-read (session.go Phase 2) sees `0` → session **survives**.
- If the sweep's `delete` runs first → `ReattachClearDetached`'s lookup misses →
  returns **false** → the reconnect (websocket.go) resets `WSAttached` to false
  and bails into `fakeAckAndClose`, so the client reconnects cleanly on a fresh
  session rather than serving a manager-unknown ghost.

`server/websocket.go` re-attach now calls `h.sessions.ReattachClearDetached(id)`
in place of the bare `session.DetachedAt.Store(0)` (still after the WSAttached
CAS-win so only the winner commits), and on `false` undoes the latch and returns
`(nil,0,false)`.

### Why not (б) (re-check WSAttached under sm.mu)

Rejected: the gate `ghostSweepEligible` acquires `h.sessions.Get` (sm.mu RLock)
**then** `h.tunnelsMu`. Phase 1 already calls the gate **under `sm.mu.RLock()`**;
calling any sm.mu-taking work from there self-deadlocks (RWMutex can't upgrade).
The existing code explicitly keeps the Phase-2 gate call *outside* `sm.mu` for
lock-order safety. Adding a WSAttached re-check under `sm.mu` would either
deadlock or require leaking Tunnel state into core. Variant (в) needs no new
lock-order edge — it reuses the lock the delete already holds. The existing
Phase-2 `DetachedAt` re-read (session.go) is the pairing read that now observes
the serialized clear; it stays as defence-in-depth.

---

## How the regression tests reproduce / pin the race

`core/session_ghost_sweep_test.go` (core-level — no Handler, no
`disableBackpressureForTest` needed):

1. `TestReattachClearDetached_ClearsLiveSession` — happy path: present session →
   `DetachedAt` cleared, returns true.
2. `TestReattachClearDetached_FailsForSweptSession` — session already removed →
   returns false (drives the websocket.go abort-attach branch).
3. `TestCleanupDetachedGhosts_TOCTOU_ReattachBeforeSweepDelete` — **deterministic**
   ordering (1): the reconnect commits via the real `sm.mu`-serialized path,
   THEN the sweep runs with an eligible gate (`return true`, mirroring the audit
   window where the gate observed `WSAttached==false`). Asserts the session is
   NOT swept, survives in the manager, and `DetachedAt==0`. Fails against a bare
   `Store` that is not serialized with the delete.
4. `TestCleanupDetachedGhosts_TOCTOU_ConcurrentReattach` — **genuinely concurrent**:
   sweep goroutine and reconnect goroutine race the same session 200× with no
   enforced order. Asserts the safety invariant — the forbidden state
   (`commitOK==true && wasSwept==true`, i.e. reconnect believed it succeeded yet
   the session was swept) NEVER occurs, and outcomes stay mutually consistent.
   **Run under `go test -race` on Linux/CI** (Windows dev box has no cgo/-race)
   to catch ordering violations the deterministic test can't.

An earlier draft hooked the sweep's gate callback to invoke
`ReattachClearDetached`; that deadlocked because Phase 1 calls the gate under
`sm.mu.RLock()` (10-min timeout panic). The deadlock itself confirmed the
lock-order constraint that ruled out variant (б); the test was rewritten to the
two forms above.

---

## Verification (Windows dev box)

- `go build ./...` → **OK**
- `go vet ./server/... ./core/...` → **OK**
- `go test ./core/ -run 'GhostSweep|Reattach|TOCTOU|Detached' -v` → **9/9 PASS**
- `go test ./core/ -count=1` → **ok 8.9s**
- `go test ./server/ -count=1` → **ok 16.8s**
- `go test ./server/ -count=1 -shuffle=on` → **ok 17.0s** (no flake reintroduced)
- gofmt: the three touched files are flagged ONLY for CRLF→LF (gofmt -d shows
  every identical line as -/+); a pre-existing untouched file (server/handler.go)
  is flagged the same way. Per project rule "CRLF — не массово" left as-is; edits
  preserved CRLF.

### For Linux/CI
- `go test -race -count=3 ./core/ ./server/` (the `-race` flag is the point for
  `TestCleanupDetachedGhosts_TOCTOU_ConcurrentReattach`; 200 iters × 3 widens the
  interleaving net).

---

## Risks

1. **Behavioural change on the lost-race path:** a reconnect that wins the
   WSAttached CAS but finds the session already swept now resets `WSAttached` and
   bails to `fakeAckAndClose` (was: served a ghost). This is the intended cure —
   the client reconnects on a fresh session — but it converts a rare silent
   corruption into a clean re-handshake; if any caller assumed CAS-win implies
   attach-success, that assumption is now false (only the re-attach path is
   affected; the fresh-handshake attach path is unchanged).
2. **Concurrency test is probabilistic on the dev box (no -race):** ordering (2)
   in `TestCleanupDetachedGhosts_TOCTOU_ConcurrentReattach` may not fire every run
   without -race scheduling pressure; the deterministic test covers ordering (1)
   unconditionally, and -race on CI covers the rest. The safety assertion (no
   forbidden state) holds regardless of which ordering the scheduler picks.
