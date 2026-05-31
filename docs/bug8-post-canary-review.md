# Bug #8 — Post-Canary Final Code Review

**Date:** 2026-05-31
**Reviewer:** fresh adversarial post-canary pass (after 5h43m clean canary + diag removal)
**Scope:** full Bug #8 per-stream flow-control delta (client + server), with focus on
the root-cause fix (byte_budget vs frame delivery) and verification that the
just-removed diag instrumentation left no broken seams.
**Predecessor:** `docs/bug8-final-impl-review.md` (pre-canary, verdict READY-TO-SHIP,
2 MEDIUM / 4 LOW accepted as canary risks).

## VERDICT: SHIP

The canary closed both pre-canary MEDIUM items, the root-cause fix is present and
correct, the diag removal is clean (build + vet + full test suite pass, no dangling
references), and no new BLOCKER/HIGH defect was found. The credit chain, negotiation
symmetry, atomics, and teardown paths re-verified against the live code all hold.

The single residual item is the `-race`-only data-race observation on the unsynchronized
`poolSlot.transport` pointer (LOW-1 below) — a PRE-EXISTING characteristic of the pool
that Bug #8 merely adds one more reader to. It did not and could not surface in a
non-`-race` canary; it is not a ship blocker but should be confirmed on a Linux `-race`
run as already mandated by the carry-over checklist.

## Severity counts

- BLOCKER: 0
- HIGH: 0
- MEDIUM: 0
- LOW: 2 (1 pre-existing race observation, 1 cosmetic carry-over)
- Pre-canary MEDIUM-1 (ack-race): CLOSED by canary
- Pre-canary MEDIUM-2 (credit-wait metrics): CLOSED — now implemented

---

## Root-cause fix CONFIRMED? — YES

The byte_budget check is now strictly AFTER frame delivery in
`client/ws_pool.go`. The frame is decrypted, routed to its stream via
`RouteToStream`, and ONLY THEN is the per-slot byte budget evaluated. There is no
`continue`/`return`/drop on the budget-tripping frame.

Delivery (`ws_pool.go:2728-2732`):

```go
if chunk.Flags == core.FlagUDP {
    cl.RouteToStream(streamID, chunk.Payload)
} else {
    cl.RouteToStream(streamID, chunk.Payload[2:])
}
```

Budget check, placed AFTER delivery, with an explicit regression comment
(`ws_pool.go:2734-2778`):

```go
// Preemptive byte-based rotation — checked AFTER the frame is
// decrypted and routed to its stream (above). CRITICAL: this block
// MUST come after RouteToStream. Previously it sat BEFORE decrypt
// and did `continue` on the budget-tripping frame, DROPPING that
// already-read downlink frame — a hole in the stream's TCP byte
// sequence ...
if budget := slot.byteBudget.Load(); budget > 0 {
    total := slot.downBytes.Add(int64(len(data)))
    if total >= budget && byteBudgetRotationAllowed(time.Since(slotStart), p.byteBudgetMinInterval) {
        if p.gracefulDrain {
            if slot.getState() == slotReady {
                slot.downBytes.Store(0)
                go p.startDrain(cl, idx, "byte_budget")
            }
            // NO continue/return — the frame is already delivered; just
            // loop to the next ReadMessage.
        } else if p.maybeRotateSlot(cl, idx, slot, "byte_budget", msgCount, slotStart, total) {
            return   // <-- returns AFTER the frame was delivered; no frame lost
        }
    }
}
```

In both branches the frame has already reached `RouteToStream` before any
rotation/drain/`return`. The graceful path explicitly does NOT `continue`; the
hard-rotation path `return`s only after delivery. The TCP-hole that produced
`SEC_E_DECRYPT_FAILURE` is structurally impossible on this path now. The 5h43m
canary (0 overflow drops, 0 decrypt_fails, 79 MB downloads OK) is consistent with
this.

Verified-no-other-drop-path: the only other `continue` statements in the read loop
sit BEFORE a frame is even a deliverable data frame — `session == nil` (2690-2691),
`DecryptChunkSafe` error (2695-2697), `len(Payload) < 2` (2699-2701), stale-frame
streamID-reassignment drop (2716-2724). None of these discard a *successfully
decrypted, owned* downlink frame after partial accounting; the stale-frame drop is
a deliberate W5 correctness drop for a frame belonging to a re-homed streamID and
is counted (`StaleFrameDroppedTotal`).

---

## Re-verified holistic checks (all PASS)

### Credit chain end-to-end — PASS
Server starts `newStreamCredit(int64(flowWindow))` per CONNECT when `flowEnabled`
(websocket.go:671-675) → `waitForCredit(done)` gate BEFORE `tc.Read` (815) →
`consume(n)` after enqueue (844) → client downlink `conn.Write` then
`OnStreamConsumed(streamID, len(data))` (tcp.go:797, AFTER the write, only on
success) → credit-sender emits WINDOW_UPDATE → server `cr.add(delta, int64(flowWindow))`
+ `cond.Signal` (925) → relay unblocks. Start window == client effective window
(both = ack `effectiveWindow`). No credit lost.

### OnStreamConsumed placement — PASS
`tcp.go:774` writes to the app, `tcp.go:797` credits. On the write-error path
(774-795) the relay drains `incomingCh` and returns WITHOUT calling
`OnStreamConsumed` — correct: app never received those bytes, so no credit is
returned for them (the stream is tearing down anyway).

### Negotiation — synchronous ack, symmetric fail-open — PASS
- Server emits the FLOWCTL-ack synchronously inside `authenticateFirstFrame`
  (websocket.go:200-208) BEFORE returning to `runWebSocketSession` (called at
  websocket.go:491). The relay loop / `flowEnabled` decision happens strictly after
  the ack is on the wire.
- Server fail-open: if `WriteMessage` of the ack fails, `effectiveWindow = 0`
  (websocket.go:214-216) → `flowEnabled = flowWindow > 0` is false → relay runs
  ungated. Symmetric with a client that never saw the ack.
- Client reads the ack synchronously in `UpgradeToWS` (ws_transport.go:533-548)
  BEFORE constructing the async writer (554) and BEFORE the slot reader starts
  (reader spawns only after `connectSlot` sets `slotReady`, post-`UpgradeToWS`).
  Timeout → stays OFF, increments `FlowNegotiationTimeout`.
- Old client vs new server: client sends no FLOWCTL marker → server's
  `ParseFlowCtlMarker` returns ok=false → no ack, `effectiveWindow=0`, both OFF.
- New client vs old server: old server ignores the marker (no ack) → client's
  500ms read times out → client OFF. No hang: the client read deadline is reset to
  zero (536) immediately after, and the first frame is already sent, so the session
  proceeds ungated. PASS.

### Atomics / races at the seams — PASS (static; -race deferred)
- `streamFlowState.pendingDelta` (atomic.Uint64): `OnStreamConsumed` Add; sender
  reads via `Load`, then `CompareAndSwap(d, 0)` and gives back `Add(d)` on send
  failure (stream_flow.go:150-176). The give-back is additive and race-safe.
- `lastSentNs` (atomic.Int64): single `Load` at line 161 (the Task6 CRITICAL
  double-Load is gone — confirmed only one `lastSentNs.Load()` in the tick),
  `Store` at 170. No torn read.
- `c.flowControlEnabled` / `c.flowWindow` / `c.flowTransport` written under
  `streamMu` in `EnableFlowControl` BEFORE `startCreditSender` launches the sender
  goroutine (stream_flow.go:48-60) — happens-before via goroutine start. The
  `flowTransport` lock-free read in `sendWindowUpdate` is safe (assign-once,
  never mutated).
- Server credit map guarded by `creditsMu`; each bucket by `streamCredit.mu`.
  `cond.Signal` + `closed` always set under `c.mu` (stream_credit.go) → no lost
  wakeup. `waitForCredit` re-checks `done` and `closed` after every wake (44-65).
- Session teardown wake goroutine (websocket.go:937-944) closes ALL credits on
  `<-done` → every blocked `waitForCredit` returns -1 → relay exits. No leak/
  deadlock. The goroutine is created unconditionally but is a harmless no-op when
  `flowEnabled` is false (empty `credits` map) and always terminates when `done`
  closes.

### Credit-gate is per-stream-relay, not reader-loop — PASS
`waitForCredit` is called only inside the per-stream relay goroutine
(websocket.go:815, inside the `go func(sid, tgt, s)` launched per CONNECT), never
in the session reader-loop. A credit-starved stream blocks only its own relay
goroutine; the target socket applies its own backpressure. No head-of-line
blocking across streams. Window clamp `2*window` in `add` (stream_credit.go:79).

### Boundary cases — PASS
- window=0 (flow off): client `flowDesiredWindow=0` → no marker, no ack-read; server
  `negotiateFlowWindow(0, max)=0` (stream_credit.go:8-9). Relay ungated — identical
  to pre-Bug-8 path.
- `ParseWindowUpdate` rejects payloads < 6 bytes with an error, never panics
  (chunk.go:253-260); delta is `uint32`, `add` widens to `int64` — no overflow at
  the clamp.
- `ParseFlowCtlMarker` rejects nil/short/wrong-magic (flowctl.go:32-42).
- streamID is `uint16`; credit map keyed by `uint16`. The W5 stale-frame guard
  (ws_pool.go:2716-2724) prevents a re-homed streamID from being mis-credited.

### Diag removal — clean — PASS
- `proxy/socks5/memconn.go`: the diag-only `created` field is gone; the boevoy
  `Close`/`CloseWrite`/`CloseRead` + `peerFullClose`/`fullCloseOnce` machinery is
  intact and correct (only the app end fires `peerFullClose`, exactly once).
- `proxy/socks5/tcp.go`: the half/full-close detector (`fullCloseSignaler`,
  `writeClosed()` branch at 675-681), `connectConfirmed` handling (718-762), and the
  `peerFullClose`/`ctx2.Done`/idle-grace selects (798-811) are all intact. The
  removed diag fields (`streamAgeMs`, `downlinkBytes`, `relayMs`, `fullClose`) leave
  no dangling references — `grep` finds them only in comments/test names.
- `go build ./...` clean, `go vet ./client/ ./server/ ./core/ ./proxy/...` clean —
  these would fail on an unused field or dead reference.

### Metrics — PASS, both pre-canary MEDIUMs closed
- Client: `FlowWindowUpdatesSent`, `FlowWindowUpdateDropped`, `FlowNegotiationTimeout`
  (stats.go:275-277, exported 665-671). All atomic, single-count per event.
- Server: `FlowWindowUpdatesRecv`, `FlowSessionsActive` (gauge),
  **`FlowStreamCreditWaitsTotal` + `FlowStreamCreditWaitMsTotal`** (metrics.go:209-214,
  exported 718-722) — this is the pre-canary MEDIUM-2 gap, now WIRED at
  websocket.go:816-819. `FlowSessionsActive` Add(1)+defer Add(-1) in one scope
  (websocket.go:505-506) — symmetric, no double-count.
- Pre-canary MEDIUM-1 (ack-race asymmetry): the 5h43m canary showed 0 anomalous
  resets / 0 decrypt_fails and large downloads completing, i.e. no field evidence of
  server-ON/client-OFF stalls. Considered CLOSED by the canary's stated clean result.

---

## LOW findings (non-blocking)

### LOW-1 — `poolSlot.transport` read without synchronization (pre-existing; Bug #8 adds a reader)
File: `client/ws_pool.go:1679` (write in `connectSlot`) vs `:2436`
(`TryWriteControlMessageForStream`, called from the per-client credit-sender
goroutine).
`slot.transport` is a plain pointer field. It is written once per (re)connect at
1679 (before `setState(slotReady)`) and read lock-free by several call sites
(1537, 1577, 2545) AND now by the Bug #8 credit-sender via
`TryWriteControlMessageForStream`. Under the Go memory model a concurrent
pointer write (reconnect) + read (credit-sender) is a data race, even though on all
supported architectures a word-sized pointer store is atomic in practice. This is a
PRE-EXISTING property of the pool; Bug #8 only adds one more concurrent reader from
an independent goroutine. A non-`-race` canary cannot surface it. **Action: confirm
on the mandated Linux `go test -race -count=3 ./client/` run.** If `-race` flags it,
the clean fix is to make `transport` an `atomic.Pointer[...]` (or read it under the
existing slot state discipline) — but the gate is already `getState() in
{slotReady,slotDraining}` (2439), so the practical risk is a benign torn read of a
pointer that is never set to nil. Not a ship blocker.

### LOW-2 — `streamFlowState.window` sourced from client-wide `c.flowWindow`, not the slot's window (carry-over from pre-canary LOW-3)
File: `client/client.go` (`window: c.flowWindow`), `ws_pool.go:1680-1684`.
Unchanged from pre-canary. In production all slots converge to the same effective
window (uniform server max + uniform client desired), so no byte loss or threshold
drift. Cosmetic divergence from the spec's per-slot intent. The per-slot
`poolSlot.flowWindow` field remains effectively unused for sizing. Document or
collapse to a single client-level field in a future cleanup.

---

## Verification log

- `go build ./...` → clean.
- `go vet ./client/ ./server/ ./core/ ./proxy/...` → clean (no output).
- `go test ./core/ ./client/ ./server/ ./proxy/...` → all PASS
  (`core` cached, `client` 48.3s, `server` cached, `proxy/socks5` cached).
- `grep` for removed diag fields (`streamAgeMs|downlinkBytes|relayMs|fullClose|created`)
  → only comments and test names; no live code references.
- `-race`: NOT run (no gcc/CGO on this Windows host). Carry-over: MUST run
  `go test -race -count=3 ./core/ ./client/ ./server/` on CI/Linux — this is the
  only unexecuted gate and the way LOW-1 would be definitively cleared.

## Carry-over before final sign-off
1. Linux `-race` run (covers LOW-1 and the design §9.10 gate).
2. Optional cleanup: LOW-2 per-slot vs client-wide window field collapse.
