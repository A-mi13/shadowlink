# Bug #8 Task 10 — Server-side flow control: adversarial review

Date: 2026-05-30
Scope: flow-control additions in `server/websocket.go`, `server/stream_credit.go`,
`server/handler.go` (flowMaxWindow), `server/metrics.go` (counters), `core/flowctl.go`.
NOT in scope (excluded per brief): Live Decoy / live-blog removal WIP captured in the same commit.

## Test/build gates

- `go test ./server/ -run 'TestNegotiateFlowWindow|TestStreamCredit' -v` → PASS (5/5)
- `go build ./...` → PASS
- `go test ./server/` (full package) → PASS (12.4s)

---

## SPEC CONFORMANCE — ✅ (all 5 checks pass)

### 1. authenticateFirstFrame ✅
- ack emitted **synchronously BEFORE** runWebSocketSession: marker handling at
  websocket.go:192-207 lives inside `authenticateFirstFrame`, which returns to
  `handleWebSocket` (line 456) which only then calls `runWebSocketSession`
  (line 480). No reader/writer goroutine exists yet at ack time. ✅
- Marker rides the **encrypted** payload: parsed from `chunk.Payload` AFTER
  `session.DecryptChunkSafe` (line 164) — confirmed; flowctl.go doc confirms it
  rides inside the encrypted Chunk.Payload, no cleartext DPI signal. Ack built
  with `BuildFlowCtlMarker` then `session.EncryptChunk(ack)` (line 200-201). ✅
- All returns → 2 values: every `return nil, 0` (8 sites) + success `return
  session, effectiveWindow` (line 219). Build passes → signature consistent at all
  callsites. ✅

### 2. credit-gate BEFORE tc.Read ✅
websocket.go:797-811 computes `limit` from `waitForCredit` BEFORE `tc.Read(buf[:limit])`
at line 812. `got <= 0 → return` (line 804). `limit=min(buf,got)` via int(got) clamp
(807-809). ✅

### 3. consume(n) only on writeMsg success ✅
consume runs at 823-830 AFTER `writeMsg(enc) != nil → return` guard (820-822) and AFTER
`encErr != nil → return` (817). Only reached on the success path. ✅

### 4. FlagWindowUpdate parses + replenishes correct credit ✅
websocket.go:899-911: `ParseWindowUpdate` → `credits[wuStreamID]` under creditsMu →
`cr.add(delta, int64(flowWindow))`. Correct stream keyed by parsed ID. Counter ticked.
Note: cap uses static `flowWindow` (negotiated effectiveWindow), consistent with init —
correct, not the per-stream remaining. ✅

### 5. teardown: credit.close() in all 3 sites ✅
- FlagFin: lines 847-854 under creditsMu, close + delete. ✅
- relay defer: lines 785-793 under creditsMu, close + delete. ✅
- done-watcher: lines 921-928 iterates map, close each (no delete — map dropped with
  session, fine). ✅

`default` case → `UnknownFlag.Add(1)` (914) ✅. FlowSessionsActive gauge ±1 with defer
(494-495) ✅.

---

## QUALITY (adversarial) — APPROVED (no BLOCKER/CRITICAL; 1 HIGH, 2 MEDIUM, 2 LOW)

### Q1 — Reader-loop deadlock: NO ✅
`waitForCredit(done)` is called ONLY inside the per-stream relay goroutine spawned at
FlagConnect (the `go func(sid, tgt, s)` at line 676, relay loop 796-835). The session
reader-loop (line 578 goroutine) NEVER calls waitForCredit — it only does map ops under
creditsMu for init/add/close (all O(1), non-blocking). Confirmed distinct goroutines.
No head-of-line blocking across streams (invariant I2 holds). ✅

### Q5 — int(got) overflow: NO ✅
`got` is clamped at `2*window` in `add` (stream_credit.go:79); window ≤ flowMaxWindow
= 1<<20 (1 MiB). Max got = 2 MiB ≪ MaxInt. `int(got)` safe on 32-bit too. ✅

### Q6 — ack-write-failure desync — HIGH (design gap, NOT a hang; downgraded from candidate BLOCKER)
Brief's hypothesis: ack WriteMessage fails (slow client) → server returns
effectiveWindow>0 (flow ON server-side) but client never got ack (flow OFF client-side)
→ client never sends WINDOW_UPDATE → server hangs forever on waitForCredit.

Verdict: the desync is **real** but does **NOT hang the session forever**, because
`waitForCredit(done)` is woken by the done-watcher (lines 921-928) when the WS tears
down, and the WS *will* tear down: a client that thinks flow is OFF keeps reading and
the relay drains the initial window (1 MiB) then blocks; the connection is still subject
to ping/pong read-deadline (60s) and writer-error closeDone paths. So the failure mode
is **a single stream stalling after its first window (~1 MiB) until session-level
timeout**, not a permanent goroutine leak. Still a correctness defect:

- websocket.go:201-204 ignores the WriteMessage return value (`_ = conn.WriteMessage`).
  On ack-write failure the server should treat flow as **NOT negotiated** (return
  effectiveWindow=0) so it never gates reads the client can't replenish. As written, the
  server commits to flow-ON regardless of whether the peer received the ack.
- Recommended fix: capture the WriteMessage error; on error `return session, 0`
  (flow disabled, fail-open to the un-gated relay path). This makes ack delivery a
  precondition for server-side gating — matching the client's view.
- Severity HIGH not BLOCKER: bounded by session timeout, single-stream impact, requires
  ack-write failure (rare: 2s write deadline on a fresh post-upgrade conn). But it
  degrades exactly the large-download case Bug #8 exists to fix, so worth fixing before
  field canary.

### Q2 — done-watcher race with late FlagConnect — MEDIUM
The done-watcher (921-928) runs **once** after `<-done`. Sequence to consider:
watcher acquires creditsMu, iterates current map, closes all, releases. If a FlagConnect
is processed AFTER that iteration and inserts `credits[newID]` (660-663), that credit is
never closed by the watcher.

Mitigation already present: the reader-loop that processes FlagConnect is itself
draining toward exit once `done` fired (it shares the same conn; ReadMessage will error
and `closeDone` fires). More importantly, **every** relay goroutine has its own defer
(785-793) that closes its credit, AND the relay's first action is `waitForCredit(done)`
— since `done` is already closed, the relay's pre-block `select{case <-done: return -1}`
(stream_credit.go:46-50) returns -1 immediately, relay returns, defer closes the credit.
So a late credit is reaped by the relay defer, not leaked. **No permanent leak**, but the
done-watcher is not the closer in that window — the invariant "done-watcher closes all"
is technically violated for late entries. Cosmetic/robustness: acceptable as-is given the
relay-defer backstop; document the backstop or set a `closed` flag on the map so late
inserts close immediately. Not blocking.

### Q3 — credits map concurrent access — ✅ (one nit, LOW)
All map operations are under the same `creditsMu`:
- init (FlagConnect 661-663) ✅
- gate read (799-801, 824-826) ✅
- add (FlagWindowUpdate 905-907) ✅
- close+delete (FlagFin 848-853, relay defer 787-792, done-watcher 923-927) ✅
LOW nit: the gate copies the `*streamCredit` pointer under the lock then releases before
calling waitForCredit (correct — must not hold creditsMu while blocking). The
streamCredit's own mu serializes its internal state. No data race. ✅

### Q4 — waitForCredit done wiring — ✅
`done` passed to waitForCredit (803) is the same session `done` (515). Wakeup on
teardown is via `cr.close()` (sets closed + cond.Signal under mu) from the done-watcher,
NOT via the channel directly (sync.Cond can't select). stream_credit.go correctly:
(a) checks done before Wait (46-50), (b) re-checks done AND closed after wakeup (53-60).
Test `TestStreamCredit_WaitReturnsWhenDoneClosed` + `_CloseUnblocks` cover both. No lost
wakeup (Signal held under mu, M4). ✅

### Q-extra — consume can drive available negative, gate then waits — LOW (correct by design)
`consume(n)` subtracts the full `n` read (stream_credit.go:69-73) which can exceed the
gated `limit` only if limit==len(buf) (flow disabled path doesn't consume). When flow is
on, limit≤got≤available, so consume keeps available≥0 in the common path; but `add` cap
and the `<=0` gate handle any transient negative correctly (gate blocks until add brings
it positive). Behaviorally sound. LOW.

### Q-extra2 — WindowUpdate not seq-num-gated against the gate, but is AcceptSeqNum-gated — ✅
FlagWindowUpdate passes through the reader-loop's `AcceptSeqNum` (line 614) before the
switch, so replayed WINDOW_UPDATE frames can't inflate credit. ✅

---

## Severity counts
- BLOCKER: 0
- CRITICAL: 0
- HIGH: 1 (Q6 ack-write-failure → server should fail-open to flow=0)
- MEDIUM: 1 (Q2 done-watcher vs late FlagConnect — backstopped by relay defer, document/harden)
- LOW: 3 (Q3 nit, Q-extra consume sign, map-late-insert cosmetic)

## Recommendation
SPEC ✅ / QUALITY APPROVED. Ship-eligible after addressing Q6 (HIGH): capture the ack
WriteMessage error in authenticateFirstFrame and `return session, 0` on failure so
server-side gating is never enabled without confirmed ack delivery. Q2 is adequately
backstopped by the relay defer; harden opportunistically.
