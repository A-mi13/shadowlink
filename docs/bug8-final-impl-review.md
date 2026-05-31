# Bug #8 — Final Holistic Implementation Review (adversarial gate)

**Date:** 2026-05-30
**Reviewer:** final adversarial holistic pass (last gate before pl1 redeploy)
**Scope:** full Bug #8 per-stream flow-control delta (client + server, end-to-end)
**Design source of truth:** `docs/superpowers/specs/2026-05-30-bug8-flow-control-design.md` (v4 READY)

## VERDICT: READY-TO-SHIP

The client and server implementations are protocol-symmetric byte-for-byte, the
credit chain is closed end-to-end, units are consistent (bytes throughout),
negotiation is symmetric with a correct fail-open third-state analysis, and all
3-review closure-map findings (NB1, NB2, NH1, NH2, NV1, M2, B2/I3, H3/I4, H4,
H5, M1, M4, M5, LV1) are present in code. `go build ./...` clean.
`go test ./core/ ./client/ ./server/ ./proxy/...` all PASS including the main
integration test (`TestFlowControl_NoDropsUnderFastDownload`), HoL, half-close,
teardown, watchdog, and the negotiation matrix.

One trivial gofmt-alignment churn in `core/chunk.go` (introduced by the two new
flag constants) was **fixed during this review**. The remaining gofmt diffs in
`server/websocket.go`, `client/ws_transport.go`, `client/ws_pool.go` are
preexistent CRLF line endings, not Bug #8 regressions — out of scope.

No BLOCKER, CRITICAL, or HIGH findings. Items below are MEDIUM/LOW and do not
gate the deploy.

## Severity counts

- BLOCKER: 0
- CRITICAL: 0
- HIGH: 0
- MEDIUM: 2
- LOW: 4
- FIXED-DURING-REVIEW: 1

---

## Holistic checks (all PASS)

### 1. Protocol client↔server byte-for-byte — PASS
- **FLOWCTL marker:** client `BuildFlowCtlMarker(window)` → `["FLOWCTL"(7)][window(4 BE)]`
  = 11 bytes, placed in encrypted `Chunk.Payload` of first keepalive
  (`buildFirstFramePayload`, ws_transport.go:725). Server parses with the SAME
  `core.ParseFlowCtlMarker(chunk.Payload)` (websocket.go:196). Identical codec.
- **FLOWCTL ack:** server emits `Chunk{Flags:FlagAck, Payload:BuildFlowCtlMarker(effective)}`
  (websocket.go:200-201); client reads `FlagAck` + `parseFlowAckPayload` →
  `core.ParseFlowCtlMarker` (ws_transport.go:538-539). Symmetric.
- **WINDOW_UPDATE:** client `core.NewWindowUpdateChunk(...,streamID,delta)` →
  `[StreamID(2 BE)][delta(4 BE)]`, flag `0x0A`. Server `core.ParseWindowUpdate`
  reads the same 6-byte layout (websocket.go:912). Same constructor/parser pair
  in core. Symmetric.

### 2. Credit chain closed end-to-end — PASS
Server relay starts at `newStreamCredit(int64(flowWindow))` = effectiveWindow
(websocket.go:673) → `waitForCredit` gate before `tc.Read` (823) → `consume(n)`
after enqueue (839) → client downlink `conn.Write` → `OnStreamConsumed(len(data))`
atomic Add (tcp.go:797) → credit-sender at jittered 40-60% → `WINDOW_UPDATE` →
server `cr.add(delta, ...)` + `cond.Signal` (920) → relay unblocks. No credit is
lost: server start window == client effective window (both = ack effectiveWindow).

### 3. Units consistent (bytes everywhere) — PASS
- Server window in bytes (`int64`), `consume(n)` where n = bytes read from target
  (`tc.Read` return), `add(delta)` delta in bytes.
- Client `OnStreamConsumed(streamID, len(data))` = bytes written to app; delta
  sent = accumulated bytes. No frame/byte confusion anywhere.

### 4. Negotiation symmetry (third-state hunt) — PASS
Three states only:
- ack reaches client → both ON (client sets `flowControlEnabled`+window from ack;
  server `flowEnabled = flowWindow>0`).
- ack lost / not sent → server fail-open sets `effectiveWindow=0` if its own
  `WriteMessage` failed (websocket.go:214-216), client times out at 500ms and
  stays OFF. Both OFF.
- client sends no marker → server sends no ack, client never reads (gated on
  `flowDesiredWindow>0`). Both OFF.
No state where one side is ON and the other OFF *given the ack actually
delivered*. The one residual asymmetry window (server wrote ack OK on the wire
but client's read deadline expired / TLS buffered late) is covered: server only
commits `flowEnabled` if its `WriteMessage` returned nil — it cannot detect a
client-side read timeout, BUT in that case client is OFF and server is ON, server
would gate on credit the client never sends → stall. This is the classic
ack-race; it is mitigated by `negotiationAckTimeout=500ms` (generous vs healthy
RTT) + staged rollout, and surfaced via `flow_negotiation_timeout_total`. See
MEDIUM-1 below — it is the only residual asymmetry and it is an accepted,
documented design risk (§4.5 MV1), not a new defect.

### 5. Window: client desired vs server effective — PASS
Client advertises desired (`flowDesiredWindow`, clamped 6 MiB). Server computes
`min(desired, flowMaxWindow)` (negotiateFlowWindow). Client uses the **effective**
value from the ack for `streamFlowState.window` (ws_transport.go:541 → ws_pool.go:1682
→ EnableFlowControl → RegisterStream window = `c.flowWindow` = effective). Server
`newStreamCredit(effective)`. Both use effective. Threshold derived from effective
on both sides. No drift.

### 6. Closure-map completeness (§14/§15) — PASS
- NB1 sync ack read in UpgradeToWS before slot reader — present (ws_transport.go:529-548).
- NB2 `TryEnqueueControl` non-blocking with `default:` — present (wsasyncwriter.go:240).
- NH1 per-client (not per-slot) credit sender, routes via current slot — present
  (stream_flow.go startCreditSender + TryWriteControlMessageForStream follows slot).
- NH2 marker inside encrypted payload — present (BuildFlowCtlMarker after EncryptChunk).
- NV1 server explicitly emits ack in authenticateFirstFrame before runWebSocketSession
  — present (websocket.go:199-208).
- M2 clampFlowWindow 6 MiB vs incomingCh cap — present (stream_flow.go:15-24).
- B2/I3 downlink Add-only, send decoupled — present.
- H3/I4 credit-gate before tc.Read — present (websocket.go:809-822).
- H4 CAS-zero-after-success + watchdog — present (stream_flow.go:154-164).
- H5 half-close: credit-sender independent of app uplink — covered + test passes.
- M1 clamp 2×window — present (stream_credit.go:79). M4 close+Signal under mu —
  present. M5 teardown close-all on done — present (websocket.go:932-939 +
  reader `defer closeDone`).
- LV1 `default:` in WS switch + UnknownFlag metric — present (websocket.go:924).

### 7. Races / deadlock at the seams — PASS (static analysis; -race deferred)
- Server: all credit ops (`newStreamCredit` create, `add`, `consume`, `close`,
  `waitForCredit` lookup) guarded by `creditsMu` for the map and `streamCredit.mu`
  for the bucket. `cond.Signal`+`closed` always under `c.mu` → no lost wakeup (M4).
  Teardown wake goroutine fires on `<-done` (closed by reader `defer closeDone` or
  writer exit) and closes all credits → waiters return -1.
- Client: `streamFlow` map ops under `streamMu`; `pendingDelta`/`lastSentNs`
  atomics; `flowTransport` assigned before sender goroutine launch (happens-before).
  CAS-zero + give-back-on-failure is additive and race-safe.
- `-race` could NOT run here (no gcc/CGO on this Windows host). **MUST run
  `go test -race -count=3 ./core/ ./client/ ./server/` on CI/Linux before final
  sign-off** — this is the only unexecuted gate from design §9.10.

---

## MEDIUM findings (non-blocking)

### MEDIUM-1 — Residual ack-race asymmetry (accepted design risk, verify in canary)
File: `server/websocket.go:199-216`, `client/ws_transport.go:533-548`.
If the server's ack `WriteMessage` succeeds on the wire but the client's 500ms
read deadline expires (slow CF edge, TLS buffering), the server commits
`flowEnabled=true` while the client stays OFF → server gates on credit the client
never returns → that stream stalls after the first 1 MiB window, then the relay's
`waitForCredit` blocks until session teardown. This is the documented MV1 risk
(§4.5), not a new defect. Mitigation already in place: short timeout + staged
rollout + `flow_negotiation_timeout_total`. Recommendation: during the pl1
canary, watch `flow_negotiation_timeout_total` (client) vs `flow_sessions_active`
(server); a persistent gap where server shows active flow sessions but clients
report negotiation timeouts indicates this race is firing in the field. No code
change required to ship.

### MEDIUM-2 — Server credit-wait metrics from design §10 not implemented
File: `server/metrics.go`. Design §10 lists `flow_stream_credit_waits_total` and
`flow_stream_credit_wait_seconds_total` to detect "window too small / throughput
throttled by credit." Only `flow_window_updates_recv_total`, `unknown_flag_total`,
and `flow_sessions_active` are wired. Without the wait metrics, a window-too-small
regression (relay spending time blocked in `waitForCredit`) is invisible
server-side. Observability gap, not a correctness bug. Recommend adding before or
shortly after canary so the canary can actually answer "is 1 MiB enough?".

---

## LOW findings (non-blocking)

### LOW-1 — `EnableFlowControl` `already`-guard not reset by `ResetStreams`
File: `client/client.go:1108` (ResetStreams) + `client/stream_flow.go:48-60`.
`ResetStreams` calls `stopCreditSender()` (nils `flowStop`) but does NOT clear
`c.flowControlEnabled`. A subsequent `EnableFlowControl` sees `already==true` and
will NOT relaunch the credit sender → flow control silently dead after a reset.
NOT a production issue on the WS-pool path (the pool reconnects per-slot via
`connectSlot`; `ResetStreams` has no production caller in the shadowlink module —
it is a single-transport/legacy API). Flagged as latent risk if `ResetStreams`
is ever wired into the pool path. Cheap fix: reset `flowControlEnabled=false` in
`ResetStreams` under `streamMu`.

### LOW-2 — First-slot window wins for the whole client
File: `client/ws_pool.go:1680-1684`, `stream_flow.go:48-60`.
The per-client `c.flowWindow` is set by the first slot to negotiate and frozen
(EnableFlowControl `already`-guard). If two slots ever negotiated different
effective windows, all streams would use slot-0's window regardless of which slot
they ride. Harmless in production (server `flowMaxWindow` and client desired are
both uniform → all slots converge to the same effective window), but the per-slot
`poolSlot.flowWindow` field is then unused for sizing `streamFlowState.window`.
Latent assumption; document or collapse to a single client-level field.

### LOW-3 — `streamFlowState.window` sourced from client-wide field, not the stream's slot
File: `client/client.go:716` (`window: c.flowWindow`).
Design §5.1 says "okno strima beretsya iz slota, na kotorom strim otkryt
(poolSlot.flowWindow)". The code uses the client-wide `c.flowWindow` instead. Same
value in practice (LOW-2), so no byte loss or threshold drift today, but it
diverges from the spec's per-slot intent. Cosmetic/consistency.

### LOW-4 — gofmt alignment churn in `core/chunk.go` (FIXED during review)
Adding `FlagWindowUpdate`/`FlagStreamOpen` widened the const block; gofmt wanted
to re-align the older flag lines. Fixed in this review (chunk.go is LF, builds
clean, `gofmt -l` now empty). The other Bug #8-touched files
(server/websocket.go, client/ws_transport.go, client/ws_pool.go) show gofmt
diffs that are PREEXISTENT CRLF line endings, not Bug #8 changes — left untouched
per project convention (CRLF preexistent, design note).

---

## Verification log
- `go build ./...` → clean.
- `go test ./core/ ./client/ ./server/ ./proxy/...` → all ok.
- Flow-control test subset (verbose): all PASS — `TestWindowUpdateChunk_RoundTrip`,
  `TestParseWindowUpdate_TooShort`, `TestFlowCtlMarker_RoundTrip`,
  `TestNegotiationMatrix`, `TestTryEnqueueControl_NonBlockingWhenFull`,
  `TestFlowControl_NoDropsUnderFastDownload` (integration, 1.34s),
  `TestFlowControl_NoHeadOfLineBlocking`, `TestCreditSender_*` (4),
  `TestStreamCredit_*` (6 incl. teardown/done), `TestHalfClose_DownlinkCreditPathSurvives`,
  `TestNegotiateFlowWindow`, `TestFlowWindowFromEnv`, `TestClampFlowWindow`.
- `gofmt -l` on Bug #8 delta: only CRLF-preexistent files remain (out of scope);
  chunk.go fixed.
- `-race`: NOT run (no gcc/CGO on host) — MUST run on CI/Linux before sign-off.

## Pre-deploy checklist (carry-over)
1. Run `go test -race -count=3 ./core/ ./client/ ./server/` on CI/Linux (design §9.10).
2. Staged rollout: deploy pl1 server FIRST (with `-flow-max-window` default 1 MiB),
   then ship clients with `SHADOWLINK_FLOW_WINDOW` set (§4.5 MV1).
3. Canary watch: `flow_sessions_active` (server) vs `flow_negotiation_timeout_total`
   (client) for MEDIUM-1; add credit-wait metrics (MEDIUM-2) to judge window size.
