# Bug #8 — Drain-break causal trace: download stream 87 dies 36ms after byte_budget drain

Date: 2026-05-30
Method: code-trace only (no new diag run). Field log fixed point:

```
14:19:15.723 "WS pool slot drain started" slot=9 replacement_slot=7 reason=byte_budget active_streams=1
14:19:15.726 "uplink done"          stream=87 dest=104.18.54.45 elapsed=5.865s err=EOF fullClose=false
14:19:15.759 "downlink write error" stream=87 closed pipe downlinkBytes=37120474 chunks=1333 streamAgeMs=5898 fullClose=true ctxErr=<nil>
```

## TL;DR root cause

`fullClose=true` on stream 87 is produced by **tun2socks itself**, NOT by our drain and NOT by our cancel.
The chain is:

1. `byte_budget` drain at 15.723 does NOTHING to stream 87's plumbing (proven below). It is concurrent, not causal.
2. tun2socks `pipe()` runs two `unidirectionalStream`s over our memConn `appConn` (= `remoteConn` from tun2socks' POV):
   - `origin->remote` (uplink, app→relay): hit EOF at 15.726 → `originConn.CloseRead()` + `remoteConn.CloseWrite()` (= **appConn.CloseWrite()** → half-close, only d1 closed → `ourConn.writeClosed()==false`). This is the benign "uplink done fullClose=false".
   - `remote->origin` (downlink, relay→app): `io.CopyBuffer(originConn, remoteConn)` returned ~33ms later because **`originConn.Write` failed** — the gVisor TUN endpoint to the local app reset/closed.
3. Both unidirectional copies done → `pipe()` returns → `handleTCPConn` runs `defer remoteConn.Close()` = **`appConn.Close()`**.
4. `memConn.Close()` (app end, isAppEnd=true) closes BOTH directions incl. d2 and fires `peerFullClose`.
5. Our downlink relay goroutine, mid-`conn.Write(data)` into `ourConn` (writes d2), now sees d2 closed → `io.ErrClosedPipe` ("closed pipe") with `connWriteClosed.writeClosed()==true` (d2 closed) → logged `fullClose=true`, `ctxErr=<nil>` (we never cancelled ctx2).

So: **the thing that closes appConn is tun2socks' `defer remoteConn.Close()` in `tunnel/tcp.go handleTCPConn`, fired because the `remote->origin` download copy returned when `originConn.Write` (gVisor → local app) failed.** The local app aborted its own TCP connection.

## Detailed per-question trace

### A. What does startDrain/drain do to the streams of slot 9 at drain start (before watchdog teardown)?

`startDrain` (client/ws_pool_drain.go:358) at drain-start performs ONLY:
- Gate 4 inflight cap (atomic), Gate 5 capacity floor, Gate 6 `tryMarkDraining` CAS (slotReady→slotDraining on slot 9), Gate 7 `claimFreeSlot` (=7).
- `go connectReserveSlot(cl, 7, 9)` + `go drainWatchdog(cl, 9, ...)`.

It does NOT:
- touch `streamMap` (stream 87 → slot 9 mapping untouched),
- close `incomingCh` for any stream,
- call `handleSlotDeath` (that is ONLY reached on watchdog teardown / reader error),
- touch slot 9's `session` or `transport`.

`handleSlotDeath` (ws_pool.go:2954) is what closes `cl.streamChans[id]` for every stream on the slot (lines 2971-2985) and sends a session FIN — but it runs only at watchdog teardown. drainWatchdog ticks at 500ms (`drainPollInterval`); the break happened at 36ms. So teardown did NOT run. Confirmed: drain start is inert w.r.t. stream 87.

### B. Does uplink (StreamWrite / WriteMessageForStream) keep working while slot 9 is slotDraining?

Yes. `WriteMessageForStream` (ws_pool.go:2369) and `WriteControlMessageForStream` (2397) both accept `st == slotReady || st == slotDraining` (lines 2380, 2408). So uplink data frames AND WINDOW_UPDATE credit frames for stream 87 continue to ride slot 9's session during drain. No write failure is introduced by drain. (Moot anyway — the uplink already EOF'd at 15.726.)

The byte_budget reader branch (ws_pool.go:2695-2712) on the graceful path calls `startDrain` then `slot.downBytes.Store(0)` and `continue` — the slot-9 reader KEEPS reading downlink frames and routing them to stream 87's `incomingCh` via `RouteToStream`. Downlink is NOT starved by drain. (Pinned by `ws_pool_drain_test.go` which asserts no immediate `return` after the byte_budget startDrain.)

### C. Where does fullClose=true come from? (the core)

`fullClose` in the log = `connWriteClosed.writeClosed()` = `ourConn.wr.isClosed()` = d2 closed (memconn.go:255, 126).
d2 is closed only by `appConn.Close()` (memConn app end → `c.wr.close()`+`c.rd.close()`, memconn.go:216-225). `appConn.CloseWrite()` closes only d1 (uplink) and would leave `writeClosed()==false`.

`appConn.Close()` is invoked exclusively by tun2socks `handleTCPConn`'s `defer remoteConn.Close()` (tunnel/tcp.go:40), which runs after `pipe()` returns, which requires BOTH `unidirectionalStream`s to finish (tcp.go:47-55).

- Stream `origin->remote` finished at 15.726 (app sent FIN on its write side — normal HTTP request completion). tun2socks did `remoteConn.CloseWrite()` (half-close) — matches "uplink done fullClose=false".
- Stream `remote->origin` = `io.CopyBuffer(originConn, remoteConn)` (tcp.go:60). It reads from `remoteConn` (=appConn.Read = consumes d2 that OUR relay writes) and writes to `originConn` (gVisor `gonet.TCPConn` to the local app, core/tcp.go:72-76). For this copy to return in 36ms it was NOT:
  - `remoteConn.Read` EOF — our relay never closed d2 (we were actively writing into it; the "closed pipe" we logged is the symptom, not the cause),
  - the 60s half-close `SetReadDeadline(tcpWaitTimeout)` set on remoteConn at 15.726 (tcp.go:72, tunnel.go:19 = 60s — far in the future).
  Therefore it returned because **`originConn.Write` returned an error**: the gVisor TCP endpoint to the local app was reset/closed by the app (Chrome aborted the socket — RST / closed read side).

When `originConn.Write` errors, the copy returns → `pipe` returns → `defer remoteConn.Close()` = `appConn.Close()` → d2 closed + peerFullClose fired → our in-flight `conn.Write(data)` returns `io.ErrClosedPipe` ("closed pipe"), `writeClosed()==true`, `ctx2.Err()==nil`. Exact match to the 15.759 line.

`ctxErr=<nil>` independently confirms our code did NOT cancel: the uplink half-close branch (tcp.go:679-685) returns WITHOUT cancel on `writeClosed()==false`, and no `peerFullClose`/`ctx2.Done` path had fired before the write. The teardown came from outside our relay — from tun2socks reacting to the dead gVisor endpoint.

### D. byte_budget relationship — is the drain causal or coincidental?

`reason=byte_budget` means slot 9's `downBytes` (ws_pool.go:2688, per-slot downlink counter, incremented per routed frame in slotReader) crossed `slot.byteBudget` AND `byteBudgetRotationAllowed(slotAge, minInterval)` passed (10s floor). Stream 87 alone pumped 37MB through slot 9, so it tripped the budget. The drain therefore fires *because* a download is hot — it is temporally correlated with active downloads by construction. But the drain's start path (section A) touches nothing on stream 87, accepts draining-slot writes (section B), and does not reach `handleSlotDeath` for 500ms+. **The drain is a bystander, not the agent that closed appConn.** The agent is the app's own RST surfaced via `originConn.Write` failure.

The open second-order question (NOT provable from this log): WHY did the app RST right then. Candidates, in rough likelihood order:
1. The app (Chrome) legitimately aborted that request/connection (user navigated, fetch cancelled, HTTP/1.1 conn reuse churn). Benign; not our bug.
2. A brief downlink stall caused by flow-control credit starvation or incomingCh(512) backpressure during the budget-trip window made gVisor's send buffer to the app stall, and *something* upstream gave up — but a 36ms window is too short for any of our 200ms/8ms credit watchdogs to matter, and a stall does not by itself produce a `Write` error (it would block, then 60s deadline). So this is unlikely to be the trigger by itself.
3. gVisor endpoint reset for an unrelated reason (window/keepalive) — keepalive idle is 60s, not relevant at 36ms.

The previous Bug #8 fix attempts (commit 69a8d1a flow-control credit, abbab1c trace removal "root fixed via flow control") did NOT eliminate this — the field log post-dates flow control. That is consistent with the close originating in tun2socks/gVisor (the app side), which flow control does not govern.

## What this rules out

- NOT drain teardown (watchdog hadn't ticked).
- NOT our `cancel()` (ctxErr=nil; half-close branch doesn't cancel).
- NOT a write rejection on the draining slot (WriteMessageForStream accepts slotDraining).
- NOT incomingCh close (handleSlotDeath not reached).
- NOT the 60s half-close deadline (too far out).
- NOT our relay closing d2 (we were writing it; we never call appConn.Close, only ourConn.Close on relay EXIT — which happens AFTER, in the dialer goroutine defer).

## Remaining uncertainty / next diag

The chain TO appConn.Close is proven from code + log. What is NOT proven from this single log is the *upstream reason* the gVisor endpoint reset (app-initiated abort vs. an induced stall). To close that, the decisive diagnostic is on the `remote->origin` copy / gVisor side:

- Log the exact error returned by `originConn.Write` in tun2socks `unidirectionalStream` for `dir=="remote->origin"` (patch the vendored v2.6.0 `tunnel/tcp.go:60-62` Debugf to a structured field, or wrap `originConn`/`remoteConn` to capture the terminating error + direction + bytes copied). If it is `tcpip.ErrConnectionReset`/`ErrConnectionAborted` → app RST (case 1, not our bug). If it is `ErrClosedForSend`/timeout → induced stall (case 2).
- Correlate `downlinkBytes` continuity: pre-15.726 was downlink still flowing frames into stream 87 right up to 15.759, or did RouteToStream record overflow (cap-512 drops) in that window? `flushBufferOverflow` is emitted at UnregisterStream — grep the same log for "stream buffer overflow drops" on stream 87.
