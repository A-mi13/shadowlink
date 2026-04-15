# ShadowLink CF CDN Regression Audit

## Scope

This document is an audit report only. No product code changes are included.

Context from [FOR-CODEX.md](</D:/Job/shadowlink/FOR-CODEX.md>) was checked against the current client and server code paths involved in `viaCF` WebSocket pool mode.

## Executive Summary

Most likely root cause is not a generic protocol breakage and not the origin server. The stronger fit is:

1. Cloudflare-facing WebSocket slots are hitting backpressure under real browser burst load.
2. The client turns that backpressure into full slot death too aggressively.
3. Pool recovery then amplifies the outage through `meltdown` cooldown behavior.

Direct mode staying healthy at 225 Mbps makes nginx/origin/session crypto much less likely as the primary fault domain.

## Main Findings

### 1. Writer-side timeout is a strong candidate for the first failure

`WSAsyncWriter` applies a per-frame write deadline of 30 seconds to every WebSocket frame in [core/wsasyncwriter.go](</D:/Job/shadowlink/core/wsasyncwriter.go>):

- `NewWSAsyncWriter(...): writeTimeout = 30 * time.Second` at `core/wsasyncwriter.go:57-67`
- `writeFrame()` sets `SetWriteDeadline(now + writeTimeout)` and then calls `WriteMessage(...)` at `core/wsasyncwriter.go:135-137`
- `Run()` exits on the first write error at `core/wsasyncwriter.go:94-96`, `110-120`

On the client side, `UpgradeToWS()` starts that writer and closes the WebSocket connection if the writer exits in [client/ws_transport.go](</D:/Job/shadowlink/client/ws_transport.go>):

- async writer created at `client/ws_transport.go:304-306`
- writer goroutine closes the connection on error at `client/ws_transport.go:318-324`

Inference: if Cloudflare stalls a frame for longer than 30 seconds, the writer can kill the slot even if the protocol/session state is still otherwise valid. The subsequent reader-side failure is then a secondary symptom.

### 2. The pool recovery policy can magnify a partial Cloudflare hiccup into a full outage

`WSPoolTransport` has built-in meltdown logic in [client/ws_pool.go](</D:/Job/shadowlink/client/ws_pool.go>):

- default `MeltdownWindow = 5s` at `client/ws_pool.go:136-137`
- default `MeltdownThreshold = ceil(size/2)` at `client/ws_pool.go:139-142`
- default `MeltdownCooldown = 10s` at `client/ws_pool.go:145-146`
- reconnect loop pauses while cooldown is active at `client/ws_pool.go:322-365`
- slot death increments recent-death count and can trigger cooldown at `client/ws_pool.go:382-407`

With `8` slots, the default threshold becomes `4` deaths in `5s`. If several CF-facing slots fail close together, reconnect is intentionally paused, which matches the observed "pool enters meltdown cooldown, decrypts collapse to zero" pattern.

This does not look like the primary trigger, but it is a clear outage amplifier.

### 3. `viaCF` mode is already treated as specially fragile by the client

In [cmd/nixavpn-client/engine_shadowlink.go](</D:/Job/shadowlink/cmd/nixavpn-client/engine_shadowlink.go>), `viaCF` mode explicitly reduces load per slot:

- `viaCF` detection at `engine_shadowlink.go:266-267`
- `MaxStreamsPerSlot = 4` at `engine_shadowlink.go:268`
- `MaxPendingPerSlot = 2` at `engine_shadowlink.go:269`

That is consistent with the code already acknowledging that Cloudflare behaves worse under aggressive multiplexing than direct origin mode.

### 4. The slot reader itself is not obviously the original cause

The slot reader in [client/ws_pool.go](</D:/Job/shadowlink/client/ws_pool.go>):

- reads with a 30-second timeout at `client/ws_pool.go:761`
- ignores timeout-like read errors and continues at `client/ws_pool.go:772-773`
- only declares slot death on non-timeout errors at `client/ws_pool.go:775-776`

That makes pure reader timeout a weaker primary explanation. A writer-originated connection close fits the observed cascade better because it would surface to the reader as a non-timeout terminal error.

### 5. Per-WS stream ownership on the server is strict, but this is not the best fit for the reported symptom

Server WebSocket handling keeps a per-connection `streams` map in [server/websocket.go](</D:/Job/shadowlink/server/websocket.go>):

- map creation at `server/websocket.go:205-206`
- `FlagData` lookup uses the current WS session's map at `server/websocket.go:270-274`
- stream registration/removal occurs at `server/websocket.go:306-323`, `341-343`, `371-373`

This is architecturally important, but it would more likely cause misrouted or dropped stream data, not synchronized death of all CF slots after 20-40 seconds while direct mode remains healthy.

## Hypothesis Ranking

### H1. CF rate limiting on handshake POSTs

Status: plausible, but secondary.

Why:

- Pool mode creates multiple slots, each with its own session setup path.
- This can make cold start and reconnect storms worse.

Why not primary:

- Your reported failure window is after active browsing, not only during initial setup.
- `CONNECT_OK` latency is reportedly still normal.

### H2. Cloudflare edge backpressure / tail drop under browser burst

Status: strongest fit.

Why:

- Reproduces only through Cloudflare, not direct IP.
- `viaCF` already has reduced concurrency settings.
- A slow or blocked frame write aligns with the 30-second writer deadline and near-simultaneous slot death.

### H3. MTU / fragmentation around ~32 KB WebSocket frames

Status: weak.

Why:

- Current code evidence points more strongly to write-side deadline behavior than to a frame-size-specific break.
- Direct mode using the same protocol path argues against a generic framing defect.

### H4. nginx / origin buffering problem

Status: weak.

Why:

- Direct mode hits the same origin and stays fast.
- The fault domain is much more likely client <-> CF edge behavior.

### H5. `meltdown` is too aggressive

Status: confirmed as amplifier, not primary trigger.

Why:

- The code clearly freezes reconnect attempts after a moderate number of slot deaths.
- That can convert a transient edge problem into a longer user-visible outage.

### H6. New hypothesis: writer deadline, not reader timeout, is the real first domino

Status: strongest code-level inference.

Why:

- 30-second per-frame write deadline exists.
- Writer closes the socket on failure.
- Reader then sees terminal errors and declares slot death.
- This explains the "everything dies together" pattern better than isolated reader stalls.

## Root Cause Assessment

Working conclusion:

Cloudflare mode is likely failing because the current pooled WebSocket client treats CF backpressure as a fatal slot error too quickly. The immediate candidate is the async writer's 30-second per-frame deadline, with pool meltdown logic making recovery materially worse once several slots die in a short window.

Confidence: medium.

Reason confidence is not high:

- I did not run live traffic reproduction in this environment.
- Go toolchain is not available here, so no local instrumentation build/test was possible.

## What I Would Verify First

These checks should confirm or falsify the main hypothesis quickly.

1. Raise logging around writer exit in `client/ws_transport.go`.
   Capture the original `writer.Run()` error before the reader reports slot death.

2. Log whether slot death was preceded by:
   `writer exit` -> `conn.Close()` -> `slot reader error`

3. In CF mode only, compare:
   current behavior vs a temporary build with a much larger WS write timeout
   for example `120s`

4. Track whether meltdowns are preceded by 4+ writer exits inside 5 seconds.

If that pattern appears, the primary cause is effectively proven.

## Minimal Validation Plan

1. Start from current code without architectural rewrites.
2. Add diagnostics only:
   log writer-exit reason, slot index, CF/direct mode, and whether reconnect entered meltdown.
3. Reproduce with `bin/connect-vpn-cdn.bat` as administrator.
4. Browse normally for 30-60 seconds.
5. Compare with `bin/connect-vpn-direct.bat`.
6. Check whether CF failures cluster around writer-side deadline expiry rather than around handshake/setup.

## Recommended Next Steps

Priority order if you want to move from audit to patching later:

1. Instrument writer-exit and slot-death causality.
2. Validate whether longer write deadline stabilizes CF mode.
3. If confirmed, tune `meltdown` separately because it is currently an amplifier.
4. Only after that, revisit larger architectural ideas such as staggered slot startup or fewer CF slots.

## Non-Findings

The current code does not support these as the best primary explanation:

- shared session contention
- generic protocol encryption failure
- origin-only nginx failure
- a server-only regression independent of Cloudflare

## Limitations

- No live reproduction was run here.
- No compile/test pass was run here because `go` is not installed in this environment.
- This report is based on static code audit plus the reproduction notes in [FOR-CODEX.md](</D:/Job/shadowlink/FOR-CODEX.md>).
