# Bug #8 — Per-stream flow-control credit stall analysis (2026-05-30)

Trace + math of why server `waitForCredit` averages 242 ms/block at a 4 MiB
window, and why that correlates with close 1006 on mature WS slots.

## Code map (traced, not guessed)

| Concern | File:line |
|---|---|
| Client credit sender (8ms ticker, 40-60% threshold, 200ms watchdog) | `client/stream_flow.go:76-165` |
| Client `OnStreamConsumed` (add-only, after `conn.Write`) | `client/stream_flow.go:195-206` + call site `proxy/socks5/tcp.go:807` |
| Client `sendWindowUpdate` → `TryStreamWriteControl` (non-blocking) | `client/stream_flow.go:173-190` |
| Server credit bucket (cond.Wait / add / consume) | `server/stream_credit.go:24-101` |
| Server relay loop — `waitForCredit` BEFORE every `tc.Read`, `consume(n)` AFTER write | `server/websocket.go:806-851` |
| Server `handleWindowUpdate` → `cr.add(delta, window)` | `server/websocket.go:915-927` |
| Window negotiation (serverMax clamp) | `server/stream_credit.go:5-15` |
| Client clamp ceiling 6 MiB | `client/stream_flow.go:15` |
| Per-stream incomingCh cap 512 | `client/client.go:710` |
| Client slot read deadline 60s | `client/ws_pool.go:2627` |
| Server WS read deadline 60s (reset on pong) | `server/websocket.go:542` |

## 1. Window math at 4 MiB with range segments

Effective window W = 4 MiB. Server emits downlink frames sized
`min(available, 32768)` per `tc.Read` (`websocket.go:828`), but the chunk
payload is further capped by server `-chunk-size` (12288 = 12 KiB on pl1).
So a 4 MiB window = ~341 in-flight frames of 12 KiB.

`available` starts at W = 4 MiB. Each `tc.Read`+write does `consume(n)`, so
`available` monotonically drops toward 0 until a WINDOW_UPDATE arrives and
`add(delta)` bumps it back up.

The server only **blocks** (`waitForCredit` with `available<=0`) when it has
sent a full window of data faster than the client returns credit. On a
36 MB range segment:

- Bytes per "window drain" = W = 4 MiB.
- Number of times the stream must refill credit on 36 MB = 36 / 4 = **9 refill
  cycles**.
- The stream actually *blocks* (hits `available<=0`) only on cycles where the
  client's credit return lags the server's send rate. Field metric:
  `flow_stream_credit_waits_total = 488` over the whole session, 117959 ms
  total → **242 ms mean per block**. With ~9 potential block points per 36 MB
  segment and many segments, 488 blocks is consistent with the stream
  hitting the wall on most refill cycles.

So the stream DOES repeatedly hit `available<=0`. Each hit = one full
client→server credit round-trip of dead air on the downlink. The question is
why each round-trip costs 242 ms when physical RTT is 50-100 ms.

## 2. Why 242 ms >> RTT — decomposing the credit-return latency

The credit-return path, end to end, is:

```
server consume() drives available→0  (server stops reading target)
   ↓ (server keeps draining the 4 MiB already in flight down to app)
client RouteToStream → incomingCh → tcp.go downlink → conn.Write(app)
   ↓
client OnStreamConsumed(n)  → pendingDelta.Add(n)      [tcp.go:807]
   ↓  *** WAIT FOR NEXT 8ms TICK ***                   [stream_flow.go:99]
creditSenderTick: is pendingDelta >= 0.4-0.6 * W (~1.6-2.4 MiB)?  [stream_flow.go:144]
   ↓  *** ACCUMULATE until threshold crossed ***
sendWindowUpdate → TryStreamWriteControl (non-blocking enqueue)   [stream_flow.go:189]
   ↓  WINDOW_UPDATE frame crosses network (≈ ½ RTT)
server FlagWindowUpdate → cr.add(delta) → cond.Signal()           [websocket.go:925]
   ↓
waitForCredit wakes, relay resumes reading target
```

There are **three additive latencies stacked on top of the network ½-RTT**,
and the dominant one is structural, not the network:

### (a) THE THRESHOLD IS THE ROOT — credit is withheld until 40-60% of the
### window is consumed by the app, NOT sent eagerly.

`creditSenderTick` (stream_flow.go:144-152) only emits a WINDOW_UPDATE when
`pendingDelta >= window * ratio` where ratio ∈ [0.4, 0.6]. At W=4 MiB that is
**1.6–2.4 MiB of app-consumed bytes per WINDOW_UPDATE**.

Consequence: the server sends 4 MiB, drives `available` to 0, and then must
**wait for the client app to consume 1.6–2.4 MiB before a single credit byte
is returned**. The credit does not trickle back as the app drains — it is
batched into one big lump released only after ~50% of the window is gone.

This means the server's *unblock time* is gated by how long the local app
takes to pull ~2 MiB out of `incomingCh` through `conn.Write`, PLUS the
network ½-RTT for the update to arrive. The "wait" the server measures is
**app-drain-time + tick-latency + ½RTT**, and app-drain-time of a 2 MiB lump
over a memConn/loopback at the instantaneous app read rate is exactly the
multi-hundred-ms term that pushes 80 ms RTT up to 242 ms.

Critically: because credit is released in one 2 MiB lump, the server unblocks,
sends 2 MiB (~half a window) almost instantly, hits `available<=0` AGAIN, and
must wait for the *next* lump. The downlink therefore moves in **2 MiB
bursts separated by 242 ms stalls** — a sawtooth, not a smooth stream. That
sawtooth is the user-visible "рывки/паузы".

### (b) 8 ms tick latency — secondary.

`OnStreamConsumed` only does `pendingDelta.Add` (invariant I3, never sends).
The actual send waits for the next `creditSenderInterval = 8ms` tick
(stream_flow.go:99,106-107). Worst case +8 ms, mean +4 ms. Real but small
relative to (a).

### (c) Watchdog does NOT rescue this case.

The 200 ms watchdog (`creditWatchdogNs`, stream_flow.go:78,149) fires only
when `lastSentNs != 0` AND `pendingDelta>0` AND 200 ms elapsed. During a
sustained download `pendingDelta` is climbing fast and crosses the 50%
threshold well before 200 ms, so the watchdog rarely engages — the threshold
path dominates. The watchdog only helps the *tail* (last sub-threshold
fragment), not steady-state throughput.

### Net decomposition of the 242 ms

```
242 ms ≈ time-for-app-to-consume-~2MiB-lump   (dominant, threshold-driven)
       + ~4-8 ms  (8ms tick quantization)
       + ~40-80 ms (½ RTT for WINDOW_UPDATE delivery)
       + ε         (cond.Signal wake, negligible)
```

The mechanism latency (threshold batching + tick) is what makes 242 ms ≈
2.5–5× the physical RTT. It is NOT pure BDP — pure BDP would show the stall
shrinking to ~½RTT as the window grows. See §4.

## 3. Credit-stall → close 1006 on mature slots (THE KILL CHAIN)

Trace the slot during a credit stall:

1. Server relay blocks in `waitForCredit` (websocket.go:815). While blocked it
   does NOT call `tc.Read` and does NOT enqueue any downlink data frame.
2. The WS slot is a *shared* multiplexed conn. During the stall, the ONLY
   thing keeping bytes flowing on that TCP connection is:
   - the server ping (~45 s log-normal jitter, websocket.go:573), and
   - the client keepalive (~20 s log-normal jitter, tcp.go:295 / ws pool).
3. Both client and server arm a **60 s read deadline** that is reset on
   pong/traffic (`server/websocket.go:542`, `client/ws_pool.go:2627`).
4. A 242 ms stall is far under 60 s, so a *single* stall is harmless. The
   problem is **cumulative + correlated with idleness**: on a mature slot
   (age ~97 s) the downlink is moving in the §2(a) sawtooth — long quiet
   gaps where the slot looks idle from the network's point of view. The
   server-side `available<=0` stall means the origin TCP target is also being
   read in bursts, so the *whole* slot has periods of zero downlink bytes.
5. A middlebox/TSPU on a bare-origin direct TCP path (viaCF=false, the field
   mode) reaps long-lived TCP flows that go quiet. The sawtooth's quiet
   windows + the slot's maturity (age 97 s, past any grace) make it a reaping
   candidate. When the middlebox/origin drops the TCP, the client's blocking
   `ReadMessage` returns `close 1006 / i/o timeout` → `handleSlotDeath`
   (ws_pool.go:2677). The slot dies, every active stream on it dies, the app
   sees "Ошибка сети", the download stalls at ~70 MB.

So credit-stall does not *directly* send a close frame — it **manufactures the
idle/bursty downlink pattern that gets the mature direct-origin slot reaped**.
The flow-control sawtooth is the proximate cause of the slot looking idle; the
reaper is the bare-origin middlebox/per-conn timeout (confirmed earlier in
MEMORY as the close-1006-on-mature-slots signature, not our writer rotation).

## 4. Linearity / BDP extrapolation

Data points: W=1 MiB → 525 ms ; W=4 MiB → 242 ms.

If the stall were pure BDP (network-bound), doubling the window halves the
stall, and the stall would asymptote to ~½RTT. Fit the two points to a model
`wait ≈ a + b/W`:

```
525 = a + b/1
242 = a + b/4
⇒ 283 = b·(1 - 1/4) = 0.75·b  ⇒ b ≈ 377   ;  a ≈ 525 - 377 = 148
```

So `wait(W) ≈ 148 ms + 377/W(MiB)`.

- The **148 ms floor (`a`)** is window-INDEPENDENT. It does not shrink no matter
  how large the window. That floor is the mechanism latency: threshold-batching
  app-drain time + 8 ms tick + ½RTT. **This is the smoking gun that it is NOT
  pure BDP** — a pure-BDP curve would have a ≈ ½RTT ≈ 40 ms, not 148 ms.
- The **377/W term (`b`)** IS the BDP/refill-frequency component: bigger window
  = fewer refill cycles = less aggregate waiting.

Extrapolate to a target wait of ~80 ms (≈ RTT): `80 = 148 + 377/W` gives a
**negative W — unreachable.** You cannot reach 80 ms by growing the window
alone, because the 148 ms floor exceeds 80 ms. Growing the window is a
diminishing-returns palliative (fix A/D); the floor must be attacked directly
(fix B/C). At W=8 MiB the model predicts ~195 ms; at 16 MiB ~172 ms — still
>2× RTT. Window growth alone never fixes it.

## 5. Fix evaluation

- **A. Bigger window (8–16 MiB).** Palliative. Per §4 it only chips at the
  377/W term, leaves the 148 ms floor intact; predicted 8 MiB→195 ms,
  16 MiB→172 ms. Also forces growing incomingCh cap 512 (client.go:710) and
  clamp 6 MiB (stream_flow.go:15) in lockstep (8 MiB/12 KiB ≈ 683 frames >
  512). Not the root. **Reject as primary.**

- **B. Lower threshold 50%→25% (or lower).** Directly shrinks the dominant
  term in the 148 ms floor: credit is returned after the app drains 1 MiB
  instead of 2 MiB, so the stall and the sawtooth amplitude both halve. Cost:
  more, smaller uplink WINDOW_UPDATE frames (DPI surface) — but WINDOW_UPDATE
  is a tiny control frame already jittered through the encrypted control
  channel; doubling its rate from ~2/window to ~4/window is negligible vs the
  20 s keepalive cadence. **Strong, cheap, architectural.**

- **C. Eager credit by tick (drop threshold, send whatever accumulated every
  8ms).** This is the HTTP/2-style "return credit as you consume" model and
  eliminates the threshold floor entirely — credit trickles back continuously
  so the server `available` rarely hits 0, killing both the stall AND the
  sawtooth idle gaps that get the slot reaped. Cost: up to one WINDOW_UPDATE
  per 8 ms per active stream during a fast download (~125/s/stream worst
  case). Mitigate with a small floor (e.g. send if pendingDelta ≥ 1–2 chunk
  sizes, i.e. ≥ ~32 KiB) so idle ticks send nothing. **Best architectural fix
  — turns batched-lump credit into a sliding window.**

- **D. Dynamic window autotuning.** Correct long-term (mirrors HTTP/2 BDP
  estimation) but heaviest to build and still rides on top of the threshold
  unless B/C is also done. Defer.

- **E. Keepalive/deadline hardening so the slot survives quiet windows.**
  Treats the *symptom* (slot reaped during sawtooth gaps) not the cause. Worth
  doing defensively (the 242 ms gaps are small; a more aggressive keepalive
  during active-but-credit-stalled streams would mask reaping), but it does
  not restore throughput — the download still moves in 2 MiB sawtooth bursts.
  Secondary/complementary.

### Recommended: **C with a small byte floor, + B as the trivial interim, + E as defensive insurance.**

C (eager credit, floor ≈ 1–2 chunks ≈ 32 KiB) is the architecturally correct
sliding-window model: it removes the 148 ms floor, smooths the downlink so the
slot never goes sawtooth-idle, and so it fixes both the 242 ms stall AND the
close-1006 reaping in one change. B (threshold 25%) is the one-line interim if
C needs design time. A/D are palliatives; D only worth it after C as a refinement.

## 6. Confidence

**High** on the root cause (threshold-batched credit return produces a
window-independent ~148 ms latency floor confirmed by the 2-point
linear-in-1/W fit, plus the §2 code trace showing credit is withheld until
40-60% app-consumption). **High** that window growth alone cannot reach RTT
(floor > RTT). **Medium-high** on the kill-chain step that the sawtooth
specifically causes the mature direct-origin slot to be reaped: the mechanism
is consistent with all field facts (mature slot, direct origin, close 1006,
0 overflow drops) but the *final* "middlebox reaps quiet TCP" link is
inferential — it cannot be byte-proven without a server-side TCP-level trace
correlating a `waitForCredit` stall window against the exact close-1006
timestamp. That single correlation (server pcap or a relay log line stamping
"blocked in waitForCredit Nms" immediately before the reader EOF) would
upgrade it to fully proven.
