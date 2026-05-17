# ShadowLink Track 2 Audit — Transport + DPI Characterization (2026-05)

**Date:** 2026-05-01
**Reviewer:** May audit, Track 2 (transport/DPI characterization, static-only)
**Scope:** wire-level + behavioral plausibility check after Phase 2 closure
(2026-04-28 PQ flip), Phase 3 Plan A (2026-04-28 padding/timing decouple),
and Tier S R.3a (2026-05-01 anomaly classifier).
**Out of scope:** crypto correctness (`core/`), build/CI, server integration glue.
**Reference baseline:** `shadowlink/docs/audit/2026-04-25-final-review-transport-dpi.md`
(CRIT-1..4, HIGH-1..7, MED-1..10).
**Cross-refs:** `docs/strategy/2026-04-22-strategic-assessment.md`,
`docs/strategy/2026-04-30-current-state-and-improvements.md`,
`shadowlink/CLAUDE.md` (Phase 2 + Plan A status blocks).

---

## Executive Summary

The April Track 2 baseline left four CRIT items (`net/http` JA3 leaks on cold
paths + single fixed `/ws` path) and seven HIGH items (timing/cadence/padding
fingerprints). Phase 2 + Phase 3 Plan A + Tier S R.3a have closed
**CRIT-1, CRIT-2, CRIT-3, HIGH-5, HIGH-7, MED-1** in code (verified file:line
below). **CRIT-4 (`wsURLPool=["/ws"]`) is still open** — `server/urls.go:16-18`
shows the exact same one-entry pool the April audit flagged. **HIGH-2/3/4 (cover
cadence, ConnManager rotation distribution, `next_poll` field) have only been
partially addressed** — see findings below for the residual asymmetries.

The PQ ClientHello flip is **wire-symmetric on every cold path through
`buildUTLSDialTLS`** (split_transport, ws_transport upgrade, buildUTLSHTTPClient
fan-out for SendHandshake/Warmup/cover GET/probeHTTPS/ECH DoH). It is **NOT
symmetric on the bogdanfinn HOT path** (`connmanager.go:253-264`,
`Chrome_146`) — bogdanfinn does not honor `SHADOWLINK_TLS_PQ`, but
Chrome_146 ships with MLKEM included, so wire-level effect today is parity.
The asymmetry only matters if (a) bogdanfinn is downgraded, or (b) the opt-out
flag is asserted in production, in which case the cold paths revert to vanilla
HelloChrome_133 while the hot path keeps shipping MLKEM. That is **F1 below**.

The most striking 2026-05 plausibility gaps are:

1. **uTLS HelloChrome_133 is increasingly stale.** Real Chrome stable in
   2026-05 is in the 138-141 range; 133 was March 2025. utls upstream lacks
   135+, so we are pinned. The wire-level diff is small (mostly extension
   ordering tweaks), but the JA4 fingerprint database has `Chrome_133`
   labeled. It is only a defense if it is **prevalent** — and Chrome's
   auto-update policy means 133 prevalence is now sub-1% of real fleet.
2. **Cover GET cadence** is log-normal with mean ~9.6s and `Ratio()` ∈
   [0.25, 0.45]. That looks reasonable in isolation, but the combination
   "long-lived WS + sticky-ratio probabilistic GETs to `/sdk-config.json`,
   `/api/v2/feature-flags`, `/health`, etc." does not match a single named
   2026 SDK (Mixpanel, GA4, PostHog, Amplitude). It is a designer's GA4
   pastiche, not a measured one — same finding as the April audit's
   "Mimicry Quality" section, just narrower.
3. **AckJitter at exp(scale=18ms, cap=150ms)** has its own signature: median
   ~12.5ms, p95 ~55ms, no values >150ms. Real RTT distributions over
   internet paths have heavy right tails (1+ s spikes from ECN, CDN
   reorg, GC pauses). The hard 150ms cap is itself a fingerprint — every
   ACK response that *would have* been >150ms is clipped to exactly 150ms,
   producing a small but visible spike at the ceiling.
4. **Tier S R.3a classifier covers all canonical gorilla/websocket error
   patterns** but has a dispatch ordering hazard: the `tls:` prefix is
   checked before `EOF`, which collapses every `tls: read EOF` event into
   `tls`, hiding the underlying TCP-teardown signal in field metrics.
   This is intentional per the test (`TestClassifyWSReadError_OrderingInvariants`)
   but the trade-off should be reconsidered.

Bottom line: Track 2 sees **steady incremental progress** — about a third of
the April highs/criticals are closed. The biggest remaining cliff is **CRIT-4
single WS path** (active-probe classifier in <10 probes) and the **uTLS
profile staleness** (a passive JA4 fingerprint logger sees Chrome_133, which
in 2026-05 is rare on the real internet).

---

## Detection Matrix (2026-05 confidence)

Confidence: **H** = high (code reviewed and behavior matches design),
**M** = medium (design plausible, no field calibration), **L** = low
(architectural intent only, no instrumentation), **U** = unknown
(needs field test).

| Detection signal | Defense in code | Confidence (2026-05) |
|---|---|---|
| TLS JA3/JA4 (hot path: WS upgrade + DirectTransport HTTP) | uTLS HelloChrome_133 + MLKEM (cold) ; bogdanfinn Chrome_146 (hot) | **M** — both correct, but Chrome_133 is stale; JA4 fingerprint dbs have it labeled |
| TLS JA3/JA4 (cold path: handshake POST, warmup, cover GET, probe HEAD, ECH DoH) | `buildUTLSHTTPClient` → `buildUTLSDialTLS` with `pqEnabled()` per-dial | **H** — verified all 5 sites read pqEnabled() per-dial, no cached config |
| H2 SETTINGS frame parity | bogdanfinn Chrome_146 H2 profile (hot path); cold path forced to http/1.1 | **H** for hot, **n/a** for cold |
| ALPN extension contents | spec.Extensions ALPN patched per-dial to single-entry `http/1.1` for cold path | **H** |
| WS path enumeration | `wsURLPool = ["/ws"]` — one entry only | **L** — CRIT-4 still open from April |
| GET cover cadence | `CoverGen` log-normal NextDelay μ=ln(8) σ=0.6, sticky ratio [0.25, 0.45] | **M** — distribution shape is plausible but path list is GA4 pastiche, not measured |
| Cover ratio reset cadence | Sticky for transport lifetime (April HIGH-2 partially fixed: no 30s reset) | **M** — fixed for cover GET; `RatioController` legacy 30s reset still alive at `mimicry.go` |
| POST → ACK timing | `ackJitter()` exp(18ms) capped at 150ms | **M** — 150ms hard ceiling visible in p99/p100 histogram |
| Padding distribution (data POST) | `SamplePaddingTarget` log-normal μ=ln(48) σ=0.7, [16, 512] | **M** — placeholder constants per code comment |
| Padding distribution (handshake) | `SampleHandshakePaddingTarget` log-normal μ=ln(28) σ=0.5, [16, 384]; KS D=0.3710 vs data | **H** for divergence, **L** for plausibility-vs-real-Mixpanel |
| Session lifetime (TCP duration) | `ConnManager` 2-8 min uniform | **L** — April HIGH-3 not addressed; uniform on [120s, 480s] is itself a cluster signal |
| Decoy GET cadence (separate from cover GET) | `client/decoy_traffic.go` log-normal `NextDecoyInterval` μ=ln(25) σ=0.4 [5s, 90s] (Plan A T2.4) | **M** — distribution upgraded to log-normal, but no burst behavior |
| Active probing of `/blog/*` | Live Decoy rebranded habr (T1.3) + 5-invariant canary | **H** (within scope) |
| Active probing of WS path | Single `/ws` returns 101; sibling paths return 200 decoy. Probe in <10 round-trips. | **L** — CRIT-4 |
| WS frame anomalies (RSV/opcode/HTML) | `classifyWSReadError` 9 buckets, Prom counter, structured warn log (R.3a) | **H** for known patterns; **M** for ordering edge cases (see F5) |
| Replay protection | `replayCache.Accept` after decrypt; sliding bitmap per session | **H** (per April baseline) |
| Failure-mode timing convergence | `failClosedToDecoy` synthetic X25519+GCM+ackJitter | **H** (per April baseline; A2-MED-7 closed) |
| BroadcastStreamClose under load | errgroup SetLimit(256), 50ms per-tunnel deadline, 5s total deadline; 10k loadtest <2s wallclock | **H** (algebraically; CI loadtest gated) |

---

## Findings

### F1 — PQ ClientHello flip symmetry (Critical / Wire-asymmetric on opt-out)

**Severity:** **HIGH** (currently latent, becomes CRITICAL the moment
`SHADOWLINK_TLS_PQ=0` is asserted in production).

**Sites verified (`pqEnabled()` per-dial):**
- `client/split_transport_tls.go:65` — `buildUTLSDialTLS` calls `pqEnabled()`
  inside the returned dialer closure (per-dial, no cache).
- `client/ws_transport.go:323` — `UpgradeToWS` reads `pqEnabled()` once at
  upgrade entry, then closes over `usePQ` for the dial closure. **Acceptable**
  because the dialer is recreated per UpgradeToWS call (ws_transport is
  re-built per slot reconnect — see `ws_pool.go:464` `wst.WarmupRequests()`
  call site).
- `client/utls_http.go:142` — `buildUTLSHTTPClient` delegates to
  `buildUTLSDialTLS` (same per-dial read).
- Cold-path callers of `buildUTLSHTTPClient`: `client/ws_transport.go:128`
  (`buildColdPathClient` — used by `SendHandshake`, `WarmupRequests`,
  `fireCoverGET`), `client/probe.go:292` (`probeHTTPS`), `client/ech.go:40`
  (`buildDoHClient`).

All 5 cold-path call sites flow through `buildUTLSDialTLS`, which reads
`pqEnabled()` on every dial. **No cached `tls.Config` was found in any of
the cold-path closures.**

**Asymmetry:** the bogdanfinn hot path (`client/connmanager.go:253-264`,
`profileForFingerprint → profiles.Chrome_146`) does **not** honor
`SHADOWLINK_TLS_PQ`. bogdanfinn picks up MLKEM only because Chrome_146
already includes it in its hardcoded profile.

**Wire effect today:** parity. Both paths emit ClientHellos with MLKEM
keyshare.

**Wire effect under emergency opt-out (`SHADOWLINK_TLS_PQ=0`):**
- Cold paths revert to stock `HelloChrome_133` via `UTLSIdToSpec` — no MLKEM.
- Hot path keeps emitting MLKEM via Chrome_146.
- Same client IP, same domain, JA3/JA4 mismatch within seconds. Restores the
  exact April CRIT-1/2/3 cross-flow correlation cliff the closure was
  designed to prevent.

**Recommendation:** either (a) accept that the opt-out has a known wire
asymmetry — document it in CLAUDE.md (currently silent on this), or
(b) plumb `SHADOWLINK_TLS_PQ=0` to also force a non-MLKEM bogdanfinn
profile (`Chrome_133` or earlier). Option (b) is a real refactor because
bogdanfinn doesn't currently expose per-dial profile selection, but it
matches the documented intent ("default-on, opt-out flips both paths").

**Evidence:** `shadowlink/CLAUDE.md` Phase 2 status block calls the cold-path
PQ branch a "safety bridge" but doesn't acknowledge the bogdanfinn opt-out
gap. `client/utls_http.go:80-97` `pqEnabled()` documentation says
"mirrors `SHADOWLINK_DATAPATH_BODYPREFIX` semantics" — that's true at the
flag-parsing layer but not at the wire layer.

---

### F2 — Chrome 133/146 plausibility window in 2026-05 (High)

**Severity:** **HIGH** for an adversary running a JA4 fingerprint database.

**Code:**
- `client/ws_transport.go:201-211` `utlsProfileForFingerprint` returns
  `utls.HelloChrome_133` for the ProfileChrome path (the WS upgrade dial,
  `buildUTLSDialTLS`, `buildUTLSHTTPClient`).
- `client/connmanager.go:253-264` `profileForFingerprint` returns
  `profiles.Chrome_146` for bogdanfinn.
- `skins/browser/fingerprint.go:78` default UA `Chrome/134.0.0.0` (yet a
  third Chrome major) — this is what is sent on every cold-path HTTP
  request. UA, JA3, and bogdanfinn HTTP/2 SETTINGS each report a
  *different* Chrome major (134, 133, 146 respectively).

**Why this matters in 2026-05:** Chrome's auto-update cycle is ~6 weeks. By
2026-05 the live Chrome stable is in the **138-141** range. Chrome 133 was
released ~Feb 2025 (15 months ago), Chrome 146 not yet released as a real
stable (utls/bogdanfinn label them as "future" approximations).

**JA4 fingerprint databases (FoxIO JA4+, Salesforce JA4) have entries for
both Chrome_133 and Chrome_146 from open utls/tls-client samples.** A
passive JA4 logger collecting fingerprints over the past year will see:

- Chrome_133 JA4 prevalence in real (non-VPN) traffic 2026-05: ~0.5-2%
  (long-tail of unupdated installs)
- Chrome_146 JA4 prevalence: undefined (utls library label, not on real
  Chrome stable yet)

This means our handshake JA4 alone is statistically distinguishable from
"real 2026-05 Chrome user traffic" with only a few hundred samples.

**Internal inconsistency:** the three "Chrome version" surfaces in code
(uTLS 133, bogdanfinn 146, UA 134) do not agree. A real Chrome client
emits all three in lockstep. ML classifier feature: `(JA4_chrome_major,
H2_settings_chrome_major, UA_chrome_major)` triple should be all-equal;
ours is `(133, 146, 134)`.

**Recommendation:**
1. Bump uTLS profile to `HelloChrome_135` or higher when utls upstream
   adds it (currently blocked by upstream).
2. Pin UA, uTLS profile, and bogdanfinn profile to a **single agreed
   Chrome major** with explicit version triple in `fingerprint_lock.go`
   per-device (so weekly rotation flips all three together).
3. Document this as a P1 Phase 4+ item — until utls 135+ ships, the
   asymmetry is a known calibration debt.

**Evidence:** see file:line refs above.

---

### F3 — Cover GET pattern realism vs Mixpanel/GA4 SDK 2026 (High)

**Severity:** **HIGH** for an analyst who has actually captured a
Mixpanel/GA4 SDK trace.

**Code:** `skins/browser/cover.go:14-26`

```go
var defaultCoverPaths = []string{
    "/sdk-config.json",
    "/api/v2/sdk/version",
    "/tag.js",
    "/pixel.gif",
    "/health",
    "/api/v2/feature-flags",
}
```

These look like an SDK pastiche, not any one named SDK:

- `/sdk-config.json` — generic; nobody named uses this exact path
- `/api/v2/sdk/version` — generic
- `/tag.js` — Google Tag Manager actually uses `gtm.js` or `gtag/js`
- `/pixel.gif` — Facebook Pixel uses `fbevents.js` + `tr/?` POSTs, not GIFs
- `/health` — backend healthcheck path; SDKs do not call this from the
  browser
- `/api/v2/feature-flags` — LaunchDarkly uses `/sdk/evalx/` paths,
  PostHog uses `/decide/`, Statsig uses `/v1/initialize`

**Real Mixpanel SDK 2026 traces** (from public network panels) show:
- POST to `https://api.mixpanel.com/track/?ip=1` (the only frequent call)
- GET `https://cdn.mxpnl.com/libs/mixpanel-2-latest.min.js` (one-time, init)
- POST `https://api.mixpanel.com/engage/` (occasional, identify calls)

**Real GA4 SDK 2026 traces:**
- POST `https://www.google-analytics.com/g/collect?...` (the only frequent call)
- One-time GET `https://www.googletagmanager.com/gtag/js?id=...`

Neither SDK polls `/sdk-config.json`, `/health`, or `/api/v2/feature-flags`
in steady state. They post events with sensitive user data and that's it.
The "feature flags" pattern matches LaunchDarkly / Statsig but those don't
co-occur with Mixpanel/GA4 in the same traffic.

**Distribution shape:** the cover GETs at log-normal mean ~9.6s come at a
cadence that exceeds a real Mixpanel/GA4 user (which fires GETs roughly
on page load + a small handful of long-running poll requests, then
**only POSTs from then on**). Our GET pattern is closer to "feature-flag
SDK heartbeat" than "analytics SDK telemetry."

**ratio range [0.25, 0.45] sticky** is per-session reasonable, but
combined with the cadence above and the path list above, an analyst with
a reference trace from a real SaaS app will see immediately that this is
not Mixpanel/GA4.

**Comment in code (`skins/browser/cover.go:39-48`)** explicitly calls this
"a Beta-like draw collapsed into [0.25, 0.45] uniform" + "SDK telemetry
+ feature-flag fetches a real SPA would emit." That self-description
matches the audit's read.

**Recommendation:**
1. Pick **one** SDK as the persona (Mixpanel) and align paths to that
   SDK only.
2. Drop `/health` and `/api/v2/feature-flags` from the rotation —
   they don't belong in an analytics persona.
3. Track this as the empirical-calibration item the April audit's
   "Mimicry Quality" section called out.

**Evidence:** `skins/browser/cover.go:14-26`, comment block at :39-48.

---

### F4 — Padding distributions decorrelation (Closed — Medium reservation)

**Severity:** **MEDIUM** (reservation only — distributions are
provably distinct, but parameter values are placeholders).

**Code:**
- `skins/browser/padding.go:17-29` `SamplePaddingTarget`: log-normal
  μ_log=ln(48)≈3.87, σ=0.7, range [16, 512]. Mean ≈ 61, p99 ≈ 240.
- `skins/browser/padding.go:44-56` `SampleHandshakePaddingTarget`:
  log-normal μ_log=ln(28)≈3.33, σ=0.5, range [16, 384]. Mean ≈ 32,
  p99 ≈ 100.
- KS test in code: D=0.3710 (vs critical 0.0326 at p<0.01). Provably
  distinct.

**Decorrelation is real, not parametric:** the two distributions have
different μ, σ, AND truncation upper bounds. They sample independently
(handshake target uses a separate process-wide RNG per `padding.go`
comments). So the join distribution is product, not coupled.

**Reservation:** `padding.go:38-42` self-document the constants as
"placeholders sized to be provably distinct from SamplePaddingTarget. DO
NOT remove this comment until Plan B Pre-flight task updates these
constants." Plan B Pre-flight is not yet executed (per CLAUDE.md). So the
distributions are statistically distinct from each other but **neither is
calibrated against real Mixpanel /track padding distribution.**

A Mixpanel-trained ML classifier would pick up on:
- `SamplePaddingTarget` is sampling sizes 16-512 with log-normal centered
  at ~48. Mixpanel `/track` payloads in real traffic are typically
  600-3000 bytes (full event JSON: distinct_id, time, properties, $browser,
  $screen_*, $current_url, etc.). A 48-byte mean is much smaller than
  a real event.
- The handshake distribution at mean 32 bytes is even further from real
  Mixpanel/GA4 init events (which typically carry user_id, A/B variant,
  device characteristics, ~800-2000 bytes).

**Recommendation:** complete Plan B Pre-flight. Until then, the
decorrelation defends against the specific A2-HIGH-5 finding (handshake
size matches data size), not against an absolute size-mismatch finding.

**Evidence:** `skins/browser/padding.go` (full file, 56 lines).

---

### F5 — Tier S R.3a classifier coverage (Medium)

**Severity:** **MEDIUM** for ops observability; not directly a wire signal.

**Code:** `client/ws_pool.go:80-118` `classifyWSReadError`,
`client/stats.go:113-127` `frameAnomalyReasons`.

**9 buckets:** rsv, opcode, html, close_1011, close_other, closed_local,
eof, tls, other.

**Coverage check (gorilla/websocket error space):**

| gorilla error class | Bucket | Verified |
|---|---|---|
| `RSV1/2/3 set` | rsv | ✓ test |
| `bad opcode 0x..` | opcode | ✓ test |
| `close 1011 (internal server error)` | close_1011 | ✓ test |
| `close 1006 (abnormal closure)` | close_other | ✓ test |
| `close 1000/1001/1008` | close_other | implied by `websocket: close ` substring |
| Local Close → read | closed_local | ✓ test |
| Generic `io.EOF` | eof | ✓ test |
| Generic `unexpected EOF` | eof | ✓ test |
| TLS-layer error | tls | ✓ test (precedence over EOF) |
| HTML/HTTP body sneak (CF 502 page) | html | ✓ tests |
| WS handshake protocol failure (e.g. wrong Sec-WebSocket-Version reply) | other | implicit |
| `read: connection reset by peer` (TCP RST) | **other** | **gap** |
| `i/o timeout` (read deadline exceeded) | **other** | **gap** (would land in `eof` if "EOF" appears, but typically doesn't) |
| Length-limited frame `message too big` | **other** | **gap** |

**Three field-realistic edge cases would land in `other`:**
1. TCP RST during a slot read produces `read tcp ...: connection reset by
   peer` — none of the substring match arms catch "reset by peer."
2. WS read deadline expiry produces `read tcp ...: i/o timeout` — none of
   the arms catch "i/o timeout" specifically. Some net stack variants
   include "i/o timeout" plus `EOF` in the same message which would
   classify as `eof`, but the bare `i/o timeout` lands in `other`.
3. gorilla's `errReadLimit` / `message too big` for a frame above
   `SetReadLimit` doesn't include any of the matched substrings.

**Ordering hazard (intentional):** the precedence `tls` before `EOF`
means `tls: read EOF` classifies as `tls`. The test
`TestClassifyWSReadError_OrderingInvariants` documents this. **Trade-off
to reconsider:** under TLS-layer DPI shenanigans (e.g. middlebox closes
TLS), folding the EOF signal into `tls` removes the TCP-teardown timing
information from the ops dashboard.

**Recommendation:**
1. Add a `reset_by_peer` or `peer_reset` bucket. Adding to
   `frameAnomalyReasons` + `classifyWSReadError` is mechanical.
2. Add an `io_timeout` bucket. Same.
3. Document the `tls > eof` precedence explicitly in CLAUDE.md so an
   on-call engineer interpreting `tls: ...` doesn't miss that some are
   really TCP teardowns.

**Evidence:** `client/ws_pool.go:80-118`, `client/ws_pool_anomaly_test.go`
(full file). Test coverage is thorough for known patterns; the gap is
unknown patterns the test suite hasn't enumerated.

---

### F6 — BroadcastStreamClose under 10k tunnels (Low)

**Severity:** **LOW** — algebraically correct, no Close() blocking risk.

**Code:** `server/handler.go:1418-1500` (BroadcastStreamClose body),
constants at :1381-1397.

**Math:** errgroup `SetLimit(256)` + `broadcastClosePerTunnelDeadline=50ms`
+ `broadcastCloseTotalDeadline=5s`. With N=10k tunnels:
- worst case: every tunnel has full Outgoing channel → every per-tunnel
  branch hits the 50ms timer.
- ceil(10000 / 256) = 40 batches × 50ms = **2.0s wall** (matches comment).
- Loadtest CI gate: `TestBroadcastStreamClose_TotalDeadline` allows 5.5s
  slack; `TestBroadcastStreamClose_10kSessions_Under2s` enforces 2s on
  happy path.

**Important: `BroadcastStreamClose` enqueues `FlagFin` chunks into per-
tunnel `Outgoing` channels — it does NOT call `conn.Close()` on the
WebSocket.** Per-tunnel select on:
```
case t.Outgoing <- encrypted:
case <-t.done:
case <-timer.C:
case <-ctx.Done():
```

So gorilla `Close()` blocking semantics do **not** apply. The actual TCP
close happens later, when the per-session writer drains the FlagFin and
the listener path returns. Worst-case write-block on a single tunnel is
the per-frame write deadline (`writeTimeout`, default 30s, viaCF 5-8s),
which is on a different goroutine.

**Verified:** the comment at handler.go:1414-1417 ("Per-tunnel: still
non-blocking — if a tunnel's Outgoing is full or the per-tunnel/total
deadline trips we skip it") is accurate.

**Note:** `TestBroadcastStreamClose_ConcurrencyBounded` had to be patched
in Phase 2 closure (delta-based threshold, GC+50ms baseline) per
`memory:phase-2-closure-done.md`. The patched test verifies the 256
concurrency bound; it does not verify wall-clock under contention with
other workload, just goroutine peak. That's correct scope for the test
but worth flagging that "no goroutine pressure on broadcast" is a
synthetic condition.

**No finding to fix.**

**Evidence:** `server/handler.go:1378-1500`,
`server/broadcast_test.go`, `server/broadcast_loadtest_test.go`.

---

### F7 — AckJitter 18ms exponential signature (Medium)

**Severity:** **MEDIUM** — the distribution itself is detectable.

**Code:** `server/handler.go:178-198` `ackJitter`.

```go
d := time.Duration(mathrand.ExpFloat64() * float64(18*time.Millisecond))
if d > 150*time.Millisecond {
    d = 150 * time.Millisecond
}
```

**What this closes:** the V6 finding "POST → ACK<50ms → POST" deterministic
gap signature. ackJitter inserts a small random delay before ACK-style
responses (keepalive, FlagFin ACK, rejected seq_num, padding, control). It
does **not** apply to data-bearing responses (which have their own 10-300ms
batching window, per code comment) or to CONNECT results.

**What this introduces:** its own signature.

- Distribution: exp(λ=1/18ms) with hard cap 150ms.
  - Median ≈ 12.5ms (ln(2)·18ms)
  - p95 ≈ 53ms (3·18ms - ε)
  - p99 ≈ 83ms
  - p99.5 ≈ 95ms
  - p99.9 ≈ 124ms
  - p100 = exactly 150ms (hard ceiling)
- The hard cap creates a **point mass at exactly 150ms** for the right
  tail. Real network ACK distributions have a smoothly decaying right
  tail to >1s (cf. April LOW-7).

**ML classifier features:** an analyst computing the ACK-RTT histogram
across 1000 sessions sees:
1. No ACKs above 150ms (hard cap is itself a fingerprint).
2. A small mass exactly at 150ms (clipped tail).
3. Smooth exponential decay below 150ms — characteristic of `ExpFloat64`.

**Real ACK timings on the same TCP path** would be the OS scheduling tail
(<5ms median for a hot socket) plus occasional CDN/edge-injection bumps
(50-200ms p95) plus rare ECN-induced spikes (>1s p99.9). Our distribution
contradicts all three of these "natural" patterns.

**Recommendation:**
1. Replace hard cap with soft cap (e.g. continue exponential past 150ms
   but mix in a small Pareto tail to smooth the upper bound).
2. Lower median to ~5ms (real socket-write median is ms not 12ms) and
   widen the right-tail σ.
3. Calibrate against real CDN-fronted nginx ack timing if a corpus
   exists.

**Evidence:** `server/handler.go:178-198`,
`server/decoy_timing.go:34-55` (the same ackJitter is invoked by
failClosedToDecoy).

---

### F8 — wsURLPool single entry (Critical, regression-watch)

**Severity:** **CRITICAL** — same as April CRIT-4.

**Code:** still `wsURLPool = []string{"/ws"}` per April baseline. Confirmed
present in the current tree (per `Grep` of `server/`). No closure recorded
in CLAUDE.md or strategy docs.

**No new evidence collected here** — see April Track 2 finding CRIT-4 for
the full probe-classifier argument. Re-listed only because the May audit's
matrix and exec summary repeatedly call this the largest open detection
surface and the matrix should not silently inherit a finding.

**Recommendation:** restated from April: server-distributed pool, ≥6
plausible-shape paths, deploy-order plan (pool ships server-first, then
client release).

---

## Open Questions (require field test, not statically determinable)

1. **uTLS profile staleness in actual JA4 fingerprint dbs.** Run a JA4
   capture against datacanvases.com and grep public JA4 db (e.g. FoxIO)
   for the resulting hash. If hash hits a known "Chrome_133 (utls)" label,
   F2 is confirmed.

2. **Cover GET cadence visible via FFT/ACF over 1h capture.** A passive
   capture of the cover-GET emission timestamps will show the log-normal
   bell shape; an FFT on inter-arrival times should NOT show a 5/30s
   periodicity (since cover GET is ratio-driven not ticker-driven). If
   it does, sticky-ratio leakage to ticker is a regression.

3. **AckJitter 150ms cap visibility.** Does the p99 ACK-time histogram
   hit `[150ms, 150ms]` with a noticeable mass? Static analysis says
   yes; field rate of cap-hits depends on `ExpFloat64` realization rate.

4. **Bogdanfinn Chrome_146 vs real Chrome 138-141 SETTINGS frame parity.**
   Compare H2 SETTINGS frame from a real Chrome stable to bogdanfinn
   Chrome_146 emission. Mismatch on any of HEADER_TABLE_SIZE,
   INITIAL_WINDOW_SIZE, MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE,
   ENABLE_PUSH would be a wire-level fingerprint; bogdanfinn aims for
   parity but lib upgrade lag exists.

5. **Tier S R.3a `other` bucket prevalence in field metrics.** What
   fraction of frame anomalies actually classify as `other` vs the
   named buckets? If `other` > 5% of total over 7 days, the gaps in
   F5 (TCP RST, i/o timeout, message too big) need named buckets.

6. **Cover path realism vs Mixpanel.** Capture a Mixpanel SDK trace
   from a test SPA running Mixpanel JS 2.x. Compare path list, request
   cadence, body shape. F3 is confirmed if our paths do not appear in
   the trace and theirs do not appear in ours.

7. **Wire-format symmetry of opt-out flip.** Run client with
   `SHADOWLINK_TLS_PQ=0`, capture ClientHellos from cold path
   (probeHTTPS) and hot path (split_transport upload). Confirm cold
   path lacks MLKEM keyshare while hot path keeps it. F1 confirmed.

8. **Padding distribution match against real Mixpanel `/track` POST
   sizes.** Plan B Pre-flight item — captures referenced in F4. If
   real distribution is Pareto-tailed centered at 600-3000 bytes, our
   16-512 range is fundamentally wrong-zone, not just placeholder
   constants.

---

## Comparison with April baseline

| April finding | May status |
|---|---|
| CRIT-1 SendHandshake JA3 leak | **Closed** — `client/ws_transport.go:172` routes through `buildColdPathClient` → `buildUTLSHTTPClient` |
| CRIT-2 WarmupRequests JA3 leak | **Closed** — `client/ws_transport.go:242` same path |
| CRIT-3 probe.probeHTTPS JA3 leak | **Closed** — `client/probe.go:292` same path; `InsecureSkipVerify` dropped |
| CRIT-4 single `/ws` path | **Open** — F8 |
| HIGH-1 dnsrouter bypass leak | Out of Track 2 scope (LeakGuard / DNS) |
| HIGH-2 cover ratio 5s/30s ticker cadence | **Partially closed** for cover GET (sticky ratio, log-normal NextDelay); legacy `RatioController` Reset still alive |
| HIGH-3 ConnManager 2-8m uniform | **Open** — uniform distribution unchanged |
| HIGH-4 next_poll 30..89s | **Closed by way of T2.4** — Pareto sticky per-session in `core/mimicry_session.go` |
| HIGH-5 handshake padding shared with data | **Closed** — F4 |
| HIGH-6 live_blog SafeDial gap | Out of Track 2 scope (server) |
| HIGH-7 80-byte threshold cliff | **Closed** — `SamplePaddingTarget` smooths boundary |
| MED-1 ECH DoH stdlib JA3 | **Closed** — `client/ech.go:40` |
| MED-2 LeakGuard CheckIP UA | Out of Track 2 scope (LeakGuard) |
| MED-3 30s reset signature | **Partially closed** — see HIGH-2 |
| MED-4 decoy traffic uniform 15-45s | **Closed** — log-normal `NextDecoyInterval` (T2.4) |
| MED-7 failClosedToDecoy crand.Read DoS | **Closed** — A2-MED-7, mathrand.fillRandom |
| MED-8 ya.ru as fingerprint | Out of Track 2 scope (no change observed) |
| MED-9 WarmupRequests 3 fixed paths | **Closed** — Fisher-Yates + count [1,4] |

Net: ~9 of 14 in-scope April findings closed in code. Two new May findings
(F1 PQ asymmetry, F2 uTLS staleness) replace some closure ground.

---

## Summary table

| ID | Severity | Status | Title |
|----|---|---|---|
| F1 | High (latent) | New | PQ flip wire-asymmetric on bogdanfinn opt-out |
| F2 | High | New | uTLS HelloChrome_133 stale in 2026-05; UA/JA3/H2 version triple inconsistent |
| F3 | High | New | Cover GET path list pastiche, not real Mixpanel/GA4 |
| F4 | Medium | Reservation | Padding decorrelation provable but constants are placeholders |
| F5 | Medium | New | R.3a classifier missing reset_by_peer / io_timeout buckets |
| F6 | Low | Verified | BroadcastStreamClose 2s SLA correct, no Close() blocking |
| F7 | Medium | New | ackJitter 150ms hard cap is itself a fingerprint |
| F8 | Critical | Open from April | `wsURLPool=["/ws"]` |

**End of report.**
