# Wire/Transport DPI Trigger Followup (2026-05-02)

**Date:** 2026-05-02
**Reviewer:** Stage 1 audit (read-only verify + extension)
**Reference baseline:** `2026-05-01-track2-transport-dpi.md`
**Scope:** F2/HIGH-3/F3 verify + missed wire/transport pattern scan.
**Out of scope:** crypto, build/CI, server-only flows, Mixpanel calibration (retired by 2026-04-28 pivot), Tier S Resilience (separate track).

---

## Pre-flight

- **utls version:** `v1.8.3-0.20260301010127-aa6edf4b11af` (custom pre-release commit on top of v1.8.3)
- **bogdanfinn/tls-client version:** `v1.14.0`
- **Available `HelloChrome_*` in utls (from `u_parrots.go`):**
  `HelloChrome_58`, `_62`, `_70`, `_72`, `_83`, `_87`, `_96`, `_100`, `_102`, `_106_Shuffle`, `_115_PQ`, `_120`, `_120_PQ`, `_131`, **`_133`** (max non-PSK stable). No `_135`, `_136`, `_137`, `_138`, or higher. The comment in `connmanager.go:255` ("utls upstream lacks HelloChrome_135+") is confirmed accurate against the cached module.
- **Available `profiles.Chrome_*` in bogdanfinn `v1.14.0` (from `profiles/profiles.go`):**
  `Chrome_130_PSK`, `Chrome_131`, `Chrome_131_PSK`, **`Chrome_133`**, `Chrome_133_PSK`, **`Chrome_144`**, `Chrome_144_PSK`, **`Chrome_146`**, `Chrome_146_PSK`. Note: `Chrome_144` exists and was not used before; it sits between the two current choices.

---

## Verify F2 — Chrome version triple

### Inventory of every Chrome-major hardcode

| File:Line | Value | Path | Context |
|---|---|---|---|
| `client/ws_transport.go:204` | `utls.HelloChrome_133` | uTLS cold-path (WS upgrade, cover GET, handshake POST, warmup) | PQ-on: MLKEM via safety-bridge; PQ-off: stock 133 |
| `client/utls_http.go:37` | `utls.HelloChrome_133` | `pqClientHelloSpec()` base spec | Same pool as ws_transport |
| `client/connmanager.go:276` | `profiles.Chrome_146` | bogdanfinn hot-path, PQ-on (default) | H2 SETTINGS + MLKEM via Chrome_146 |
| `client/connmanager.go:274` | `profiles.Chrome_133` | bogdanfinn hot-path, PQ-off | C2 closure: symmetric with cold-path |
| `skins/browser/fingerprint.go:78` | `Chrome/134.0.0.0` | `chromeUA` default — used by `Fingerprint.UserAgent()` | WSTransport handshake POST, cover GET, WarmupRequests |
| `skins/browser/request.go:51` | `Chrome/131.0.0.0` | `UserAgents[0]` — `defaultUserAgent` | DirectTransport `BuildUploadRequest` / `BuildCoverTrafficRequest` fallback |
| `client/decoy_traffic.go:213` | `Chrome/134.0.0.0` | `defaultUA` const | Decoy traffic GET requests |
| `client/leakguard/check.go:29` | `Chrome/134.0.0.0` | `chromeUserAgent` const | CheckIP request |
| `server/handler.go:1660` | `Chrome/134.0.0.0` | UA map in server-side `exportClientConfig` | Server-only, not wire-visible to DPI |

### Current status

**C2 closure is confirmed.** `client/connmanager.go:270-286` reads `pqEnabled()` and returns `Chrome_133` when PQ is disabled, `Chrome_146` when enabled. Test `TestProfileForFingerprint_PQOptOut_ReturnsLegacyChrome` (`connmanager_test.go:231`) pins the contract. The prior F1 opt-out asymmetry is **closed** for the bogdanfinn path.

**F2 remains OPEN in two dimensions:**

1. **Three-major triple mismatch on the default-on path:**
   The wire simultaneously carries:
   - uTLS JA4: derived from `HelloChrome_133` (major 133)
   - bogdanfinn H2 SETTINGS / JA4: from `Chrome_146` (major 146)
   - UA string from `fingerprint.go:78`: `Chrome/134.0.0.0` (major 134)

   A real Chrome client emits all three surfaces with the same major. The
   `(JA4_major=133, H2_SETTINGS_major=146, UA_major=134)` triple is a
   per-device fingerprint stable across reconnects.

2. **Fourth Chrome major via DirectTransport fallback:**
   `skins/browser/request.go:65` sets `defaultUserAgent = UserAgents[0]` =
   `Chrome/131.0.0.0`. Any code path that calls `BuildUploadRequest` or
   `BuildCoverTrafficRequest` without an explicit UA argument falls back to
   Chrome/131 — a fifth version on the wire. DirectTransport (`transport.go`)
   uses these builders for `SendChunk` and the ratio-controller cover traffic;
   it passes the session UA explicitly only when the session has a fingerprint
   attached. In unit tests (no session) and any edge case where the UA argument
   is empty, Chrome/131 leaks. This is a latent fourth Chrome major not flagged
   in the prior audit.

**Upstream gating:** utls has no `HelloChrome_135+` in v1.8.3. Fixing the uTLS side requires either (a) waiting for upstream, or (b) deriving a custom spec from `HelloChrome_133` with extension-ordering tweaks. bogdanfinn v1.14.0 has `Chrome_144` which sits between 133 and 146 — using it for the PQ-off path would narrow the 133↔146 jump but still leave the UA triple inconsistent.

---

## Verify HIGH-3 — Rotation distribution

### ConnManager rotation

`skins/browser/mimicry.go:188-191`:
```go
func (sl *SessionLifecycle) NextActiveInterval() int {
    return sl.minActive + rand.IntN(sl.maxActive-sl.minActive+1)
}
```

`NewSessionLifecycle()` (`mimicry.go:179-186`): `minActive=120`, `maxActive=480`.
Result: **uniform discrete [120, 480] seconds**. Distribution shape: flat histogram across 361 values. A passive observer collecting TCP session durations over ~50 connections sees a rectangular histogram — the opposite of the log-normal or exponential distributions seen with real SPA analytics SDKs (which have heavy right tails from long-open tabs).

`startRotation` in `connmanager.go:340-378` uses `SessionLifecycle` when `minRotation >= 2*time.Minute` (always true for production config). No distribution change since the prior audit. **HIGH-3 is confirmed OPEN.**

### Other rotation/lifetime sites

| File:Line | Distribution | Range | Note |
|---|---|---|---|
| `skins/browser/mimicry.go:190` | uniform | [120, 480]s | ConnManager TCP lifetime — HIGH-3 |
| `skins/browser/mimicry.go:195-203` | weighted discrete | 70% [500,1499]ms, 30% [1500,3000]ms | Gap between reconnects — bimodal, not detectable as uniform |
| `skins/browser/decoy_interval.go` | log-normal μ=ln(25), σ=0.4, [5s,90s] | T2.4 closure | decoy_traffic GET inter-arrival — closed |
| `core/mimicry_session.go` | Pareto α=1.5, [5,600]s sticky | T2.4 closure | next_poll sticky per session — closed |
| `skins/browser/cover.go:119-136` | log-normal μ=ln(8), σ=0.6, [1s,60s] | T1.6 cover GET | inter-probe delay — closed |
| `client/ws_ready_pool.go:104` | point-mass 25s | keepalive tick | NEW finding — see below |
| `client/ws_pool.go:487` | point-mass 20s | keepalive tick | NEW finding — see below |
| `server/websocket.go:391` | point-mass 20s | WS ping tick | server-side, not client wire |

**HIGH-3 is the only open item in this category.**

---

## F3 Decision Matrix

### Current state after C1 (2026-05-02)

`skins/browser/cover.go:30-37` (post-C1):
```go
var defaultCoverPaths = []string{
    "/sdk-config.json",
    "/api/v2/sdk/version",
    "/tag.js",
    "/pixel.gif",
    "/decide",
    "/lib.min.js",
}
```

C1 removed `/health` and `/api/v2/feature-flags`; added `/decide` (Mixpanel
feature-flag lookup, also used by PostHog) and `/lib.min.js` (SDK bundle). The
prior `/health` and `/api/v2/feature-flags` calls were the most obviously
non-SDK entries; the substitutions are more defensible. However:

- `/sdk-config.json` and `/api/v2/sdk/version` have no named counterpart in
  Mixpanel, PostHog, or GA4 SDK traffic (2026 traces).
- `/tag.js` does not match any named SDK path: GTM uses `gtm.js` / `gtag/js`,
  Mixpanel uses `mixpanel-2-latest.min.js`.
- `/pixel.gif` appears in some ad-tech pixel calls but not in analytics SDKs.
- `/decide` matches PostHog's `/decide/` endpoint and is plausible.
- `/lib.min.js` is generic enough to not flag any specific SDK.

The path list remains a designer's composite, not a measured trace of a single
named SDK. The strategic pivot (2026-04-28) retired Mixpanel calibration as a
phantom signal, so the question is whether cover GET serves any purpose at all.

### Decision matrix

**Option 1 — Retire fully**

| Dimension | Assessment |
|---|---|
| Wire effect | Eliminates a class of periodic GET requests during an otherwise WS-only session. TSPU sees only WS frames + keepalives. Matches Reality/Hysteria2/TrustTunnel behavior (no cover GETs). Removes one correlated signal. |
| Implementation effort | `client/ws_transport.go:528-534` (remove `NewCoverGen` + `runCoverScheduler` goroutine spawn). `skins/browser/cover.go` (can be deleted or left dormant). `client/stats.go` (remove cover-GET metric series). ~3 files, LOW effort. |
| Trade-off | Loses the "100% WS frames" mitigation. But the strategic context says TSPU does not parse encrypted bodies — cover GETs defend against a signal that TSPU may not be measuring. Risk: some passive classifiers DO count GET/POST ratio on the TLS session as an HTTP/2 metadata signal. Eliminating it resolves ambiguity cleanly. |
| Backcompat | Server-side: cover GETs hit the decoy handler (`decoy.ServeHTTP`) — server already handles them correctly and ignores them. No server change required. |

**Option 2 — Drastically reduce**

| Dimension | Assessment |
|---|---|
| Wire effect | Ratio ∈ [0, 0.05], cadence median 60s+, paths: `/favicon.ico`, `/robots.txt`, `/`. One GET per ~60-120s is behaviorally consistent with a browser tab checking for service-worker updates or doing lazy resource fetches. Hard to distinguish from a real SPA. |
| Implementation effort | `skins/browser/cover.go:56-107`: change sticky ratio band from [0.25, 0.45] to [0.0, 0.05]; change log-normal params from μ=ln(8) to μ=ln(60) (1-min median); replace `defaultCoverPaths` with 3-entry generic list. ~1 file, LOW effort. |
| Trade-off | Retains the "not 100% WS" property at very low cost. Generic paths (`/favicon.ico`) generate near-zero classifier signal. Disadvantage: still produces a new TLS connection per GET (cover GET uses `buildColdPathClient` not the WS connection), which is a JA3-visible event. At low ratio this is ~1 event per minute — noise-level. |
| Backcompat | No server change required. |

**Option 3 — Keep as-is**

| Dimension | Assessment |
|---|---|
| Wire effect | Current paths post-C1: `/decide`, `/lib.min.js` are PostHog/generic plausible; `/sdk-config.json`, `/api/v2/sdk/version`, `/tag.js`, `/pixel.gif` are not matched to any named 2026 SDK. Ratio [0.25, 0.45] means 1 GET per ~4 POSTs — a detectable pattern if an analyst has a Mixpanel reference trace and sees our paths don't appear in it. |
| Implementation effort | Zero. |
| Trade-off | Leaves the path-list inconsistency open. An analyst with a reference corpus of real SPA traffic can flag `sdk-config.json` as a non-standard path. Against a passive classifier without labeled SDK reference data, the signal is ambiguous (plausibly custom SaaS). |
| Backcompat | N/A. |

**No winner picked — user decision required.**

---

## New Findings

### NEW-1 — Fixed-period keepalive tickers (HIGH)

**Severity:** HIGH for a passive FFT/ACF adversary; LOW for a stateless classifier.

**Sites:**
- `client/ws_pool.go:487`: `time.NewTicker(20 * time.Second)` — client-side keepalive to all ready slots.
- `client/ws_ready_pool.go:305`: `time.NewTicker(p.cfg.KeepaliveInterval)`, default `25 * time.Second` (`ws_ready_pool.go:104`) — idle ready-pool keepalive.
- `proxy/socks5/tcp.go:227`: `time.NewTicker(20 * time.Second)` — per-stream keepalive in TCP relay goroutine.
- `server/websocket.go:391`: `time.NewTicker(20 * time.Second)` — server-side WS ping. (Server-only; included for completeness but out of client-fix scope.)

**Trigger pattern:** A passive adversary capturing WS frame timestamps over
multiple connections sees encrypted binary frames arriving at a metronomic 20s
or 25s cadence during idle periods. FFT of inter-frame arrival times shows a
sharp peak at 0.05Hz (20s) or 0.04Hz (25s). This distinguishes ShadowLink from
real browser WebSocket traffic (e.g. a live-update SPA whose heartbeat varies
based on server push events and JavaScript timers with natural skew).

The `keepaliveLoop` in `ws_pool.go:487` is the most visible because it fires
regardless of whether data flows through the slot. During idle periods (no SOCKS5
streams), the only WS frames are these 20s keepalives — a perfectly periodic
encrypted-binary stream.

**Proposed fix:** Replace the fixed `time.NewTicker` with a jittered timer loop.
Pattern: `base + rand.Int63n(jitterRange)`. For a 20s base, a ±30% jitter
(14-26s, uniform) destroys the FFT peak at trivial cost. Even ±10% (18-22s)
reduces the autocorrelation peak by ~60%.

Implementation scope:
- `client/ws_pool.go:487`: replace `time.NewTicker(20*time.Second)` with a loop
  that calls `time.NewTimer(jitteredInterval(20*time.Second, 0.3))` each iteration.
- `client/ws_ready_pool.go:103-104`: change `KeepaliveInterval` from a single
  value to a `(base, jitterFraction)` pair, or add a `KeepaliveJitter` field.
  Apply jitter inside `keepaliveLoop` rather than in the ticker construction.
- `proxy/socks5/tcp.go:227`: same pattern.

A helper `jitteredKeepalive(base time.Duration, jitter float64) time.Duration`
extractable to `client/util.go` would keep all three sites consistent.

**Estimated effort:** LOW (single helper + 3 call sites, all in `client/` and `proxy/socks5/`).

---

### NEW-2 — `sec-ch-ua` header entirely absent (HIGH)

**Severity:** HIGH for an adversary running a Chrome-version consistency check.

**Sites checked:**
- `client/ws_transport.go:181-183` — handshake POST: only `Content-Type`, `User-Agent`, `Accept`.
- `client/ws_transport.go:257-259` — WarmupRequests: `User-Agent`, `Accept`, `Accept-Language`. No `sec-ch-ua`.
- `client/ws_transport.go:588-590` — cover GET: `User-Agent`, `Accept`, `Accept-Language`. No `sec-ch-ua`.
- `skins/browser/request.go:142-149` — `BuildUploadRequest` headers: `X-Request-ID`, `User-Agent`, `Accept`, `Accept-Encoding`, `Accept-Language`, `Origin`, `Referer`, `Cache-Control`. No `sec-ch-ua`.
- `client/split_transport.go:328-334` — upload headers: same set. No `sec-ch-ua`.
- `client/decoy_traffic.go:175-185` — has `Sec-Fetch-*` but no `sec-ch-ua`.

**Trigger pattern:** Chrome 90+ sends `sec-ch-ua`, `sec-ch-ua-mobile`, and
`sec-ch-ua-platform` on every HTTPS request. Their absence on an HTTP/2
connection that simultaneously presents a Chrome JA4 fingerprint is a
browser-class contradiction. Real Chrome never omits these on non-navigation
sub-resource requests.

For a Chrome 133 UA the expected values are:
```
sec-ch-ua: "Chromium";v="133", "Not(A:Brand";v="99", "Google Chrome";v="133"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
```

For Chrome 146 they would differ in the version field. Today we emit Chrome/134
UA (or Chrome/131 via `defaultUserAgent`) without any `sec-ch-ua` — a
combination that no real Chrome has ever produced since 2021.

**Proposed fix:** Add a `chromeCHUA(majorVersion int) map[string]string` helper
in `skins/browser/fingerprint.go` that returns the three `sec-ch-ua` header
values for a given Chrome major. Call sites in `ws_transport.go`, `request.go`,
and `split_transport.go` populate headers from this map when `fp.Name() ==
ProfileChrome`. For Safari and Firefox these headers are absent (correct — only
Chromium-family sends them).

The fix is gated on F2 resolution: the version in `sec-ch-ua` must match the JA4
major to avoid worsening the triple mismatch. Defer to the same ticket that
aligns uTLS/bogdanfinn/UA major. But the *absence* of the header is
independently wrong even at the wrong version.

**Estimated effort:** MEDIUM (new helper in `skins/browser/fingerprint.go` +
updates to `ws_transport.go`, `request.go`, `split_transport.go`, `decoy_traffic.go`).

---

### NEW-3 — `defaultUserAgent` (Chrome/131) vs `chromeUA` (Chrome/134) split (MEDIUM)

**Severity:** MEDIUM — latent fourth Chrome major on the wire.

**Sites:**
- `skins/browser/request.go:51,65`: `UserAgents[0]` = `Chrome/131.0.0.0`; assigned to `defaultUserAgent`.
- `skins/browser/fingerprint.go:78`: `chromeUA` = `Chrome/134.0.0.0`.

`BuildUploadRequest` (`request.go:103-107`) uses `defaultUserAgent` when the
optional `userAgent` argument is empty. `BuildCoverTrafficRequest` (`request.go:162-163`)
does the same. DirectTransport (`client/transport.go`) calls these builders.
When DirectTransport's caller does not supply a session-fingerprint UA, these
calls fall back to Chrome/131 — a fifth distinct Chrome major on the wire if
DirectTransport and WSTransport are used concurrently from the same device, or
a fourth if only DirectTransport is used.

The `UserAgents` slice has a deprecation comment (`request.go:48`) pointing to
`Fingerprint.UserAgent()`, but `defaultUserAgent` is not deprecated and is
silently used as a fallback.

**Proposed fix:** Change `defaultUserAgent` to use the same value as `chromeUA`
by dereferencing the package-level variable rather than `UserAgents[0]`:

```go
// In request.go — always mirrors fingerprint.go's chromeUA:
var defaultUserAgent = chromeUA  // NOT UserAgents[0]
```

Or, since `chromeUA` is in a different file but same package, this is a single
one-line change. Additionally, delete or unexport `UserAgents` to prevent future
callers from accidentally using Chrome/131.

**Estimated effort:** LOW (single line in `skins/browser/request.go`; optional cleanup of `UserAgents` export).

---

### NEW-4 — DirectTransport cover ticker 5s + 30s point-mass periods (MEDIUM)

**Severity:** MEDIUM — FFT-visible during DirectTransport usage, but DirectTransport
is not the primary production path (WSTransport is preferred for CF CDN).

**Sites:**
- `client/transport.go:189`: `time.NewTicker(5 * time.Second)` — fires `CoverBudget()` check every 5s.
- `client/transport.go:193`: `time.NewTicker(30 * time.Second)` — fires `rc.Reset()` every 30s.

**Trigger pattern:** The 5s ticker produces a periodic POST-or-no-op cadence.
Even when `CoverBudget()` returns 0 (no cover traffic sent), the ticker fires a
check + goroutine wake every 5s. If budget > 0, an encrypted POST fires, making
the 5s period visible in inter-POST timing. The 30s reset ticker is an internal
counter flush, not directly wire-visible, but it causes a budget-burst every 30s
as the ratio resets to zero and the next 5s tick sees a large `CoverBudget()`.

**Proposed fix:** Replace both fixed tickers with jittered timers following the
same pattern as NEW-1. The 5s check can jitter ±50% (2.5-7.5s range). The 30s
reset can jitter ±20%. This eliminates the 5s FFT peak during DirectTransport
sessions.

**Estimated effort:** LOW (2 timer replacements in `client/transport.go`).

---

## Summary table

| ID | Severity | Status | Title |
|----|---|---|---|
| F1 | High (latent) | Closed by C2 on opt-out path; open for documentation gap | PQ flip wire-asymmetric — C2 resolves opt-out; default-on MLKEM gap documented |
| F2 | High | Open — C2 partial (PQ-off symmetry only) | Chrome 133/146/134/131 version quad inconsistent |
| F3 | High | Improved (C1), not resolved; user decision required | Cover GET path realism — see decision matrix |
| HIGH-3 | High | Open — unchanged | ConnManager `NextActiveInterval()` uniform [120,480]s |
| NEW-1 | High | Open | Fixed-period 20/25s keepalive tickers — FFT-visible |
| NEW-2 | High | Open | `sec-ch-ua` headers absent on all Chrome HTTP requests |
| NEW-3 | Medium | Open | `defaultUserAgent` Chrome/131 vs `chromeUA` Chrome/134 split |
| NEW-4 | Medium | Open | DirectTransport 5s + 30s cover tickers — periodic cadence |

---

## Open questions for user

1. **F3 decision:** Option 1 (retire), Option 2 (reduce to [0,0.05] generic paths), or Option 3 (keep as-is)? The strategic pivot makes Option 1 the cleanest choice, but Option 2 costs almost nothing and keeps the 100%-WS mitigation.

2. **F2 sequencing:** NEW-2 (`sec-ch-ua`) fix is gated on an agreed Chrome major. Do you want to pick a single major now (e.g. "align everything to Chrome/133 since that's what utls exports") while waiting for utls 135+? Or defer until utls upstream ships a higher Chrome version?

3. **NEW-1 jitter scope:** The `ws_ready_pool.go` `KeepaliveInterval` config field is public API used by `cmd/nixavpn-client`. Changing its semantics requires coordinating with the CLI entry point. Preferred approach: (a) add `KeepaliveJitter float64` field defaulting to 0.3, or (b) rename to `KeepaliveBase` and document jitter is always applied?
