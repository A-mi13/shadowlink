# ShadowLink Final Review — Transport & DPI Evasion

**Date**: 2026-04-25
**Scope**: `client/transport.go`, `client/ws_transport.go`, `client/probe.go`, `client/split_transport.go`, `client/decoy_traffic.go`, `client/leakguard/`, `client/dnsrouter/`, `client/ech.go`, `skins/browser/{request,mimicry,fingerprint,fingerprint_lock,urls,shaping}.go`, `server/{handler,websocket,live_blog,live_blog_canary,live_blog_timing,html_rewriter,decoy_timing,safedial,decoy,urls}.go`
**Reviewer**: Opus subagent (network-security / DPI-evasion focus)
**Out of scope**: pure crypto correctness (`core/`), build pipeline, NixaVPN integration glue
**Cross-references**: `shadowlink/docs/research/2026-04-19-dpi-evasion-state-of-art.md`,
`shadowlink/CLAUDE.md`, memory/`cf-cdn-facts.md`, memory/`shadowlink-dpi-action-plan-2026-04.md`

---

## Executive Summary

ShadowLink, after the April 2026 audit cycle (T1.3 Live Decoy + T1.4 V1 closure +
WB TURN/WhitePass cleanup), is in significantly better DPI-resistance shape than
any open-source HTTPS-stego comparable I know of in this project's class
(Naïveproxy, Cloak, Xray-XHTTP). The architecture-level invariants are solid:

- TLS fingerprint via uTLS on **all the hot paths** (CDN POST upload,
  WebSocket upgrade, SplitTransport upload + download stream) — this closed
  P0.5 from the April action plan.
- HTTP/2 SETTINGS frames go through `bogdanfinn/tls-client` Chrome-133 /
  Safari-16 / Firefox-135 profiles; default Go `http2.Transport` is no longer
  on a hot path.
- Wire-level token leakage (the V1 / V2 vectors flagged in the action plan)
  has been migrated to body-prefix on the HTTP data path (Phase B
  hybrid-dispatch) and to first-frame auth on WebSocket (Phase C). Default
  for `SHADOWLINK_DATAPATH_BODYPREFIX` is still off pending the 48 h soak —
  this is a **known canary-stage migration**, not a regression.
- Live Decoy (T1.3) reduces fingerprintability of the decoy itself by
  rebranding live habr.com content; the 5-invariant canary loop catches
  upstream-HTML drift before it leaks into served bytes.
- LeakGuard with kill-switch is implemented atomically with rollback per
  platform; DNS/IPv6 backup is restored in the right order on failure.

That said — **the review found 3 wire-visible Go-fingerprint leaks still
present on cold paths** that an adversary can probe deterministically. The
impact is best characterized as: anyone who is **already suspicious of the
domain** (because TSPU / CF-side has seen anomalies) can confirm
"this is a Go-based proxy, not a real browser" by triggering one of these
paths. They don't constitute "VPN detection from N=1000 samples" by
themselves, but they collapse the cost of confirmation from "needs ML
classifier" to "needs a single targeted probe."

The other dominant finding is **mimicry quality**: the analytics envelope
mimicry, response inflation, and ratio controller are mathematically
sensible but they all encode **a designer's mental model of GA4/Mixpanel
traffic, not a measured one**. There is no live calibration loop against a
real GA4 corpus, and several implementation choices diverge from how real
SDKs behave in ways DPI ML can pick up on with enough samples. This is the
single biggest improvement vector for the next audit cycle.

Bottom line: ShadowLink is shipping-ready against current TSPU rules and
against an ML classifier that hasn't been trained on ShadowLink yet. It is
**not** ready against a focused investigation of a specific endpoint by a
state-level analyst — the cold-path leaks plus mimicry-model gaps would
collapse that investigation in hours, not days.

---

## DPI-Resistance Assessment

**Adversary models, ranked 1-5 (5 = ShadowLink defeats this adversary
reliably; 1 = ShadowLink is easily defeated).**

| Adversary | Capability | Resistance | Notes |
|---|---|---|---|
| **TSPU (Russia, current rules)** | SNI parsing, JA3/JA4, packet-size clustering, 15-20 KB freeze on suspicious flows, stateful QUIC drop | **4/5** | Hot paths use uTLS + Chrome H2 SETTINGS. Live Decoy + brand rewriting defeats path-based detection on `/`. Cold-path leaks (probe.go, ws_transport handshake/warmup) are detectable but not on the steady-state flow. |
| **TSPU + ML classifier trained on legit GA4 traffic** | Cross-layer RTT, payload-size distribution match, request graph (POST/GET ratio, cadence) | **3/5** | Decoy GET mix (V5 fix) helps, but the request graph still has measurable artifacts: POST→ACK<150ms is jittered but the tail is too tight (max 150ms vs real GA4 long tails); the 5s cover-budget tick is a behavioral signal; 30s ratio-controller reset is a regular signature. |
| **Cloudflare middlebox** | Per-flow byte limits, WS lifetime, h2 ping behavior, IP reputation | **4/5** | Hot paths fall back gracefully (`SplitTransport` fresh TCP per POST + persistent stream download; WS Pool with meltdown protection). The `cf-cdn-facts.md` analysis confirms CF doesn't break VLESS-style 1-WS-per-stream. The risk is wholly bounded by client-side concurrency caps. |
| **ISP middlebox (РТК / МГТС home)** | Connection-based TLS policing (bbs#546), aggressive throttling on whitelisted-SNI flows | **3/5** | Per slot byte counter (`ws_pool.go: downBytes`) rotates before the 15-20 KB threshold — good. But `SplitTransport` upload is one POST = one TCP, no streaming, so each POST trips the same TLS-record cost. No record-layer fragmentation yet (P1 in action plan). |
| **Active prober (TSPU-style probe of domain)** | GET /, GET /ws, GET /api/v1/config, POST junk JSON, replay captured handshake | **4/5** | Live Decoy serves rebranded habr content on `/blog/*` and clean SPA on `/`. Failed POSTs route through `failClosedToDecoy` with synthetic-cost crypto + ackJitter — successfully blends fail/success on timing. Replay is gated by `replayCache.Accept` after decrypt. The remaining gap: `wsURLPool=["/ws"]` is a single fixed path; an automated prober pairing GET `/ws` (with WS Upgrade) → 200 decoy with POST `/ws` (JSON) → decoy can statistically separate ShadowLink-host from "other server with /ws endpoint" in ~200 probes. |
| **State-level analyst with packet captures + targeted probing** | Triangulation across all of the above + JA3 of cold-path requests + body prefix size analysis on POSTs across days | **2/5** | The cover-traffic budget logic is observable (every 5s tick of upload-only POST), the `5-10m ConnManager rotation` cadence is a strong signal even with `SessionLifecycle` jitter, and the mimicry-engine choices are all "designer's idea of GA4," not calibrated. |

**Net stance**: production-ready against current adversaries, vulnerable to a
sustained ML-vs-targeted-flow investigation.

---

## Strengths

1. **uTLS + Chrome HTTP/2 SETTINGS via `bogdanfinn/tls-client`** —
   `client/connmanager.go:140-189`. The C1 audit finding from earlier work
   is fully closed on the `DirectTransport` / `CDNTransport` hot path. This
   is the single most important DPI defense and it is correct.

2. **uTLS dial in `SplitTransport`** — `client/split_transport_tls.go:34-91`
   wires uTLS into `stdhttp.Transport.DialTLSContext` and pins ALPN to
   `http/1.1` to prevent Go's `net/http` from triggering an h2 upgrade that
   would defeat the Chrome H2 SETTINGS spoofing. Pinning ALPN inside the
   ClientHello is the right defense (P0.5 from action plan).

3. **First-frame WebSocket auth** — `server/websocket.go:57-97` plus
   `client/ws_transport.go:224-343`. The legacy `Authorization: Bearer`
   header on WS upgrade was a giveaway (V7); now the upgrade carries no
   auth-bearing header and authenticates via the first binary frame. The
   1500ms timeout + `firstFrameReadLimit=8KiB` + `fakeAckAndClose` (random
   200-2000B + ackJitter close) all blend failed-auth into legit close
   timing.

4. **Failure-mode timing convergence** — `server/decoy_timing.go:34-70`'s
   `failClosedToDecoy` runs synthetic-cost X25519 keypair + AES-GCM Open +
   `ackJitter()` + `httpPlaceholderRequest()` regardless of the real failure
   reason (rate-limit, decrypt, replay, auth). This is the right
   architecture for defeating timing oracles. The synthetic cost matches
   the real handshake path (X25519 scalar mult dominates).

5. **Live Decoy invariant canary** — `server/live_blog_canary.go:35-65`
   ships 5 invariants (size, brand presence, source-brand leak, internal
   link leak, CDN string leak) and a 3-fail consecutive tracker that
   escalates from Warn to Error. The visible-text filter via
   `canaryHTMLTagRe` is sound — it strips tags before checking for
   "Хабр"/"Habr" so code blocks don't false-positive.

6. **SafeDial SSRF protection on CONNECT** — `server/safedial.go:50-100`
   resolves all IPs and rejects if **any** is private (correct DNS-rebinding
   defense). Connects to the resolved IP, not the hostname (TOCTOU defense).
   IPv6 ranges (`::1/128`, `fc00::/7`, `fe80::/10`) are covered.

7. **Body-prefix wire format** — `skins/browser/request.go:381-400` (BuildDataPayload / ParseDataPayload)
   plus `client/datapath.go:43-103`. The session token is now wrapped
   inside the encrypted payload's base64 envelope; cover traffic
   (`client/transport.go:215-260`) and real data POSTs share **byte-identical
   headers** (W4 invariant) via `buildDataPostHeaders`. This closes V2 from
   the action plan.

8. **Decoy traffic with weighted paths and Sec-Fetch-* headers** —
   `client/decoy_traffic.go:74-93` plus `:138-205`. Per-path Accept and
   Sec-Fetch-Dest values (style/script/image/empty/document) match what
   Chrome actually sends; `Sec-Fetch-Site: same-origin` is correct for SPA
   subresources.

9. **Per-device weekly fingerprint persistence** —
   `skins/browser/fingerprint_lock.go:11-83`. Each device picks one of
   Chrome (70%) / Safari (18%) / Firefox (12%) and holds it for 7 days.
   With 1000 users the aggregate distribution looks like the real internet.
   Per-session UA rotation would itself be a fingerprint.

10. **MITM hard-fail in handshake fallback** —
    `client/client.go:255-268`. If `runHandshakeSequence` gets HTTP 200 +
    non-JSON body on the new path, it surfaces as `Status=200` and the
    fallback to legacy is **refused** when `InsecureSkipVerify=true`. This
    prevents an on-path adversary from forcing downgrade by stripping
    `_v` from the response.

---

## Findings

### CRITICAL — DPI / wire format / leak risks

#### CRIT-1. Default `net/http` Go fingerprint leak in WS handshake POST

**File**: `client/ws_transport.go:122-145` (`SendHandshake`)

The WebSocketTransport's pre-upgrade HTTP handshake is sent via a vanilla
`&http.Client{Timeout: 15*time.Second}` with no custom Transport, no
`DialTLSContext`, no uTLS. After all the careful uTLS wiring elsewhere, the
**very first POST** that creates the session goes out with Go's stdlib JA3:

```
helloID := utlsProfileForFingerprint(fp) // ws_transport.go:254 — used for the WS dial
//                                  but NOT for SendHandshake at :122
httpClient := &http.Client{Timeout: 15 * time.Second}  // :123 — STDLIB
```

**Why this matters**: TSPU / CF / ML classifiers see two distinct TLS
fingerprints from the same client IP on the same domain within seconds —
"Go-stdlib" for the handshake, "Chrome 133" for the WS upgrade. That
inconsistency is a high-confidence proxy signal regardless of how good the
individual fingerprints are. It is also detectable by a **single passive
JA3 fingerprint logger** at the network edge.

**Fix**: route `SendHandshake` through `connManager.Do` like
`DirectTransport.SendHandshake` does. The infrastructure already exists.

**Severity**: **CRITICAL**. Currently mitigated only because most production
sessions use `DirectTransport`/`CDNTransport` (which are correctly uTLS-wrapped);
WSPool and viaCF code paths *do* use `WebSocketTransport.SendHandshake`. Any
client that goes through the WS pool ships a Go-stdlib JA3 on its first POST.

---

#### CRIT-2. Default `net/http` Go fingerprint in `WarmupRequests`

**File**: `client/ws_transport.go:168-207`

```go
client := &http.Client{Timeout: 5 * time.Second}  // :194
resp, err := client.Do(req)
```

This is intended to *help* DPI evasion ("real browser browses before
opening WS") but the GETs go out with Go-stdlib JA3, which is **worse**
than skipping the warmup entirely. A real browser's GETs share JA3 with the
subsequent WS upgrade. Here, `WarmupRequests` ships Go JA3, then `UpgradeToWS`
ships Chrome 133 JA3 a few hundred ms later — same domain, same socket
peer, two different fingerprints. That is the cleanest possible "this is
not a real browser" signal.

**Fix**: route warmup GETs through the same uTLS dialer the WS upgrade uses,
or remove `WarmupRequests` until that's plumbed.

**Severity**: **CRITICAL**. Same JA3-mismatch class as CRIT-1 — easier to
trigger because it runs even before authentication.

---

#### CRIT-3. Probe engine uses Go-stdlib HTTPS with `InsecureSkipVerify`

**File**: `client/probe.go:196-216`

```go
client := &http.Client{
    Timeout: 3 * time.Second,
    Transport: &http.Transport{
        TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
        DisableKeepAlives: true,
    },
}
```

The probe runs at startup against `cdnDomain` and `ya.ru` — both observable
by TSPU. The Go-stdlib JA3 plus `InsecureSkipVerify: true` is **exactly**
the stdlib-Go fingerprint cybersecurity tools train on. Even ignoring DPI,
running `InsecureSkipVerify: true` against ya.ru is gratuitous: ya.ru has
real certs and ya.ru is the canonical Russian-whitelist canary, so any
weirdness on the JA3 there gets flagged hard.

**Why it matters even more in 2026**: TSPU has explicitly added
"connection-based TLS policing" against profiles it has seen mixed with VPN
traffic (bbs#546, 2025-11). A user whose probe.go hits ya.ru with
Go-stdlib JA3 and then minutes later hits the CF domain with Chrome JA3
from the same IP raises the cross-flow correlation score significantly.

**Fix**: route probes through uTLS too, OR drop `InsecureSkipVerify` and
swap to `HEAD https://www.cloudflare.com` / a similar reputable target that
won't tolerate unusual JA3.

**Severity**: **CRITICAL**. Runs unconditionally at startup on every
client. The mitigation cost is small (uTLS dialer already built in
`split_transport_tls.go:buildUTLSDialTLS`).

---

#### CRIT-4. Single fixed WebSocket path enables active probing classifier

**File**: `server/urls.go:16-18`

```go
var wsURLPool = []string{
    "/ws",
}
```

Real analytics SaaS endpoints expose WS on **multiple paths and never on
`/ws`** (Mixpanel uses `/socket.io`, GA4 doesn't use WS at all,
PostHog uses `/decide`, Amplitude uses `/2/httpapi`). A TSPU prober that
runs:

```
GET /ws                     → 101 (or 426/connection close from gorilla)
GET /socket.io/ /decide /poll → decoy 200 from h.decoy
```

separates ShadowLink hosts from "real analytics SaaS" with one round-trip.
The comment at `server/urls.go:11` ("real analytics/SPA backends expose WS
on a small, fixed set of URLs") is **not** what real SaaS does.

**Fix**: rotate WS paths from a server-distributed pool (the comment block
already mentions "deploy order constraint" — this work was started but
the pool stayed at one entry). Use real SaaS-shaped paths like
`/api/v1/socket`, `/realtime`, `/_ws/sync`, picked deterministically from a
client-known set. Better still: pick the path from the same `URLPool`
distribution the upload paths come from so they share the analytics-SaaS
shape.

**Severity**: **CRITICAL** for active-probing resistance. Probe classifier
detects this in <10 probes. Currently the only thing saving it is that
TSPU isn't running this exact probe yet.

---

### HIGH — meaningful weakening of mimicry / fingerprint surface

#### HIGH-1. `dnsrouter` upstream forwards via system routing — DNS leak risk in TUN mode

**File**: `client/dnsrouter/router.go:144-178`

The DNS router listens on `127.0.0.1:53/5353`, accepts queries from the
local resolver, and forwards to `1.1.1.1:53` via `net.DialUDP`. In system-
VPN (TUN) mode there's a host route to the VPN server (and additional
bypass routes for `.ru` domains). The forward UDP query to 1.1.1.1 will
follow whatever the kernel's routing table says — and on Windows /
Linux, with a default-route-via-TUN configuration, that goes through the
tunnel correctly. **But on macOS** (and Linux misconfigured cases), the
default route may not be the TUN if the user was already running another
VPN and gateway routing is split. There's no explicit binding to the TUN
interface for the upstream socket.

Worse, the **bypass DNS route is added _after_ the upstream query is
sent** (`router.go:139-178`): the query goes to 1.1.1.1, gets a response,
and only then does `addBypassRoute` add the IP to the routing table. If
the user's first lookup is for a bypass domain, the **outbound query** to
1.1.1.1 still goes through the default route (TUN), not bypass. That's not
strictly a leak (it goes through the tunnel and Cloudflare answers
normally), but it means the DNS router design doesn't actually prevent
bypass-domain queries from being visible to TSPU on the route between the
exit node and 1.1.1.1.

**Fix**: bind the upstream UDP socket to the TUN interface explicitly, and
document the leak window where the first query for a bypass domain still
traverses the tunnel.

**Severity**: **HIGH** for the bypass-routing model's promised behavior.
Not a leak per se, but a divergence from the design.

---

#### HIGH-2. Cover traffic ratio controller has predictable cadence

**Files**: `client/transport.go:185-260` (`startCoverTraffic`),
`skins/browser/mimicry.go:100-162` (`RatioController`)

```go
ticker := time.NewTicker(5 * time.Second)
resetTicker := time.NewTicker(30 * time.Second)
```

5-second ticks for cover budget evaluation + 30-second resets are visible
in the wire trace as a **bimodal beat**: every 5s the client may emit a
cover POST if the upload/download ratio is below 2.5; every 30s the
counters reset, breaking the ratio momentarily and likely triggering a
cover POST burst. Real GA4 doesn't have this behavior — telemetry is
event-driven, not cron-driven.

A passive observer logging POST inter-arrival times across 10 minutes can
extract the 5s tick frequency via FFT (or trivially via histogram). This
is a behavioral fingerprint independent of payload mimicry.

**Fix**: jitter both tickers (e.g. tick at `[3s, 7s]` uniform) and stagger
the reset to a random phase per session.

**Severity**: **HIGH**. Predictable cadence is a gold-standard ML signal.

---

#### HIGH-3. ConnManager 2-8 minute rotation duration is a session-length signal

**File**: `client/connmanager.go:84-89, 279-317`

```go
if config.MinRotation == 0 {
    config.MinRotation = 2 * time.Minute
}
if config.MaxRotation == 0 {
    config.MaxRotation = 8 * time.Minute
}
```

`SessionLifecycle.NextActiveInterval()` returns 120-480s (per
`mimicry.go:177-189`). Real browser TLS connections to a single domain are
much more variable: a SPA might keep an h2 connection alive for 10
minutes (idle keep-alive), while AJAX requests open and close TCPs in
seconds. The 120-480s **uniform** distribution does not match either
extreme.

A TSPU classifier with N ≥ 100 sessions per IP can fit a histogram of
"connection-lifetime to this domain" and detect the uniform-on-[120s,480s]
distribution. The mean (~5min) is also too tight a clustering for real
analytics traffic, which is dominated by very-short and very-long TCPs.

**Fix**: replace uniform with a long-tailed distribution (e.g. log-normal
matching real browser TCP lifetimes). Add a small fraction of "abandoned"
TCPs (RST after 5-10s) and a small fraction of "long-lived" TCPs (>30min).

**Severity**: **HIGH**. Session-length distribution is a primary feature
in published TLS-flow classifiers (Xue et al. NDSS'25 lists it explicitly).

---

#### HIGH-4. `BuildInflatedDownloadResponse` `next_poll` value range is non-empirical

**File**: `skins/browser/request.go:240-262`

```go
var nextPoll int
if rand.IntN(2) == 0 {
    nextPoll = 30 + rand.IntN(60)  // 30..89 seconds
}
```

50% of responses carry `next_poll: 30..89`; 50% don't. Real analytics
backends overwhelmingly do **not** send a `next_poll` hint at all, or
send a fixed-per-tenant value. The 50/50 toggle plus the 30-89s range is
neither plausible (legit servers don't roulette per-response) nor matched
to any reference. This was added after V3 cleanup (where 3 of 4 fields were
removed) but the remaining `next_poll` is still a designer's invention.

**Fix**: either drop `next_poll` entirely (`UseInflatedResponses=false` is
already default) or make it a per-server-startup constant that doesn't
vary per-response.

**Severity**: **HIGH** for ML-classifier matching, **MEDIUM** in practice
because `UseInflatedResponses` defaults to false. Document the default and
consider deleting `BuildInflatedDownloadResponse` outright.

---

#### HIGH-5. `BuildHandshakePayload` padding-target is shared with data POSTs

**File**: `skins/browser/request.go:402-418`

```go
target := pd.UploadSize()  // same distribution as data chunks
```

The handshake payload is padded to the same upload-size distribution
(80-2000 bytes weighted) as data POSTs. That's the right idea — make the
first packet blend with steady-state. **But** in practice, real analytics
init events (the equivalent of "handshake") tend to be **larger** than
event posts (they carry user_id, device fingerprint, A/B variants, etc.),
not the same distribution. A first POST of 80 bytes followed by 20 more
of 80-200 bytes is detectable as inverted from real analytics.

**Fix**: bias handshake size toward the upper tail (351-2000B range, ~30%
weight). Trivial change — just sample two `UploadSize()` and take the
larger, or use a separate `HandshakeSize()` method.

**Severity**: **HIGH** for first-packet matching. Probably OK at low
volume but matters for an ML classifier with ≥1000 samples.

---

#### HIGH-6. Live Decoy upstream `http.Client` lacks IP pinning — SSRF-via-DNS-hijack

**File**: `server/live_blog.go:107-119`

```go
h.httpClient = &http.Client{
    Timeout: cfg.UpstreamTimeout,
    CheckRedirect: func(req *http.Request, via []*http.Request) error {
        ...
        host := req.URL.Host
        if host != pinnedHost && host != pinnedCDNHost {
            return fmt.Errorf("live_blog: redirect to off-host %q refused", host)
        }
        return nil
    },
}
```

`CheckRedirect` runs *after* `DialContext` resolves the hostname. If
`habr.com` DNS is hijacked (rogue resolver in `/etc/resolv.conf`,
compromised authoritative server, or operator-misconfigured `Upstream:
"http://internal-host"`), the first request resolves to a private IP and
connects there. `CheckRedirect` only fires on 3xx — if the bad target
returns 200, the SSRF is uncaught.

The current scope is bounded because the operator controls the
`upstream:` config field, but T1.3's promise is "habr proxy" and
operators may not realize `upstream:` accepts any URL.

**Fix**: wire a `DialContext` that runs `safedial.SafeDial` (already
built for the CONNECT path) — refuses private IPs after DNS resolution.

**Severity**: **HIGH**. SSRF attack surface that bypasses the existing
SafeDial defense the project already has.

---

#### HIGH-7. `ws_transport.SendChunk` uses 80-byte padding threshold tied to PayloadDistribution

**File**: `client/ws_transport.go:432-434`

```go
if len(data) < 80 {
    data = browser.PadToSize(data, t.pd.UploadSize())
}
```

Padding control chunks (`FlagConnect`, `FlagFin`) below 80 bytes is
correct in principle. But `PayloadDistribution.UploadSize()` returns
**80-150 bytes 45% of the time**, so a control chunk that was originally
35 bytes gets padded to 80-150 — only ±70 bytes of variation around the
threshold. A length-clustering DPI classifier still sees a peak at
~80-100 bytes with a sharp lower bound at exactly 80.

**Fix**: pad to a value drawn from a continuous distribution that crosses
the 80-byte boundary smoothly (e.g. `min(UploadSize(), 30+IntN(200))`).

**Severity**: **HIGH** for length-distribution matching, lower in practice
because control chunks are <5% of frame count.

---

### MEDIUM — implementation issues with bounded blast radius

#### MED-1. ECH DoH query uses Go-stdlib HTTP

**File**: `client/ech.go:28-36`

```go
httpClient := &http.Client{Timeout: 5 * time.Second}
resp, err := httpClient.Post(
    "https://1.1.1.1/dns-query",
    "application/dns-message",
    ...
)
```

DoH to 1.1.1.1 from Russia is itself benign (1.1.1.1 is whitelisted), but
it's another Go-stdlib JA3 emission. Lower-priority because (a) only fires
if `ECHEnabled=true`, (b) the destination is a generic DNS service so JA3
inconsistency has lower correlation value than on the project domain.

**Fix**: route through uTLS too. Same dialer pattern as elsewhere.

**Severity**: **MEDIUM**. JA3 leak but to a non-correlated destination.

---

#### MED-2. `LeakGuard` `CheckIP` uses Go-stdlib HTTP through SOCKS5

**File**: `client/leakguard/check.go:32-38`

The post-connect ipinfo.io check uses Go-stdlib HTTP. The traffic is
inside the tunnel (socks5 proxy), so server-side observation only sees
the encrypted ShadowLink envelope. **But** the SOCKS5 layer sees the raw
`Host: ipinfo.io` and `User-Agent: Go-http-client/1.1` strings going out
the exit node. If the exit node ever logs request paths (CDN-level CF
might), the Go UA leaks.

**Fix**: use a Chrome UA at minimum.

**Severity**: **MEDIUM**. Cosmetic issue, no DPI consequence.

---

#### MED-3. `RatioController.Reset()` once per 30s creates a regular signature

Already covered in HIGH-2; calling it MED here only to note that the
"reset every 30s" timer is a separate fingerprint from the "tick every 5s"
one and both need fixing.

---

#### MED-4. `decoy_traffic.go` interval is uniform on [15, 45] seconds

**File**: `client/decoy_traffic.go:124-128`

```go
interval := 15*time.Second + time.Duration(rand.IntN(30))*time.Second
```

A uniform 15-45s distribution for fake GETs doesn't match real browser
behavior. Real users have **bursty** browsing: a click triggers 3-10
fetches in <2 seconds, then 30-120s of inactivity, then another burst.
The current cadence emits one GET every ~30s steadily, which is the
exact opposite of bursty.

**Fix**: use a Pareto / log-normal inter-arrival distribution, and
occasionally emit a burst of 3-5 requests within 1 second (matching
"clicked a link" behavior).

**Severity**: **MEDIUM**. The current behavior is better than no GETs
but still distinguishable from real traffic with N ≥ 200 samples.

---

#### MED-5. Live Decoy 5-invariant canary doesn't cover JS rewriting

**File**: `server/live_blog_canary.go:35-65`

The 5 invariants check HTML body bytes for size, brand, source-brand,
internal links, and CDN strings. None of them check rewritten **JavaScript**.
habr.com ships JS that may contain `"habr"` strings, `window.location`
links to `/ru/articles/...`, or `habracdn.net` references inside template
strings. The HTMLRewriter strips none of those (it preserves
`<script>` content via `preserveTags`) so a habr JS asset that references
the source brand inside a string literal will leak to the served page.

**Fix**: extend the canary's I3 (visible-text brand check) to scan the
full body, not just `<tag>`-stripped text. Or add an explicit I6 invariant
that strips visible HTML AND inline scripts AND searches for the source
brand.

**Severity**: **MEDIUM**. Caught by the existing I5 (`habracdn.net`)
substring check for the CDN case but not for the brand case.

---

#### MED-6. WS path probing — gorilla returns 400 vs decoy 200 on different inputs

**File**: `server/websocket.go:280-318` + `server/handler.go:185-225`

`handleWebSocket` is gated by `IsAllowedWSPath` and `WSUpgrade.Allow`, but
once those pass, gorilla's `wsUpgrader.Upgrade(w, r, nil)` returns its
own 400 if the request lacks `Sec-WebSocket-Key` or has a wrong
`Sec-WebSocket-Version`. A probe with `Upgrade: websocket` but no
`Sec-WebSocket-Key` gets 400 from gorilla; a probe with no
`Upgrade: websocket` to `/ws` falls through to the decoy and gets 200.
Different status codes for missing-vs-malformed Upgrade is detectable.

**Fix**: either pre-validate the Upgrade headers and route invalid ones
to decoy, or override gorilla's `Error` callback to also serve decoy.

**Severity**: **MEDIUM**. Probe classifier signal but bounded.

---

#### MED-7. `failClosedToDecoy` uses `crand.Read` for synthetic costs

**File**: `server/decoy_timing.go:38-42, 53-55`

`crand.Read` (crypto/rand) is correct for security-sensitive randomness
but it's slow under load. Each failed POST does 4 `crand.Read` calls
(~32+32+12+64 bytes). At wire-rate failure under DDoS, this becomes a CPU
DoS amplifier. `mathrand.Read` would be fine here — these bytes never
leave the synthetic pipeline.

**Severity**: **MEDIUM**. DoS amplifier potential under attack, no
security impact (the random-bytes feed a GCM Open that fails anyway).

---

#### MED-8. Probe endpoint `ya.ru` is itself a fingerprint

**File**: `client/probe.go:50`

Hard-coding `https://ya.ru` as the Russian-network canary ties every
ShadowLink client to a single deterministic outbound at startup. TSPU
already correlates ya.ru hits with subsequent VPN domain hits (they
publish takedown stats). Use a small whitelist (yandex.com, mail.ru,
ria.ru) and round-robin per startup.

**Severity**: **MEDIUM**. Behavioral fingerprint of "this client always
hits ya.ru first."

---

#### MED-9. `WarmupRequests` paths are predictable

**File**: `client/ws_transport.go:172-176`

```go
paths := []string{"/", "/about", "/api/v1/config"}
```

Three fixed paths in a fixed order. A passive observer sees:
`GET / → GET /about → GET /api/v1/config → WS upgrade /ws` every time a
WSPool slot reconnects. That's a unique transition signature. (Also the
order of paths is not randomized — `paths[i]` for i=0..count-1.)

**Fix**: shuffle paths and pull from a server-distributed pool.

**Severity**: **MEDIUM**. Bounded by CRIT-2 (which obviates this — the
warmup is detectable on JA3 first).

---

#### MED-10. `WSPoolTransport` meltdown threshold/cooldown configurable but defaults log session-event signal

**File**: `client/ws_pool.go:90-99`

The meltdown protection is correct in design but its presence is itself a
fingerprint when triggered: if 3 slots die within `meltdownWindow`, the
client pauses reconnects for `meltdownCooldown`. From CF / TSPU side, this
looks like "client retried a few times then went silent for N seconds
then came back." That's an unusual reconnect pattern — real browsers
either give up or keep retrying. Worth jittering the cooldown
significantly (current default is fixed).

**Severity**: **MEDIUM**. Behavioral signal, bounded by frequency.

---

### LOW — minor cleanup / hardening

- **LOW-1.** `client/dnsrouter/router.go:298` — `IsLoopback`/`IsPrivate`
  filters when extracting A records means private-IP CDN responses (e.g.
  legit corporate intranet domains in bypass mode) are silently dropped.
  Document or remove.
- **LOW-2.** `server/handler.go:843-849` — `300 * time.Millisecond` wait
  for active-connection batching is a fixed value. Real CDN backends use
  log-normal jitter. Low impact since this is server-side timing.
- **LOW-3.** `core` chunk pooling (`core.GetBuffer`/`PutBuffer`) is used
  inconsistently; some `make([]byte, len)` allocations in
  `server/handler.go:866` could move to pool. Performance, not security.
- **LOW-4.** `skins/browser/fingerprint.go:78-80` — UA strings are
  Chrome 134 / Firefox 136 / Safari 18.3.1, hard-coded as defaults.
  Stable through 2026 but will look stale by mid-2027 if not refreshed.
- **LOW-5.** `client/transport.go:282` — `t.urlPool.NextUploadPath()`
  returns the **next** path uniformly, but the pool only has 6 entries
  (`urls.go:10-17`). After a few requests, the path entropy is visible.
  Increase pool to ~20+ paths and weight by realism (`/api/v2/events`
  much more often than `/graphql`).
- **LOW-6.** `live_blog.go:540-573` `fetchUpstream` doesn't forward any
  request headers; it sends a fixed Chrome UA. If habr later starts
  varying CSS based on `Accept-Language`, the rewritten output will
  always be Russian-locale. Probably intentional, worth documenting.
- **LOW-7.** `server/handler.go:130-148` — `ackJitter()` has a 150ms hard
  cap; real network ACK timing has a longer tail. Bumping to `300ms` or
  giving a 5% probability of `1-3s` spikes would match real
  load-balanced responses.

---

## Mimicry Quality

This is the deepest architectural concern in the audit.

### Payload distribution

`PayloadDistribution.UploadSize()` (`mimicry.go:29-41`) and
`DownloadSize()` (`mimicry.go:49-61`) return values from hard-coded
piecewise-uniform distributions purportedly matching GA4. Concerns:

1. **No empirical basis.** I cannot find any reference in the code,
   spec, or research notes that ties these bins to a measured GA4 corpus.
   The bin edges (80, 150, 351, 800, 2001) and the percentages (45/35/15/5)
   look like a designer's ballpark, not a fitted distribution.
2. **Piecewise uniform inside each bin.** Real network payloads inside any
   given size class follow a continuous distribution (typically
   power-law-tailed). A piecewise-uniform produces visible "shelves" in
   any density estimate of size vs. count — exactly what an adversary
   computing a histogram-distance metric would see.
3. **Upload and download distributions are independent.** Real analytics
   has correlated upload-download (a bigger event request often gets a
   bigger config response). Independent sampling produces uncorrelated
   pairs which is itself detectable in a 2D scatter.

**Recommendation**: collect a sample of real GA4/Mixpanel traffic from a
test SPA, fit a kernel-density estimator, and replace the piecewise-uniform
with sampling from the KDE. Alternatively, use a public CDN-level dataset
(TLS lengths from Wireshark captures of legit traffic) — Cloudflare has
published aggregate stats.

### Ratio controller

`RatioController` (`mimicry.go:106-162`) targets a 2.5-3.5
upload:download byte ratio. Issues:

1. The target range is constant. Real analytics ratios swing wildly with
   user activity (mostly-receiving vs. mostly-sending phases).
2. Cover bytes pad **upload** to maintain ratio, but real analytics
   apps don't behave this way — when traffic is asymmetric, it stays
   asymmetric.
3. The 30s reset window means the ratio is computed over a fixed window
   that always starts at session boundaries. Real measurements would use a
   sliding window.

**Recommendation**: replace with a sliding-window EMA (e.g. half-life
60s) and let the target ratio drift over a session matching observed
real-traffic phases.

### Session lifecycle

`SessionLifecycle` (`mimicry.go:177-201`) returns active 120-480s + gap
500-3000ms. The ratio of "active time" to "gap" (>99% active) doesn't
match real browsing where idle gaps can be minutes-to-hours. Also,
`NextGapDuration` is bimodal (70% short / 30% long) — a real distribution
is more skewed (95% very short, 5% multi-minute).

**Recommendation**: model the gap distribution with three regimes:
30% transient (<200ms), 60% short (200ms-30s), 10% long (30s-30min).

### Net mimicry verdict

**3/5**. Architectural pieces exist and are correctly placed in the
transport layer. The numbers don't come from data, and several behavioral
patterns (5s cover tick, 30s ratio reset, bimodal gap) are themselves
fingerprints. With ≥1000 samples per client, an ML classifier trained on
mixed legit/ShadowLink traffic would identify ShadowLink with high
confidence (estimate: 80-90% precision at 50% recall).

**Proposed next-cycle work**: build a `mimicry-calibration/` directory
with:
- a packet-capture harness against test SPAs
- a Python notebook fitting distributions
- a code generator emitting the resulting bin edges + weights into Go
  constants
- a CI gate that fails if the constants drift from the measured
  distribution by >5% Earth-mover distance

---

## Live Decoy (T1.3) Critical Path

T1.3 is well-engineered overall. The most important gates are correct:
strict article-ID regex (`canaryArticleIDRe = ^\d{1,10}$`), upstream URL
validation, redirect host pin, body-size cap, response-size oracle defense
(`writeNginxLike404` with embedded canonical 404 body for failed CDN
paths). The canary loop with consecutive-fail tracking is a sound
operational primitive.

### SSRF surface

Already covered as HIGH-6 above: `fetchUpstream` lacks `DialContext` IP
filtering. The redirect-host pin handles 3xx but not the initial DNS
resolution. Add `safedial.SafeDial` to close the gap.

### HTML rewriter

The stream rewriter (`html_rewriter.go:107-241`) uses `golang.org/x/net/html`
tokenizer with explicit recursion-depth cap (`MaxTagDepth=200`) and
output-byte cap (`MaxOutputBytes=2MB`). Both panics and depth overflows
recover via the `defer recover()` at line 108. Tokens inside
`code/pre/script/style/noscript/textarea` are passed through raw — correct
to avoid breaking JS but means MED-5 (script-content brand leak) is
unaddressed.

The `rewriteText` function (`html_rewriter.go:464-481`) uses
`bytes.ReplaceAll` per token. **Order matters**: replacing "Хабр" with
"Brand" then "Habr" with "Brand" may double-process (if Brand contains
"Habr"). Currently safe because `BrandTo="Brand"` doesn't share substrings
with `BrandFromTokens`, but worth a fixed-point iteration check or a
Aho-Corasick replacement to make it order-independent.

### Canary metrics integrity

`runCanaryOnce` (`live_blog_canary.go:117-165`) updates metrics through
`atomic.Counter` adds. The `LastHealthyUnix` store is unconditional on
`result.ok()`. The 30s startup delay before first canary is sensible —
prevents server-startup CPU contention. The 3-fail consecutive escalation
to ERROR log is the right operational signal.

The metric `decoy_live_blog_canary_ok_total` should tick once per canary
interval (default 15min). If it doesn't, ops needs to know — but the
current code treats fetch-failure (`runCanaryOnce` line 119-126) as a
silent non-event for `CanaryOK`, only incrementing `CanaryFetchFail`.
That's correct, but the dashboard rule should be: **alert if
`canary_ok_total` doesn't tick for 2× canary_interval**, and **separate
alert if `fetch_fail` rises**.

### Fallback timing

`applyFallbackJitter` (`live_blog_timing.go:17-33`) makes every
fail/rate-limit path complete in `target ± jitter` ms. Verified: target
defaults to 200ms, jitter to 50ms. That's tight enough to overlap with
real-cache-hit timing (which is probably <50ms) but with a measurable
median offset. The exact target should match the **median real
upstream-fetch time**, not be a fixed designer constant.

### Live Decoy verdict

**4/5**. Production-ready. Two improvements:
1. SafeDial-protect upstream HTTP client (HIGH-6).
2. Extend canary I3 to script content (MED-5).
3. Calibrate `FallbackLatencyMs` to median upstream-fetch time empirically.

---

## Comparison with Naïveproxy / V2Ray-vmess / Hysteria2

| Property | ShadowLink | Naïveproxy | V2Ray-VMess | Hysteria2 |
|---|---|---|---|---|
| TLS fingerprint | uTLS Chrome/Safari/Firefox + locked-per-device | Chrome via Chromium net stack (real) | uTLS via Xray | uTLS Chrome |
| HTTP/2 SETTINGS | Chrome via tls-client | Chrome (real Chromium) | Xray-managed | n/a (QUIC) |
| Steganography layer | Application-layer JSON (analytics envelope) | HTTP/2 forward proxy (real CONNECT) | Custom binary | QUIC + custom obfuscation |
| Cover traffic | Yes (cover budget + GET decoys) | No | No | Salamander obfuscation |
| Decoy site | Yes (live habr proxy) | No (passes to real upstream) | No | No |
| Active-probe resistance | Strong (failClosedToDecoy + Live Decoy) | Strong (real Chromium proxy) | Weak (VMess auth fails differently) | Medium |
| TSPU 15-20KB throttle | Per-slot byte rotation in WS pool | n/a (h2 multiplexed) | n/a | Bypassed by hopping |
| First-packet matching | Padded handshake (V1 spec) | Real Chromium | Visible | n/a |
| Wire-protocol replay protection | ReplayCache + seq_num + AcceptSeqNum | TLS session resumption | Limited | Built-in |
| Mimicry calibration | Designer-defined distributions | n/a (real client) | n/a | n/a |
| Open-source vs closed | Open | Open | Open | Open |
| **Where ShadowLink wins** | Live Decoy + cover ratio + per-device fingerprint lock + first-frame WS auth | — | — | — |
| **Where ShadowLink lags** | Cover-tick cadence detectability; cold-path JA3 leaks; mimicry calibration; single-WS-path | naive uses real Chromium so cover is "free" | VMess has known DPI signatures | Hysteria2 has clean QUIC obfuscation but blocked in RU |

**Headline**: ShadowLink is closer to Naïveproxy than to VMess — comparable
sophistication in TLS handling, **better** decoy story (Live Decoy vs.
naive's pass-through), **worse** mimicry-calibration story (naive doesn't
need to mimic — it *is* a real Chromium client). Hysteria2 is in a
different blast zone (QUIC-blocked in RU) and not directly comparable.

---

## Open Questions

1. **Has the body-prefix migration completed its 48h soak?** The
   `SHADOWLINK_DATAPATH_BODYPREFIX` flag still defaults off
   (`client/datapath.go:23`). The action plan called for default-flip
   after a clean 48h. Are we past that? If yes, flip the default. If no,
   what's blocking?
2. **What's the empirical median of `fetchUpstreamArticle` latency?**
   `FallbackLatencyMs` defaults look like a guess. If habr median is
   500ms, the 200ms fallback creates a timing gap visible to a probe.
3. **WS path rotation pool size and timing.** CRIT-4 calls out that
   `wsURLPool=["/ws"]` is detectable. Operationally: rotating the pool
   requires server deploy *before* client release. Has this been planned?
4. **Cover traffic's `next_poll` field — is `UseInflatedResponses`
   actually disabled in production?** Code defaults it to false but
   YAML config can override. Recommend verifying current production
   config and considering deletion of `BuildInflatedDownloadResponse`
   altogether.
5. **Mimicry calibration corpus.** Does the team have any captured
   GA4/Mixpanel traffic that would let us replace the designer-specified
   distributions with measured ones? If not, can we collect ~10GB of
   web-app analytics traffic from a test SPA to use as a calibration
   reference?
6. **Probe.go fingerprint surface.** CRIT-3 fixes `ya.ru` HEAD. Does the
   probe still need to run unconditionally at every startup, or could it
   be cached for N hours? A cached probe means fewer startup-time
   fingerprints visible.
7. **The Decoy traffic generator's HTTP/1.1 `Connection: close`
   behavior.** With `DisableKeepAlives: true` on `SplitTransport.uploadClient`,
   each fake GET in `decoy_traffic.go` opens a fresh TCP. Real browsers
   reuse connections. Is the action-plan V1 (Connection:close pattern)
   still actionable, and what's the migration plan?
