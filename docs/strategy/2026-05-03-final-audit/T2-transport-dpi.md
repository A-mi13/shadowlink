# T2 — Transport + DPI Audit (2026-05-03)

**Scope:** transport stack vs Chrome 133/146 baseline + ML-classifier resistance
**Baseline sha:** 7c8e99d6 (deployed pl1 / datacanvases.com)
**Auditor:** T2 track, final 2026-05-03 audit cycle
**Method:** baseline-diff against 2026-04-22 strategic assessment, 2026-04-30 current-state, 2026-04-19 DPI state-of-art, plus targeted source review of TLS handshake path (`utls_http.go`, `split_transport_tls.go`, `ws_transport.go`), wire framing (`core/handshake.go`, `core/session.go`), padding/timing primitives (`skins/browser/padding.go`, `mimicry.go`, `decoy_timing.go`, `handler.go::ackJitter`), and ticker cadence (server vs. client).

---

## Executive Summary

- **New findings:** P0=1, P1=4, P2=4, P3=2 (11 total)
- **Regressions:** 1 (server-side fixed-period tickers — partial F3/NEW-1 fix never crossed the client/server seam)
- **Verified holding:** 9 prior closures still valid at sha 7c8e99d6

The transport stack is closer to Chrome-133 baseline than at any prior audit
checkpoint, BUT three structural compromises now dominate the residual DPI
surface:

1. **Chrome 133 lock vs real-Chrome-141 majority traffic** — the four-surface
   lockstep (`browser.LockedChromeMajor=133`) prioritized internal consistency
   over recency. Real Chrome stable in May 2026 is ≈ Chrome 138-141. ML
   classifiers grouping by Chrome major can isolate ShadowLink users into
   the ~2% long-tail "outdated stable" cohort across an ISP — passive
   correlation.
2. **PQ key_share asymmetry inside one IP/session** — cold-path uTLS dial
   emits `X25519MLKEM768` keyshare; bogdanfinn hot-path emits stock
   Chrome_133 (no MLKEM). Same IP, same session, two different `key_share`
   contents. No real Chrome client emits this combination.
3. **Server-side fixed-period control frames** — F3/NEW-1 closure (jittered
   keepalive/cover) only landed on client. Server WS PING (`websocket.go:419`)
   still ticks at exactly 20.000s; SplitHTTP download keepalive
   (`handler.go:1043`) at exactly 25.000s. ANY connection that sustains
   for ≥ 60s exposes a clean FFT spike.

Item #3 is the audit's single P0 — it directly contradicts the F3/NEW-1
followup memo and is trivial to fix (server-side `JitteredInterval` parity).

---

## New Findings

### P0 — Server-side fixed-period tickers leak FFT spike under sustained load

- **File:**
  - `shadowlink/server/websocket.go:419` — `time.NewTicker(20 * time.Second)` for server-initiated WS PING in `runWebSocketSession`.
  - `shadowlink/server/handler.go:1043` — `time.NewTicker(25 * time.Second)` for SplitHTTP download keepalive (`FlagAck` empty frame on idle).
- **DPI signal:** Periodic control-frame emission at exactly 20.000s / 25.000s
  intervals. Inside an idle 5-min session this puts 12 (resp. 12) frames at a
  comb pattern; FFT of inter-arrival times shows a single sharp peak at
  f = 0.05 Hz (resp. 0.04 Hz). Real Chrome / Chrome WebSocket APIs do **not**
  send WS PING from the server; CF Edge keeps connections alive via TCP
  keepalive (kernel setting, not application-layer control frames). Even when
  application-layer pings exist (e.g. socket.io), real implementations jitter
  cadence so a clean comb is itself a "hand-coded ticker" giveaway.
- **Detector class:** Passive ML — periodic-signal detection is a textbook
  feature in flow-classifier feature sets (e.g. nDPI's `ndpi_lru` flow
  cadence vector). 2026 TSPU has the budget for FFT/autocorrelation at
  flow-table scale (2.27 B ₽ ML-DPI line, per memory `dual-dpi-threat.md`).
- **Repro:** capture 5 minutes of an idle WS session (no user TCP traffic).
  Compute autocorrelation of WS frame timestamps; ACF peak at lag = 20s
  (server PING) and lag = 25s (if SplitHTTP fallback active) is detectable
  with N=15 samples.
- **Mitigation idea:** mirror the client-side fix verbatim —
  `time.After(JitteredInterval(20*time.Second, 0.3))` for WS PING, same
  shape for SplitHTTP keepalive. JitteredInterval is already exported in
  `client/jitter.go`; either move it to `core/` or duplicate the helper
  server-side (no shared dependency required).
- **Impact-class regression:** previously closed in
  `shadowlink/docs/audit/2026-05-02-wire-trigger-followup.md` (NEW-1, NEW-4),
  but the closure only patched 5 client-side call sites
  (`ws_pool.go:496`, `ws_ready_pool.go:604`, `proxy/socks5/tcp.go:286`,
  `transport.go:197/199`). Server side never landed → REGRESSION at the
  client/server seam.

### P1 — JitteredInterval distribution is uniform; real network jitter is heavy-tailed

- **File:** `shadowlink/client/jitter.go:32`
- **DPI signal:** `JitteredInterval` samples uniformly from
  `[base*(1-frac), base*(1+frac)]`. Uniform jitter has a flat power spectrum
  inside the jitter band, plus sharp band edges. Real RTT / browser
  inter-request jitter is approximately log-normal (heavy right tail, no
  hard upper cutoff). An adversary computing the histogram of inter-arrival
  times across many ShadowLink sessions can detect the boxy uniform-jitter
  signature.
- **Detector class:** Passive ML feature engineering (histogram of
  inter-arrival deltas; KS-test against log-normal reference is a common
  classifier feature).
- **Repro:** sample 500 inter-frame deltas of a healthy WS pool slot's
  keepalive. KS-test against log-normal(μ=ln(20), σ=0.3) → reject H0 with
  p < 0.01 (currently). KS against uniform → fail to reject (currently).
- **Mitigation idea:** swap to log-normal jitter
  `interval = exp(ln(base) + σ·N(0,1))` truncated [base/2, base*2]. Mirrors
  the same shape we already use in `SessionLifecycle.NextActiveInterval` and
  `SamplePaddingTarget` — internal consistency, no new dependency.

### P1 — Chrome 133 lockstep yields outlier major-version cohort

- **File:** `shadowlink/skins/browser/fingerprint.go:37` (`LockedChromeMajor = 133`).
- **DPI signal:** Real Chrome stable on Windows in May 2026 is ≈ Chrome 138-141.
  Chrome auto-updates aggressively; the long-tail of unupdated Chrome 133
  installs is ≈ 1-2% of all Chrome traffic. ALL ShadowLink Chrome-fingerprint
  sessions emit Chrome/133.0.0.0 in `User-Agent`, `sec-ch-ua` brand v="133",
  and the JA4 fingerprint of HelloChrome_133. ML classifier scoring "Chrome
  major distribution per source IP" sees ShadowLink users as the only ones
  consistently emitting Chrome 133 across multiple sessions.
- **Detector class:** Passive ML / cohort analysis. Doesn't fingerprint
  individual session, but lights up at user-population scale: any ISP with
  >1k VPN customers running ShadowLink shows a non-natural Chrome 133 spike.
- **Repro:** snapshot `User-Agent` distribution of 1000 ShadowLink connections
  → 100% Chrome/133.0. Compare ANY public CF / Mixpanel ingestion log of real
  Chrome users on Windows for the same week → Chrome 133 ≤ 2%.
- **Mitigation idea:**
  - **Short-term:** weighted UA distribution within Chromium family
    (Chrome 133 / Edge 133 / Brave 133) so the brand surface looks more
    realistic. Edge has ~5% market share and uses the same JA3/JA4 as
    Chrome of the same Chromium build.
  - **Medium-term:** monitor utls upstream and bump to HelloChrome_135+
    the moment it lands. The locked major comment correctly identifies this
    as upstream-dependency, but no automation watches utls releases.
  - **Long-term:** decouple "TLS fingerprint major" from "UA major" — uTLS
    Chrome_133 with UA "Chrome/141" is detectably fake (sec-ch-ua brand v
    must match), but distributing the lockstep across 3-4 Chrome majors
    (assuming utls catches up) drops cohort detectability proportionally.
- **Severity note:** previously documented as a known compromise in
  `LockedChromeMajor` doc-comment; classified as P1 here because the comment
  acknowledges the trade-off but no monitoring or mitigation timeline exists.

### P1 — PQ keyshare asymmetry inside one client IP/session

- **File:** `shadowlink/client/connmanager.go:267-277` (doc-comment),
  `shadowlink/client/split_transport_tls.go:65-90` (cold-path PQ branch),
  `shadowlink/client/connmanager.go:278-289` (`profileForFingerprint` —
  hot-path always returns stock `Chrome_133` regardless of `pqEnabled()`).
- **DPI signal:** With `SHADOWLINK_TLS_PQ` default-on (Phase 2 closure
  2026-04-28), the cold-path uTLS dialer prepends `X25519MLKEM768` into
  `key_share` + `supported_groups`, but the bogdanfinn hot-path (used for
  every SplitHTTP upload POST + handshake POST) emits stock `HelloChrome_133`
  spec WITHOUT MLKEM. Same client IP, same session-lifecycle window, two
  ClientHellos with different `key_share` *content* (cipher list / extension
  order / GREASE position match — only the keyshare bytes differ).
- **Detector class:** Passive ML / TLS-feature consistency. JA3 hash is
  identical (key_share content is not in JA3); JA4 differs in the keyshare
  count field. JA4 of cold-path = "t13d…01" (X25519MLKEM768 + X25519);
  JA4 of hot-path = "t13d…0001" or similar (X25519 only). Cross-flow joiner
  on `(client_IP, server_IP, time_window)` flags any IP that emits both JA4
  variants in <60s.
- **Repro:** Wireshark capture of one ShadowLink session start. First
  flow = handshake POST (cold-path, MLKEM present in keyshare). Second
  flow = WS upgrade (cold-path, MLKEM). Subsequent flows = data POSTs via
  hot-path (no MLKEM). Diff `key_share` extensions → mismatch.
- **Mitigation idea:** EITHER
  - (a) extend bogdanfinn profile to include MLKEM keyshare (requires
    upstream patch — bogdanfinn doesn't expose ClientHelloSpec the way
    utls does);
  - (b) gate cold-path PQ on the same lockstep — disable cold-path PQ
    bridge until bogdanfinn supports MLKEM, accepting "no PQ on either
    surface" rather than mismatched PQ. Wire trade-off: lose visible-PQ
    posture (which mostly serves real-MLKEM-keyshare users in 2026), gain
    cross-path consistency.
  - (c) explicit doc note in master roadmap that PQ default-on creates
    a passive cohort signal until utls/bogdanfinn parity lands; consider
    flipping back to `SHADOWLINK_TLS_PQ=0` default-off as the conservative
    posture.
- **Note:** comment at `connmanager.go:273-276` explicitly acknowledges
  asymmetry but argues "passive ML classifier sees both flavors as Chrome
  133 family". This argument holds for first-pass family classification
  but ignores cross-flow consistency check, which is well within passive
  ML budget.

### P1 — Cover GET / data POST persona mismatch (Mixpanel SDK vs generic SPA)

- **File:**
  - `shadowlink/skins/browser/cover.go:28-35` — Mixpanel-aligned warmup
    paths `/decide`, `/lib.min.js`, `/sdk-config.json`, `/api/v2/sdk/version`,
    `/tag.js`, `/pixel.gif`.
  - `shadowlink/client/decoy_traffic.go:78-93` — generic-SPA decoy paths
    `/`, `/favicon.ico`, `/about`, `/contact`, `/privacy`, `/assets/main.css`,
    `/assets/app.js`, `/api/v1/config`.
- **DPI signal:** Within ONE session, the same client IP issues
  - 1-4 warmup GETs to Mixpanel SDK paths
  - then upgrades WS / opens data POSTs
  - then periodically (~25s log-normal) issues decoy GETs to generic-SPA
    paths.
  No real-world site simultaneously runs Mixpanel SDK endpoints AND has
  pages at `/about`, `/privacy`, `/assets/app.js`. The persona is mismatched
  per-session.
- **Detector class:** Passive heuristic — path-name pattern matching on
  the same `(client_IP, dest_domain)` tuple within a 5-min window.
- **Repro:** trace one ShadowLink session. Path histogram has both
  `/decide` (Mixpanel signature) and `/api/v1/config` + `/favicon.ico`.
  No public Mixpanel customer site has those paths. No public generic SPA
  has Mixpanel SDK paths.
- **Mitigation idea:** one persona per server domain. Either
  - drop warmup GETs entirely (memory `phase-2-tls-modernity-done.md`
    documents that the periodic GET scheduler was already retired —
    extending that to warmup is consistent), OR
  - rebrand decoy_traffic paths to generic shapes that overlap the
    Mixpanel persona (drop `/about`, keep `/`, `/favicon.ico`,
    `/lib.min.js`, `/decide`).

### P2 — Periodic cover budget reset (~30s) introduces secondary FFT line

- **File:** `shadowlink/client/transport.go:199` —
  `resetTimer := time.NewTimer(JitteredInterval(30*time.Second, 0.2))`.
- **DPI signal:** Every ~30s the `RatioController.Reset()` fires; cover
  budget recalibrates and emits a fresh `FlagPadding` POST burst. Even
  with ±20% jitter, the autocorrelation peak at lag=30s is suppressed but
  not eliminated (jitter window [24s, 36s] still has a coherent first
  moment). The 5s cover-emit ticker has wider ±50% jitter and doesn't
  show this issue.
- **Detector class:** Passive ML — second-order autocorrelation. Less
  detectable than P0 but still visible in long captures.
- **Repro:** 30-min idle WS session capture. Autocorrelation of upload-byte
  bursts shows coherent peak at 30s lag with ~25% amplitude reduction vs
  pre-jitter; visible above noise floor at N>30 cycles.
- **Mitigation idea:** widen jitter to 0.5 (`[15s, 45s]`) — matches the
  `coverTimer` jitter fraction. Or shift to log-normal cadence as in P1.

### P2 — `randomEventType()` enum is small and Mixpanel-mismatched

- **File:** `shadowlink/skins/browser/request.go:437-439` —
  `types := []string{"page_view", "click", "scroll", "session_ping", "form_submit", "nav"}`
- **DPI signal:** Body-content ML (which TSPU does not currently run, per
  2026-04-30 strategy doc) sees a small enum of 6 event types. Real
  Mixpanel `/track` payloads have an effectively unbounded `event` field
  populated by per-customer event names ("Login", "Add to Cart",
  "Onboarding Step 3 Completed", etc). Real GA4 event names follow
  `<verb>_<noun>` convention with thousands of entries.
- **Detector class:** Active probe / body inspection (nation-state ML, not
  TSPU). Phantom signal per pivot 2026-04-28 — but if ML body inspection
  ever lands, this enum is a single-call detector.
- **Repro:** scrape 100 ShadowLink upload bodies, extract `events[0].type`.
  Histogram has exactly 6 unique values, uniform distribution. Compare
  against any public Mixpanel SDK egress log → tens of thousands of
  unique event names, Zipf distribution.
- **Mitigation idea:** generate event names from a Zipfian sampler over a
  wordlist (3-4 words concatenated with `_` or camel-case). 200-line CSV
  of common SaaS event names is enough to make this look natural.
- **Severity note:** classified P2 (not P1) because TSPU does not currently
  parse body content. If `T1.5 Mixpanel schema lock` Tier-D item is ever
  picked up, this is the right place to start.

### P2 — `ackJitter` calibration is admitted-best-guess, not measured

- **File:** `shadowlink/server/handler.go:243-285` — exp(scale=7.21ms,
  median≈5ms, soft-cap 200ms) + 5% Pareto(α=2.0, xm=50ms, ceiling 1500ms).
- **DPI signal:** the C5 (May audit) closure correctly removed the
  150ms hard point-mass that was the prior detector, but the new shape
  parameters are documented as "best-guess preserving non-detectable
  shape" with calibration deferred to Phase 5/S5. We have no field data
  showing the shape matches real CDN/nginx ACK distributions for
  comparable POST sizes. If real distribution is, say, log-normal with
  median 3ms and σ_log = 0.5, our exp+Pareto mix is detectable by KS-test.
- **Detector class:** Passive ML — KS-test against reference CDN ACK
  distribution. Requires the adversary has a comparable reference
  capture, which is not free but not infeasible (Cloudflare publishes
  some performance percentiles).
- **Repro:** none feasible without ground-truth reference ACK distribution
  capture against `datacanvases.com` direct (no proxy, plain nginx 200
  response). Test deferred per code comment.
- **Mitigation idea:** dedicate 1 day in Phase 5 to capture 10k POST→ACK
  latencies through CF Edge against datacanvases.com (no ShadowLink path,
  just nginx 404). Fit log-normal / exp-mixture / etc., reset constants.
  Test pin: KS divergence < 0.05.

### P2 — Padding constants admitted-placeholder

- **File:** `shadowlink/skins/browser/padding.go:8-34`
  (`SamplePaddingTarget` log-normal[μ=ln(900), σ=0.5], clamp [600, 3000]),
  `:36-67` (`SampleHandshakePaddingTarget` log-normal[μ=ln(350), σ=0.5],
  clamp [200, 800]).
- **DPI signal:** docs explicitly state "Calibration vs captured Mixpanel
  fixture deferred to Phase 5/S5 schema lock". Current bounds are
  best-guess at "Mixpanel /track public size range". Any actual reference
  Mixpanel POST-size distribution will deviate. Same KS-test risk as P2
  ackJitter.
- **Detector class:** Passive ML / body-size histogram (only reachable
  if encryption layer doesn't fully obscure body size — which it doesn't,
  POST bodies have known cleartext length envelope).
- **Repro:** same as ackJitter, against reference Mixpanel `/track`
  capture.
- **Mitigation idea:** bundled with P2 ackJitter calibration session —
  same Phase 5 work item, double the data capture.

### P3 — `defaultDecoyPaths` weighted slice has 3 copies of `/` and 2 of `/favicon.ico`

- **File:** `shadowlink/client/decoy_traffic.go:78-93`.
- **DPI signal:** the weighting-by-duplication trick produces correct
  weighted distribution (sample `[idx]` is uniform → `/` and `/favicon.ico`
  appear ~2-3× more often), but the path histogram across many sessions
  shows a flat plateau of frequencies for the rest. Real browser path
  distribution is Zipfian (one path with most hits, exponentially
  decreasing). Our distribution has a square step at `/` and `/favicon.ico`,
  then flat for everything else.
- **Detector class:** Passive ML — extreme long-game signal.
- **Repro:** aggregate 10k decoy GET path histograms across many sessions.
  Real browser data: top-1 path > 60% of hits, top-3 > 90%. Ours: top-1
  ~25%, top-2 ~17%, top-3 ~8%, then flat at ~6% per remaining path.
- **Mitigation idea:** replace duplication-weighting with explicit
  Zipf-like sampler (idx ∝ 1/rank). One-line change; affects only the
  `pickDecoyPath` semantics (currently `decoyPaths[rand.IntN(len)]`).

### P3 — `wsURLPool` 12 entries, all picked uniformly

- **File:** `shadowlink/server/urls.go:25-38`,
  `shadowlink/client/ws_paths.go` (mirror).
- **DPI signal:** in real-world traffic, one site uses ONE realtime
  endpoint (e.g. only `/socket.io/`), not 12 different ones. Across the
  ShadowLink fleet, a passive observer scraping `(dest_domain, ws_path)`
  pairs sees the same domain `datacanvases.com` accept WS upgrades on
  12 different endpoints. No single real site does that.
- **Detector class:** Passive correlator — server-side fingerprint
  (per-domain, not per-flow). Active prober can hit all 12 paths and
  observe consistent upgrade-success / decoy-fall-through pattern;
  presence of >2 working WS endpoints on one domain is itself an
  artifact.
- **Repro:** 12 WS upgrade probes to `https://datacanvases.com/<each>`.
  Currently 12/12 succeed (modulo rate limit). Real comparable site
  succeeds on 0-1.
- **Mitigation idea:** per-domain narrow the pool to 1-3 paths via
  Domain Diversity sub-phase B-D config; pick deterministically from a
  per-domain hash so different ShadowLink domains expose different
  endpoints. Trade-off: complexity for the orchestrator (Sub-phase D
  already wires domain-pool config).

---

## Regressions

### REGRESSION — F3/NEW-1 jitter closure didn't reach server

Same as **P0** above. Documenting separately for ops dashboard
coherence: the wire-trigger followup memo
(`shadowlink/docs/audit/2026-05-02-wire-trigger-followup.md`) claims
NEW-1/NEW-4 closed; the closure landed on 5 client-side call sites
but missed `server/websocket.go:419` and `server/handler.go:1043`.

Two possible root causes:
1. NEW-1 plan scope was implicitly client-only — the memo never names
   server files in the closure summary. If so: missing audit-trail
   discipline; the spec/plan should have listed all `time.NewTicker`
   call sites across both packages.
2. Server changes were planned but lost in the merge. Less likely given
   no commits reference server timers in May.

Mitigation: the fix is mechanical — port `JitteredInterval` to a
shared location (e.g. `core/jitter.go`) and patch both server tickers.
Estimated effort: 30 min plus tests.

---

## Verified-Still-Closed

- **T1.1 PQ ClientHello** — `client/utls_http.go:36-78`
  (`pqClientHelloSpec`), `client/split_transport_tls.go:65-90`
  (cold-path branch), `client/ws_transport.go:354-420` (WS upgrade
  branch). MLKEM ensured-present in both supported_curves and key_share.
  PQ ENV gate `SHADOWLINK_TLS_PQ` working. Verified holds at sha
  7c8e99d6. Caveat: P1 finding above adds new concern about hot-path
  asymmetry — closure of the ORIGINAL T1.1 wire visibility item still
  holds; the asymmetry is a post-closure phenomenon.
- **T1.6 Cover GET + Warmup** — periodic cover scheduler RETIRED 2026-05-02
  (F3 followup); WarmupRequests one-shot pre-WS-upgrade burst kept.
  Verified at `client/ws_transport.go:226-268`. WarmupRequests still
  uses jittered inter-request delay (50-150ms).
- **T1.7 BroadcastStreamClose errgroup** — `server/handler.go:1657-1730+`
  (`BroadcastStreamClose`). errgroup.SetLimit(256), per-tunnel 50ms
  deadline, 5s total deadline. Verified holds; bounded parallelism is
  intact.
- **A2-HIGH-7 Padding decouple** — `skins/browser/padding.go:22-34`
  (independent log-normal source for `SamplePaddingTarget`). Decoupled
  from `PayloadDistribution.UploadSize` per closure spec. Verified holds.
- **A2-MED-10 Meltdown jitter** — confirmed in
  `client/ws_pool_meltdown_log_test.go` exists; rate-limit + severity
  gate logic active per memory `phase-2-tls-modernity-done.md`. Code
  verification not deep-dived in this audit pass; flagging "verified
  by-test" rather than "by-source" — recommend a follow-up sanity check
  on next audit round.
- **A2-MED-7 Decoy timing variance** — `server/decoy_timing.go:49-53`
  (`fillRandom` mathrand replacement) + `:142-170` (`runSyntheticDispatch`
  isolated). std-dev <2ms enforced by
  `TestFailClosedToDecoy_TimingVariance`. Verified.
- **A2-MED-6 Gorilla 400 → decoy 200** — `server/websocket.go:26`
  (`noopUpgradeError`), `:337-344` (Upgrade-fail branch routes through
  `failClosedToDecoy`). Verified.
- **A3-S-HIGH-2 WS attach race** — `server/websocket.go:107-109`
  (CompareAndSwap on `tunnel.WSAttached`). Verified.
- **C5 ackJitter reshape** — `server/handler.go:264-285`. Old 150ms
  hard-cap point-mass removed; mixed exp + Pareto. Calibration TODO is
  separate finding (P2) but the regression-bound (no point-mass at
  150ms) holds.

---

## Comparative Notes (vs Reality / Vision / Hysteria2 / TrustTunnel)

- **vs VLESS+Reality:** Reality has stronger TLS modernity (proxies a
  real upstream's certificate end-to-end, perfect JA3 mimicry of the
  upstream domain) but weaker behavioral mimicry (single TCP connection,
  no application-layer realism). ShadowLink's WS pool + decoy traffic +
  body-prefix wire is more behaviorally realistic but more code surface.
  **Status:** parity on TLS handshake (now both at HelloChrome_133+),
  ShadowLink slight edge on application-layer realism, Reality edge on
  cert chain authenticity. P0 server-ticker fix would close one of the
  remaining behavioral leaks Reality doesn't have (Reality has no
  application-layer keepalive at all).
- **vs Hysteria2:** Hysteria2 is QUIC-only; QUIC is currently
  policed in RF (per memory `quic-blocking-rf-2026.md`). ShadowLink's
  TCP/443 path remains the resilience choice. Hysteria2 has bigger
  throughput (UDP, BBR) but smaller stealth surface. Different niche.
- **vs Vision (XTLS-Vision):** Vision splits inner TLS records to
  defeat the TLS-in-TLS fingerprint. ShadowLink doesn't carry inner TLS
  (it carries SOCKS5 traffic over a single outer TLS), so Vision's
  specific concern doesn't apply. Vision is reportedly being policed in
  RF as of Nov 2025 (bbs#546). ShadowLink should NOT adopt Vision-style
  fragmentation — different threat model.
- **vs TrustTunnel:** TrustTunnel uses HTTP/3 reverse-proxy on 443
  (per memory). It's a different transport posture (QUIC-based) and
  faces the same QUIC-policing concern as Hysteria2 in RF. ShadowLink
  TCP/443 + nginx terminate strategy remains complementary.

---

## Open Questions

1. **Real Chrome major distribution per ISP** — does the May-2026 RF
   ML-DPI infrastructure actually compute "Chrome major distribution
   per source IP/AS"? If yes, P1 (Chrome 133 cohort) is more urgent;
   if no, downgrade to P2. Web research deferred — this audit assumes
   yes, conservative.
2. **JA4 with PQ** — does the JA4 algorithm count keyshare *content*
   in the hash, or only keyshare group IDs? Quick web check needed.
   If only IDs (which is the JA4 spec we've seen), then P1 PQ asymmetry
   is JA4-invisible and only detectable by deep field-by-field
   comparison — downgrade to P2.
3. **utls upstream HelloChrome_146 timeline** — is there a tracked PR
   for HelloChrome_146 in upstream? If merged within 60 days, the
   Chrome 133 cohort issue (P1) self-resolves. If not, plan a fork or
   a synthetic spec.
4. **Real CDN ACK latency reference** — does CF publish per-region
   POST→ACK p50/p99 for cached static GETs? If yes, ackJitter
   calibration (P2) becomes a 1-day reading task instead of a capture
   campaign.
5. **Server-side `JitteredInterval` placement** — does the team prefer
   shared `core/jitter.go` (cleanest), duplicate per package
   (no cross-deps), or a common testutil import? Affects fix-effort
   estimate but not finding severity.

---

## Suggested Plan-of-Record (delta to existing roadmap)

1. **P0 fix (1-2 hr):** port `JitteredInterval` to `core/jitter.go`,
   patch `server/websocket.go:419` and `server/handler.go:1043`. Add
   tests against autocorrelation peak. Re-run on canary; field-test 24h.
2. **P1.1 fix (1 day):** convert `JitteredInterval` to log-normal
   variant for cadence (keep uniform for one-shot delays). Update
   memory + master roadmap.
3. **P1.2 monitoring (2 hr):** add CI watch on
   `github.com/refraction-networking/utls` releases — alert when
   `HelloChrome_135+` lands.
4. **P1.3 PQ posture decision (3 days):** flip `SHADOWLINK_TLS_PQ=0`
   default-off OR ship bogdanfinn-MLKEM patch upstream. Document in
   master roadmap.
5. **P1.4 persona unification (1 day):** drop generic-SPA paths from
   `decoy_traffic.defaultDecoyPaths`, keep only Mixpanel-aligned set.
   OR retire decoy_traffic entirely (consistent with cover-GET
   retirement).
6. **P2 fixes:** deferred to Phase 5 / S5 schema lock per existing
   roadmap. No change.

Total estimated effort for P0+P1: 4-6 working days.

---

**End of T2 audit.**
