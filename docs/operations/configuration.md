# ShadowLink — Configuration Reference

Audience: operators deploying the client or the server, and integrators wiring
the mobile facade. Every value below was read out of the Go source; file and
line are given so a claim can be checked in one jump.

**Source of truth: the code, not this file.** This project has been burned by
config comments that described a mechanism that was not executed — a YAML
comment claimed `ws_pool_size` defaulted to 6 when the engine used 8, and
`SHADOWLINK_BYTE_BUDGET_MIN_INTERVAL` is documented in a code comment as
"tunable" while no code ever reads it (§7.7). Where this document and the code
disagree, the code wins and this document is a bug.

Verified against the tree at `docs/operations/configuration.md` creation time,
2026-08-24, module `github.com/nixavpn/shadowlink`, Go 1.26.

## Status legend

| Mark | Meaning |
|---|---|
| VERIFIED | Read in the shipped source; default taken from the literal, not from a comment |
| DEPRECATED | Still parsed, still reaches the config struct, no longer drives behaviour |
| NO-EFFECT | Parsed or documented, but nothing reads it — setting it does nothing |
| UNREACHABLE | Read by live code that the production configuration never enters |

---

## 1. DO NOT CHANGE WITHOUT A MEASUREMENT

Read this section before touching anything in §4.2, §4.3, §4.4, or §7.

The timing values in this project are **not defaults chosen for taste**. They
are the output of field measurements against TSPU (the RKN DPI middlebox),
taken over multi-hour packet captures and log runs on real Russian ISP paths.
`CLAUDE.md` hard rule 8 states the constraint directly: timing constants are
not to be changed "by eye".

Three reasons an arbitrary change is worse than it looks:

1. **The window is not a global constant.** ACM IMC 2022 established that TSPU
   is deployed inline at the edge of each ISP and is *heterogeneous across
   regions and operators*. A value measured on one AS is not a value for all
   ASes. The measured cut window on the working AS was 84–118 s by age — but
   that number is an artifact of our own rotation policy as much as of the
   censor's, which is why the project reasons in *hazard among survivors*, not
   in death histograms.
2. **The rotation budget is not the sum you think it is.** Never add the
   pieces at the call site. The only correct source is
   `WSPoolTransport.worstCaseTeardown()` (`client/ws_pool.go`), which sums
   `base + stagger + sweep + deferred + teardown_cap`. Adding by hand has
   produced a figure wrong by 1.6× (a dropped `staggerOffsetCap`) and wrong
   twice more in the `sweep` term alone.
3. **Green tests will not catch the regression.** The failure mode is a timing
   signature observable on the wire — a periodic line in packet arrival phase,
   or a connection-age distribution narrow enough to be a better classifier
   than JA3. No unit test measures that. It is measured with `pktmon` captures
   and `tools/firstpackets -phase`.

### 1.1 Environment variables in this class

| Variable | Why it is dangerous |
|---|---|
| `SHADOWLINK_MAX_SLOT_AGE` | The rotation threshold itself. Raising it walks slots into the observed age-cut band; lowering it raises TLS-connection churn to the origin, which is a P0-class signal (per-IP connection policing) |
| `SHADOWLINK_STAGGER_STEP`, `SHADOWLINK_STAGGER_OFFSET_CAP` | The offset **adds to** the rotation threshold per cell, it does not spread inside it. `cap` is a no-op while `(2·poolSize − 1)·step ≤ cap` — a condition, not a property: it comes alive at `poolSize ≥ 9` |
| `SHADOWLINK_STICKY_MAX_DRAIN_AGE`, `_STICKY_MAX_TOTAL_BYTES`, `_STICKY_MAX_SLOTS` | Sticky must be **strictly greater** than `SHADOWLINK_DRAIN_HARD_CAP` or the mechanism silently never runs while the log keeps printing `sticky_outcome=age_backstop`. Equality breaks it exactly like "less than" does; this has been stepped on twice |
| `SHADOWLINK_KEEPALIVE_INTERVAL` | The base of a log-normal sampler with window `[base/2, base*2]`. At base 5 s worst-case slot silence is 10 s, which is the conservative `middleboxSilentCutFloor`. Raising the base raises worst-case silence past that floor |
| `SHADOWLINK_AGE_CUT_MIN_AGE` | The floor at which a terminal read error gets *labelled* `age_cut`. It is a label, not an observation — `isAgeCut()` does not inspect the error type. Moving it moves every downstream statistic |
| `SHADOWLINK_DRAIN_HARD_CAP`, `_DRAIN_IDLE_THRESHOLD` | Feed `worstCaseTeardown()`. `deferred + teardown_cap` is ~73 % of the overhead; the drain cap is one of the two large terms |
| `SHADOWLINK_READY_CAPACITY_FLOOR_FRACTION` | Lowering it *masks* a capacity leak rather than fixing one, and moves the pool towards clinch — the exact condition the storm-brake gate exists to prevent |

### 1.2 Hard-coded constants in this class (no env flag, deliberately)

| Constant | Value | Location | Why it is not a knob |
|---|---|---|---|
| `creditSenderInterval` | 8 ms | `client/stream_flow.go:77` | It ticks a `time.Ticker` that sends real WINDOW_UPDATE bytes to the origin — a 125 Hz line, measured on the wire at `R@8ms = 0.9445` for the dominant 71-byte packet class before the fix, `0.0008` after. Changing the period reproduces the line at a new scale; the fix was a jittered `time.Timer`, not a different number. Shrinking it also risks the credit-stall that previously idled a slot into a `close 1006` |
| `middleboxSilentCutFloor` | 10 s | `client/ws_pool.go:2883` | The conservative silence budget that bounds `keepaliveSpreadMax`. Observable but **not proven** as the censor's threshold — cuts have been seen both above and below it. Treat it as an invariant on our own spread, not as a measured limit |
| `rotationWatchdogTick` | 500 ms | `client/ws_pool.go:685` | The **phase anchor for the entire pool**, including drain close times, which inherit their phase from `startDrain`. It is woken by a `time.Timer` re-armed at `tick + uniform[0, tick)`; reverting to a plain `time.NewTicker` re-materialises a 500 ms grid in close events without any edit to the drain code. Guarded by `TestRotationWatchdogLoop_UsesJitteredTimerNotTicker` |
| `keepaliveSpreadMax` | 400 ms | `client/ws_pool.go:2862` | Bounded by `middleboxSilentCutFloor`; the keepalive interval subtracts it, so raising it eats directly into the silence budget |
| `drainPollInterval` | 500 ms | `client/ws_pool_drain.go:52` | Its grid is 100 % alive relative to drain start — it is safe only because its phase is inherited from the jittered sweep. It is a dependency, not a free parameter |
| `streamAckThrottleInterval` | 50 ms | `client/client.go:1214` | Not a ticker but a since-last-send gate: under continuous saturation it self-synchronises to exactly 50 ms intervals. Left unchanged deliberately (hard rule 8); jitter was added around it instead (`client.go:1252`) |
| `stickyRecheckInterval` | 5 s | `client/ws_pool_drain.go:58` | The step by which a sticky drain deadline is extended; interacts with the `hard_cap < sticky` invariant |
| `drainCatastrophicBackoff` | 150 s | `client/ws_pool_drain.go:80` | Not included in `worstCaseTeardown()` at all — under pool degradation a slot can reach ~220 s |
| `byteBudgetMinRotationInterval` | 10 s | `client/ws_pool.go:1160` | Wall-clock floor between slot readiness and its first byte-budget rotation. Without it, saturation rotates a slot several times per second and the pool collapses |

**Rule of thumb.** If you intend to change any of the above: take a `pktmon`
capture before and after, run `tools/firstpackets -phase -pcap <file>` on both,
and compare vector strength `R` at the tick period. The pass criterion is
`R < 0.2`; "share of events in the modal bin" is *not* a criterion — it falls
automatically for any tick under a second, so it measures your knob rather than
the observability.

---

## 2. Where a setting can come from

| Layer | Client | Server |
|---|---|---|
| CLI flags | `cmd/nixavpn-client/main.go:62-74` | `cmd/shadowlink-server/main.go:51-112` |
| YAML file | `cmd/nixavpn-client/config.go` + `engine/config.go` | `server/fileconfig.go` |
| `sl://` URL | `client/slurl.go:38` (`ParseSLURL`) | n/a |
| Environment | scattered, see §4 and §7 | see §7.5 |
| Mobile facade | `mobile/config.go` | n/a |

### 2.1 Client precedence — and one place it is not what the comment says

The comment at `cmd/nixavpn-client/main.go:107` reads *"SOCKS address: CLI flag
> YAML config > random port."* The code below it does not implement the middle
term:

```go
if *socksAddr != "" {
    cfg.SOCKS = *socksAddr
} else {
    cfg.SOCKS = randomSOCKSAddr()   // YAML value is overwritten unconditionally
}
```

So the effective precedence is **CLI flag → random port in 10000–60000**, and
the YAML key `socks:` is NO-EFFECT (§8.2). The random default is intentional
(port 1080 is a documented proxy-detection heuristic); only the YAML override
is missing.

Everything else on the client follows: **CLI flag → config source → engine
default**, where the config source is exactly one of `-import`, `-config`,
`-api`, or an auto-discovered `nixavpn.yaml` / `nixavpn.yml`
(`main.go:460-492`).

### 2.2 Server precedence

`DefaultConfig()` → YAML via `FileConfig.ApplyTo` → **explicitly passed** CLI
flags. "Explicitly passed" is real: `flag.Visit` records which flags the user
typed, so a flag left at its default does not clobber a YAML value
(`cmd/shadowlink-server/main.go:167-168`). Three exceptions apply their value
unconditionally: `-flow-max-window`, `-migrate-grace`, `-migrate-max-orphaned`,
`-migrate-max-orphaned-total` (the last three are pre-seeded from env, so the
resolved value is still the intended one).

---

## 3. Client YAML

File shape (`cmd/nixavpn-client/config.go:20`, `engine/config.go:70`):

```yaml
protocol: shadowlink
socks: "127.0.0.1:1080"      # NO-EFFECT — see §2.1 and §8.2
system_vpn: false
shadowlink: { ... }
vless: { ... }
api: { ... }
```

### 3.1 Top level — `main.Config`

| Key | Type | Default | Effect | Status |
|---|---|---|---|---|
| `protocol` | string | `""` → auto | `auto` \| `shadowlink` \| `vless`. Auto prefers VLESS when a `vless:` section exists, else ShadowLink (`main.go:496-512`) | VERIFIED |
| `socks` | string | overwritten | SOCKS5 listen address. **Never read** — see §2.1 | NO-EFFECT |
| `system_vpn` | bool | `false` | TUN mode + LeakGuard. `-system-vpn` can turn it on but not off (`main.go:131-133`) | VERIFIED |
| `shadowlink` | object | nil | ShadowLink protocol section, §3.2 | VERIFIED |
| `vless` | object | nil | VLESS+Reality section, §3.3 | VERIFIED |
| `api` | object | nil | Remote config fetch, §3.4 | VERIFIED |

`proxy_user` / `proxy_pass` are `yaml:"-"` — generated fresh per launch
(`main.go:123`, user `nix`, 16 random bytes hex). They cannot be configured,
by design: an externally settable value could be made weak.

### 3.2 `shadowlink:` — `engine.ShadowLinkConfig` (`engine/config.go:70`)

| Key | Type | Default | Effect | Status |
|---|---|---|---|---|
| `server` | string | — | `host:port`. In production a **bare origin IP**; the domain goes in `sni` | VERIFIED |
| `pubkey` | string | — | Server X25519 public key, 64 lowercase hex chars | VERIFIED |
| `websocket` | bool | `false` | Gates the whole WS-transport block together with `system_vpn` (`engine/engine.go:340`). Without either, the data path falls back to 20 ms polling tickers | VERIFIED |
| `tls` | bool | `false` | TLS for the transport dial | VERIFIED |
| `auto` | bool | `false` | Carried through from the URL; not consulted by the engine's transport selection | VERIFIED |
| `cdn` | string | `""` | **Legacy, and the name lies about the mechanism** — see §8.1 | VERIFIED |
| `ech` | bool | `false` | Carried through; parsed from `ech=1` | VERIFIED |
| `routing` | object | nil | `bypass` / `force` / `block` lists, §3.5 | VERIFIED |
| `origin` | string | `""` | Origin IP for a direct WS dial; sets WS target to `origin:443` with SNI from `server` (`engine/engine.go:344-348`) | VERIFIED |
| `sni` | string | `""` | TLS ServerName override — the full-direct mode (IP host + domain SNI) | VERIFIED |
| `cfip` | string | `""` | Pin a specific CDN edge IP | VERIFIED |
| `ws_pool` | bool | `false` | Enables the pooled WS transport. **Not parseable from an `sl://` URL** — §8.3 | VERIFIED |
| `ws_pool_size` | int | **8** (`engine/engine.go:429-432`) | Pool slots. `< 1` → 8. In the experimental per-stream mode the ready-pool default is **6** instead (`engine.go:378-381`). **Not parseable from `sl://`** — §8.3 | VERIFIED |
| `backup_servers` | []string | nil | Fallback `host:port` endpoints; must share the same pubkey | VERIFIED |
| `cdns` | []string | nil | SNI rotation pool, max 8 (`client/slurl.go:24`) | VERIFIED |

⚠ The old YAML comment claiming `ws_pool_size` defaults to 6 was wrong for the
pooled path. The literal at `engine/engine.go:431` is `poolSize = 8`.

### 3.3 `vless:` — `main.VLESSConfig` (`cmd/nixavpn-client/config.go:43`)

| Key | Type | Default | Effect |
|---|---|---|---|
| `address` | string | — | Server host |
| `port` | int | 443 when absent from the URL | Server port |
| `uuid` | string | — | VLESS user UUID |
| `public_key` | string | — | Reality public key (`pbk`) |
| `short_id` | string | — | Reality short ID (`sid`) |
| `sni` | string | — | Reality SNI |
| `fingerprint` | string | — | uTLS fingerprint name (`fp`) |
| `flow` | string | — | e.g. `xtls-rprx-vision` |
| `encryption` | string | `""` → `none` | VLESS encryption suite |
| `mldsa65_verify` | string | `""` | ML-DSA-65 client verify, base64url; empty = not sent |

All VERIFIED. VLESS is CLI-only: `engine/` deliberately excludes it so the
mobile `.aar` does not pull xray-core (`engine/config.go:12-20`).

### 3.4 `api:` — `main.APIConfig`

| Key | Type | Effect |
|---|---|---|
| `url` | string | NixaVPN API base URL; two GETs to `/api/v1/client/full-config?protocol=…` |
| `token` | string | Bearer token |

VERIFIED (`config.go:57`, `config.go:214-253`). A 404 for a protocol is not an
error — it means that protocol is unavailable on that server.

### 3.5 `routing:` — `client.RoutingConfig`

Exactly three keys: `bypass`, `force`, `block`.

⚠ **A built-in bypass list is always merged and cannot be disabled**:
`*.ru`, `*.рф`, `*.su`, `*.by`, `*.kz`, `*.ua`, `*.am`
(`engine/engine.go:759-773`). Your rules are appended *before* the defaults, so
they are evaluated first and effectively win on conflict. There is no switch to
turn the built-in list off.

---

## 4. Client environment variables

All of these are read at process start or at transport construction; none is
re-read at runtime. Boolean parsing in `engine/` uses `envBoolDefault`
(`engine/engine.go:1072`): case-insensitive, whitespace-trimmed; `0/false/no/off`
→ false, `1/true/yes/on` → true, **anything unrecognised silently returns the
default**. Durations use `envDurationDefault` (`engine.go:1088`, Go duration
syntax); unparseable → default.

### 4.1 Transport selection

| Variable | Type | Default | Effect | Source | Status |
|---|---|---|---|---|---|
| `NIXAVPN_FORCE_PER_STREAM_WS` | `=1` | off | One dedicated WS per SOCKS5 CONNECT instead of the pool. **Costly:** the UDP dispatcher has no third branch, so all UDP falls to a 20 ms ticker sending a real encrypted frame per tick | `engine/engine.go:365` | VERIFIED |
| `NIXAVPN_DISABLE_WS_POOL` | `=1` | off | In per-stream mode only: skip the ready-pool | `engine/engine.go:377` | UNREACHABLE unless per-stream is forced |
| `NIXAVPN_FORCE_WS_POOL` | `=1` | off | Force the WS pool even when `cdn` is set without `origin`/`sni` (which otherwise routes to SplitHTTP — §8.1) | `engine/engine.go:425` | VERIFIED |
| `SHADOWLINK_PHASED_WARMUP` | bool | on | Phased pool warmup vs legacy linear stagger. Only consulted by `WSReadyPool`, which is constructed **only** in per-stream mode | `client/ws_ready_pool.go:21`, used at `:132` | UNREACHABLE in the pooled default |
| `SHADOWLINK_SOCKS5_COALESCE` | bool | on | Coalesce SOCKS5 CONNECTs within a 50 ms window, max 2 parallel (`proxy/socks5/tcp.go:46-49`) | `proxy/socks5/tcp.go:36`, used at `server.go:49` | VERIFIED |
| `SHADOWLINK_DATAPATH_BODYPREFIX` | bool | **on** | `0` reverts to the legacy `Authorization: Bearer` data path. Only useful against a pre-Phase-0 server. **Now also a config field** — §8.4 | `client/datapath.go:31` | VERIFIED |

### 4.2 Slot rotation — see §1 first

| Variable | Type | Default in code | Effect | Source |
|---|---|---|---|---|
| `SHADOWLINK_MAX_SLOT_AGE` | duration | **75 s** | Base rotation threshold per slot. Only applied in direct mode (`origin` or `sni` set) | `engine/engine.go:509` |
| `SHADOWLINK_STAGGER_STEP` | duration | **6 s** | Per-cell offset step; cell `idx` gets `idx × step ± step/2`, **added to** the threshold | `engine/engine.go:625` |
| `SHADOWLINK_STAGGER_OFFSET_CAP` | duration | **45 s** | Clamp on that offset. No-op while `(2·poolSize − 1)·step ≤ cap` | `engine/engine.go:626` |
| `SHADOWLINK_AGE_CUT_MIN_AGE` | duration | **45 s** | Age floor above which a terminal read error is *labelled* `age_cut`. A label, not a detector | `engine/engine.go:627` |
| `SHADOWLINK_KEEPALIVE_INTERVAL` | duration | **5 s** | Base of the log-normal keepalive sampler; window `[base/2, base×2]`, minus `keepaliveSpreadMax` | `engine/engine.go:616` |
| `SHADOWLINK_READY_CAPACITY_FLOOR_FRACTION` | float | **0** → constant **0.75** | Fraction of `poolSize` that must be `slotReady` for the storm-brake to let a drain through. Not range-checked here; `client.normalizeFloorFraction` clamps | `engine/engine.go:636`, constant at `client/ws_pool.go:1089` |

The field configuration documented in `CLAUDE.md` differs from these code
defaults on several of them (notably `MAX_SLOT_AGE` 70 s and `STAGGER_STEP`
1 s), set through the launcher scripts. Read the launcher, not this table, to
learn what a given field run actually used.

### 4.3 Graceful drain — see §1 first

| Variable | Type | Default in code | Effect | Source | Status |
|---|---|---|---|---|---|
| `SHADOWLINK_GRACEFUL_DRAIN` | bool | **on** | `0` restores legacy hard rotation (no drain). Useful as a bisection tool. ⚠ With it off, `worstCaseTeardown()` loses `deferred + tear` — 55 s, 39 % of the prod budget | `engine/engine.go:559` | VERIFIED |
| `SHADOWLINK_DRAIN_HARD_CAP` | duration | **30 s** | Max time a slot may sit in `slotDraining` before forced teardown | `engine/engine.go:560` | VERIFIED |
| `SHADOWLINK_DRAIN_IDLE_THRESHOLD` | duration | **30 s** | A drain may finish early when remaining streams have been idle this long. `0` disables the idle gate | `engine/engine.go:578` | VERIFIED |
| `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX` | int | 2 | Reaches `WSPoolConfig.DrainIdleStreamsMax` and the `drainIdleStreamsMax` slot field — and is then **never read**. Setting it emits a one-time deprecation WARN and changes nothing | `engine/engine.go:579`, stored at `client/ws_pool.go:2335`, no reader | **DEPRECATED / NO-EFFECT** |
| `SHADOWLINK_STICKY_MAX_DRAIN_AGE` | duration | `client.DefaultStickyMaxDrainAge` = **15 s** (`client/ws_pool.go:1550`) | Sticky backstop: how long a draining slot may be held for an active download. `0` is translated to `-1` to reach the kill gate — an unset env would otherwise resolve to 10 m | `engine/engine.go:603-607` | VERIFIED |
| `SHADOWLINK_STICKY_MAX_TOTAL_BYTES` | int (bytes) | **256 MiB** | Second sticky limit | `engine/engine.go:608` | VERIFIED |
| `SHADOWLINK_STICKY_MAX_SLOTS` | int | **0** → auto | Third sticky limit; first limit reached wins | `engine/engine.go:609` | VERIFIED |

⚠ **The sticky invariant.** `sticky > hard_cap` must hold **strictly**. At
`sticky ≤ hard_cap` the first deadline check goes straight to teardown and the
extension path is unreachable — while the log keeps printing
`sticky_outcome=age_backstop`, i.e. the mechanism *looks* alive. The only
reliable health signal is `sticky_active > 0` in the health line;
`drain_duration` is not one, because a healthy 15 s → 20 s → 25 s extension
ladder lands on exactly `25s`, the same value a dead mechanism produces.
Guards: `TestStickyDrainBudget_HardCapNotBelowSticky`,
`TestStickyDrainBudget_DefaultsSatisfyStickyReachability`.

### 4.4 Stream migration and flow control

| Variable | Type | Default | Effect | Source | Status |
|---|---|---|---|---|---|
| `SHADOWLINK_STREAM_MIGRATION` | bool | **on** | Client-side kill switch for per-stream migration; advertised in the FLOWCTL marker. Also read in `engine/` to warn when an aggressive drain cap is combined with migration off | `client/ws_transport.go:764`, used `:890`; `engine/engine.go:568` | VERIFIED |
| `SHADOWLINK_MIGRATE_THRESHOLD` | duration | **45 s** (`client/migrate_watchdog.go:40`) | Base slot age at which active streams become migration candidates; jittered by `U(0.7, 1.0)`, sampled once per (re)connect. Non-positive → default | `client/migrate_watchdog.go:56` | VERIFIED |
| `SHADOWLINK_MIGRATE_SPREAD` | duration | **8 s** (`migrate_watchdog.go:48`) | Width of the per-stream `U(0, spread)` scheduling delay | `client/migrate_watchdog.go:71` | VERIFIED |
| `SHADOWLINK_FLOW_WINDOW` | uint (bytes) | **1 MiB** (`client/ws_pool.go:2359`) | Desired per-stream flow-control window; effective window is `min(client, server)`. `0` disables. Clamped to **6 MiB** (`client/stream_flow.go:15`) | `client/stream_flow.go:29` | VERIFIED |
| `SHADOWLINK_REASSEMBLY_GAP_TIMEOUT` | duration | **2 s** (`proxy/socks5/tcp.go:435`) | Hole-fill backstop in downlink reassembly. `≤ 0` or unparseable → default | `proxy/socks5/tcp.go:442` | VERIFIED |
| `SHADOWLINK_REASSEMBLY_BUFFER` | int (bytes) | **4 MiB** (`tcp.go:436`) | Per-stream reorder cap. `≤ 0` → default | `proxy/socks5/tcp.go:456` | VERIFIED |

⚠ The `anti-tspu-tuning` skill table lists `SHADOWLINK_FLOW_WINDOW` as
defaulting to 4 MiB. The literal is `1 << 20` at `client/ws_pool.go:2359`.

### 4.5 TLS fingerprint

| Variable | Type | Default | Effect | Source | Status |
|---|---|---|---|---|---|
| `SHADOWLINK_TLS_PQ` | bool | **on** | `0` reverts the cold path to the stock `HelloChrome_133` spec without the MLKEM keyshare safety bridge. On utls v1.8.3 the wire effect is ≈ no-op because Chrome 133 already carries MLKEM768 | `client/utls_http.go:142` | VERIFIED |
| `SHADOWLINK_FP_POOL` | bool | **on** | `0` forces Chrome 100 %, ignoring server-sent weights and the persisted profile. Emergency rollback of population mimicry without a redeploy | `client/fpstate.go:81`, used `client/client.go:319` | VERIFIED |

⚠ Do **not** use `SHADOWLINK_FP_POOL` to introduce fingerprint randomisation.
Hard rule 2: a random fingerprint is unique, and uniqueness is the signal. The
flag exists to force *less* variety, not more.

### 4.6 Routing, DNS and leak protection (CLI client only)

These live in `cmd/nixavpn-client/main.go` and therefore do **not** apply to
the mobile facade, which contains no DNS or leak-guard code at all.

| Variable | Type | Default | Effect | Source | Status |
|---|---|---|---|---|---|
| `SHADOWLINK_BYPASS_ENABLED` | bool | **on** | `0/false/no/off` skips the bypass dialer wrap. Opt-out semantics | `main.go:764` | VERIFIED |
| `SHADOWLINK_SPLIT_DNS` | bool | **follows bypass** | Local split-DNS forwarder. Unset → follows bypass. An unrecognised value keeps the default *and logs a WARN* — a typo must be visible | `main.go:807` | VERIFIED |
| `SHADOWLINK_SPLIT_TUNNEL` | bool | **off** | Opt-**in**: bypass ranges are not allowed past the kill switch unless explicitly enabled. Only `1/true/yes/on` enable | `main.go:791` | VERIFIED |
| `SHADOWLINK_LEAKGUARD_STRICT` | bool | **on** | Opt-**out**: a LeakGuard enable failure aborts startup. `0/false/no/off` continues without kill-switch protection. Inverted to fail-secure in round 18 | `main.go:841` | VERIFIED |
| `SHADOWLINK_ADMIN_OVERRIDE` | bool | **on** | `0` skips the network fetch of the signed admin CIDR override and uses only the on-disk cache | `main.go:778` | VERIFIED |
| `SHADOWLINK_BYPASS_HMAC_KEY` | hex string | unset | HMAC key for verifying the admin override, provisioned out of band. Unset / non-hex / `< 16` bytes disables override fetching with a log line | `main.go:857` | VERIFIED |
| `SHADOWLINK_DNS_STUB_IPS` | CSV IPv4 | unset | Extra censorship block-page stub IPs, **appended** to the built-in `89.221.226.6`. Invalid entries are skipped with a WARN. ⚠ Read at package-variable init — §8.5 | `client/dnsproxy/stub.go:29` | VERIFIED |

---

## 5. Client CLI flags

`cmd/nixavpn-client/main.go:62-74`. Subcommands checked before flag parsing
(`main.go:40-58`): `version`, `check-ip`, `connect` (the default).

| Flag | Type | Default | Effect |
|---|---|---|---|
| `-import` | string | `""` | Import config from a `vless://` or `sl://` URL |
| `-config` | string | `""` | Path to the YAML config |
| `-api` | string | `""` | NixaVPN API base URL |
| `-token` | string | `""` | API auth token |
| `-protocol` | string | `auto` | `auto` \| `shadowlink` \| `vless` |
| `-socks` | string | `""` | SOCKS5 listen address. Empty → random port 10000–60000. `0.0.0.0` / `::` is forced back to `127.0.0.1` with a WARN (`main.go:114-120`) |
| `-system-vpn` | bool | `false` | TUN + LeakGuard. Can enable, cannot disable a YAML `system_vpn: true` |
| `-check-ip` | bool | `false` | Print the exit IP after connecting |
| `-log` | string | `info` | `quiet` \| `info` \| `debug` \| `trace` |
| `-log-file` | string | `""` | Also append logs to this file |
| `-verbose` | bool | `false` | DEPRECATED — maps to `-log=debug` only when `-log` is still at `info`; logs a WARN |

Exactly one config source is used, in this order: `-import`, `-config`,
`-api`, then auto-discovery of `nixavpn.yaml` / `nixavpn.yml` in the working
directory (`main.go:460-492`). No source → error exit.

---

## 6. `sl://` URL

Parsed by `client.ParseSLURL` (`client/slurl.go:38`), emitted by `BuildSLURL`
(`:141`). Round-trip is guaranteed for the parameters below.

```
sl://<64-hex-pubkey>@<host>:<port>?tls=1&ws=1&auto=1&sni=<domain>
```

Realistic full-direct example — **placeholders only, never a live key or a
production IP**:

```
sl://0000000000000000000000000000000000000000000000000000000000000000@203.0.113.10:443?tls=1&ws=1&auto=1&sni=example.com&backup=203.0.113.11:443
```

| Query parameter | Maps to | Notes |
|---|---|---|
| *(userinfo)* | `pubkey` | Exactly 64 **lowercase** hex chars; anything else is rejected |
| *(host:port)* | `server` | Port defaults to `443` when absent |
| `tls` | `tls` | Truthy only for the literal string `1` |
| `ws` | `websocket` | Literal `1` |
| `auto` | `auto` | Literal `1` |
| `ech` | `ech` | Literal `1` |
| `cdn` | `cdn` | ⚠ Changes the transport — §8.1 |
| `origin` | `origin` | Origin IP for a direct WS dial |
| `sni` | `sni` | TLS ServerName; the full-direct mode |
| `cfip` | `cfip` | Pin one CDN edge IP |
| `backup` | `backup_servers` | Comma-separated; an entry without `:port` gets `:443` |
| `cdns` | `cdns` | Comma-separated SNI pool, hostname-validated, **max 8** |
| `socks` | `Socks` | Parsed, then **dropped** — §8.2 |
| `id` | `ClientID` | Parsed, then **dropped** — §8.2 |

Security properties worth knowing: more than one `@` in the authority is
rejected outright (SSRF via `sl://key@host@evil.com`), and `cdns` entries are
matched against `^[a-zA-Z0-9.\-]+$` before use.

⚠ **`ws_pool` and `ws_pool_size` have no URL form** — §8.3.

---

## 7. Server configuration

### 7.1 CLI flags — `cmd/shadowlink-server/main.go`

| Flag | Type | Default | Effect |
|---|---|---|---|
| `-config` | string | `""` | YAML config path |
| `-listen` | string | `:443` | Listen address |
| `-cert` / `-key` | string | `""` | TLS certificate / private key |
| `-server-key` | string | `""` | ShadowLink static X25519 private key file (64 hex chars) |
| `-decoy` | string | `""` | Decoy site directory |
| `-max-clients` | int | 500 | Concurrent client sessions |
| `-max-conns` | int | 8 | Concurrent connections per client, advertised in ServerHello |
| `-chunk-size` | int | 12288 | Max chunk payload — deliberately below the 16 KB TSPU threshold |
| `-session-timeout` | int (s) | 0 = keep default (90) | Idle session timeout |
| `-cleanup-interval` | int (s) | 0 = keep default (10) | Session sweep period |
| `-behind-proxy` | bool | false | Trust `X-Forwarded-For` |
| `-mgmt-port` | int | 0 = disabled | Management API port |
| `-mgmt-bind` | string | `127.0.0.1` | Management API bind |
| `-mgmt-key` | string | `""` | Management API key (`X-Management-Key`) |
| `-default-max-devices` | int | 3 | Device limit per user |
| `-flow-max-window` | int | 1048576 | Max per-stream flow window granted; **`0` disables flow control**. Always applied |
| `-stream-migration` | bool | true | Server-side migration kill switch |
| `-origin-death-teardown` | bool | false | Signal `FlagStreamClose` when a stream's origin TCP dies |
| `-migrate-grace` | duration | `SHADOWLINK_MIGRATE_GRACE` or 8s | How long an orphaned relay waits for RESUME |
| `-migrate-max-orphaned` | int | `SHADOWLINK_MAX_ORPHANED` or 16 | Orphaned relays per client |
| `-migrate-max-orphaned-total` | int | `SHADOWLINK_MAX_ORPHANED_TOTAL` or 1024 | Global orphan ceiling |
| `-decoy-snapshot-paths` | string | `index.html` | Comma-separated decoy HTML paths pre-baked for rate-limit responses |
| `-decoy-snapshot-strict` | bool | true | Fail startup if a snapshot path cannot be baked |
| `-gen-key` | bool | false | Print a fresh keypair and exit |
| `-validate-config` | string | `""` | Parse a YAML config, print `OK`, exit — no server starts |

Subcommand: `shadowlink-server export-client-config -config … -domain …`
(`cmd/shadowlink-server/export.go:18`) with `-port`, `-ws`, `-auto`, `-cdn`,
`-format` (`yaml`\|`url`\|`both`), `-output`, `-name`.

### 7.2 Server YAML — root keys (`server/fileconfig.go:31`)

| Key | Type | Default | Effect | Status |
|---|---|---|---|---|
| `listen` | string | `:443` | Listen address | VERIFIED |
| `cert` / `key` | string | — | TLS files | VERIFIED |
| `server_key` | string | — | Static key file. Supports `${ENV_VAR}` expansion (`fileconfig.go:319`) | VERIFIED |
| `decoy` | string | — | Decoy directory | VERIFIED |
| `domain_decoy_map` | map | nil | Per-Host decoy. Two accepted shapes: legacy `host: /dir`, and `host: {directory, persona}`. The two cannot coexist in one file | VERIFIED |
| `max_clients` | int | **500** (`server/config.go:288`) | Concurrent sessions | VERIFIED |
| `max_conns` | int | **8** | Per-client connections | VERIFIED |
| `chunk_size` | int | **12288** | Chunk payload cap | VERIFIED |
| `session_timeout_sec` | int | **90** | Idle session timeout. Values `≤ 0` are ignored — `0` would mean sessions never expire | VERIFIED |
| `cleanup_interval_sec` | int | **10** | Sweep period. `≤ 0` ignored — it would busy-loop the sweeper | VERIFIED |
| `behind_proxy` | bool | false | Trust XFF | VERIFIED |
| `trusted_proxies` | []string | nil | CIDRs / bare IPs of reverse-proxy hops for the XFF walk. Loopback is always implicitly trusted, so nginx-on-localhost needs no entries. Env override: `SHADOWLINK_TRUSTED_PROXIES` | VERIFIED |
| `block_domains` | []string | nil | Domain suffixes the server refuses to dial | VERIFIED |
| `authorized_clients` | []string | nil | Allowed client IDs; empty = open mode | VERIFIED |
| `origin_death_teardown` | bool | nil → **off** | Bug #10 gate; CLI flag wins | VERIFIED |
| `fingerprint_weights` | map[string]int | nil → chrome 100 % | Relative browser-profile weights embedded in ServerHello. ⚠ Weights must mirror the real regional browser population — an unrealistic proportion is itself the anomaly | VERIFIED |
| `idle_timeout_sec` | int | — | **Validated to `[60,600]`, then ignored.** The HTTP `IdleTimeout` stays at its 300 s hardcode. Startup logs `idle_timeout_wired=false` | **NO-EFFECT** |
| `server_header` | string | — | Accepted, never emitted. Startup logs `server_header_wired=false` | **NO-EFFECT** |

### 7.3 `management:` (`server/fileconfig.go:131`)

| Key | Type | Default | Effect |
|---|---|---|---|
| `port` | int | 0 = disabled | Management API port |
| `bind` | string | `127.0.0.1` | Bind address |
| `key` | string | `""` | API key; supports `${ENV_VAR}` expansion |
| `default_max_devices` | int | 3 | Device limit per user |

### 7.4 `mimicry:` (`server/fileconfig.go:145`) — one key of six is wired

| Key | Type | Validated range | Wired? | Status |
|---|---|---|---|---|
| `inflation` | bool | — | **yes** → `Config.UseInflatedResponses`, default **true** (`fileconfig.go:415`) | VERIFIED |
| `cover_traffic` | bool | not validated | **no** | **NO-EFFECT** — §8.6 |
| `ws_pool_size` | int | `[1,8]` | no; logged `ws_pool_size_wired=false` | NO-EFFECT |
| `decoy_get_interval_burst_ms` | int | `[100,1000]` | no | NO-EFFECT |
| `decoy_get_interval_quiet_sec` | int | `[15,300]` | no | NO-EFFECT |
| `preamble_count_min` | int | `[1,5]` | no | NO-EFFECT |
| `preamble_count_max` | int | `[3,15]`, `≥ min` | no | NO-EFFECT |

Range violations are **fail-fast**: `LoadConfigFile` returns an error naming
the field and the observed value, and the server does not start. That is true
even for the keys that are then ignored — a config can be rejected for an
out-of-range value in a knob that does nothing.

### 7.5 `rate_limit:` (`server/fileconfig.go:114`, defaults in `server/handler.go`)

| Key | Type | Default | Effect |
|---|---|---|---|
| `ws_upgrade.burst` | int | 18 | WS-upgrade bucket burst |
| `ws_upgrade.refill_per_min` | int | 30 | WS-upgrade refill |
| `handshake.burst` | int | 50 | Handshake bucket burst |
| `handshake.refill_per_min` | int | 300 | Handshake refill |
| `client_id_lru_size` | int | 10000 | LRU of recently seen authenticated clientIDs |
| `client_id_ttl_min` | int | 60 | Per-clientID exemption TTL, minutes |
| `client_id_soft_limit` | int | 60 | Per-clientID soft cap per window |
| `client_id_soft_window_sec` | int | 60 | Sliding window for the soft limit |
| `client_id_data_bytes_per_sec` | int | 52428800 (50 MiB/s) | Per-clientID byte ceiling on the exempt data path. **Negative = unlimited** |

Splitting the buckets is deliberate: a WS-pool reconnect cascade must not
starve a live session's data POSTs.

### 7.6 Server environment variables

| Variable | Type | Default | Effect | Source |
|---|---|---|---|---|
| `SHADOWLINK_RL_TOKENBUCKET` | bool | **on** | `0/false/no/off` reverts to the legacy rate-limit path | `server/ratelimiters.go:13` |
| `SHADOWLINK_RL_CLIENTID_EXEMPT` | bool | **on** | Disables the ClientID exemption fast path | `server/ratelimiters.go:26` |
| `SHADOWLINK_TRUSTED_PROXIES` | CSV | unset | Overrides the YAML `trusted_proxies` when non-empty. Parsed once at handler construction; an invalid entry falls back to loopback-only trust with a WARN | `server/handler.go:295` |
| `SHADOWLINK_MIGRATE_GRACE` | duration or bare seconds | 8 s | Seeds the `-migrate-grace` flag default | `cmd/shadowlink-server/main.go:108` |
| `SHADOWLINK_MAX_ORPHANED` | int > 0 | 16 | Seeds `-migrate-max-orphaned` | `main.go:110` |
| `SHADOWLINK_MAX_ORPHANED_TOTAL` | int > 0 | 1024 | Seeds `-migrate-max-orphaned-total` | `main.go:112` |
| *(any)* `${VAR}` in YAML | string | — | `server_key` and `management.key` expand a whole-value `${VAR}` reference; an unset var logs a WARN and leaves the literal | `server/fileconfig.go:319` |

The server-side duration parser is more lenient than the client's: it accepts
both `8s` and a bare `8` (seconds), and rejects non-positive values.

### 7.7 A variable that does not exist

`SHADOWLINK_BYTE_BUDGET_MIN_INTERVAL` is named in a code comment at
`client/ws_pool.go:1158` as the way to tune `byteBudgetMinRotationInterval`.
**No code reads it.** The only writer of `WSPoolConfig.ByteBudgetMinInterval`
is the fallback at `client/ws_pool.go:2248`, which assigns the constant. Setting
this variable does nothing. Status: **NO-EFFECT** — the constant is in §1.2.

---

## 8. Traps

Each of these was verified in the source for this document. They are listed
because each one has a plausible-but-wrong reading.

### 8.1 `cdn` is legacy, and the name lies about the mechanism

Setting `cdn` *without* `sni` and *without* `origin` does not merely add a
layer — it **changes the transport**. At `engine/engine.go:424`:

```go
viaCFDefault := slCfg.CDN != "" && slCfg.Origin == "" && slCfg.SNI == ""
forceWSPool  := os.Getenv("NIXAVPN_FORCE_WS_POOL") == "1"
usePool      := (...) && (!viaCFDefault || forceWSPool)
```

With `viaCFDefault` true the WS pool is skipped entirely and the client logs
`viaCF: using SplitHTTP (TSPU-immune fresh-TCP-per-POST)` (`:429`). The
SplitHTTP fallback then only engages when `system_vpn` is also set
(`:691`); otherwise the client drops to a single WS, and on failure to a poll
mode with 20 ms tickers.

Production is **direct to a bare origin IP** — hard rule 1. `cdn` is retained
for URL-format compatibility, not as a supported mode. If you have set it and
did not intend a transport change, remove it or pair it with `sni`/`origin`.

### 8.2 Three settings that are parsed and then thrown away

- **`socks:` in client YAML** — overwritten unconditionally by a random port
  (§2.1). Use `-socks`.
- **`socks=` in an `sl://` URL** — `client.ParseSLURL` fills
  `ClientFileConfig.Socks` (`slurl.go:89`), but the CLI's mapper
  `parseSLURL` (`cmd/nixavpn-client/config.go:132-145`) does not copy it, and
  `ParseImportURL` hardcodes `SOCKS: "127.0.0.1:1080"` (`config.go:181`) —
  which §2.1 then overwrites anyway.
- **`id=` in an `sl://` URL** — same path: parsed into
  `ClientFileConfig.ClientID`, not copied by the CLI mapper. The CLI generates
  a fresh UUID per connect. (The mobile facade *does* support a persistent
  client ID, via `Config.ClientIDHex` — a different code path.)

### 8.3 `ws_pool` and `ws_pool_size` are YAML-only

Both exist in `engine.ShadowLinkConfig` with YAML tags, and neither appears in
`ParseSLURL` or `BuildSLURL` (`client/slurl.go`). A config imported from an
`sl://` link therefore always takes the engine defaults: pool enabled via
`websocket`/`system_vpn`, size 8. To set them you need a YAML file.

### 8.4 `SHADOWLINK_DATAPATH_BODYPREFIX` now has a config field above it

`defaultDataPathBodyPrefix` is a **package variable** initialised from the env
at `client/datapath.go:31`. Since the addition of
`ClientConfig.DataPathBodyPrefix *bool` (`client/client.go:290`), the effective
value is resolved per transport by `resolveDataPathBodyPrefix`
(`client/datapath.go:57`):

**field (`*bool`, when non-nil) → package default (env) → `true`.**

The snapshot is taken at transport construction (`client/client.go:328`), so
changing the env after start has no effect on an existing transport. Guard:
`TestClientConfig_DataPathBodyPrefix_OverridesEnvDefault`.

### 8.5 `SHADOWLINK_DNS_STUB_IPS` is read before `main()`

```go
var knownStubIPs = buildStubIPSet(os.Getenv(stubIPsEnvVar))
```

`client/dnsproxy/stub.go:29` — a **package-level variable initialiser**. It runs
during package init, before any config file is read and before `main` starts.
Consequences:

- it can only be set in the process environment, never from YAML or a URL;
- setting it later in the process (e.g. `os.Setenv` from your own code) has no
  effect;
- the value is *appended* to the built-in list, never replaces it.

### 8.6 `mimicry.cover_traffic` is ignored more quietly than its neighbours

`MimicryConfig.CoverTraffic` (`server/fileconfig.go:146`) is parsed and then
referenced nowhere outside its own declaration — not in `ApplyTo`, not in
validation, and — unlike `ws_pool_size`, `idle_timeout_sec` and the rest — not
even in the `logMimicryConfig` "wired=false" startup notice
(`cmd/shadowlink-server/main.go:386-408`). An operator who sets it gets no
signal at all that it does nothing.

The client-side cover traffic that does exist is a different thing entirely:
`DirectTransport.startCoverTraffic` (`client/transport.go:265`), driven by
`Shaper.CoverTrafficRatio` (`skins/browser/shaping.go:16`), not by server YAML.

### 8.7 `SHADOWLINK_DRAIN_IDLE_STREAMS_MAX` reaches the struct and dies there

The value travels all the way: env → `engine/engine.go:579` →
`WSPoolConfig.DrainIdleStreamsMax` → `poolSlot.drainIdleStreamsMax`
(`client/ws_pool.go:2335`). Nothing ever reads that field — only comments
mention it. Setting the variable produces a one-time deprecation WARN and no
behavioural change. To disable the idle gate, use
`SHADOWLINK_DRAIN_IDLE_THRESHOLD=0`.

### 8.8 Silent fallbacks on bad values

`envBoolDefault` returns the **default** for an unrecognised string, and
`envDurationDefault` / `envIntDefault` / `envFloatDefault` do the same for
unparseable input (`engine/engine.go:1072-1128`). So
`SHADOWLINK_GRACEFUL_DRAIN=flase` silently leaves graceful drain **on**. The
one place that warns about an unrecognised value is
`SHADOWLINK_SPLIT_DNS` (`cmd/nixavpn-client/main.go:815-818`). Verify with the
startup log lines, not with the assumption that a typo would have failed loudly.

---

## 9. Examples

### 9.1 Minimal client YAML — full-direct, the production shape

```yaml
protocol: shadowlink
shadowlink:
  server: "203.0.113.10:443"     # bare origin IP — placeholder
  sni: "example.com"             # TLS ServerName
  pubkey: "0000000000000000000000000000000000000000000000000000000000000000"
  tls: true
  websocket: true
```

`ws_pool` is not required here: `websocket: true` already enters the WS block,
and `ws_pool_size` defaults to 8.

### 9.2 Annotated client YAML

```yaml
protocol: shadowlink            # auto | shadowlink | vless
system_vpn: false               # true = TUN + LeakGuard (needs admin/root)
# socks: "127.0.0.1:1080"       # NO-EFFECT (§8.2) — use -socks on the CLI

shadowlink:
  server: "203.0.113.10:443"    # host:port; production = bare origin IP
  sni:    "example.com"         # TLS ServerName for the IP above
  pubkey: "0000000000000000000000000000000000000000000000000000000000000000"
  tls:       true
  websocket: true               # gates the WS transport block
  ws_pool:      true            # explicit; implied by websocket in practice
  ws_pool_size: 8               # default 8 — do not change without §1

  # Alternative endpoints tried when the primary handshake fails.
  # Must share the same X25519 pubkey.
  backup_servers:
    - "203.0.113.11:443"

  routing:
    bypass:                     # merged ON TOP of the built-in CIS list (§3.5)
      - "*.local"
      - "*.internal"
    force:                      # always through the tunnel
      - "*.example.org"
    block:                      # refused outright
      - "ads.example"

api:                            # optional: fetch config from the panel instead
  url:   "https://panel.example.com"
  token: "REPLACE_ME"
```

### 9.3 Server YAML

```yaml
listen: "127.0.0.1:10443"       # nginx terminates TLS in front (hard rule 4)
server_key: "${SHADOWLINK_SERVER_KEY_FILE}"   # ${VAR} expansion is supported
decoy: "/var/www/decoy"

max_clients: 500
max_conns:   8
chunk_size:  12288              # keep below the 16 KB TSPU threshold

session_timeout_sec:  90        # 0/negative is ignored, not "never expire"
cleanup_interval_sec: 10

behind_proxy: true
trusted_proxies:                # loopback is always trusted; usually empty
  - "10.0.0.0/8"

management:
  port: 9443
  bind: "127.0.0.1"
  key:  "${SHADOWLINK_MGMT_KEY}"
  default_max_devices: 3

rate_limit:
  handshake:  { burst: 50, refill_per_min: 300 }
  ws_upgrade: { burst: 18, refill_per_min: 30 }
  client_id_lru_size: 10000

mimicry:
  inflation: true               # the ONLY wired key in this section (§7.4)

fingerprint_weights:            # must mirror the real regional population
  chrome: 100
  firefox: 0
```

Validate before restarting anything:

```bash
shadowlink-server -validate-config /etc/shadowlink/config.yaml
```

### 9.4 Import from a URL

```bash
nixavpn-client -import "sl://0000000000000000000000000000000000000000000000000000000000000000@203.0.113.10:443?tls=1&ws=1&auto=1&sni=example.com"
```

Remember §8.3: an imported config cannot carry `ws_pool_size`. If you need a
non-default pool size, import once, write the YAML, and edit it.

### 9.5 Running with environment overrides

```bash
# Emergency: roll back population FP mimicry and the PQ ClientHello path
SHADOWLINK_FP_POOL=0 SHADOWLINK_TLS_PQ=0 \
  nixavpn-client -config nixavpn.yaml -log=debug -log-file=run.log

# Bisection: is the bug in graceful drain?
SHADOWLINK_GRACEFUL_DRAIN=0 nixavpn-client -config nixavpn.yaml

# Server: disable the ClientID rate-limit exemption fast path
SHADOWLINK_RL_CLIENTID_EXEMPT=0 \
  shadowlink-server -config /etc/shadowlink/config.yaml
```

Field runs should write to a file (`-log-file`) or at least run with console
QuickEdit disabled: an accidental mouse selection in a Windows console has
blocked output for 428 s and stopped the whole rotation loop, producing
connection ages of 505 s. The censor does not care why the process stalled.

---

## 10. Cross-references

- `CLAUDE.md` — hard rules; rule 1 (no CDN / domain fronting), rule 2 (no FP
  randomisation), rule 8 (timing constants)
- `.claude/skills/anti-tspu-tuning` — the threat model the rotation constants
  come from, and how to read the hazard/exposure counters
- `docs/integration/mobile-sdk.md` — the `mobile/` facade: `Config` fields,
  callback contract, what the platform must implement
- `docs/operations/server-install.md` — nginx, systemd, key provisioning
- `docs/protocols/flow-control-v2.md` — the window negotiation behind
  `SHADOWLINK_FLOW_WINDOW` and `-flow-max-window`
- `docs/PHASES-CHANGELOG.md` — why a given default is what it is
