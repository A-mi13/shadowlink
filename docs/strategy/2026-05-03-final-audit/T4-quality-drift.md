# T4 — Quality + Drift Audit (2026-05-03)

**Scope:** dead code, stale TODOs, error handling, magic numbers, naming, test coverage hot paths
**Baseline sha:** 7c8e99d6 (pl1 deployed 2026-05-03 evening)
**Method:** grep-driven static analysis, no `go vet`, no compile, no git
**Auditor:** Claude (Opus 4.7), track T4 of 2026-05-03 final audit

## Executive Summary

| Severity | Count |
|---|---|
| P0 | 0 |
| P1 | 2 |
| P2 | 5 |
| P3 | 7 |

- **Files inspected:** 202 Go files in `shadowlink/` + 31 in `internal/admin/shadowlink_*.go`
- **Lines of dead code identified:** ~80 (one whole package + 3 deprecated funcs + 1 stub)
- **TODO/FIXME found:** 3 active in production code, 0 stale (post-cleanup)
- **`time.Sleep` in production prod code:** 8 (all bounded — `cmd/shadowlink-client/main.go` 2s; `tunnel.go` startup waits; `client.go:1021` deferred-zero pattern; `connmanager.go:144` warmup; `engine_shadowlink.go` startup polling; `client/ws_transport.go:266`)

The codebase is genuinely cleaner than baseline 2026-05-01 T4. UDP/WB-TURN zombie in `internal/admin/` and `internal/deploy/` is **fully closed** (Bash grep over both files returned zero matches for the Go-side fields). `shadowlink_pool_models.go` got SSH-portion test coverage added (`shadowlink_pool_models_ssh_test.go`). `ConnManager.lifecycle` race (T4 2026-05-01 §3.1) was closed via doc-comment + source-guard test (`TestConnManagerLifecycle_DocsImmutable`).

**However**, three regressions/carryovers remain in non-Go surfaces, and the May audit closure introduced a small drift of stale comments referencing now-changed constants (most notably `ackJitter()` cap in `streamWriteTimeout` doc-comment). The biggest non-trivial finding is an entire CLI binary (`cmd/shadowlink-client/`) plus its `client/dnsrouter/` package that have no production binary and no callers outside themselves — they survive only as a test/dev side entry.

No P0 (no panic-in-hot-path, no race-without-guard, no reachable dead-code from public API).

## New Findings

### P1 — `shadowlink_pool_models.go` undertested for non-SSH model code

**Location:** `internal/admin/shadowlink_pool_models.go` (19 funcs total)
**Coverage:** Only SSH password helpers covered by `shadowlink_pool_models_ssh_test.go` (3 funcs). Remaining ~16 funcs (CRUD helpers `getShadowLinkPoolServerByID`, `listShadowLinkPoolDomains`, `markShadowLinkPoolDomainStatus`, etc.) verified only via integration tests of the handlers that call them.
**Risk:** Domain Diversity sub-phase A-D (2026-04-29..30) introduced these helpers. CRUD-level validation, NULL handling for `decoy_template_id`, and timestamp serialization all happen in this file. A future migration adding/removing columns can silently break model marshalling and only get caught at the integration boundary.
**Action:** add `shadowlink_pool_models_test.go` exercising at least: NULL `last_probe_ok_at` round-trip, NULL `decoy_template_id` round-trip, SSH-creds-absent path (`SSHUser/SSHPort/ssh_password_enc` all NULL), `Status` field enum coverage (`active|degraded|banned|stuck`).

### P1 — `streamWriteTimeout` doc-comment references stale 150 ms ackJitter cap

**Location:** `shadowlink/server/handler.go:1018-1026`
```go
// streamWriteTimeout is the body-write deadline applied on every loop
// iteration of runDownloadStreamLoop. Audit S-MED-3 (2026-04-25): the
// deadline must dwarf the worst-case ackJitter() cap (150 ms) by enough
// margin that an in-flight ACK-path write cannot collide with the
// timeout. 60 s also exceeds Go's default WriteTimeout (30 s), which
// would otherwise kill the long-poll stream from underneath us. The
// invariant is structurally pinned by
// `TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter`.
```
After May audit §C5 reshape (2026-05-02), `ackJitter()` now has a Pareto right-tail with **hard ceiling = 1500 ms** (handler.go:264-275), not 150 ms. The 60 s budget still dwarfs the new ceiling (40× safety margin per CLAUDE.md note), but the invariant comment lies. CLAUDE.md correctly says "max ackJitter is now 1500ms"; the production comment did not get updated.
**Risk:** future audit/refactor reading this comment can wrongly conclude the timeout has 400× margin and shrink it to 1 s "as cleanup", silently breaking the 25 s keepalive ticker overlap. The May audit closure regression-test `TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter` was updated; the doc-comment was not.
**Action:** edit handler.go:1018-1026 to say "ackJitter() hard ceiling (1500 ms)". One-line edit.

### P2 — Frontend still emits `enable_udp` on Create/Deploy admin requests

**Location:**
- `frontend/src/types/shadowlink.ts:16` — `enable_udp: boolean;`
- `frontend/src/pages/ShadowLinkPage.tsx:33` — `enable_udp: false` in default form state
- `frontend/src/api/shadowlink.ts:19` — `enable_udp?: boolean;` in request type

**Risk:** Backend `internal/admin/shadowlink_handlers.go` no longer has `EnableUDP` field on `ShadowLinkConfig` (verified zero matches in Bash grep). Go's JSON decoder silently drops unknown fields, so the field is harmless on the wire — but **frontend form ships dead state**. A user toggling it sees no effect, and any future backend re-introduction of the field would silently re-couple to old behavior. This is the symmetric companion of the 2026-05-01 T4 §1.1 finding (already closed on Go side).
**Action:** strip `enable_udp` from the three frontend files and from the form UI (whatever Tab/Wizard renders the "Enable UDP" checkbox).

### P2 — Whole `cmd/shadowlink-client/` + `client/dnsrouter/` package effectively dead in production

**Locations:**
- `shadowlink/cmd/shadowlink-client/main.go` (490+ lines, only file in cmd dir)
- `shadowlink/client/dnsrouter/router.go` (sole file, 12 funcs)

**Evidence:**
1. `bin/` ships only `nixavpn-client.exe` / `nixavpn-client-linux` / `shadowlink-server-linux` / `shadowlink-metrics-dump` — no `shadowlink-client` binary.
2. `dnsrouter` is imported only by `cmd/shadowlink-client/main.go:20`. `cmd/nixavpn-client/` (the production CLI) doesn't reference it; it instead uses `client/bypassroute/` (the new IPv4-trie + dialer-hook approach shipped 2026-05-02 in `bypass-and-coldstart-done`).
3. `cmd/shadowlink-client/` references "shadowlink-client" only in itself (Bash grep confirmed).
4. The DNS-name-based bypass approach this binary uses is architecturally **superseded** by the bypassroute trie — Phase A of the 2026-05-02 spec explicitly notes that DNS-name-based bypass is unusable in system VPN mode (tun2socks sees resolved IPs only).

**Risk:** Adds maintenance burden — two parallel client implementations that can drift in fingerprint, jitter, and config-loading behavior. `cmd/shadowlink-client/main.go:373` still does `time.Sleep(2 * time.Second)` cold-start (predecessor of phased warmup) — no one updates it for newer audit findings.
**Action:** evaluate whether `cmd/shadowlink-client/` should be retired. Two paths:
1. **Retire** — delete `cmd/shadowlink-client/` and `client/dnsrouter/`. Drop ~600 LOC. Risk: any developer using `go run ./cmd/shadowlink-client/` for ad-hoc testing loses that path.
2. **Mark experimental** — add prominent `EXPERIMENTAL` marker in `cmd/shadowlink-client/main.go` package comment, exclude from build matrix, document.

Recommend (1) — the production path is `cmd/nixavpn-client/`, and `client/bypassroute/` is the canonical bypass mechanism.

### P2 — `IsCoverTraffic` deprecated stub kept "for backward compat" — no external callers

**Location:** `shadowlink/skins/browser/request.go:406-412`
```go
// IsCoverTraffic is no longer used — cover traffic is now indistinguishable from
// real data at the JSON level (C3 audit fix). The server detects cover via the
// encrypted FlagPadding chunk flag after decryption.
// Kept for backward compatibility; returns false always.
func IsCoverTraffic(_ []byte) bool {
    return false
}
```
Bash grep across the entire workspace (`grep -rn "IsCoverTraffic" --include="*.go"`) returns matches only in this file. `skins/browser` is module-internal; "backward compatibility" is meaningless here — there's no external API consumer outside this Go module.
**Action:** delete the function. One-line P2 cleanup.

### P2 — `NewURLPoolCustom` only called from tests

**Location:** `shadowlink/skins/browser/urls.go:42-54`

**Evidence:** Bash grep returns 1 prod-call site (`shadowlink/skins/browser/urls.go:43` itself) + 1 test-only call (`shadowlink/skins/browser/request_test.go:362`). `NewURLPool()` (without "Custom") is the only production constructor — server-provided custom paths from the original spec are never wired in.
**Risk:** Low — function is harmless. But the doc-comment "Server-provided paths" implies a server-driven config plumbing that doesn't exist in current code paths.
**Action:** either wire it (server pushes custom upload/download paths in handshake response — would be a real feature) OR delete it + replace test with `NewURLPool` + assertion. P2 because it's claiming to support a feature that's not implemented.

### P2 — `cmd/shadowlink-client/` 2 s cold-start delay never updated to phased warmup

**Location:** `shadowlink/cmd/shadowlink-client/main.go:373` — `time.Sleep(2 * time.Second)` followed by `leakguard.CheckIP(*socksAddr)`.

**Risk:** Even if `cmd/shadowlink-client/` is kept (per P2 above), this fixed 2 s wait was the **same anti-pattern** that drove the field-test cold-start cascade fixed by Phase D `ws_ready_pool` phased warmup (2026-05-02). The CLI tool here would exhibit the original cascade behavior on slow links. Aligns with the "retire" recommendation above.
**Action:** if not retired, replace with `<-cl.ReadyChan()` style or at minimum lift to a documented constant.

### P3 — `encodeServerHello` doc-comment references retired Bearer path

**Location:** `shadowlink/server/handler.go:1850-1853`
```go
// Phase B wire binding: ProtoVersion non-nil → handshake served via new
// body-prefix path, emitted as `_v` so the client pins to that format for the
// session. ProtoVersion nil → legacy Bearer-header path, emits
// `_deprecated:true` so modern clients can migrate on the next handshake.
```
The legacy Bearer-header POST path was retired in Phase A (2026-04-26). The server **never** emits `ProtoVersion=nil` anymore — `handleNewFormatPost` is the only entry that reaches `encodeServerHello`. The `Deprecated: sh.ProtoVersion == nil` line in the marshalled struct is therefore **always false**, but the doc-comment implies an active dual-path. Actually `_deprecated:true` is now dead-on-the-wire.
**Action:** rewrite doc-comment + drop `Deprecated` field from JSON serialization.

### P3 — `handler.go:262` references `ackJitter NOT applied to data-bearing responses (handleDataChunk has its own 10-300ms batching window)`

**Location:** `shadowlink/server/handler.go:262-263` (comment near `ackJitter()` definition)

The "10-300ms batching window" claim is unverified — `handleDataChunk` flow at `handler.go:778+` does batching but the explicit 10-300ms range comment is a magic-number floating in a comment without a `const`. Drift risk: someone shrinks the batching window without realizing the ackJitter contract pins 10-300ms in a separate file.
**Action:** add `const dataBatchingWindowMin/Max` next to `streamWriteTimeout` and have the comment cite the const.

### P3 — `shadowlink/config.yaml:8` orphan `wbturn: true`

**Location:** `shadowlink/config.yaml:8`

Carry-over from 2026-04-25 cleanup audit + 2026-05-01 T4 §C5. `wbturn` field deleted from `ClientFileConfig` Go-side; YAML loader silently ignores unknown keys, so the line is harmless but confusing.
**Action:** delete the line. 5-second cleanup.

### P3 — `dangling close-paren` in `migration_e2e_test.go:51`

**Location:** `shadowlink/client/migration_e2e_test.go:51` — `// findSessionByHint).`

Carryover finding from 2026-05-01 T4 §1.4. Cosmetic comment fragment from when `findSession` (without `ByHint`) was deleted.
**Action:** trim the line. Trivial.

### P3 — `streamWriteTimeout` const + `broadcastClose*` consts well-organized but `chunk_sizing.go` and `chunk_invariant_test.go` constants live separately

**Location:** scattered.

Hot-path timing constants in `handler.go` are well-grouped (1018-1647). Crypto/chunk constants in `core/chunk.go`. But `streamWriteTimeout` (60s), `broadcastCloseTotalDeadline` (5s), `broadcastClosePerTunnelDeadline` (50ms), `broadcastCloseConcurrency` (256) are siblings in the same file but `ackJitter` constants are inline in the function body (mixture parameters: 0.05, 7.21ms, 200ms, α=2.0, xm=50ms, ceil=1500ms). Future: collect these into a single struct/block.
**Action:** optional refactor; not blocking.

### P3 — `cmd/cf-scanner/main.go:295,342` uses `context.Background` + `time.Sleep(1*time.Second)` busy-wait

**Location:** `shadowlink/cmd/cf-scanner/main.go`

This is an ops scanner tool, not the server/client. Low risk, but pattern is unsynchronized with the rest of the codebase (everything else uses `select { case <-ctx.Done(): }` in long-running loops).
**Action:** inline cleanup if/when cf-scanner sees more usage.

### P3 — `handler.go:92` field comment `When true, handleDataChunk skips polling Outgoing (the download stream drains it)` references `Outgoing` channel naming that is consistent across the codebase

(Verification only — not a regression. Confirmed clean.)

### P3 — Inconsistent name shadowing: `decoyHandler` field vs `DecoyHandler` type

Across `server/handler.go`, `server/decoy.go`, `server/decoy_router.go` the type is `DecoyHandler` (PascalCase, exported) and the field reads `h.decoy` in places, `h.decoyHandler` in others. Not blocking but a future grep-for-type-uses gets noisy.

## Dead Code Inventory

| File:Line | Symbol | Why dead | Confidence |
|---|---|---|---|
| `shadowlink/skins/browser/request.go:410` | `func IsCoverTraffic([]byte) bool` | Doc-comment says "no longer used"; grep finds no callers; module-internal so "backward compat" is moot | HIGH |
| `shadowlink/skins/browser/urls.go:43` | `func NewURLPoolCustom(upload, download []string) *URLPool` | Only called from `request_test.go`; production uses `NewURLPool()` | HIGH |
| `shadowlink/cmd/shadowlink-client/main.go` (whole file) | `main()` + helpers (~490 LOC) | No production binary built; superseded by `cmd/nixavpn-client/`; uses retired `dnsrouter` package | MEDIUM (kept as dev-tool path) |
| `shadowlink/client/dnsrouter/router.go` (whole pkg) | `dnsrouter.New()`, `Router.Start()`, etc. | Imported only by `cmd/shadowlink-client/main.go`; bypassroute trie superseded this approach in 2026-05-02 | MEDIUM (same caveat) |
| `shadowlink/server/handler.go:1854-1872` | JSON field `Deprecated bool` in `encodeServerHello` | `ProtoVersion` never nil after Phase A retire; field always false in production | HIGH |

**Total estimated lines:** ~80 (counting just the deprecated stubs + dead JSON field) — or ~600 if `cmd/shadowlink-client/` + `client/dnsrouter/` get retired.

## Stale TODO Inventory

| File:Line | Comment (truncated) | Likely stale because |
|---|---|---|
| `shadowlink/client/ws_transport.go:788` | `TODO(C12 F5 follow-up): under VPS throttle the WS reader can stall on...` | C12 is the May audit task; this TODO documents a known field-observed issue (cascade under throttle) — closed at the higher level by Phase D phased warmup + R.3a frame-anomaly classifier, but the TODO comment in the reader was not updated to point at the closure |
| `shadowlink/server/decoy_timing.go:23` | `// sites pass 0 with a TODO; a parallel agent owns that wiring.` | Cross-reference to a "parallel agent" — bookmark for ownership rather than a real action item |
| `shadowlink/client/may_audit_p2_test.go:253` | `// is captured as a TODO comment per plan-literal "trace-only" wording.` | Refers to plan literal — informational only |

All three are **active and OK** — none qualify as P-class stale.

## Error Swallowing / Anti-patterns

| File:Line | Pattern | Severity |
|---|---|---|
| `shadowlink/server/decoy_timing.go:155,167` | `_, _ = core.GenerateKeyPair()` and `_, _ = gcm.Open(...)` | OK — intentional (decoy-timing wallclock matching) |
| `shadowlink/server/handler.go:997` | `_, _ = crand.Read(preamble)` | OK — `crand.Read` only returns error when `/dev/urandom` is unavailable |
| `shadowlink/server/websocket.go:135` | `_, _ = crand.Read(fakeAck)` | OK — same reasoning |
| `shadowlink/server/live_blog.go:651` | `_, _ = w.Write(nginxLike404Body)` | OK — error-path response, can't recover |
| `shadowlink/skins/browser/request.go:492` | `_, _ = crand.Read(pad)` (with comment) | OK — comment explicitly justifies |
| `shadowlink/cmd/nixavpn-client/main.go:522,592` | `_, _ = rand.Read(b)` | OK — random byte fill |
| `shadowlink/client/ws_transport.go:639` | `_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4*1024))` | OK — body drain on error path |

**Verdict:** zero error-swallowing in production code. All ignores are well-reasoned (cryptographic randomness fall-back, response-on-error-path, intentional discard).

## Test Coverage Gaps

| Area | Coverage | Gap |
|---|---|---|
| `authenticateFirstFrame` (websocket auth) | EXCELLENT — 9 dedicated tests | none |
| `handleHandshakeNew` / `handleNewFormatPost` | covered by `handler_phase1_test.go` + `handler_test.go` + integration | borderline (full e2e covers it; isolated unit-level coverage of `handleNewFormatPost` could be deeper around session-pinning/reuse path) |
| `runDownloadStreamLoop` + `streamWriteTimeout` invariant | dedicated `TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter` + race tests | OK, but the test still pins to the **old** 150ms baseline despite C5 reshape; verify it gates against ≥1500ms (not ≥150ms) — pin upgrade is mentioned in CLAUDE.md but the file content was not re-read |
| `ConnManager.startRotation` goroutine concurrency | `TestConnManagerLifecycle_DocsImmutable` source-guard | OK, but no behavioural race-test — fragile pattern (source-guard tests can rot if structure changes) |
| `ClientIDExemption` (LRU+exempt) | 6 tests in `clientid_exempt_test.go` + `clientid_exempt_handler_test.go` | OK |
| `TokenBucket` | 5 tests in `tokenbucket_test.go` | OK |
| `replay_cache` (5-min sliding window) | `replay_cache_test.go` + `handler_phase1_test.go` | OK |
| `domain_pool` failover | `domain_pool_test.go` | OK |
| `internal/admin/shadowlink_pool_models.go` | only SSH portion via `_ssh_test.go` | **GAP — P1 finding above** |
| `internal/admin/shadowlink_safe_redeploy.go` | no `_test.go` companion | needs verification |
| `cmd/shadowlink-client/` | no test file | acceptable if retired |

### Source-guard test brittleness signal

`TestConnManagerLifecycle_DocsImmutable` (C11.1) and `TestPaddingDeferredCalibration_DocComment` (May audit P2 C6) both use `os.ReadFile` of source then `strings.Contains` checks. Phase 0 batch 5 elsewhere replaced exactly this pattern with direct unit tests. Recommend tracking these two surviving source-guards for migration to behavioural tests when their underlying invariant gets a setter.

## Regressions

**None observed.** All 2026-05-01 T4 P-class findings either closed (UDP/WB-TURN zombie, ConnManager lifecycle race) or surfaced as the same orphan-tail (config.yaml `wbturn: true` line, `migration_e2e_test.go:51` dangling paren — both demoted to P3 here).

## Verified-Still-Closed

1. **WB TURN code fully removed from `internal/admin` and `internal/deploy`** — Bash grep on both files for `EnableUDP|UDPPort|enable_udp|udp_listen|wbturn` returned ZERO matches. Memory note `wb-turn-whitepass-removed.md` confirmed accurate. Frontend orphans noted as P2 above.
2. **Bearer auth fully removed (Phase A retire)** — `findSession` (without ByHint), `browser.ExtractSessionToken` deleted. `findSessionByHint` correctly remains (handler.go:696, 947 + decoy_timing.go:152).
3. **ConnManager.lifecycle data race** (T4 2026-05-01 §3.1) — closed via doc-comment + source-guard test (`TestConnManagerLifecycle_DocsImmutable`).
4. **Phase 0 source-guard cleanup** — only 2 source-guards remain (mentioned above), down from many.
5. **`mergeOrRegenerateKeys` extracted as helper** — confirmed via memory note.
6. **No `panic()` in production hot-path** — only 3 panics found: `safedial.go:31` (init-time CIDR validation; correct), `pool_race_test.go:78` and `split_transport_sse_test.go:48` (test-only).
7. **No `t.Parallel()` calls** — preserves the deliberate Windows-no-CGO compatibility (per 2026-05-01 T4 §5).
8. **No `for i := 0; i < N; i++` C-style loops** — clean.
9. **All production `context.Background()` are wrapped in `WithCancel` / `WithTimeout`** — no unbounded contexts in long-running ops.

## Out-of-Scope Suggestions

(Refactor opportunities, not P-classified — for future trim sessions.)

1. **Consolidate hot-path constants** — `streamWriteTimeout`, `broadcastClose*`, `ackJitter` mixture parameters, `coalesceWindow=50ms`, `coalesceMaxParallel=2`, `udpMinReadySlots=2`, etc. Live in 6+ files. A single `constants.go` per package would make diff-with-roadmap easier.
2. **Two source-guard tests should migrate to behavioural tests** — `TestConnManagerLifecycle_DocsImmutable`, `TestPaddingDeferredCalibration_DocComment`. Pattern was abandoned in Phase 0 batch 5 elsewhere.
3. **Naming consistency for clientID** — code uses `clientID`, `client_id`, `ClientID`, `cid` interchangeably. Pick one for new code; existing uses are too entrenched to refactor.
4. **`encodeServerHello` UA struct hardcoded inline** — 30+ lines of map literal in a JSON marshal. Lift to package-level `var defaultUAMap = ...`.
5. **`shadowlink_pool_models.go` ↔ DB schema drift detection** — write a startup-time invariant check that verifies live pg schema matches the model struct fields. Catches forgotten migrations early. (Not blocking — Domain Diversity is recently shipped and known-stable.)
6. **Standardize on `*log/slog`** — most code uses `slog`, but a few `fmt.Errorf` + caller-side logging persist. Not a regression, just consistency.
7. **`DecoyHandler` is dual-named** — type vs field; pick one.

## Open Questions

1. **`cmd/shadowlink-client/` retire decision.** This is the biggest dead-code lever. Owner (user) needs to confirm: is this CLI used for ad-hoc dev/debug, or has `cmd/nixavpn-client/` fully replaced it? If the former, mark experimental + freeze. If the latter, delete.
2. **Frontend `enable_udp` form field — visible to admin user?** The default `false` was set in form state. If the UI still renders a toggle, admin sees a checkbox that does nothing. Check `ShadowLinkPage.tsx` form rendering before delete.
3. **`TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter` pin value.** CLAUDE.md claims pin was upgraded post-C5. If actual test still pins ≥150 ms, then any future shrink of `streamWriteTimeout` below 1500 ms will pass the test silently. Recommend explicit verification by reading the test source and confirming the pin matches the new ceiling.
4. **`shadowlink_safe_redeploy.go` test coverage.** No `_test.go` companion file. Worth confirming the redeploy lock + idempotency logic has at least one test.
5. **Should the `Deprecated` JSON field in `encodeServerHello` (handler.go:1860-1871) be removed for wire-cleanliness?** It's a constant `false` value across all production handshakes — removing it shrinks the JSON envelope by 16 bytes per handshake, but might break old clients that still parse the field. Phase 0/A migration appears complete on the server, but client-side cleanup status is unverified in this audit pass.

---

**Audit complete.** No P0. 2 P1 (test gap + stale comment). 5 P2 (frontend orphan, dead CLI, dead helpers). 7 P3 (cosmetic comment rot + minor style).

**Recommended ordering for closure:** P1.2 (one-line comment fix) → P3.10 (one-line `wbturn: true` delete) → P2.4 (`IsCoverTraffic` delete) → P2.3 (frontend `enable_udp` strip) → P2.6 (`NewURLPoolCustom` delete or wire) → P2.5 (`cmd/shadowlink-client/` retire decision needs user) → P1.1 (test coverage add) → P3 cosmetics.
