# Final Audit — Master Findings Sheet

**Date:** 2026-05-03
**Baseline sha:** 7c8e99d6 (pl1 / datacanvases.com, deployed 2026-05-03)
**Tracks consolidated:** T1 (architecture+crypto), T2 (transport+DPI), T3 (server+integration), T4 (quality+drift), T5 (web research 2026-05)
**Track outputs:** see sibling `T1-…md` … `T5-…md`.

---

## Executive Summary

### Findings counts (rolled up)

| Severity | T1 | T2 | T3 | T4 | T5 | **Total** |
|---|---:|---:|---:|---:|---:|---:|
| **P0** | 0 | 1 | 1 | 0 | 2 | **4** |
| **P1** | 2 | 4 | 4 | 2 | 2 | **14** |
| **P2** | 4 | 4 | 5 | 5 | 1 | **19** |
| **P3** | 3 | 2 | 4 | 7 | 0 | **16** |
| **REGRESSION** | 0 | 1 | 0 | 0 | — | **1** |

### Headline takeaways

1. **Crypto core (X25519 ECDH → HKDF-SHA256 → AES-256-GCM) is solid.** Все апрельские/майские closures держатся: T1.4 body-prefix migration, Phase 2 PQ cold-path symmetry, A1-M1..M4 replay/clientID, C11.2/C11.3 atomic publish, C14 strict 16-byte clientID, replay-cache encClientID-keyed (после фикса 2026-04-30). 9 baseline spot-checks — 0 регрессий в T1 file scope.
2. **Один P0 — REGRESSION** (T2): F3/NEW-1 jittered keepalive дотянулся до 5 client-side call-sites, но **не до server-side тикеров** в `server/websocket.go:419` (20s WS PING) и `server/handler.go:1043` (25s SplitHTTP keepalive). Wire-trigger followup memo от 2026-05-02 утверждает закрытие; реально landed только client. FFT spike детектируется на любой ≥60s idle session. Mechanical fix.
3. **Один P0 — operational blocker** (T3): `RotateAppSecret` (`internal/admin/shadowlink_token_rotation.go:53`) ссылается на колонку `cf_api_token_enc`, которой нет в production-схеме (миграция 072 создала `cf_api_token`). Тесты используют sqlite shim с другим именем — drift не ловится. **Документированный workflow ротации `APP_ENCRYPTION_KEY` сломан с первого вызова.** До фикса админу запрещено жать кнопку «Rotate Encryption Key».
4. **Два P0 — strategic / competitive** (T5): (a) единый wire-shape across всех ShadowLink-серверов + hardcoded :443 — AmneziaWG 2.0 ranged-headers concept покрывает per-server diversification, у нас нет; (b) ProxyCorr (Computer Networks Oct 2025) делает flow correlation устойчиво к size padding — наш T2.4/A2-HIGH-5 padding не закрывает этот вектор, нужны *поведенческие* контр-сигналы (browsing simulation bursts, XHTTP-style upload/download split).
5. **Самые опасные P1 группы:**
   - **Wire/DPI** (T2): JitteredInterval uniform не log-normal; Chrome 133 cohort outlier vs реальная популяция Chrome 138+; PQ keyshare asymmetry между cold-path uTLS и hot-path bogdanfinn внутри одной сессии; persona mismatch Mixpanel-warmup vs generic-SPA decoy_traffic.
   - **Admin/integration** (T3): shell-injection через `source_dir` в decoy template handler; WS CONNECT dial goroutine с `context.Background()` не bound к WS session done; `DisableLiveBlog` DB-vs-SSH inconsistency window; `DeleteShadowLinkPoolDomain` гонка с in-flight orchestrator.
   - **Crypto** (T1): timing-oracle между success-handshake и failClosedToDecoy (CPU asymmetry ~150-200µs); latent shared-slice race в `pqClientHelloSpec`.
6. **Quality drift низкий.** WB TURN полностью убран, Bearer auth retired, ConnManager lifecycle race закрыт. 2 P1 quality (test gap + stale comment), без P0. Frontend имеет 3 orphan refs на `enable_udp` (backend-side cleaned), целая dead подсистема `cmd/shadowlink-client/` + `client/dnsrouter/` (~600 LOC superseded by `cmd/nixavpn-client/` + `client/bypassroute/`).
7. **Strategic gap (T5):** competitor движение быстрее наших циклов аудита. AmneziaWG 2.0 (релиз 2026-03-25) интегрирован в Windscribe и Nym; VLESS Encryption (PR #5067) добавляет ML-KEM-768 + 0-RTT внутри VLESS payload (не только TLS); AnyTLS амортизирует handshakes через session-ticket reuse. Geedge leak (Sep 2025, 572 GiB GFW source) — wave of academic papers Q3+ ожидается.

### Verified-still-closed (consolidated highlights)

- **T1.4 body-prefix migration default-on**, Phase A bearer retired, WS first-frame auth working
- **Phase 2 PQ ClientHello + cold-path symmetry** через `pqEnabled()` mirror
- **A1-M1..M4 / C11.2 / C11.3 / C14** все hold — replay cache на encClientID, sendEpoch atomic-pointer rekey, MimicrySession publish-before-map, strict 16-byte clientID decode-side
- **B1 nginx flock + atomic rollback**, **A2 X-SL-RL sentinel**, **A3-S/I-HIGH-1..5** admin auditMiddleware + validators, **A4-M2/M5** deployingTimestamps eviction + idempotent closeTunnel
- **C2 ClientID exemption (LRU 10k, TTL 1h, soft-cap 60/min)** wired в handshake escape hatch + data-path bypass без soft-cap (X1 Stage 2)
- **C9 RunDone mirror + C10 M2 newborn-orphan + C5 ackJitter reshape**
- **WB TURN полностью удалён** из admin/deploy (Bash grep zero matches), Bearer auth удалён (`findSession`, `ExtractSessionToken` deleted)
- **Phase 0 source-guard cleanup** — только 2 источник-guards остались
- **No `panic()` in production hot-path**, **no error-swallowing patterns** в production code

---

## Master Findings Sheet

### P0 (4 findings)

| ID | Track | Title | File:Line | Why-it-matters | Effort |
|---|---|---|---|---|---|
| **P0-1** | T2 | **REGRESSION** Server-side fixed-period tickers leak FFT spike | `shadowlink/server/websocket.go:419`, `shadowlink/server/handler.go:1043` | Periodic 20s/25s comb pattern detectable by autocorrelation/FFT at flow-table scale (TSPU 2.27 B ₽ ML-DPI line). Real CF Edge keeps WS alive via TCP-layer keepalive; app-layer hand-coded ticker = giveaway. F3/NEW-1 closure landed client-only. | 1-2 hrs (port `JitteredInterval` to `core/jitter.go`, patch 2 server sites, add ACF regression test) |
| **P0-2** | T3 | `RotateAppSecret` targets non-existent column `cf_api_token_enc` | `internal/admin/shadowlink_token_rotation.go:53`; migration 072 created `cf_api_token` | Документированный `APP_ENCRYPTION_KEY` rotation workflow выдаёт SQL ошибку при первом вызове. Operator может удалить `APP_ENCRYPTION_KEY_PREVIOUS` post-failure → все CF tokens un-decryptable. Tests use sqlite shim with column name матчащим code → bug invisible под `go test`. | 5 min (rename code reference to `cf_api_token` + update sqlite shim в тестах + add startup invariant probe) |
| **P0-3** | T5 | Hardcoded `:443` + единый wire-shape across all servers | `shadowlink/server/server.go`, `shadowlink/server/config.go`, `shadowlink/client/transport.go`; AmneziaWG 2.0 reference [1][2] | Habr 990236 показывает: TSPU «too lazy» делать deep-inspection всех портов — фокус на 443. Все ShadowLink инстансы share одинаковый WS endpoint pool (12 paths), JSON envelope, binary frame layout `[hint(4) || token(32) || chunk]`, Mixpanel-mimic responses. **Один universal DPI rule срабатывает на ВСЕ инстансы.** AmneziaWG 2.0 ranged-headers (H1-H4) per-server demonstrates the fix. | Multi-week. (a) per-server alternate port via admin config + client; (b) per-server URL pool hash from domain; (c) per-server randomized 1-4-byte magic prefix on chunk header. |
| **P0-4** | T5 | Cover GET retired, but ProxyCorr correlates flows even с padding | `shadowlink/skins/browser/cover.go`, `shadowlink/client/decoy_traffic.go`; ProxyCorr [27] | Self-attention spatio-temporal модель (Computer Networks Oct 2025) accurate **across diverse encrypted proxy protocols, robust under random size padding**. Прямо бьёт A2-HIGH-5 / T2.4 / C6 padding. Habr 1009542: WS-Upgrade-then-bidirectional pattern detectable wire-pattern signature, separate from content padding. | Multi-week. (a) browsing simulation bursts (heavy-tail, 5-30 min) — 5-15 GETs к decoy с varying paths/timings, mimics real tab navigation; (b) XHTTP-style upload/download split (separate domains) breaks ProxyCorr's state-transition assumption; (c) cross-layer RTT jitter в burst boundaries (Xue NDSS'25). |

### P1 (14 findings)

| ID | Track | Title | File:Line | Why-it-matters |
|---|---|---|---|---|
| **P1-1** | T1 | Asymmetric ScalarMult cost timing oracle (success vs failClosedToDecoy) | `server/decoy_timing.go:143-170` vs `server/handler.go:494-531` | На fail-decoy 1× X25519 ScalarMult, на success 3×. Дельта ~150-200µs. ackJitter median ≈5ms маскирует median-to-median, но stationary observer на CDN edge per-IP histogram'ом видит distribution shift в нижнем тейле. **Application-aware indistinguishability concern**, не break confidentiality. |
| **P1-2** | T1 | `pqClientHelloSpec` mutates shared Extension slice (latent race) | `client/utls_http.go:42-77` | utls v1.8.3 returns Extension pointers from shared package descriptor table. `append`-to-front на shared slice = race UB. Currently dormant (hasMLKEM short-circuits in Chrome_133), но утls upstream bump может silently активировать. Fix: defensive deep-copy spec + extension structs. |
| **P1-3** | T2 | JitteredInterval uniform, не log-normal | `client/jitter.go:32` | Real network jitter heavy-tailed; uniform даёт boxy distribution с sharp band edges, KS-test против log-normal reference reject H0. Mirror existing `SessionLifecycle.NextActiveInterval` shape. |
| **P1-4** | T2 | Chrome 133 cohort outlier vs реальная Chrome population (138-141) | `skins/browser/fingerprint.go:37` `LockedChromeMajor=133` | Real Chrome stable May 2026 ≈ Chrome 138-141. Long-tail Chrome 133 ≤ 2%. ALL ShadowLink Chrome-fingerprint sessions emit Chrome/133. **Cohort detection per-AS** при ML scoring "Chrome major distribution per source IP" — выделяет нас как outlier-cohort. |
| **P1-5** | T2 | PQ keyshare asymmetry в одной session/IP (cold-path emits MLKEM, hot-path не emits) | `client/connmanager.go:267-289`, `client/split_transport_tls.go:65-90` | Cold-path uTLS dialer emits `X25519MLKEM768`; bogdanfinn hot-path emits stock Chrome_133 без MLKEM. Same IP, same session, two key_share contents. JA4 cross-flow consistency check на `(client_IP, server_IP, time_window)` ловит. |
| **P1-6** | T2 | Cover GET / data POST persona mismatch (Mixpanel SDK vs generic SPA) | `skins/browser/cover.go:28-35` (`/decide`, `/lib.min.js`) vs `client/decoy_traffic.go:78-93` (`/`, `/about`, `/privacy`) | Real-world сайт не имеет одновременно Mixpanel SDK endpoints AND `/about`+`/privacy`. Persona mismatch per-session, passive heuristic. |
| **P1-7** | T3 | `installDecoyTemplate` shell injection через `source_dir` | `internal/admin/shadowlink_pool_decoy_templates_handlers.go:32-46`, `internal/deploy/steps_shadowlink_domain.go:121-137` | `source_dir` принимается без validation, interpolated в `mkdir -p %s && rsync …`. Sister parameter `templateName` validated regex'ом — асимметрия. RCE на pool server. Threat: super_admin (already trusted), но bypass audit-log review (внимание concentrated на `name`, не `source_dir`). |
| **P1-8** | T3 | WS CONNECT dial goroutine не bound к `runWebSocketSession.done` | `server/websocket.go:498-580`, dial at line 522 with `context.Background()` | Под cold-start cascade conditions (8-slot reconnect storm) каждый rejected upgrade может оставить dial goroutine ~10s past WS close. ~60 dial-goroutines per client per minute leaks + FD count. Не correctness break, observability/resource. Mirror `handler.go:1227-1233` POST CONNECT pattern. |
| **P1-9** | T3 | `DisableLiveBlog` writes DB перед `lockServer` → DB↔SSH inconsistency window | `internal/admin/shadowlink_handlers.go:1889-1942` | Two operators racing `DisableLiveBlog`: оба passing DB UPDATE без lock, A spawns goroutine, B gets 409 — **B already committed DB UPDATE без SSH apply.** Drift на минуты до convergence. Fix: lockServer → re-read cfg → UPDATE → spawn goroutine under lock. |
| **P1-10** | T3 | `DeleteShadowLinkPoolDomain` не gated против in-flight `provisionDomain` | `internal/admin/shadowlink_pool_domains_handlers.go:102-159` vs `shadowlink_domain_provision.go:286-343` | DELETE landing inside steps 8-11 critical section: `listDomains` уже evaluated до DELETE → orchestrator pushes nginx config с deleted domain; `setStatus(active)` no-op; nginx + CF + DB diverge до next provision/probe sweep. Self-heals, но logs DONE despite drift. |
| **P1-11** | T4 | `streamWriteTimeout` doc-comment stale (says 150ms ackJitter cap, actually 1500ms post-C5) | `server/handler.go:1018-1026` | After May audit §C5 reshape, ackJitter hard ceiling = 1500ms (Pareto right-tail). 60s budget still dwarfs (40× margin), но invariant comment lies. Risk: future refactor читает comment, shrinks timeout to 1s "as cleanup" → silently breaks. CLAUDE.md updated, comment не updated. |
| **P1-12** | T4 | `internal/admin/shadowlink_pool_models.go` undertested | model layer (~16/19 funcs) | Только SSH-portion covered. Domain Diversity sub-phase A-D model layer без unit-тестов на NULL handling, status enum, timestamps, decoy_template_id NULL round-trip. Future migration drift catches at integration boundary, не unit. |
| **P1-13** | T5 | Universal padding отсутствует на binary frame headers | `skins/browser/padding.go`, `server/websocket.go::authenticateFirstFrame` (parser hardcodes 4-byte hint + 32-byte token offsets) | Каждый WS frame `[hint(4) || token(32) || encrypted_chunk]`. First 36 bytes constant-shape. Encrypted chunk has T2.4 padding, но frame structure deterministic. AmneziaWG 2.0 universal-padding (S1..S4 0..32/64 byte prefix on ALL message types). Fix: `[pad(0-32) || hint || token || chunk]` + length-byte prefix. |
| **P1-14** | T5 | JA4 cluster density vs Chrome 133 — JA4DB CatBoost AUC 0.998 trained on real population | `skins/browser/fingerprint.go::LockedChromeMajor=133` | uTLS lacks Chrome_135+. Real Chrome population already 138+. CatBoost trained on JA4DB sees Chrome_133 в low-density cluster → bot likelihood. Akamai's 31.01.2026 PQ baseline cements this. Workaround: custom ClientHelloSpec для Chrome 138 (как делаем для PQ MLKEM сейчас) или PR в utls upstream. |

### P2 (19 findings) — concise list

| ID | Track | Title | File:Line |
|---|---|---|---|
| P2-1 | T1 | Bypass admin override HMAC scope omits `etag` (rollback / freshness oracle) | `client/bypassroute/admin_fetch.go:85-99` |
| P2-2 | T1 | `ServerHello` UA validation permissive — compromised server может re-fingerprint client fleet | `server/handler.go:1854-1881`, `client/client.go:423-435` |
| P2-3 | T1 | Newborn-orphan eviction holds full write lock (DoS amplification под attack volume) | `core/session.go:554-581` |
| P2-4 | T1 | `serverHelloJSON.UA` map keys not bounded to fixed enum | `client/client.go:422-435` |
| P2-5 | T2 | ✅ CLOSED 2026-05-05 — covered by P1-3 log-normal sampler. Both `coverTimer` (5s) and `resetTimer` (30s) now use `JitteredIntervalLogNormal(_, 0.5)`; FFT secondary line at 30s lag eliminated by heavy-tailed truncated [15s, 60s] distribution. Doc-comment in `client/transport.go::startCoverTraffic` records the closure. | `client/transport.go:199` |
| P2-6 | T2 | ✅ CLOSED 2026-05-05 — `eventTypePool` expanded from 6 → 17 unique events with weighted distribution (page_view 30%, session_* 20%, click_* 25%, long-tail 25%). 100-element pre-rolled slice for O(1) lookup. Tests: `TestRandomEventType_PoolWellFormed`, `TestRandomEventType_DistributionSpread` (chi-square > 100, family ratios within ±30%), `TestRandomEventType_NoLegacyEntries`. | `skins/browser/request.go:429-485` |
| P2-7 | T2 | `ackJitter` calibration admitted-best-guess, не measured against real CDN ACK distribution | `server/handler.go:243-285` |
| P2-8 | T2 | Padding constants admitted-placeholder (`SamplePaddingTarget`, `SampleHandshakePaddingTarget`) | `skins/browser/padding.go:8-67` |
| P2-9 | T3 | `handleDataChunk` holds `stream.mu` across blocking `TargetConn.Write` | `server/handler.go:786-812` |
| P2-10 | T3 | `runDeployingEvictor` без defer-recover — single panic kills TTL safety net | `internal/admin/shadowlink_handlers.go:122-133` |
| P2-11 | T3 | `probeFailCounter` orphan-entry leak after domain delete | `internal/admin/shadowlink_pool_probe_scheduler.go:39-58` |
| P2-12 | T3 | `runOnce` probe sweep single-threaded — sustained timeouts саturate interval | `internal/admin/shadowlink_pool_probe_scheduler.go:94-115` |
| P2-13 | T3 | `live_blog` canary loop uses `context.Background()` для upstream fetch logging | `shadowlink/server/live_blog_canary.go:156` |
| P2-14 | T4 | Frontend orphan `enable_udp` (3 файла) | `frontend/src/types/shadowlink.ts:16`, `pages/ShadowLinkPage.tsx:33`, `api/shadowlink.ts:19` |
| P2-15 | T4 | Whole `cmd/shadowlink-client/` + `client/dnsrouter/` package effectively dead (~600 LOC) | `shadowlink/cmd/shadowlink-client/` + `shadowlink/client/dnsrouter/` |
| P2-16 | T4 | `IsCoverTraffic` deprecated stub — нет external callers, module-internal | `skins/browser/request.go:406-412` |
| P2-17 | T4 | `NewURLPoolCustom` only called from tests | `skins/browser/urls.go:42-54` |
| P2-18 | T4 | `cmd/shadowlink-client/` 2s cold-start delay never updated to phased warmup | `cmd/shadowlink-client/main.go:373` |
| P2-19 | T5 | Per-WS-slot handshake amortization gap (8 handshakes за короткий window vs AnyTLS session reuse) | `client/ws_pool.go`, `client/ws_ready_pool.go` |

### P3 (16 findings) — listed in source files

См. T1 §"P3", T2 §"P3", T3 §"P3", T4 §"P3" для полного списка. Briefly:
- Crypto hygiene (T1 P3): `rand.Read` error ignored в `NewSessionManager`; 300s wall-clock window без monotonic guard; `EncryptedClientIDSize=65` forward-compat hazard.
- Transport hygiene (T2 P3): `defaultDecoyPaths` weighted-by-duplication даёт flat plateau вместо Zipf; wsURLPool 12 entries on one domain — нереалистично для real site.
- Admin (T3 P3): re-encryption churn в `RotateAppSecret`; aggregate eviction count не logged; `runApplyLiveBlog` без re-validate `cfg.Domain`.
- Quality drift (T4 P3): `encodeServerHello` doc-comment ссылается на retired Bearer path; `Deprecated bool` JSON field always-false; `wbturn: true` orphan в `shadowlink/config.yaml:8`; dangling close-paren в `migration_e2e_test.go:51`; constants scattered across files.

---

## Regressions

### REGRESSION-1 — F3/NEW-1 jitter closure didn't reach server (P0-1 above)

**Documented closed in:** `shadowlink/docs/audit/2026-05-02-wire-trigger-followup.md` (NEW-1, NEW-4)
**Now broken at:** `server/websocket.go:419`, `server/handler.go:1043`
**Root cause hypothesis:** plan scope was implicitly client-only (memo never names server files). Audit-trail discipline gap — spec/plan should have listed all `time.NewTicker` call sites.
**Fix complexity:** mechanical (port `JitteredInterval` to `core/jitter.go`, patch 2 server tickers, add tests).

**No other regressions detected** в T1, T3, T4 file scopes. Все baseline closures held at sha 7c8e99d6.

---

## Verified-Still-Closed (consolidated)

| Closure | Track verified by | Status |
|---|---|---|
| **T1.1 PQ ClientHello + cold-path symmetry** | T1, T2 | Hold (caveat: P1-5 keyshare asymmetry между cold/hot path is post-closure phenomenon, не break of original closure) |
| **T1.4 body-prefix migration default-on** | T1 | Hold |
| **T1.6 Cover GET retired + Warmup kept** | T2 | Hold (caveat: P0-4 ProxyCorr concern is *new*, не reopens old closure) |
| **T1.7 BroadcastStreamClose errgroup** | T2 | Hold |
| **A1 backoff overflow clamp + slotBackoffDuration slow-start** | T1 | Hold |
| **A1-M2 sendEpoch atomic-pointer rekey** | T1 | Hold |
| **A1-M3/M4 plaintext zero + clientID strict (decode-side)** | T1 | Hold |
| **A2-HIGH-5 handshake/data padding split (KS D=0.3710)** | T2 | Hold |
| **A2-HIGH-7 padding distribution decouple** | T2 | Hold |
| **A2-MED-7 failClosedToDecoy timing variance (<2ms std-dev)** | T2 | Hold (caveat: P1-1 ScalarMult cost asymmetry is *new* finding outside variance bound) |
| **A2-MED-6 gorilla 400 → decoy 200** | T2 | Hold |
| **A2-MED-10 meltdown jitter (rate-limit + severity gate)** | T2 | Hold (verified by-test, not by-source — spot check next round) |
| **A3-S-HIGH-1 Content-Type discriminator** | T3 | Hold |
| **A3-S-HIGH-2 WSAttached CAS gate** | T3 | Hold |
| **A3-S-HIGH-3 dialCtx bound to tunnel.done (POST CONNECT path only)** | T3 | Hold (caveat: WS path missing — see P1-8) |
| **A3-I-HIGH-1..5 admin auditMiddleware + validators + applyMutex + findShadowLinkBinary** | T3 | Hold |
| **A3-I-MED-6 MigrateToYAML transaction wrap** | T3 | Hold |
| **A4-M2/M5 deployingTimestamps eviction + idempotent closeTunnel** | T3 | Hold |
| **B1 nginx race lock (flock + atomic backup/restore + nginx -t)** | T3 | Hold |
| **C2 ClientID exemption (LRU 10k, TTL 1h, soft-cap 60/min)** | T3 | Hold (X1 Stage 2 data-path soft-cap removal confirmed) |
| **C5 ackJitter reshape (no 150ms point-mass)** | T2 | Hold (caveat: P2-7 calibration deferred) |
| **C9 mirror RunDone server-side** | T3 | Hold |
| **C10 M2 newborn-orphan 30s eviction** | T1, T3 | Hold (caveat: P2-3 DoS amplification under adversarial volume — closure design correct against legit-fail single-orphan case) |
| **C11.2 SetStatsCallbacks atomic publish** | T1 | Hold |
| **C11.3 MimicrySession publish-before-map** | T1 | Hold |
| **C11.1 ConnManager lifecycle race source-guard** | T4 | Hold |
| **C14 strict 16-byte clientID decode** | T1 | Hold |
| **HKDF protoVersion bind (downgrade attack closed)** | T1 | Hold |
| **Replay cache key = encClientID ciphertext** | T1 | Hold (post 2026-04-30 data-plane drift fix) |
| **Token cipher v1 (AES-256-GCM with v1. prefix)** | T1 | Hold |
| **WB TURN fully removed (Go side)** | T4 | Hold (frontend orphan: P2-14) |
| **Bearer auth retired (`findSession`, `ExtractSessionToken` deleted)** | T4 | Hold |
| **`mergeOrRegenerateKeys` extracted as helper (Phase 1 P1)** | T4 | Hold |
| **Phase 0 source-guard cleanup** | T4 | Hold (only 2 source-guards remain — `TestConnManagerLifecycle_DocsImmutable`, `TestPaddingDeferredCalibration_DocComment`) |

---

## Competitive Matrix vs Reality / Vision / Hysteria2 / TrustTunnel / AmneziaWG 2.0 / AnyTLS / VLESS Encryption

(Колонки: ✅ ShadowLink имеет; ⚠ partial / behind; ❌ отсутствует; — irrelevant)

| Capability | ShadowLink | VLESS+Reality | XTLS-Vision | Hysteria2 | TrustTunnel | **AmneziaWG 2.0** | AnyTLS | VLESS Encryption (PR#5067) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **TLS 1.3 modernity** | ✅ uTLS Chrome_133 | ✅ proxies real upstream cert | ✅ | ✅ | ✅ | — (UDP/WG-based) | ✅ uTLS | ✅ |
| **PQ ClientHello (X25519MLKEM768)** | ✅ via uTLS Chrome_133 | ✅ | ✅ | ⚠ TLS-level only | ⚠ | ❌ | ✅ | ✅ |
| **PQ inside payload (post-decryption forward secrecy)** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ ML-KEM-768 hybrid |
| **PQ signature (mldsa65 auth)** | ❌ | ✅ optional | ⚠ | ❌ | ❌ | ❌ | ❌ | ✅ |
| **JA3/JA4 mimicry (locked browser fingerprint)** | ⚠ Chrome 133 (population is 138+) | ✅ proxies upstream | ✅ | ⚠ | ⚠ | — (not TLS-based) | ✅ | ✅ |
| **GREASE injection** | ✅ (via uTLS) | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ |
| **Application-layer realism (decoy site)** | ✅ live decoy + Mixpanel-mimic | ⚠ static page upstream | ❌ | ❌ | ⚠ | — | ⚠ HTTP fallback | ❌ |
| **Body-content steganography (JSON envelope)** | ✅ Mixpanel/GA4-mimic | ❌ random ciphertext | ❌ | ❌ | ❌ | — | ❌ | ✅ TLSv1.3 record header pattern |
| **Per-server wire diversification** | ❌ единый shape | ⚠ only via different upstream targets | ⚠ | ⚠ randomized port-hopping | ⚠ | ✅ ranged headers H1-H4 + CPS | ⚠ | ❌ |
| **Universal padding на ALL message types** | ⚠ payload only, headers fixed | ❌ | ❌ | ⚠ Salamander obfs random bytes | ⚠ | ✅ S1..S4 prefixes 0-32/64 | ✅ DSL config | ✅ alternating padding.delay |
| **Pre-handshake noise / signature packets** | ⚠ Warmup deterministic 1-4 GETs | ❌ | ❌ | ❌ | ❌ | ✅ Jc series randomized count | ❌ | ❌ |
| **Session ticket reuse / handshake amortization** | ❌ per-slot independent (8 handshakes/window) | ⚠ | ⚠ | ✅ QUIC 0-RTT | ✅ | — (UDP, no TLS) | ✅ idle session multiplexing | ✅ 0-RTT |
| **Replay protection** | ✅ encClientID 5min sliding window | ✅ | ✅ | ✅ | ✅ | ✅ MAC | ✅ | ✅ 0-RTT replay protection |
| **Multi-domain pool / failover** | ✅ Sub-phase B-D Domain Diversity | ❌ | ❌ | ⚠ | ⚠ | ❌ | ❌ | ❌ |
| **System VPN mode (TUN, kill-switch, DNS leak protection)** | ✅ tun2socks + LeakGuard | ❌ (proxy-only) | ❌ | ⚠ | ⚠ | ✅ kernel module | ❌ | ❌ |
| **Bypass routing (.ru CIDR-trie)** | ✅ in-process trie + dialer hook | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Rate limiter (TokenBucket + ClientID exemption)** | ✅ may-audit closure | ❌ | ❌ | ⚠ basic | ⚠ | ❌ | ❌ | ❌ |
| **Live decoy (real-content proxy)** | ✅ T1.3 habr-mirror | ❌ | ❌ | ❌ | ❌ | — | ❌ | ❌ |
| **Behavioral counter to flow correlation (ProxyCorr-class)** | ❌ statistical padding only | ❌ | ❌ | ⚠ BBR variants | ⚠ | ⚠ Jc + universal padding helps but not tested vs ProxyCorr | ⚠ DSL timing schedule | ❌ |
| **QUIC-based transport** | — TCP-based by design | — | — | ✅ | ✅ | — UDP-based | — | — |
| **Russia field status 2026-05** | ✅ working на pl1 | ⚠ port 443 trigger; high port works | ⚠ being policed (bbs#546) | ❌ QUIC blocked | ❌ QUIC blocked | ✅ "successfully bypasses" per testers | ⚠ emerging | ⚠ early adoption |

### Where ShadowLink leads (✅ unique advantages)

1. **Body-content steganography + live decoy** — никто из competition не делает Mixpanel/GA4 envelope mimicry. SS-2022 / VMess-AEAD = random bytes (entropy-fingerprintable). Reality = upstream cert mimicry, but ciphertext random. Long-term defensive posture: encryption-only protocols (random bytes) considered «dead» per Habr 2026.
2. **Multi-domain pool + bypass routing** — Sub-phase B-D Domain Diversity + `.ru` CIDR-trie unique to ShadowLink. Direct competitor to "many small domains" tactic but built-in.
3. **System VPN mode** — TUN + kill-switch + DNS leak protection встроенные. Reality/Vision/AnyTLS — proxy-only, требует internal-routed app или внешний tun2socks.
4. **Live decoy (T1.3)** — real-content habr proxy at `/blog/*`. Active probe от TSPU видит legitimate-looking content при URL inspection. AmneziaWG 2.0 не имеет HTTP-layer decoy (UDP-based).
5. **Token cipher rotation infrastructure** — `APP_ENCRYPTION_KEY` rotation workflow с migration support (after P0-2 fix).

### Parity / partial-coverage zones

1. **TLS modernity** — parity with Reality/AnyTLS на JA3/JA4 (now both at HelloChrome_133+). PQ ClientHello — parity (we do it via uTLS).
2. **Replay protection** — parity (5-min sliding window encClientID).
3. **Rate limiting** — лидируем благодаря TokenBucket + ClientID exemption + LRU cache; competitors имеют basic IP-based.

### Where ShadowLink lags (❌)

1. **Per-server wire diversification (P0-3)** — AmneziaWG 2.0 ranged-headers + CPS demonstrates the technique. У нас все инстансы share один shape.
2. **Universal padding на ВСЕХ message types (P1-13)** — AmneziaWG 2.0 S1..S4 covers ALL packets. У нас только payload-level, frame structure fixed.
3. **Pre-handshake noise** — AWG 2.0 Jc series randomized count. У нас Warmup deterministic 1-4 GETs.
4. **Session ticket reuse / handshake amortization (P2-19)** — AnyTLS idle session multiplexing reduces per-window handshake density. WS pool 8 handshakes / start window — anomaly.
5. **PQ inside payload (post-decryption PFS)** — VLESS Encryption (PR #5067) uses ML-KEM-768 hybrid + 0-RTT inside payload. Concept-level superior to TLS-only PQ.
6. **PQ signature (auth)** — Reality добавил mldsa65 verification callback. У нас auth via session-key MAC, без quantum-resistant signature.
7. **Behavioral counter-signal to ProxyCorr (P0-4)** — статистический padding не работает против self-attention spatio-temporal модели. AmneziaWG 2.0 Jc + universal padding partially mitigate, but ShadowLink не имеет equivalent.

### Strategic implication

ShadowLink unique-edge — **application-layer realism** (live decoy + Mixpanel envelope + multi-domain pool + system VPN mode + bypass routing) — остаётся defensible. **Slipping behind** на (a) per-server diversification и (b) behavioral-correlation defense. P0-3/P0-4 вместе закроют critical strategic gaps; P1-13/P1-14/P2-19 — smaller wedge fixes.

---

## Recommended Plan-of-Record (Phase 4 sketch)

Группировка по effort buckets и dependencies. Не impl plan — sketch, к которому надо написать full spec.

### Bucket A — Quick wins (1 session, ~1-2 days total)

| ID | Task | Effort | Depends on |
|---|---|---|---|
| P0-2 | Rename `cf_api_token_enc` → `cf_api_token` в `rotateColumns` + sqlite shim | 5 min | — |
| P0-1 | Port `JitteredInterval` to `core/jitter.go`, patch server WS PING + SplitHTTP keepalive, add ACF regression test | 1-2 hr | — |
| P1-11 | Update `streamWriteTimeout` doc-comment (150ms → 1500ms ackJitter cap) | 1 line | — |
| P3 (T4) | Delete `wbturn: true` orphan в `config.yaml:8` | 5 sec | — |
| P3 (T4) | Trim `migration_e2e_test.go:51` dangling paren | 5 sec | — |
| P2-16 | Delete `IsCoverTraffic` deprecated stub | 1 line | — |
| P2-7→P3 | Add startup invariant probe для `rotateColumns` (column existence check, fail-fast) | 30 min | P0-2 |

### Bucket B — Crypto + transport hardening (1-2 sessions)

| ID | Task | Effort |
|---|---|---|
| P1-2 | Defensive deep-copy в `pqClientHelloSpec` (spec.Extensions + extension structs) | 1-2 hr + tests |
| P1-1 | Add ScalarMult cost matching to `runSyntheticDispatch` (2× GenerateKeyPair + 1× box.Open-equivalent) | 2-3 hr + benchmark |
| P1-3 | Convert `JitteredInterval` to log-normal cadence (keep uniform для one-shot delays) | 3-4 hr + KS-test |
| P1-5 | PQ posture decision: bogdanfinn-MLKEM patch upstream OR flip `SHADOWLINK_TLS_PQ=0` default-off OR doc-only acceptance | 1-3 days depending on path |
| P2-1 | Add `etag` to bypass admin override HMAC scope (server-side mirror) | 2 hr + acceptance test |
| P2-2 | Tighten `isValidUA` — pin to `LockedChromeMajor` + key enum validation | 1 hr |
| P2-3 | Two-phase newborn-orphan eviction (RLock collect → per-session write lock zero) | 2 hr + load test |

### Bucket C — Admin + integration (1-2 sessions)

| ID | Task | Effort |
|---|---|---|
| P1-7 | Add `sourceDirRe` validator + reject в `CreateShadowLinkPoolDecoyTemplate` and `InstallDecoyTemplate` | 1-2 hr + retro-scan existing rows |
| P1-8 | Bind WS dial-goroutine to `runWebSocketSession.done` (mirror POST CONNECT pattern) | 2-3 hr + leak test |
| P1-9 | Restructure `DisableLiveBlog` ordering: lockServer → re-read → UPDATE → goroutine | 2-3 hr + concurrency test |
| P1-10 | DELETE handler acquires `acquireServerProvisionLock` before DB delete | 1 hr |
| P2-9 | Copy `TargetConn` pointer under lock, release, then Write — drop lock-during-IO | 30 min |
| P2-10 | defer-recover wrapper + auto-restart в `runDeployingEvictor` | 30 min |
| P2-11 | Event-driven `probeFailCounter` cleanup в `DeleteShadowLinkPoolDomain` | 30 min |
| P2-12 | `errgroup.SetLimit(8)` parallelize в `runOnce` probe sweep | 1 hr + load test |

### Bucket D — Quality + drift cleanup (1 session)

| ID | Task | Effort |
|---|---|---|
| P2-14 | Strip `enable_udp` из 3 frontend файлов + form UI | 30 min |
| P2-15 | Retire decision: `cmd/shadowlink-client/` + `client/dnsrouter/` (~600 LOC) — preferred: delete | 30 min if delete |
| P2-17 | Delete `NewURLPoolCustom` + replace test, OR wire it (server-pushed paths in handshake) | 30 min |
| P3 (T1/T4) | `Deprecated` JSON field removal + doc-comment rewrite в `encodeServerHello` | 30 min + client backwards-compat verification |
| P1-12 | Add `shadowlink_pool_models_test.go` for non-SSH model code | 4-6 hr |

### Bucket E — Strategic / multi-week roadmap (Phase 4 candidates)

| ID | Task | Effort |
|---|---|---|
| **P0-3** | Per-server wire diversification: alternate ports + per-server URL pool hash + per-server randomized magic prefix | **2-4 weeks** (spec + impl + admin UI + client config plumbing + canary deploy) |
| **P0-4** | Behavioral counter-signal layer: heavy-tail browsing simulation bursts + XHTTP-style upload/download split + cross-layer RTT jitter | **3-5 weeks** (architecture + spec + multi-stage rollout) |
| **P1-13** | Universal padding на binary frame headers (`[pad(0-32) || hint || token || chunk]` + length byte) | **1-2 weeks** (wire-format change, requires migration plan symmetric с T1.4 body-prefix) |
| **P1-14** | Custom ClientHelloSpec для Chrome 138/146 (manual MLKEM injection mirror, новые extensions order, новые ALPS) | **2-3 weeks** (research + impl + JA4 fixture pinning + field test); или PR в utls upstream + ждать v1.9 release |
| **P2-19** | Session ticket reuse manager + idle session multiplexing (AnyTLS-style amortization) | **2-3 weeks** (TLS session ticket cache в `ConnManager`, replay-window coordination с WS first-frame auth) |
| **P2-7 / P2-8** | Phase 5/S5 schema lock: capture 10k POST→ACK latencies + Mixpanel /track size distribution через CF Edge to datacanvases.com, refit ackJitter + padding constants | **1-2 days capture + 1 week analysis + refit** |

### Suggested ordering

1. **Immediate (this week):** Bucket A (P0-1 + P0-2 + small P3 cleanups)
2. **Next session:** Bucket B (crypto/transport hardening — fast tactical wins)
3. **Subsequent session:** Bucket C (admin/integration P1s)
4. **Cleanup session:** Bucket D (quality drift — schedule when context permits)
5. **Phase 4 spec + execution:** Bucket E — start с P0-3 (per-server diversification) since it's the largest competitive gap; queue P0-4 (behavioral defense) parallel в исследовательском треке

---

## Open Questions (consolidated, deduplicated)

Из tracks:

1. **(T1)** Schema preference for P0-2 fix: rename code reference vs migration 078 `cf_api_token` → `cf_api_token_enc`. Preferred: rename code (zero migration risk).
2. **(T1)** WS dial-goroutine bound (P1-8): customer-impact telemetry under cold-start cascade — есть ли field signal или это purely defence-in-depth?
3. **(T1)** Decoy template `source_dir` validation: should `is_dynamic=true` templates use different regex (live-decoy seed без `/`-prefix)?
4. **(T2)** Real Chrome major distribution per ISP — does May-2026 RF ML-DPI infrastructure actually compute "Chrome major distribution per source IP/AS"? P1-4 severity dependent.
5. **(T2)** JA4 with PQ — does JA4 algorithm count keyshare *content* or only group IDs? Affects P1-5 detectability.
6. **(T2)** utls upstream HelloChrome_146 timeline — tracked PR? If merged within 60 days, P1-4 self-resolves.
7. **(T2)** Real CDN ACK latency reference — does CF publish per-region POST→ACK p50/p99 для cached static GETs? Affects P2-7 effort.
8. **(T2)** Server-side `JitteredInterval` placement preference — shared `core/jitter.go` (cleanest) vs duplicate per package vs testutil. Affects P0-1 effort estimate.
9. **(T3)** Probe sweep parallelism (P2-12): tune limit=8 vs limit=4? Need steady-state per-pool throughput measurement.
10. **(T3)** `probeFailCounter` cleanup point: event-driven (DELETE handler) vs periodic (set-difference в sweep)?
11. **(T4)** `cmd/shadowlink-client/` retire decision: dev/debug usage or production path fully replaced? **User decision required.**
12. **(T4)** Frontend `enable_udp` form rendering — is the toggle visible to admin user? Affects P2-14 scope (form delete vs hidden field clean).
13. **(T4)** `TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter` pin value — verify test asserts ≥1500ms (not ≥150ms) per CLAUDE.md claim.
14. **(T4)** `Deprecated` JSON field removal в `encodeServerHello` — wire-cleanliness gain (16 bytes) vs old-client backwards-compat risk?
15. **(T5)** PQ flip impact на actual MLKEM rate — `shadowlink_tls_pq_handshake_total{result="success"}` field rate? If <99%, downgrade attack signals.
16. **(T5)** Geedge leak academic timeline — InterSecLab full analysis Q3 2026. Pre-emptive defense investment in distribution-shape (not signature-specific) recommended.
17. **(T5)** VLESS Encryption (PR #5067) adoption — should we adopt PFS+0-RTT+ML-KEM-inside-payload shape? Major impl cost; monitor upstream Xray adoption first.

---

## References

- **Track outputs:** `T1-architecture-crypto.md`, `T2-transport-dpi.md`, `T3-server-integration.md`, `T4-quality-drift.md`, `T5-web-research.md`
- **Baseline strategic docs:** `shadowlink/docs/strategy/2026-04-22-strategic-assessment.md`, `2026-04-30-current-state-and-improvements.md`, `shadowlink/docs/research/2026-04-19-dpi-evasion-state-of-art.md`
- **Memory baselines:** `phase-1-debt-closure-done.md`, `phase-2-tls-modernity-done.md`, `phase-2-closure-done.md`, `may-audit-p0-done.md`, `p2-final-pack-done.md`, `bypass-and-coldstart-done.md`, `pl1-canary-2026-05-02.md`
- **Wire-trigger followup memo:** `shadowlink/docs/audit/2026-05-02-wire-trigger-followup.md` (basis for P0-1 REGRESSION classification)

---

**End of MASTER consolidation. Ready for Phase 4 spec drafting (Bucket E priorities) или immediate Bucket A execution в следующей сессии.**
