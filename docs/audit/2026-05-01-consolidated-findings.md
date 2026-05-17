# ShadowLink — Consolidated May Audit Findings (2026-05-01)

**Synthesizer:** Claude Opus 4.7 (audit-only synthesis pass).
**Inputs:** 7 track files in `D:/NIXAVPN/shadowlink/docs/audit/2026-05-01-track{1,2,3,4,5,5b,6}-*.md`.
**Baseline:** April final-review set (2026-04-25), Phase 0/1/2/3 + Domain Diversity A-D + Tier S R.1+R.3a closed.
**Scope:** dedup'нутая sumarisation существующих findings, threat-landscape deltas, competitive positioning, field-evidence cross-ref, обновлённая Tier roadmap, top-3 immediate actions.
**Out of scope:** новые findings, code changes, верификация цифр, повторные веб-исследования.

---

## 1. Executive summary

После апрельского спринта (Phase 0/1/2/3 + Domain Diversity sub-phases A-D + Tier S R.1+R.3a) ShadowLink стоит на устойчивом криптографическом основании, с **закрытыми ~9 из 14** прошлых in-scope транспортных criticals/highs (Track 2 §Comparison-with-april) и зачищенным апрельским cleanup-bag (Phase 0). Однако **поле 2026-05-01 10:44 MSK сразу выявило** два новых P0-блокера в data-plane (overflow в slot backoff, decoy-as-rate-limit ambiguity) и **landscape-research зарегистрировал 2 новых подтверждённых P0** (RU CIDR /24 whitelist практически закрепился, RU DTLS JA3/JA4 ban). Stage у нас: **defensive — ship-stable, но roadmap нужно срочно перерасставлять**, потому что Domain Diversity-D кодом готов, а в production stub'нут (SSH-bound шаги dead в orchestrator), и Phase A Bearer retire оставил незакрытым CRIT-4 (`wsURLPool=["/ws"]`).

**Топ-3 risks:** (1) F1 backoff overflow + F2 decoy-as-ratelimit — клиент storm'ит в течение секунд при первом throttle; (2) F8/CRIT-4 single-path WS pool — детектируется активным probing'ом в <10 round-trips; (3) RU CIDR /24 whitelist + DTLS ban — первая закрывает все foreign-IP origins, вторая удаляет любые DTLS/QUIC fallback идеи.

**Топ-3 wins:** (1) PQ ClientHello cold-path symmetry полностью верифицирована во всех 5 dial-sites, JA4 fixture pinned; (2) `BroadcastStreamClose` 10k-tunnel SLA <2s измерен и зелёный (F6); (3) криптографическое ядро держится — H/M-fixes базы 2026-04-25 закрыты, replay-cache sliding window, lock-free `sendEpoch`, plaintext zeroization (Track 1 closed-since-april table).

**Топ-3 actions:** (1) Tier S R.1 follow-up: clamp attempt в `slotBackoffDuration` ДО expo (Field F1) + sentinel rate-limit signal вместо decoy HTML на WS (Field F2) — оба блокеры production'а под throttle; (2) Domain Diversity SSH-pipeline wiring (Track 3 H-1) — без этого pool автоматизация — мираж, и Habr CIDR-finding промотивает C.1 в Tier S; (3) close CRIT-4 wsURLPool — server-distributed pool ≥6 plausible-shape paths (Track 2 F8), это самый большой остающийся detection signal.

---

## 2. Findings matrix (deduplicated)

Severity convention: **Critical** = blocks production / security risk. **High** = breaks UX / data corruption. **Medium** = degrades UX. **Low** = code-hygiene.

| Sev | Track | File:line | Issue | Fix direction |
|-----|-------|-----------|-------|---------------|
| **Crit** | T6 F1 | `client/ws_pool.go` slotBackoffDuration | Integer overflow при `attempt~37`: `5s × 2^N → time.Duration(MinInt64)` → `Sleep(neg)` returns instantly → reconnect storm без backoff | Clamp `attempt = min(attempt, 6)` ДО expo (`5s × 2^6 = 320s`), потом cap 60s. Или явный guard `if exp > 60s { return 60s }`. |
| **Crit** | T6 F2 | `server/handler.go` rate-limit branch (Tier S R.4 spec) | На WS upgrade при rate-limit сервер возвращает live-decoy HTML вместо явного 429 / WS close-code → клиент не отличает rate-limited / decoy / down → одинаковый exponential для всех трёх | Sentinel-сигнал внутри decoy (special header / tag) или dedicated WS close-code; клиент на rate-limit применяет longer fixed cool-down (120-300s) вместо exp |
| **Crit** | T2 F8 | `server/urls.go:16-18` (`wsURLPool=["/ws"]`) | Single WS path detected by active probe in <10 round-trips — same as April CRIT-4, **ОТКРЫТО** | Server-distributed pool ≥6 plausible-shape paths; deploy-order plan ship server-first, потом client release |
| **Crit** | T5 §5.1.1, §5.3.1 | strategy/landscape | RU CIDR /24 whitelist (Habr 1027276) + 15GB mobile cap + endpoint app VPN-detect = первая P0 закрывает single-foreign-IP origins | C.1 Domain Diversity activation **поднимается в Tier S**; исследовать domestic-ASN bunkers (Yandex Cloud / Selectel / VK Cloud) |
| **Crit** | T5 §5.1.2 | net4people #603 | RU DTLS JA3/JA4 ban (2026-03-30) подтверждает что signature-DB-driven detection мигрирует с TLS на DTLS | Не код-fix; закрывает все будущие DTLS/QUIC/WebRTC fallback идеи для РФ |
| **High** | T1 H1 | `client/ws_pool.go:1128-1159` | `handleSlotDeath` НЕ вызывает `slot.session.Destroy()` + `core.ZeroBytes(slot.token)` → AES key material leaks across every TSPU rotation / R.3a anomaly | Mirror `Close()`: добавить destroy+zero после transport close; capture prior slot в local перед overwrite `p.slots[idx]` |
| **High** | T1 H2 | `server/handler.go:1311-1340` + `core/session.go:173-196` | `findSessionByHint` верифицирует только `rk` после `Session.Rekey` → token sealed под original key → каждый authenticated request после rekey collapse в `failClosedToDecoy`. Сегодня dormant (Rekey не вызывается в production) | (a) re-seal+re-emit `EncryptedSessionToken` на Rekey, ИЛИ (b) verify против rolling pair (`rk` first, then `s.OldRecvKey()` если within grace); add `TestFindSessionByHint_AfterRekey_StillResolves` |
| **High** | T2 F1 | `client/connmanager.go:253-264` (bogdanfinn hot path) | `SHADOWLINK_TLS_PQ=0` opt-out wire-asymmetric: cold path → vanilla Chrome_133 (no MLKEM), hot path bogdanfinn Chrome_146 → MLKEM persists. JA3/JA4 mismatch within seconds. Сегодня latent | (a) Document opt-out asymmetry в CLAUDE.md, ИЛИ (b) plumb `SHADOWLINK_TLS_PQ=0` в bogdanfinn для non-MLKEM profile (Chrome_133) |
| **High** | T2 F2 | `client/ws_transport.go:201-211`, `connmanager.go:253-264`, `skins/browser/fingerprint.go:78` | uTLS Chrome_133 = Mar 2025 stale; UA Chrome 134 / uTLS 133 / bogdanfinn 146 — три разных Chrome major. JA4 db labels Chrome_133 (~0.5-2% prevalence в реале) | Bump uTLS profile когда utls upstream добавит 135+; pin UA + uTLS + bogdanfinn в один agreed Chrome major через `fingerprint_lock.go` |
| **High** | T2 F3 | `skins/browser/cover.go:14-26` | Cover GET path list — пастиш SDK телеметрии (`/sdk-config.json`, `/api/v2/feature-flags`, `/health`) — не совпадает ни с реальной Mixpanel SDK 2026, ни с GA4 | Pick **one** SDK persona (Mixpanel) и align paths; drop `/health` + `/api/v2/feature-flags` |
| **High** | T3 H-1 | `internal/admin/shadowlink_domain_provision.go:43-146`; helpers в `steps_shadowlink_domain.go:96-216` dead в production | Domain Diversity orchestrator останавливается после CF DNS; SSH-bound шаги (`InstallLECert`, `InstallDecoyTemplate`, `UploadNginxConfig`, `ReloadNginx`, `ReloadShadowLink`) вызываются ТОЛЬКО из тестов. MEMORY говорит "DONE", код говорит "manual" | Миграция 074: добавить `ssh_user/ssh_password_enc/ssh_port` в `shadowlink_pool_servers` (через `encryptToken`); расширить `provisionDomain` шагами 5-9; снять `//nolint:unused` с `getShadowLinkPoolDecoyTemplate` |
| **High** | T3 H-2 | `internal/admin/shadowlink_token_crypto.go:14-26`; `cmd/api/main.go:185-197` | `APP_ENCRYPTION_KEY` без version/rotation path/crypto-deletion strategy. Рекоммита ключа = весь pool заморожен | Hex-prefix ciphertext (`v1.<base64nonce_ct>`); env `APP_ENCRYPTION_KEY_PREVIOUS`; `/api/admin/security/rotate-encryption-key`; helper `RotateAppSecret` |
| **High** | T3 H-3 | `internal/admin/shadowlink_pool_domains_handlers.go:198-289` | `ProbeShadowLinkPoolDomain` 2xx==ok даже на CF Bot Fight challenge (200 HTML) или nginx default-decoy → false positives. `active → active` even on fail (намеренно), но без cron sweep | Probe идёт на `/_health` за CF (bearer auth) или ищет decoy-marker в body (`<title>habr</title>`); scheduler в `cmd/api/main.go` каждые N минут; degraded после M consecutive fails |
| **High** | T3 H-4 | `internal/deploy/steps_shadowlink_domain.go:167-198` (swap shell-script) | `UploadNginxConfig` swap race при concurrent invocation: T2 nginx-test fails → mv bak conf без bak → rm config → nginx без shadowlink.conf на следующем reload | Server-side `flock /var/lock/shadowlink-nginx.lock` ИЛИ `lockServer(serverID)` в `ProvisionDomainAsync`; tmp file + atomic mv с `nginx -t -c` ДО mv |
| **High** | T4 §1.1 | `internal/admin/shadowlink_handlers.go` (lines 40-41/394-395/567-569/700-733/881-894); `internal/deploy/steps_shadowlink.go` (lines 26-27/40-42/49-67/217-234) | UDP/WB-TURN zombie: `EnableUDP/UDPPort` fields + sed-patch `--enable-udp --udp-listen` всё ещё в production; flag deleted в server binary → **live Update сломает running daemon** | Удалить fields + systemd-patch sed block (carryover из 2026-04-25 cleanup audit Part A.2) |
| **High** | T6 F3 | `shadowlink/core/broadcast.go` (T1.7 errgroup); ws pool side `client/ws_pool.go` | Zombie streams живут 50+ минут с `pending=70` после cascade kill; `BroadcastStreamClose` НЕ закрывает streams когда все слоты падают (`uplink write` → `err="ws pool: no ready slots"`, но read-side не закрывается) | Audit BroadcastStreamClose triggers — должен включать "all slots dead, no ready". Force-close pending streams когда recovery > N seconds. |
| **High** | T6 F4 | client SOCKS5 connect path | Pool starvation cascade: pending=70 streams piles до восстановления одного slot'а; living slot захлёбывается, остальные 7 slot'ов попадают в decoy/rate-limit | Per-stream pre-flight: degraded pool (<2 ready) → fail-fast NEW SOCKS5 connect; bound pending size per slot; sticky assignment если single survivor |
| **Med** | T1 M1 | `server/websocket.go:606-610` | Server `runWebSocketSession` не ждёт `writer.RunDone()` перед `conn.Close()`; client делает правильно. Race → slog WARN при graceful shutdown | Mirror client pattern: `writer.Close(); <-writer.RunDone(); conn.Close()` |
| **Med** | T1 M2 + M5 | `server/handler.go:383-401, 1496-1539`; `client/ws_pool.go:402-481` | Orphan-resource theme: handshake POST успел, WS upgrade провалился → server-side session висит до cleanup loop (5 min). Под cascade — десятки orphans per client | (a) 30s timeout newborn-not-attached sessions, ИЛИ (b) client best-effort POST FIN на WS-upgrade fail (есть `core.NewStreamFinChunk`) |
| **Med** | T1 M3 | `server/handler.go:399, :236-245`; `core/mimicry_session.go:1-28` | `MimicrySession` published без happens-before edge to `buildResponse` readers — на x86 TSO works, future refactor → nil-deref в `buildResponse` | Move `MimicrySession = NewMimicrySession()` внутрь `core.SessionManager.Create` (publish-to-map даст happens-before edge) |
| **Med** | T1 M4 | `core/crypto.go:138-141, 192-197` | `DecryptClientID` не enforces `idLen == 16` symmetric к encode (encode rejects `>16`, decode accepts ≤). Не auth bypass | Add `if idLen != 16 { return nil, errors.New("invalid clientID size") }` после `idLen := int(decrypted[8])` |
| **Med** | T1 M6 | `core/session.go:239-250` | `SetStatsCallbacks` package-global writes race с `EncryptChunk`/`DecryptChunkSafe` reads на hot path. `-race` flags при тест-overlap | `atomic.Pointer[func()]` или `atomic.Value` holding `*StatsCallbacks` struct |
| **Med** | T1 M7 | `skins/browser/request.go:181-193`, `request_fuzz_test.go` | `ParseUploadRequest` JSON fuzz target всё ещё missing — JSON layer = первый attacker-controlled byte boundary на body-prefix path | Add `FuzzParseUploadRequest` per April baseline |
| **Med** | T2 F4 | `skins/browser/padding.go:17-29, 44-56` | Padding decorrelation provable (KS D=0.3710), но **constants placeholders**: `SamplePaddingTarget` mean ~48 bytes vs real Mixpanel `/track` 600-3000 bytes; handshake mean ~32 vs real init 800-2000 bytes | Plan B Pre-flight task — refit constants против captured Mixpanel reference fixture |
| **Med** | T2 F5 | `client/ws_pool.go:80-118` `classifyWSReadError` | R.3a classifier 9 buckets — gaps: TCP RST `connection reset by peer`, `i/o timeout`, `message too big` всё в `other`. `tls > eof` precedence сворачивает `tls: read EOF` в `tls`, скрывая TCP-teardown signal | Add `reset_by_peer`, `io_timeout` buckets; document `tls > eof` precedence в CLAUDE.md |
| **Med** | T2 F7 | `server/handler.go:178-198` `ackJitter` | exp(λ=1/18ms) hard cap 150ms = own signature: median ~12.5ms, p100 = exactly 150ms (point mass). Real ACK distributions имеют heavy right tail >1s | Soft cap (continue exp + small Pareto tail); lower median to ~5ms; calibrate против real CDN-fronted nginx ack |
| **Med** | T3 M-1 | `cmd/api/main.go:627-642` | Audit-trail для ShadowLink admin endpoints через inline `LogFromContext` хрупкий: добавление endpoint забывается, no CI guard, не пишет request body, race "log before lockServer fail" | Wrap `/api/admin/shadowlink/...` group в `auditMiddleware`; inline calls остаются как enrichment |
| **Med** | T3 M-2 | `internal/admin/shadowlink_handlers.go:1206` | `servers.ssh_password` plain text; pool model уже использует encrypted CF token — drift между двумя patterns | Migration: `ssh_password_enc TEXT`, backfill, drop plain; helper `getEncryptedSSHCredentials(serverID)` |
| **Med** | T3 M-3 | `migrations/073_retire_legacy_shadowlink_servers.sql` | Без UNIQUE guarantee на `protocols.name`; rollback не идемпотентен если 'ShadowLink' заново seeded | Verify UNIQUE на `protocols.name` (add migration BEFORE 073 if missing); rollback `ON CONFLICT DO NOTHING` |
| **Med** | T3 M-4 | `internal/admin/shadowlink_pool_*_handlers.go` | Audit-events не имеют `correlation_id` для admin → orchestrator → audit lifecycle. Forensics через time-window query | Migration 074: `correlation_id UUID` в audit_log; ProvisionDomainAsync генерирует UUID, прокидывает через ws+audit+slog |
| **Med** | T3 M-5 | `internal/admin/shadowlink_pool_models.go:313-326` | `RescanStuckShadowLinkPoolDomains` срабатывает только on startup; in-process crash + 10min hang в SSH dial → row застревает в `provisioning` пока не restart | Ticker every 5min next к other schedulers в `cmd/api/main.go:176-182` |
| **Med** | T3 M-6 | `internal/deploy/cloudflare_api.go:52-96` | `CFClient.do` не handles 429/5xx with retry. Burst onboarding 20 доменов → 429 → `failProvision` `degraded` | Backoff middleware (max 3 retries, exponential) на 429/502/503/504 |
| **Med** | T4 §3.1 | `client/connmanager.go:320` | `startRotation()` goroutine reads `cm.lifecycle` без lock; potential race с `SetDomainPool` (sub-phase C addition) | `-race` confirmation; добавить mutex или atomic.Pointer на lifecycle |
| **Med** | T4 §2 | `internal/admin/shadowlink_pool_models.go` | Single untested файл в pool namespace; helpers/structs likely shared between 3 handlers | Add unit tests для struct validation / helpers |
| **Med** | T6 F5 | `shadowlink/client/transport/` | "Все reader'ы вышли" loop повторяется (8s → 16s → cap); fallback poll mode активирован но behavior under throttle неясен | Trace полный код-path для StartReader + poll-fallback; add structured-log test under throttle |
| **Med** | T6 F6 | client SOCKS5 UDP path | UDP ASSOCIATE поднимается даже когда pool degraded (только slot=3 живой); UDP packets blackhole'ятся (`udp_polls=0`) | UDP ASSOCIATE проверяет readiness pool'а; failing fast если нет слотов |
| **Low** | T1 L1-L5 | crypto.go nonce regimes / wsURLPool / wg.Wait / slots[idx] ordering / ZeroBytes | L1: counter+random nonce regimes co-exist; L2: `MaxBytesPerSlot` not wired; L3: WS background goroutines не `wg.Wait`; L4: `connectSlot` partial-zero slot; L5: `ZeroBytes` could use `subtle.ConstantTimeCopy` | Tracker only |
| **Low** | T2 F6 | `server/handler.go:1378-1500` | BroadcastStreamClose 10k SLA <2s **verified** (ceil(10k/256)×50ms = 2.0s) — no Close blocking risk. `TestBroadcastStreamClose_ConcurrencyBounded` patched в Phase 2 closure | Already correct; note synthetic-condition limit |
| **Low** | T3 L-1..L-5 | `sendProvisionLog` / FallbackJitterMs=0 / description="" / cfTTLAutomatic=1 / two YAML headers | L-1 WS log severity binary; L-2 FallbackLatencyMs=0 edge case; L-3 description="" vs null contract; L-4 magic number doc; L-5 two renderers with drift | Tracker only; consolidate two YAML renderers into single canonical |
| **Low** | T4 §1.2-1.5, §4 | Comments/test stubs/migration_e2e_test.go:51 dangling paren / `slices.Contains` candidates / no `for i:=0` loops | All cosmetic / accurate / clean | Tracker only |

---

## 3. Threat-landscape deltas (2026-04-22 → 2026-05-01)

Источники: Track 5 §5.1, Track 5b §Diff.

- **RU economic disincentive (NEW class)**: 15GB international cap → ₽150/GB на mobile (objected May 1, отложен по техническим причинам billing). Track 5 §5.1.1.
- **RU platform whitelist (April 15 mandate)**: Yandex/VK/Сбер/Ozon/Wildberries/Avito/etc обязаны блокировать VPN-пользователей под угрозой потери tax benefits. §5.1.1.
- **RU endpoint device-side VPN-detect**: 22 из 30 audited Russian apps (Yandex/VK/Сбер/T-Bank/Wildberries/Кинопоиск/Ozon/etc) активно детектируют VPN и репортят на server. **Out-of-band threat — protocol-level stealth не помогает.** §5.1.3.
- **RU CIDR /24 whitelist (Habr 1027276)**: ~63K IP в whitelist через ~46M Russian addresses (~0.14%); 2,557 ASN; Yandex Cloud dominance (12,906 IP, 1 в 5). Filtering coarse-grained по /24. **Practical implication**: размещение в whitelisted /24 = почти любой fingerprint работает. §5.3.1.
- **RU DTLS JA3/JA4 ban (net4people #603, since 2026-03-30)**: Snowflake DTLS блокируется по signature DB. Шаблон signature-DB-driven detection **мигрирует с TLS на DTLS**. Закрывает все DTLS/QUIC/WebRTC fallback идеи для РФ. §5.1.2.
- **CN: Xray-core relay seizures (April 1 2026, RelyVPN-skeptical)**: physically disconnected thousands relay servers + ML traffic classification в production. Trojan/Shadowsocks dead в CN. §5.1.7.
- **CN: HTTPS type65 record injection (net4people #598)**: GFW injects HTTPS RR (alpn="h2", ipv4hint=injected); потенциально проблема для будущего ECH. §5.1.8.
- **TSPU capacity expansion (refresh)**: target 954 Tbps к 2030 (vs 752.6); funding ₽83.7B (+₽14.9B). §5.1.4.
- **CF 16KB throttle continued** на Rostelecom/MegaFon/Vimpelcom/MTS/MGTS — без новых tactics, продолжается. §5.1.5.

---

## 4. Competitive position (peer-tools state)

Источники: Track 5 §5.2, Track 5b §Авторские-комментарии и §Diff.

- **Xray-core (REALITY) v26.4.x — major**: 🔴 **VLESS Post-Quantum Encryption shipped** (PR #5067, RPRX, merged 2025-08-28, в production releases с января 2026). Это PQ на **VLESS payload layer**, не TLS. ML-KEM-768 + X25519 hybrid KEM в payload + anti-replay 0-RTT + 1-RTT PFS + padding obfuscation. Наш PQ — только в TLS ClientHello (через uTLS). **Мы fall to parity на TLS-layer, behind на payload-layer.** ML-DSA-65 signature в REALITY также добавлен. Track 5 §5.2.1.
- **Hysteria2 v2.7-2.8.x**: incremental BBR/Reno crash fixes; Brutal CC tweaks. **Не наш конкурент** — UDP throughput-king (~800 Mbps) vs наш HTTP-stealth nишa. GFW ловит un-obfuscated Hysteria2 за ~30s — Salamander обязателен в CN. §5.2.2.
- **sing-box v1.13.x / 1.14-alpha**: 🟡 AnyTLS protocol (padding scheme + custom multiplexing); kTLS TX (Linux 5.1+); TLS fragmentation + SNI spoofing с raw-socket; Post-quantum signatures в TLS config. **🟡 KEY POLITICAL POSITION**: sing-box официально дискредитировал uTLS ("not recommended for censorship circumvention", **"lacks active maintenance and has poor code quality"**, "use NaiveProxy instead"). Наш `client/ws_transport.go` использует utls v1.8.3 — задеть нашу репутацию. §5.2.3.
- **AnyTLS**: нишевый padding-focused TLS proxy без отдельного TLS mimicry (использует sing-box uTLS, наследует deprecation problem). Не учитывать. §5.2.4.
- **Trojan-GFW**: quasi-dormant (last meaningful release ~2020, single-maintainer, "under construction" Android много лет). GFW reliably ловит. **Dead branch.** §5.2.5.
- **NaiveProxy**: продолжает быть recommended choice от sing-box (Chromium 139+, real BoringSSL). Не updated с baseline. §5.2.6.
- **Snowflake**: under attack (RU DTLS JA3/JA4); workaround "random-and-mimic" works — long-term выживание open question. §5.2.6.
- **WebTunnel (Tor)**: 143+ bridges, RU distribution через Telegram. Stable но low-throughput. §5.2.6.
- **Новые имена из Track 5b**: `bytedance/g3proxy` (production-grade SNI routing + MITM, reference для per-domain routing); `fosrl/pangolin` (identity-aware VPN, архитектурно интересен для multi-tenant); `mihomo (MetaCubeX)` (enhanced Clash с VLESS Reality + Hysteria2, reference для client-side multi-protocol failover — наш Domain Diversity аналогичен); `flomesh-io/pipy` (programmable edge proxy, не прямой конкурент). Track 5b §Новые-имена.
- **AmneziaWG**: в Track 5 baseline P0-конкурент в RU (strong, 2.0 с dynamic headers с марта 2026). **Track 5b: awesome-proxy НЕ упоминает** — означает mainstream proxy-community ещё не интегрировал → конкурентное окно для ShadowLink.

**Competitive matrix (refresh 2026-05-01, Track 5 §5.2.7):**

| Protocol | RU 2026-05 | CN 2026-05 | Throughput | TLS-FP | Payload-PQ |
|---|---|---|---|---|---|
| VLESS+REALITY (Xray v26.4.x) | degraded (#490 + 16KB) | ~98% | 200-400Mbps | ML-DSA-65 + REALITY | **YES (PR#5067)** |
| Hysteria2 + Salamander | QUIC cut | ~70% w/Salamander | 800Mbps | N/A (UDP) | NO |
| AmneziaWG 2.0 | strong | ~85% | wireguard-baseline | N/A | NO |
| NaiveProxy | strong | strong | high | real Chromium | NO |
| sing-box AnyTLS | unknown field | unknown | high (kTLS) | uTLS-warned | optional |
| WebTunnel | works | works | low-medium | TLS+Tor | NO |
| **ShadowLink** | works direct origin (10-15Mbps under throttle) | untested | 10-50Mbps | uTLS Chrome_133+MLKEM768 | NO (TLS-only PQ) |

---

## 5. Field evidence cross-reference

Источник: Track 6 lab capture 2026-05-01 10:44 MSK на datacanvases.com под VPS throttle.

| Field finding | Validates / extends | Tracks |
|---|---|---|
| **F1** backoff overflow → reconnect storm | Tier S R.1 (slow-start reconnect) — fix НЕ покрыл overflow при больших attempt | T6 + Tier-S spec в `2026-04-30-current-state-and-improvements.md` |
| **F2** decoy HTML вместо 429 / WS close | Tier S R.4 spec (per-clientID handshake rate limit) **implementation-needed**; T2 §F8 wsURLPool single-path упрощает enumeration | T6 + T2 F8 + T5 5.2 (decoy similarity issue) |
| **F3** zombie streams 50+ minutes pending=70 | T2 F6 BroadcastStreamClose верифицирован SLA на happy-path, но НЕ покрывает "all slots dead" cascade. Field подтверждает gap в edge-case | T6 + T2 F6 |
| **F4** pool starvation cascade | Tier S целиком — backpressure отсутствует. Подтверждает что R.3a anomaly classifier видит проблему ex-post, но pre-flight backpressure отсутствует | T6 + T2 F5 (classifier coverage) |
| **F5** "все reader'ы вышли" loop + poll fallback uncertain | T2 F5 R.3a classifier limited buckets; T1 нет findings про reader rationale | T6 + T2 F5 + (Tier A throughput backlog) |
| **F6** UDP ASSOCIATE без ready slots | Не покрыт ни одной track-finding'ой. Новая поверхность атаки на pool readiness invariants | T6 only |

**Key validation outcome**: Field test **invalidates "Tier S R.1+R.3a is enough"** assumption: cascading failure под throttle до сих пор воспроизводится, и закрытие F1+F2 — это P0 для production'а.

---

## 6. Updated Tier roadmap

Источники: Track 5 §Action-items, Track 6 §Приоритезация, Track 1/2/3 §Recommendation секции.

### Tier S — продолжающаяся резильентность (1-3 days each)

**Сдвигается / добавляется:**
- **NEW S.0 (P0 from Field):** F1 backoff overflow clamp + F2 decoy-as-ratelimit sentinel — оба блокируют production'ный rollout под throttle.
- **NEW S.6:** Mobile bandwidth budget mode (client UI) — RU 15GB cap социальный давит на cover GET / response inflation overhead.
- **NEW S.7:** Split-tunnel guidance for Russian apps — endpoint VPN-detect требует config doc + maybe IP exclusion list.
- **PROMOTED C.1 → S.8:** Domain Diversity activation в production (код готов, но H-1 SSH-pipeline dead). Habr CIDR finding + DTLS ban делают diversity FIRST-LINE defense.
- **PROMOTED CRIT-4 → S.9:** wsURLPool ≥6 paths server-distributed (T2 F8). Single largest open detection signal.

**Закрыто/просистема:** R.1 slow-start (но не overflow), R.3a classifier (но buckets gaps F5).

### Tier A — throughput (без изменений)

A.1-A.4 остаются. Hysteria2 Brutal — не наш бой; мы в HTTP-stealth нише. T6 F5 reader loop — просветить под throttle, но не Tier S.

### Tier B — adaptive stealth-vs-throughput

Без изменений из baseline. T2 F4 padding constants Plan B Pre-flight остаётся.

### Tier C — diversity & operational maturity (приоритезировано)

- **C.1 → Tier S.8** (см выше).
- **NEW C.5:** Domestic-ASN origin research (Yandex Cloud / Selectel / VK Cloud LE-fronted egress). Habr 1027276 §3 demonstrates Yandex API Gateway viable. Risk: legal/compliance.
- **NEW C.6:** Domain Diversity ops-readiness (T3 H-2 + H-3 + H-4 + M-3..M-6) — closes 4 highs + 4 mediums в одну session.

### Tier D — strategic

- **D.5:** ✅ DONE in Track 5 (web research новые TSPU 2026 capabilities).
- **NEW D.6:** Payload-layer PQ KEM evaluation. Xray VLESS PR#5067 raises bar; not urgent, research timeline до Jan 2027.
- **NEW D.7:** Chromium-egress proxy variant research. sing-box deprecation of uTLS challenges нашу репутацию; investigate NaiveProxy-style approach как optional adjunct.
- **NEW D.8:** GREASE-aware self-test в CI. Industry baseline JA3→JA4. Easy add.
- **D.9 refresh:** T1.5 Mixpanel schema lock. Reinforced — endpoint detection + cross-correlated traffic mimicry threat.

### Tier "Don't bother"

- **DTLS / WebRTC fallback** для RU — dead end per net4people #603.
- **Trojan-GFW protocol parity** — dead branch.
- **Pure-uTLS marketing** — sing-box just deprecated this story; move to "honest limitations" framing.

---

## 7. Top-3 action items (next session, P0)

### A1. Field-driven Tier S follow-up (Phase 2 R.1 + R.4 closure)

**Что сделать:**
- Track 6 F1 (`shadowlink/client/wspool/`): clamp `attempt = min(attempt, 6)` ДО expo в `slotBackoffDuration`; verify через unit test attempt=37 → backoff ≤ 60s.
- Track 6 F2 (`shadowlink/server/handler.go` rate-limit branch ≈ Tier S R.4 spec): sentinel-сигнал внутри decoy (special HTTP header `X-SL-RL: 1` ИЛИ dedicated WS close-code 4429); client side в `client/ws_pool.go` parse sentinel и применить fixed cool-down 120-300s вместо exp.
- Track 6 F3+F4 как stretch: trigger `BroadcastStreamClose` когда "all slots dead, no ready" + per-stream pre-flight в `connmanager.SetSocks5Listener`.

**Почему P0:** field log 10:44 MSK подтверждает что Tier S R.1+R.3a НЕ покрывает cascading failure под throttle. Это active production issue на datacanvases.com.

### A2. Domain Diversity SSH-pipeline wiring + ops-readiness

**Что сделать:**
- T3 H-1: миграция 074 — добавить `ssh_user/ssh_password_enc/ssh_port` в `shadowlink_pool_servers` (через `encryptToken`). Расширить `internal/admin/shadowlink_domain_provision.go::provisionDomain` шагами 5-9: `InstallLECert` → `InstallDecoyTemplate` → `UploadNginxConfig` → `ReloadNginx` → `ReloadShadowLink`. Снять `//nolint:unused` с `getShadowLinkPoolDecoyTemplate`. Regenerate `domain_decoy_map` через `WriteShadowLinkConfigYAML`.
- T3 H-4: per-server lock на `nginx swap` (`flock /var/lock/shadowlink-nginx.lock` ИЛИ `lockServer(serverID)` в `ProvisionDomainAsync`).
- T3 H-3: probe handler endpoint `/api/admin/shadowlink/pool/domains/:id/probe` запрашивает `/_health` за CF (bearer auth) ИЛИ ищет decoy-marker `<title>habr</title>` в body; scheduler в `cmd/api/main.go` каждые 5 минут pass `status='active'` rows; degraded after 3 consecutive fails.
- (stretch) T3 H-2: `APP_ENCRYPTION_KEY_PREVIOUS` env + helper `decryptToken` тестит current → previous.

**Почему P0:** Track 5 §5.3.1 Habr CIDR finding делает Domain Diversity FIRST-LINE defense, но T3 H-1 говорит "DONE in MEMORY, manual в коде". Без этого диверсификация — мираж, и DTLS ban (§5.1.2) закрыл alternative routes.

### A3. wsURLPool server-distributed pool (CRIT-4 closure)

**Что сделать:**
- T2 F8: extend `server/urls.go` от single `["/ws"]` к pool ≥6 plausible-shape paths (например `/ws`, `/api/v1/stream`, `/realtime/connect`, `/ws/v2/events`, `/socket.io/`, `/cable`). Server-side: dispatch на любой из них в `handler.go` ServeHTTP. Client side `ws_paths.go`: weighted rotation per slot.
- Deploy-order: ship server-first (accepts all paths), затем client release (uses new paths). Bytewise `wsURLPool` parity test между client/server остаётся.

**Почему P0:** T2 F8 — единственный Critical detection signal от April baseline, который **до сих пор открыт в коде**. Active probing classifier видит single endpoint в <10 round-trips. Закрытие — server-side mechanical, client-side требует deploy coordination.

---

## 8. Open questions (требуют field-test или manual проверки)

Источники: Track 1 §Open-questions, Track 2 §Open-Questions, Track 3 §Open-Questions, Track 5 §Open-questions, Track 6 §Repro.

1. **Rekey activation roadmap.** Если `Session.Rekey` планируется в next 30 days → T1 H2 P0; иначе lock с build-time assertion. Track 1 Q1.
2. **uTLS Chrome_133 в публичных JA4 db.** JA4 capture против datacanvases.com и grep FoxIO db; если hash hits "Chrome_133 (utls)" label — F2 confirmed. Track 2 Q1.
3. **Cover GET cadence FFT/ACF over 1h capture.** Должна показать log-normal bell shape; FFT inter-arrival НЕ должна показывать 5/30s периодичность. Track 2 Q2.
4. **AckJitter 150ms cap visibility в реальной p99.** Static analysis says yes; field rate of cap-hits depends on `ExpFloat64`. Track 2 Q3.
5. **Bogdanfinn Chrome_146 vs real Chrome 138-141 SETTINGS frame parity.** Compare HEADER_TABLE_SIZE / INITIAL_WINDOW_SIZE / MAX_CONCURRENT_STREAMS / MAX_FRAME_SIZE / ENABLE_PUSH. Track 2 Q4.
6. **Tier S R.3a `other` bucket prevalence.** Если `other` > 5% за 7d → нужны named buckets (TCP RST, i/o timeout, message too big). Track 2 Q5.
7. **Cover path realism vs Mixpanel.** Capture Mixpanel SDK trace из test SPA; compare path list / cadence / body shape. Track 2 Q6.
8. **PQ opt-out wire-format symmetry.** Client с `SHADOWLINK_TLS_PQ=0`, capture ClientHellos cold path (probeHTTPS) + hot path (split_transport upload). Confirm cold lacks MLKEM, hot keeps it. Track 2 Q7.
9. **Padding distribution match against real Mixpanel `/track` POST sizes.** Если real distribution Pareto-tailed centered 600-3000 bytes → наши 16-512 wrong-zone. Track 2 Q8.
10. **Phase 0 retired metrics в frontend.** `ShadowLinkPage.LiveDecoyMetricsTab` не expects ли уже убранные `shadowlink_legacy_path_hits_total` / `shadowlink_dual_auth_detected_total` / etc? Track 3 Q1.
11. **Domain Diversity onboarding flow** — `AddDomainWizard` WS subscription path (`ServerID = "<id>"` numeric) — достаточно для UI disambiguation от server-deploy логов? Track 3 Q2.
12. **Migration 073 protocols.name vs protocol_id.** Verified deploy_handlers.go branch? Track 3 Q3.
13. **Где живёт canary `datacanvases.com`** в Domain Diversity модели — `shadowlink_pool_servers` ИЛИ legacy `servers + protocol_configs.shadowlink`? Track 3 Q4.
14. **`ShadowLinkConfig.MgmtKey` plain в `protocol_configs.config_json`.** После APP_ENCRYPTION_KEY infra (H-2) мигрировать. Track 3 Q5.
15. **`UploadNginxConfig` proxy_pass unix-socket vs T1.3 single-server TCP**: как coexist на одном VPS если admin migrate single → pool? Track 3 Q6.
16. **Реальный enforcement rate RU 15GB mobile cap** теперь когда отложен. May 2026 news watch. Track 5 Q1.
17. **Russian-ASN Yandex Cloud bunker legal viability.** Compliance + ToS review требуется. Track 5 Q2.
18. **Field-test ShadowLink через известные RU /24 CIDR whitelist** — есть ли users сообщающие connectivity problems specifically related к ASN, не protocol? Track 5 Q3.
19. **sing-box anti-uTLS stance mass-adoption** или minority view? Sentiment-watch на reddit/Telegram. Track 5 Q4.
20. **DTLS JA3/JA4 ban — будет ли рост на TLS** (RU начнёт TLS JA4 signature DB targeting)? Watch net4people. Track 5 Q5.

---

**Document status:** consolidated synthesis complete. Recommended consumer: roadmap maintainer для Tier S adjustment + stakeholder review для C.1/A2/A3 promotion.

DONE: D:/NIXAVPN/shadowlink/docs/audit/2026-05-01-consolidated-findings.md
