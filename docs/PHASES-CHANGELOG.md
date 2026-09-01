# ShadowLink — Phases & Audit Changelog (исторический архив)

> Вынесено из CLAUDE.md 2026-06-13 для экономии контекста. Это ЛЕТОПИСЬ
> завершённых фаз/аудитов (Status / Rollback / Metrics / References) — нужна
> только при откате конкретной фичи или восстановлении истории решения.
> Живые инварианты, активные ENV-флаги и dev-команды остались в CLAUDE.md.

---

## Field run 2026-08-17 (9ч38м) — QuickEdit-заморозка и недосчёт экспозиции на пути реза

Полевой прогон 09:25:34 → 19:03:13, 6 579 МБ downlink, лог
`%TEMP%/nixavpn-DEBUG-20260817-092533.log`. Разбор двумя независимыми агентами.

### Вывод 1: контур ротации стоял 428 с, и причина была ВНЕ процесса

Симптом: три периодических логгера пула замолчали и ожили в пределах 16 мс
друг от друга (`stats (delta)` 17:47:09.590 → 17:54:17.258; `WS pool health`
17:47:06.992 → 17:54:17.242; `slot death inference` 17:47:04.590 → 17:54:17.254).
Ротаций за окно — ноль, возрасты соединений дошли до **505.4 с** (slot 9,
60 МБ, 17 727 сообщений), три плановых снятия дали `slot_age` 457.7 / 502.1 /
505.9 с. `worst_case_teardown` = 140.5 с превышен в 3.6 раза. Восемь
`fast age-cut reconnect` выстрелили одной пачкой в 17:54:17.246–249.

**Причина — QuickEdit в PowerShell** (выделение мышью блокирует вывод в консоль
до Ctrl+C/Enter), подтверждена пользователем и сходится со всеми метриками:

- Данные шли на полной скорости: 71 МБ downlink, 19 198 расшифровок, 203 новых
  соединения за окно. Блокируется только вывод, не сеть.
- Фаза тикеров СОХРАНЕНА через окно: `stats` шёл на `.590`, выдал одну
  внеплановую строку на `.258` и вернулся на `.590`; `health` — `.992` → `.242`
  → `.991`. Голодавший тикер возобновился бы со сдвинутой фазой.
- Тики ДРОПНУТЫ, не накоплены: 6847 наблюдённых `stats` против 6932 ожидаемых
  = 85 тиков × 5 с = 425 с ≈ длина окна (`time.Ticker` дропает при непрочитанном
  канале).
- Файл лога **не хронологичен**: 340 инверсий (0.8 %), 294 из них в 17-м часу,
  максимальное отставание 420 с, 264 строки с меткой 17:54:17 — это флеш очереди.
- Монотонные часы не останавливались: дрейф `uptime` против wallclock 1.0–1.2 с
  за весь прогон, то есть suspend ОС исключён.

⚠ **Дефекта протокола здесь нет.** Все восемь держателей `reserveMu` прочитаны —
чистые, без сетевых операций внутри. Время на их аудит было потрачено потому, что
причину искали внутри процесса. Урок: при синхронной остановке НЕСКОЛЬКИХ
независимых тикеров сначала проверять фазу и число дропнутых тиков — это
отличает внешнюю приостановку вывода от блокировки в коде за одну команду.

⚠ **Операционное правило: QuickEdit при полевых прогонах выключать** (свойства
окна консоли → снять «Выделение мышью»), либо направлять вывод в файл, а не в
консоль. Иначе одно движение мышью останавливает ротацию на произвольное время,
пока туннель продолжает гнать трафик по стареющим соединениям — цензору причина
остановки безразлична.

### Вывод 2: `age_exposure_over_threshold_ms` терял 27 % — путь реза (ИСПРАВЛЕНО)

`accrueAgeExposure` имел единственный продовый call-site — `tearDown` внутри
`drainWatchdog` (`client/ws_pool_drain.go`). Резы приходят через
`handleSlotDeath` из `slotReader`, минуя дренаж целиком, и в счётчик не попадали.

Доказательство — арифметическое совпадение, а не рассуждение: дренажные пути дали
**3010.1 с** перебега за порогом 82 с (175 терминаций), резы — ещё **1112.6 с**
(18 соединений), фактическая экспозиция 4122.7 с. Счётчик в логе показал
`age_exposure_over_threshold_ms=3010102` — совпадение с суммой ТОЛЬКО дренажных
путей **до миллисекунды**, и оно держится почасово.

Тот же класс, что правка 2026-08-14 (тогда накопление сидело в sticky-ветке и
теряло 23 % на natural finish), но на уровень выше: «общий путь» оказался общим
только для НАШИХ терминаций. Комментарий на `accrueAgeExposure` формально верен
(«все наши»), однако рез — не наш, а имя счётчика обещает полную экспозицию.
Недосчёт снова в безопасную сторону.

### Status

- **Исправлено:** добавлен `accrueAgeExposureOnDeath(slot, cause)`
  (`client/ws_pool_drain.go`), вызывается из `handleSlotDeath`
  (`client/ws_pool.go`) сразу за CAS-ом `tryMarkDead()`.
- `deathCauseDrainTeardown` **исключён внутри метода**: он приходит в
  `handleSlotDeath` уже после `tearDown`, где экспозиция посчитана. Без фильтра
  каждый дренажный путь считался бы дважды — обратная ошибка, и она хуже:
  недосчёт занижает риск, а двойной счёт создал бы ложный тренд роста, по
  которому стали бы двигать константы (hard rule 8).
- Один проход на одну смерть гарантирует CAS `tryMarkDead()`, отдельной защиты
  от повторного вызова не требуется.
- **Констант не менялось.** Порог `ageExposureThreshold` = 82 с как был.
- Сторож: `TestAgeExposure_AccruedOnCutPath` (`client/sticky_stream_test.go`) —
  проверяет ОБА знака: накопление на `AgeCut`/`Natural`/`PreemptiveRotation` и
  молчание на `DrainTeardown`. Падал до правки, зелёный после.

### Rollback

Удалить вызов `p.accrueAgeExposureOnDeath(slot, cause)` из `handleSlotDeath` и
сам метод из `ws_pool_drain.go`; снять `TestAgeExposure_AccruedOnCutPath`.
Счётчик вернётся к прежнему поведению (только дренажные пути).

### Что прогон подтвердил независимо

- **Ось «возраст» НЕ ослабла.** Заголовочная строка лога
  `CV 0.741 против 2.700` — загрязнение выборки: 19 из 43 «смертей» артефакты
  (10 из окна сбоя ISP, 9 из окна заморозки) плюс 14 фантомов с возрастом 0.0 с.
  По чистым наблюдениям CV = **0.045** (n=9, 84.1–97.9 с) — плотнее замера
  0.26 от 2026-08-07. Порог 68 с при этом НЕ артефакт: `p10 = 85002 мс` держат
  те же девять нормальных наблюдений, он получился бы и без заморозки.
- **Таблица hazard в логе загрязнена по полосам.** Полоса 105–110 с
  (`rate_act=0.1667`, 2 реза) — **оба реза из окна заморозки**, пик
  сфабрикован. Полоса 70–75 с (1 рез) — артефакт сбоя ISP. Настоящий сигнал
  один: **85–90 с, 6 чистых резов**.
- **Фаза на wire чистая.** `R` на периоде тика 500 мс: `reader started` 0.0045,
  `drain started` 0.0032, close 0.0049 при шуме `1/√n` = 0.016. Слепой скан
  0.05–6.0 с шагом 5 мс: max R = 0.048. Правка `nextWatchdogWakeup()`
  (2026-08-14) держится на прогоне в 2.4 раза длиннее. Якорь дренажа проверен
  нетривиально — на 653 МНОГОТИКОВЫХ дренажах `R = 0.9927`.
- **Сбой провайдера 11:29–11:41 пережит корректно.** `mean alive` 7.94 → 5.50 →
  8.13, полное восстановление ёмкости за ~10 с, `healing_gave_up_total = 0` за
  все 9.5 ч. Утечка ячеек (hard rule 11) не воспроизвелась:
  `healing_retargets_total = 27` при нуле отказов. `slotobs` сбоем НЕ отравлен —
  фильтр `io_timeout` отсеял все 10 наблюдений; отравление пришло из окна
  заморозки, где `close_other` фильтр не ловит.
- Sticky жив: `sticky_active > 0` в 50 из 1142 health-строк, max 2.
  `drain_duration` = 25 с в 155 из 157 teardown (константа, о риске молчит —
  читать `slot_age`: p50 63.9 / p90 102.0 / max 104.4 с).

### Открытые дефекты наблюдаемости (НЕ исправлены)

1. **`ws_created` / `ws_died` / `ws_from_pool` — мёртвые счётчики.** Сумма каждого
   за 6847 строк статистики ровно **0** при 3848 поднятых и 43 умерших
   соединениях. Инкременты живут только в `proxy/socks5/tcp.go` (три места) —
   путь «один websocket на стрим», которым архитектура пула не пользуется.
   `ws_died=0` читается как «ничего не умерло» — ровно наоборот.
2. **`duration` в `stream buffer overflow ended` считает не то.**
   `client/stream_overflow.go` печатает `lastAt.Sub(firstAt)` — интервал между
   первым и последним дропом, а не длительность переполнения. При одном дропе
   всегда `0s`: в логе `started` 17:51:16, `ended` 17:54:17, `duration=0s`.
3. **`writeTimeout=0s` в `ws async writer exit` вводит в заблуждение.** Печатается
   поле `t.writeTimeout`, в direct-режиме не заданное; фактический дедлайн — 30 с
   по умолчанию внутри `WSAsyncWriter` (`client/ws_pool.go`). Читается как
   «записи без дедлайна» и толкает к неверному диагнозу.
4. **14 смертей с возрастом ровно 0.0 с** — все `cause=natural`, `messages=0`,
   `down_bytes=0`, на девяти разных слотах, ~раз в 25 мин. Ридер на нулевом
   возрасте с нулевым трафиком = объект слота, у которого `startedAtNs` не был
   выставлен. Портят `slot death distribution`: `age_min_ms=0`, `age_p10_ms=0`,
   и именно они дают `cv_age=1.3143`.
5. **`filterNoise` не отсеивает наши же аномально долгие смерти.** Наблюдение с
   `CloseKind="close_other"` и возрастом 293 с проходит как полноценное
   свидетельство о цензоре, хотя возраст старше `worstCaseTeardown` означает, что
   не сработал НАШ механизм. Следствие в этом прогоне: `samples_used` 8→14 за 2 с
   и ложный WARN `rotation budget reached` с `observed_age_p90=2m57.11s`.
6. **Два `rejected UA from server`** на старте: сервер предложил `chrome120` и
   `chrome131`, клиент выбрал `chrome133` и отверг оба. Реестр UA на сервере не
   знает про chrome133 — дрейф конфигураций, безвредный.

### References

- Лог прогона: `%TEMP%/nixavpn-DEBUG-20260817-092533.log`
- Прежняя правка того же класса: запись 2026-08-14 (счётчик в sticky-ветке)
- Hard rules 8–12 в `CLAUDE.md` — бюджет, ярлык `age_cut`, утечка ячеек, sticky

---

## T1.4 Data-Path V1 Closure — DEFAULT ON (2026-04-26)

`SendChunk` / `SendChunkRawBody` body-prefix migration shipped default-on
in Phase 0 (T1.4 flip). The legacy Authorization-header POST path on the
server has been retired (Phase A Bearer-path retire, 2026-04-26). The
WebSocket Bearer-header pre-upgrade auth was retired alongside (Phase 1 P0,
2026-04-26) — `findSession` and `browser.ExtractSessionToken` deleted.
WS auth is now exclusively first-frame body-prefix via `authenticateFirstFrame`.

### Status

- **Client default:** `SHADOWLINK_DATAPATH_BODYPREFIX=` (empty/unset) → body-prefix path active.
- **Emergency disable:** `SHADOWLINK_DATAPATH_BODYPREFIX=0` (or `false`/`no`/`off`) restores the legacy Bearer header. **Note:** disable will only succeed if connecting to a legacy server — the production server no longer accepts Authorization-bearing POSTs or Authorization-bearing WS upgrades.
- **Server:** legacy POST + GET+Auth dispatch removed. POST body must match the body-prefix `application/json` event-envelope shape; non-matching POSTs route through `failClosedToDecoy` (same shape as probes). v0 handshake fallback in `handleNewFormatPost` is also retired — only v1 handshakes accepted. WS upgrade no longer inspects `Authorization` header — every WS client MUST send a first-frame `[hint+token+encrypted_chunk]` keepalive within 1.5 s of upgrade or the connection is faked-acked and closed.
- **Metrics dropped:** `shadowlink_legacy_path_hits_total`, `shadowlink_dual_auth_detected_total`, `shadowlink_handshakes_legacy_total`, `shadowlink_v0_fallback_from_new_path_total`. Dashboards must be updated to drop these series.
- **Metric retained:** `shadowlink_new_path_hits_total` (renamed conceptually to "body-prefix hits"; counter still exists).

### Rollback

If field regression is observed:
1. Client side: `SHADOWLINK_DATAPATH_BODYPREFIX=0 bin/nixavpn-client.exe`. Only useful against a server still on pre-Phase-0 code.
2. Server side: revert Tasks 4-9 of `docs/superpowers/plans/2026-04-26-shadowlink-phase-0-debt-closure.md` and redeploy.

### References

- Phase 0 plan: `docs/superpowers/plans/2026-04-26-shadowlink-phase-0-debt-closure.md`
- Master roadmap: `docs/superpowers/specs/2026-04-25-shadowlink-top-tier-roadmap-design.md`
- Earlier T1.4 spec: `docs/superpowers/specs/2026-04-22-t14-direct-transport-v1-closure-design.md`
- Earlier T1.4 plan: `docs/superpowers/plans/2026-04-22-t14-direct-transport-v1-closure.md`
- Wire-format spec: `shadowlink/docs/protocols/body-prefix-v1.md`

## Phase 2 — TLS Modernity + Ops Correctness (2026-04-26)

### Status

- **T1.1 PQ ClientHello**: custom `ClientHelloSpec` derived from `HelloChrome_133` with `X25519MLKEM768` prepended in `key_share` and `supported_groups` extensions. Both the WS upgrade (`ws_transport.go:UpgradeToWS`) AND the cold-path uTLS dialer (`split_transport_tls.go:buildUTLSDialTLS` — covers `SendHandshake` POST, `WarmupRequests`, cover GET, `SplitTransport` CDN upload, `probe.probeHTTPS`, ECH DoH client) honor `SHADOWLINK_TLS_PQ`. **Note:** as of utls v1.8.3 `HelloChrome_133` already includes MLKEM768; `pqClientHelloSpec()` is a safety-bridge no-op for current utls but activates if upstream removes MLKEM. **Default ON since 2026-04-28** (Phase 2 closure flip); set `SHADOWLINK_TLS_PQ=0` (or `false`/`no`/`off`) for emergency disable.
- **T1.7 BroadcastStreamClose**: bounded-parallel via `errgroup.Group` with `SetLimit(256)`, per-tunnel 50ms deadline, 5s total deadline. Replaces serial 100ms-per-tunnel loop. SLA <2s for 10k tunnels. Loadtest measured ~10ms in dev (background-draining mock).
- **T1.6 GET cover**: **RETIRED 2026-05-02 (F3 wire-trigger followup).** The periodic GET scheduler was removed — its 30-50% GET/POST cadence was an FFT-visible signal and peer tools (Reality / Hysteria2 / TrustTunnel) ship with no cover GETs and operate cleanly inside Russia. WarmupRequests (one-shot pre-WS-upgrade burst, 1-4 GETs with randomized path order) is **kept** — it is not periodic and mimics the legitimate pre-connection asset-fetch a real browser does.
- **A2-HIGH-7 padding decouple**: `browser.SamplePaddingTarget` independent log-normal source (μ=ln(48), σ=0.7). Replaces `PayloadDistribution.UploadSize()` for padding target in `SendChunk`. Note: `t.pd` field still on struct for cleanup in future refactor.
- **A2-MED-10 meltdown log jitter**: jittered interval [0.5×, 1.5×] of 5s base + rate limiter (1/10s, burst 3) + severity gate (50% dead pool threshold). Implemented as event-driven adapter (kept existing `recordSlotDeath`-driven flow rather than manufacturing a periodic loop).

### Bogdanfinn profile

`profileForFingerprint` in `client/connmanager.go` returns `browser.LockedBogdanfinnChromeProfile()` = `profiles.Chrome_133` for the Chrome fingerprint, matching `browser.LockedUTLSChromeID()` = `utls.HelloChrome_133` on the cold-path. Phase 2 originally bumped to `Chrome_146` for newer H2 SETTINGS but the F2 lockstep (2026-05-02) reverted that — the four wire surfaces (uTLS / bogdanfinn / UA / sec-ch-ua) all align to the same Chrome major now. Bumping requires utls upstream catching up to `HelloChrome_135+` (still absent in v1.8.3).

### ENV flags added

| Flag | Default | Effect |
|---|---|---|
| `SHADOWLINK_TLS_PQ` | unset (**ON** since 2026-04-28) | Default-on flip. `=0`/`false`/`no`/`off` (case-insensitive, whitespace-trimmed) routes through stock `HelloChrome_133` via `UTLSIdToSpec`. Any other value (`=1`, `yes`, unset, garbage) keeps PQ on. Counter wiring ticks `shadowlink_tls_pq_handshake_total` on every handshake. **Note (F2 lockstep):** since 2026-05-02 the bogdanfinn hot-path emits `Chrome_133` regardless of this flag — opting out only changes the cold-path uTLS spec (drops MLKEM keyshare). |
| `SHADOWLINK_COVER_GET_RATIO` | RETIRED 2026-05-02 | Was used by the cover-GET scheduler. Scheduler retired (F3); the env variable is now silently ignored. |

### Metrics added

```
shadowlink_tls_pq_handshake_total{result}             # success|fallback|error
shadowlink_broadcast_close_drain_seconds_last         # gauge (most recent invocation)
shadowlink_broadcast_close_drain_seconds_avg          # gauge (mean since start)
shadowlink_broadcast_close_drain_count_total          # counter
shadowlink_broadcast_close_dropped_total{reason}      # timeout|done|ctx_cancel
# Cover GET counters retired 2026-05-02 (F3 wire-trigger followup):
# shadowlink_cover_get_sent_total                     # RETIRED
# shadowlink_cover_get_send_errors_total              # RETIRED
# shadowlink_cover_get_ratio_observed                 # RETIRED
```

(All exposed via existing `client/stats.go` and `server/metrics.go` text exporters — project does NOT use `prometheus/client_golang`; counters are atomic, exposition is hand-rolled.)

### JA4 fixture

`client/testdata/ja4/chrome_133_pq.txt` pins JA4 hash. Refresh procedure documented in adjacent `REFRESH.md`.

### Rollback

- Client side: `SHADOWLINK_TLS_PQ=0 bin/nixavpn-client.exe` disables PQ (cold-path drops MLKEM keyshare; hot-path stays on `Chrome_133` via F2 lockstep). `SHADOWLINK_COVER_GET_RATIO` was RETIRED with the cover scheduler — it has no effect now. PQ default-on flip means `=0` is the active opt-out; unset / `=1` both keep PQ enabled.
- Server side: T1.7 has no flag — to revert, redeploy a pre-Phase-2 binary.

### References

- Phase 2 spec: `docs/superpowers/specs/2026-04-26-shadowlink-phase-2-tls-modernity-design.md`
- Phase 2 plan: `docs/superpowers/plans/2026-04-26-shadowlink-phase-2-tls-modernity.md`
- Phase 2 closure plan: `docs/superpowers/plans/2026-04-28-shadowlink-phase-2-closure.md`

## Phase 3 Plan A — Server-Only Audit Closures (2026-04-28)

### Status

- **A2-MED-7 — failClosedToDecoy jitter source:** synthetic-data `crand.Read` calls in `server/decoy_timing.go` replaced with constant-latency `mathrand` (math/rand/v2) helper `fillRandom`. Cryptographic ops (X25519 keypair, AES-256-GCM Open) preserved — they provide the dominant timing cost. `runSyntheticDispatch` extracted from `failClosedToDecoy` so the variance-bound test can isolate steps 1-3 from the intentional `ackJitter()` distribution-matching sleep. Test `TestFailClosedToDecoy_TimingVariance` enforces std-dev <2ms (well below the 18ms ackJitter mean — catches regression where entropy-pool latency creeps back).
- **A2-MED-6 — gorilla 400 → decoy 200:** `wsUpgrader.Error` set to `noopUpgradeError` (suppresses default 400-with-text response); gorilla-Upgrade-fail and pre-upgrade rate-limit branches in `handleWebSocket` route through `failClosedToDecoy` (sanitized 200 with placeholder request). Non-allowed-WS-path branch unchanged (path is not WS-leaky). Probe vectors (malformed Sec-WebSocket-Key, wrong protocol version) now return 200 indistinguishable from random-path GETs. **Scope note:** plain GETs without `Upgrade: websocket` header never enter `handleWebSocket` — they fall through ServeHTTP top-level dispatch to direct `decoy.ServeHTTP(w, r)`, whose URL-echo behavior is a separate path-echo finding tracked outside A2-MED-6.
- **A2-HIGH-5 — handshake/data padding split:** `SampleHandshakePaddingTarget` (μ_log=ln(28)≈3.33, σ=0.5, range [16, 384]) added in `skins/browser/padding.go` alongside existing `SamplePaddingTarget`. `BuildHandshakePayload` switched to the new sampler via a process-wide RNG (sync.Once-seeded from crypto/rand, sync.Mutex-guarded) — Windows time.Now() resolution made per-call seeding produce duplicate lengths under burst calls. Two-sample KS test (N=5000, seed=42) confirms divergence: D=0.3710 ≫ critical 0.0326 (reject H0 same-distribution at p<0.01). **Placeholder constants — refit in Plan B Pre-flight against captured Mixpanel reference fixture.** `pd *PayloadDistribution` parameter retained on `BuildHandshakePayload` for ABI stability (`_ = pd`).
- **T2.4 — Response inflation tuning:**
  - **Sticky `next_poll`:** `core.MimicrySession.NextPollLambda` sampled from Pareto(α=1.5) truncated [5, 600]s at session creation (in `server/handler.go::handleHandshakeNew` after `HandshakesNewTotal.Add`). `BuildInflatedDownloadResponse(encryptedChunk, seqNum, sess *core.MimicrySession)` consults the sticky lambda + ±15% jitter; `nil` session falls back to legacy uniform 30..89s for code paths without session state. `core.MimicrySession` lives in `core/mimicry_session.go` (zero-dep struct) to avoid `core ↔ browser` import cycle; `browser.NewMimicrySession()` and `browser.NextPollSeconds(*core.MimicrySession)` hold the sampler logic. Six `buildResponse` callers in `server/handler.go` updated (sendAck, handleDataChunk paths, handleKeepalive, sendConnectResult, handleUDPData) — all already had `session *core.Session` in scope.
  - **Decoy interval:** `browser.NextDecoyInterval(rng *rand.Rand)` log-normal (μ_log=ln(25), σ=0.4, truncated [5s, 90s]). Replaces uniform `15 + rand.IntN(30)`s in `client/decoy_traffic.go::loop`. Startup-delay logic (`3 + rand.IntN(7)`s using v2 `rand`) UNCHANGED. Coexists with v2 `rand`: file imports `stdrand "math/rand"` alongside `"math/rand/v2"`.
  - **Response size sampler:** `browser.SampleResponseSize(rng *rand.Rand)` Gaussian core (μ=2048, σ=800) + 5% Pareto tail (α=2, scale=2048), truncated [256, 32768]. **Wire-up into `BuildInflatedDownloadResponse` body padding deferred to Plan B Stage 1** (Plan A ships sampler + tests).

### Architectural changes

- New struct `core.MimicrySession{NextPollLambda float64}` in `core/mimicry_session.go`. New field `core.Session.MimicrySession *MimicrySession` (nil for sessions created via `core.NewSession` directly — only initialized server-side after handshake).
- `BuildInflatedDownloadResponse` signature gained 3rd param `sess *core.MimicrySession`. `Handler.buildResponse` signature gained 1st param `session *core.Session`.
- `BuildHandshakePayload(ephPub, encClientID, pd)` — `pd` retained but ignored; padding now sourced from `SampleHandshakePaddingTarget` via package-private process-wide RNG.

### ENV flags added

None. Plan A is wire-compatible with all existing ShadowLink clients (no protocol changes — only server-side timing/distribution + client-side decoy interval cadence).

### Metrics added

None in Plan A. Plan B (wire migration) will add format/transport telemetry.

### Distribution test gates (chi-square / KS)

| Test | Statistic | Threshold |
|---|---|---|
| `TestFailClosedToDecoy_TimingVariance` | std-dev of `runSyntheticDispatch` over 1000 iters | <2ms (regression bound; ackJitter dominates real path) |
| `TestPaddingDistributionDiverges` (KS, N=5000, seed=42) | D = 0.3710 | >0.0326 (p<0.01 reject same-distribution) |
| `TestDecoyIntervalLogNormal_GoodnessOfFit` (chi-square 50 buckets, N=10000) | χ² = 39.86 | <70 (95% critical, ~49 d.o.f.) |
| `TestDecoyIntervalRejects_Uniform` | χ² = 776,653 | >1000 (provably non-uniform) |
| `TestNextPollPareto_GoodnessOfFit` | χ² = 6.56 | <70 |
| `TestNextPollSticky_PerSession` (sessions=200) | within-ratio <0.30, across-rel-stddev observed 0.54-2.6 (Pareto heavy-tail variance is expected) | within<0.30, across>0.5 |
| `TestSampleResponseSize_HasFatTail` | fraction >8KB = 0.0029 | [0.0025, 0.10] |
| `TestSampleResponseSize_DominatesGaussianCore` | fraction in μ±σ = 0.675 | >0.55 |

### Rollback

Plan A is unconditional (no feature flags). To revert any item, restore the pre-Plan-A version of the listed file(s) and rebuild:

- A2-MED-7: `server/decoy_timing.go`
- A2-MED-6: `server/websocket.go`
- A2-HIGH-5: `skins/browser/padding.go`, `skins/browser/request.go::BuildHandshakePayload`
- T2.4 sticky next_poll: `core/mimicry_session.go` (delete), `core/session.go` (drop field), `skins/browser/mimicry.go` (drop helpers), `skins/browser/request.go::BuildInflatedDownloadResponse` (drop param), `server/handler.go::buildResponse` (drop session param)
- T2.4 decoy interval: `client/decoy_traffic.go::loop` (restore uniform), `skins/browser/decoy_interval.go` (delete)
- T2.4 response size: `skins/browser/response_size.go` (delete) — was sampler-only, no production wire-up

### References

- Spec: `docs/superpowers/specs/2026-04-28-shadowlink-phase-3-wire-modernization-design.md` § 4
- Plan: `docs/superpowers/plans/2026-04-28-shadowlink-phase-3-plan-a.md`
- Master roadmap: `docs/superpowers/specs/2026-04-25-shadowlink-top-tier-roadmap-design.md`

## May-audit P2 cleanup pack (2026-05-02)

Selected closures from `docs/superpowers/plans/2026-05-01-may-audit-action-plan.md` § P2.

### C1 — Cover GET path realism

`skins/browser/cover.go::defaultCoverPaths` dropped `/health` and
`/api/v2/feature-flags` (neither matches a Mixpanel SDK endpoint).
Replacements: `/decide` (config / feature-flag lookup) and `/lib.min.js`
(SDK bundle). Pool size unchanged at 6; chi-square uniformity test
unaffected. Refit deferred to Phase 5 / S5 schema lock.

### C2 — PQ opt-out wire-format symmetry

`profileForFingerprint` in `client/connmanager.go` now reads `pqEnabled()`
and returns `profiles.Chrome_133` when PQ is disabled, mirroring the
cold-path uTLS dialer (which strips MLKEM via stock `HelloChrome_133`
spec). Default-on path unchanged: `Chrome_146`. Asymmetry resolved —
`SHADOWLINK_TLS_PQ=0` now produces a single ClientHello shape across both
the bogdanfinn hot-path and the uTLS cold-path.

### C6 — Padding constants placeholder shift

`SamplePaddingTarget` shifted from log-normal[μ=ln(48), σ=0.7], clamp
[16, 512] → [μ=ln(900), σ=0.5], clamp [600, 3000] (Mixpanel /track
public size range). `SampleHandshakePaddingTarget` shifted from
[μ=ln(28), σ=0.5], clamp [16, 384] → [μ=ln(350), σ=0.5], clamp [200,
800]. KS-divergence between the two distributions preserved (D ≫ 0.0326
critical at p<0.01). Calibration vs captured Mixpanel reference fixture
deferred to Phase 5 / S5 schema lock — guarded by
`TestPaddingDeferredCalibration_DocComment`.

### C11.1 — startRotation lifecycle race

Audit Track 4 §3.1 (MEDIUM): `cm.lifecycle`, `cm.minRotation`,
`cm.maxRotation` are read in `startRotation` without holding `cm.mu`.
Resolution: doc-comment "write-once at init, read-only thereafter; no
synchronization needed" added to the struct. All write-sites confirmed
to live in `NewConnManager` only (verified by source scan); no setter
exists. If a future setter is introduced, it MUST add an RWMutex around
these fields — guarded by `TestConnManagerLifecycle_DocsImmutable`.

## May 2026 Audit P2 — Group C Closures

### §C5 — `ackJitter` reshape

`server/handler.go::ackJitter` no longer uses the legacy exp(scale=18ms) +
hard-cap 150ms shape (which produced a detectable point-mass at p100 = 150ms).
New mixture:

- **95%** exp core: scale=7.21ms (median ≈ 5ms), soft cap 200ms.
- **5%** Pareto right-tail: α=2.0, xm=50ms, hard ceiling 1500ms.

Calibration vs real CDN nginx ACK distribution deferred to Phase 5 / S5
schema lock — current constants are best-guess preserving non-detectable
shape. Regression tests:
`TestAckJitter_HardCeilingHonored`,
`TestAckJitter_MedianApproximately5Ms`,
`TestAckJitter_ParetoTailPresent`,
`TestAckJitter_NoHardPointMassAt150Ms`.

Impact on `streamWriteTimeout` invariant: max ackJitter is now 1500ms (was
150ms); 60s write timeout still leaves 40× safety margin. Pin updated in
`TestDownloadStreamLoop_DeadlineExceedsMaxAckJitter`.

### §C10 M2 — Newborn-not-attached 30s eviction

`core.SessionManager.CleanupNewbornOrphans(now, maxAge)` evicts sessions whose
handshake completed but no transport ever attached within the grace window
(default 30s, exposed as `server.newbornOrphanMaxAge`). Wired into
`Handler.StartCleanup` ahead of the regular idle `Cleanup()`.

Mechanism: `core.Session.AttachedAt` (atomic.Int64, unix nanos) is stamped
inside `server/websocket.go::authenticateFirstFrame` on successful WS
attach — sessions with non-zero `AttachedAt` skip the orphan fast path and
fall under the regular idle timeout. Complements the client-side §C10 M5
best-effort FIN on WS upgrade failure.

Counter: `shadowlink_orphan_session_cleaned_total` (Prometheus + JSON
snapshot). A persistent non-zero rate indicates a network path where the
handshake POST succeeds but the WS upgrade fails — CF edge degradation,
NAT churn between two requests, or MITM stripping the upgrade.

### §C11 — Hot-path race-smell fixes

- **§C11.2 — `core.SetStatsCallbacks` atomic publish.** Three plain
  package-globals replaced by a single `atomic.Pointer[statsCallbacks]`
  carrying all three counters as one struct. Hot-path readers in
  `EncryptChunk`/`DecryptChunkSafe` Load once, nil-check, invoke. Closes
  the `-race` smell where concurrent Set + Encrypt could observe a torn
  intermediate.
- **§C11.3 — `MimicrySession` publish-before-map.**
  `core.NewMimicrySession()` constructor moved into `core/mimicry_session.go`
  (pure stdlib; was in `skins/browser`). `core.SessionManager.Create`
  populates `session.MimicrySession` before publishing the session into
  `sm.sessions`, giving every concurrent reader of `buildResponse` a clean
  happens-before edge to the assignment. `skins/browser.NewMimicrySession`
  preserved as a thin shim for backward compat.

## Wire-trigger followup (2026-05-02)

Followup pass on the May audit Track 2 findings. Audit document:
`docs/audit/2026-05-02-wire-trigger-followup.md`.

### F3 — Cover GET fully retired

Cover GET periodic emission was the largest open behavioral signal. Per
2026-04-28 strategic pivot, Mixpanel/SDK persona is phantom (TSPU does not
parse encrypted bodies); peer tools (Reality / Hysteria2 / TrustTunnel)
ship without cover GETs and operate cleanly inside Russia. Decision: full
retire — no scheduler, no env flag, no Prom counters. WarmupRequests
(one-shot pre-WS-upgrade burst) is unaffected and stays.

### HIGH-3 — Heavy-tail session lifetime

`SessionLifecycle.NextActiveInterval()` in `skins/browser/mimicry.go`
replaced uniform [120, 480]s with log-normal: μ=ln(300)≈5.7, σ=1.5,
truncated [60, 86400]s. Median ≈ 5min (matches old uniform center), p99
≈ 2.7h, p99.9 ≈ 8.6h — heavy right tail mimics real browser tabs that
stay open for hours. Statistical contract pinned by 6 tests in
`mimicry_lifetime_test.go` (truncation, median, p99, p99.9, chi-square
reject uniform null, log-normal moments).

### NEW-1 + NEW-4 — Jittered keepalive/cover tickers

Fixed-period `time.NewTicker` calls (20s in `ws_pool`/`ws_ready_pool`/
`proxy/socks5/tcp`, 5s + 30s in DirectTransport `client/transport.go`)
replaced with `JitteredInterval(base, jitterFraction)` from new
`client/jitter.go`. ±30% jitter on keepalives, ±50% on cover-budget
ticker, ±20% on ratio reset. Destroys FFT/ACF peaks at the prior
fixed-period frequency. `WSReadyPoolConfig.KeepaliveJitter` is a new
field with sensible default (0.3 when zero) so existing configs keep
working.

### F2 + NEW-2 + NEW-3 — Chrome 133 lockstep + sec-ch-ua headers

Four wire surfaces (uTLS JA4, bogdanfinn H2 SETTINGS, User-Agent string,
sec-ch-ua header) now align to a single Chrome major. Source of truth:
`browser.LockedChromeMajor = 133` and helpers
(`LockedUTLSChromeID`, `LockedBogdanfinnChromeProfile`, `LockedChromeUA`,
`LockedChromeCHUA`) in `skins/browser/fingerprint.go`. Why 133 — utls
v1.8.3 lacks `HelloChrome_135+` so 133 is the highest non-PSK ID
available; bumping requires utls upstream catching up.

`profileForFingerprint` in `client/connmanager.go` returns
`LockedBogdanfinnChromeProfile()` regardless of `pqEnabled()`. The PQ
opt-out env flag now only flips the cold-path uTLS spec (drops MLKEM
keyshare); the bogdanfinn hot-path stays on `Chrome_133` always. Wire
effect: same JA3/JA4 cipher list and extensions on both paths, only
key_share content differs when PQ is opted out.

`sec-ch-ua` / `sec-ch-ua-mobile` / `sec-ch-ua-platform` headers attached
at every Chrome HTTP request site: handshake POST, WarmupRequests,
WS upgrade header, BuildUploadRequest / BuildCoverTrafficRequest,
SplitTransport upload + download, decoy_traffic GET, probe HEAD, ECH
DoH POST, sendBestEffortSessionFIN. Helpers
`browser.ApplyChromeCHUAForFingerprint` (typed) and
`ApplyChromeCHUAForUA` (string) gate on the Chromium-family detection;
Safari/Firefox stay clean (they don't emit these headers in real
traces).

NEW-3: `defaultUserAgent` fallback in `skins/browser/request.go` (used
by DirectTransport when no fingerprint UA passed) was Chrome/131 via
`UserAgents[0]`. Now mirrors `LockedChromeUA()` (Chrome/133), closing a
hidden fourth Chrome major in wire surface count.

Server-side consistency cleanup (not wire-visible to TSPU):
`server/handler.go` `exportClientConfig` uses Chrome/133 too.

### Tests added

- `skins/browser/fingerprint_lock_test.go` — 9 tests covering the
  `Locked*` source-of-truth helpers + the sec-ch-ua application helpers.
- `skins/browser/mimicry_lifetime_test.go` — 6 statistical tests for
  the log-normal heavy-tail distribution.
- `client/jitter_test.go` — 8 tests for `JitteredInterval` semantics
  + `WSReadyPoolConfig.effectiveKeepaliveJitter` zero fallback.
- `client/connmanager_test.go` — old `_PQOptOut_` and `_PQDefault_`
  variants replaced with `TestProfileForFingerprint_AlwaysReturnsLockedChrome`.

## Population Fingerprint Mimicry (2026-06)

### Что

Реестр browser-профилей (Chrome 133 + Firefox 148-TLS / 147-H2) с per-client стабильным выбором, серверными весами и lockstep всех 4 wire-поверхностей как структурным инвариантом реестра. Цель: устранить кластер-сигнал TSPU «один Chrome 133 со всех клиентов» — реальная аудитория сайта = распределение браузеров и версий.

### Реестр профилей

Файл: `skins/browser/profile.go`.

Добавление нового браузера = одна запись в `allProfiles` + `validateProfile` (автоматически fail-fast при несогласованности).

**Известные gaps:**
- Safari, Edge — нет парной версии (uTLS HelloSafari не поддерживается upstream / нет bogdanfinn пары). Не добавлять до закрытия gap.
- Firefox добавлен через H2-pairing gate — SETTINGS заморожены на 133→147 (тот набор, что Chrome 133 реально видит на сервере). Firefox 148 — TLS-профиль (HelloFirefox_105 в utls как ближайший); Firefox 147 — H2-профиль bogdanfinn. Номера расходятся намеренно — utls и bogdanfinn имеют разные версии покрытия.

### Выбор профиля на клиенте

Клиент бросает кость **один раз** по весам при первом старте:
- Источник весов: `FingerprintWeights` из `ServerHello` (поле `fw`) → кэшируется в `client/fpstate.go`.
- Persist: `fp-state.bin` (atomic write, chmod 0600). Формат: JSON-сериализованный `FPState`.
- Профиль **фиксируется** (не версия) — Chrome 133 не мигрирует в 135 при обновлении. Изменение = только явная очистка state или смена весов на сервере.
- Файлы: `client/fpstate.go` (`FPState`, `ResolveProfile`, `resolveProfileWithEnv`).

### Серверные веса

YAML (`server/fileconfig.go`):

```yaml
fingerprint_weights:
  chrome: 90
  firefox: 10
```

- Передаются клиенту в `ServerHello.FingerprintWeights` (поле `fw`).
- Default при отсутствии секции = chrome 100% (безопасный режим).
- **Guardrail:** сумма весов = 0 (всё нули) логирует WARN и применяет default chrome 100%.
- ⚠ Веса должны отражать реальную популяцию РФ: Firefox ≲10-15%; Firefox >20% = сам сигнал (нетипично для аудитории). Начинать с firefox=0 (безопасно), поднимать осторожно.

### Lockstep — структурный инвариант

Профиль = согласованный набор **4 wire-поверхностей**: `{uTLS HelloID, bogdanfinn profile, UA string, sec-ch-ua}`.

`validateProfile` в `skins/browser/profile.go` проверяет заполненность всех 4 полей при старте — fail-fast.

**Важно для Chrome vs Firefox:**
- `ApplyChromeCHUAForFingerprint` / `ApplyChromeCHUAForUA` — гейтируются на Chromium-family. Firefox не эмитирует `sec-ch-ua` (real trace), соответственно хелперы пропускают эти заголовки для Firefox-профиля.
- PQ-MLKEM надстройка (`SHADOWLINK_TLS_PQ`) применяется **только для Chrome**. Firefox использует нативный key_share `HelloFirefox_*` — MLKEM не инжектируется.
- Cold-path uTLS (`split_transport_tls.go`) И hot-path bogdanfinn (`connmanager.go`) читают **выбранный профиль**.

### ENV-выключатель

`SHADOWLINK_FP_POOL=0` (или `false`/`no`/`off`, case-insensitive) → принудительно Chrome 100%, ignore весов и persist-файла.

Используется для: экстренного отката без передеплоя сервера, отладки Chrome-only поведения.

### Метрики

**Клиент** (`client/stats.go`):
```
shadowlink_age_cut_by_profile_total{profile}      # age-cut evictions по профилю
shadowlink_fingerprint_profile_active{profile}    # gauge (0 или 1) — активный профиль
```

**Сервер** (`server/metrics.go`):
```
shadowlink_handshakes_profile_total{profile}      # handshake по профилю (из UA, без client→profile binding)
```

**Приватность:** агрегат по профилю, без привязки профиля к конкретному клиенту.

### Ops-раскатка

1. Проверить baseline: `shadowlink_age_cut_by_profile_total{profile="chrome"}` — норма.
2. Поднять вес firefox в YAML pl1: `fingerprint_weights: {chrome: 90, firefox: 10}` → передеплой сервера.
3. Ждать 24-48ч — часть клиентов перевыберет профиль при следующем cold-start (или сразу, если `fp-state.bin` отсутствует / SHADOWLINK_FP_POOL сброшен).
4. Сравнить:
   - `age_cut_by_profile{profile="firefox"}` vs `{profile="chrome"}` — если firefox age-cut rate выше → РКН/TSPU режет Firefox в регионе → откатить.
   - `shadowlink_handshakes_profile_total{profile="firefox"}` — доля от общего.
5. Откатить: `fingerprint_weights: {chrome: 100, firefox: 0}` → передеплой. Клиенты вернутся к Chrome при следующем cold-start.

### Ссылки

- Спека: `docs/superpowers/specs/2026-06-09-population-fingerprint-mimicry-design.md`
- План: `docs/superpowers/plans/2026-06-09-population-fingerprint-mimicry.md`
- Реестр профилей: `skins/browser/profile.go`
- Выбор и persist: `client/fpstate.go`
- Серверные веса YAML: `server/fileconfig.go`, `server/config.go`
- Передача весов в ServerHello: `core/handshake.go`, `server/handler.go`
- Интеграция в клиент: `client/client.go` (NewClient, isValidUAForProfile)
- Метрики клиент: `client/stats.go`
- Метрики сервер: `server/metrics.go`


---

## Phase B+ (2026-05-02): Bypass routing + cold-start cascade fix

5 phases:
- Phase A — `client/bypassroute/` in-process IPv4 CIDR-trie + tun2socks dialer hook
  (`tunnel.T().SetDialer(BypassDialer)`). Embedded RIPE RU snapshot in
  `embedded_ru.bin` (regenerate via `tools/cidr-snapshot/`). No system routes.
- Phase B — admin override fullstack: migration 071, `shadowlink_bypass_cidrs` table,
  `/api/admin/shadowlink/bypass-cidrs` CRUD, frontend tab, `/api/v1/client/shadowlink/bypass`
  HMAC-signed endpoint, persistent local cache.
- Phase C — Server `TokenBucket` rate-limit v2 (`server/tokenbucket.go`). Defaults:
  WSUpgrade burst=18 refill=30/min; Handshake burst=50 refill=300/min. ClientID
  exemption (`server/clientid_exempt.go`) — LRU 10k TTL 1h, soft-limit 60/min.
  Note: exemption applies on **subsequent** handshakes (after first authenticated)
  and data-path POST. First handshake from new IP always counts against bucket.
- Phase D — Client phased warmup (`ws_ready_pool.go::WarmupPhase`, default for
  size=6: phase 0 [0] 0ms, phase 1 [1,2] +800ms, phase 2 [3,4,5] +1600ms).
  Default Size 8→6. SOCKS5 coalesce dispatcher (`proxy/socks5/coalesce.go`)
  50ms debounce + max-parallel=2 semaphore.
- Phase E — counters + `shadowlink-metrics-dump` CLI + reference Grafana board
  + alert rules. Production scrape integration explicit follow-up.

### ENV flags

| Flag | Default | Effect |
|---|---|---|
| `SHADOWLINK_BYPASS_ENABLED` | on | `=0/false/no/off` skips dialer wrap |
| `SHADOWLINK_RL_TOKENBUCKET` | on (server) | `=0` falls back to legacy sliding window |
| `SHADOWLINK_RL_CLIENTID_EXEMPT` | on (server) | `=0` skips exemption (bucket only) |
| `SHADOWLINK_PHASED_WARMUP` | on | not-set → linear stagger (legacy) |
| `SHADOWLINK_SOCKS5_COALESCE` | on | `=0` direct Acquire (no debounce) |
| `SHADOWLINK_ADMIN_OVERRIDE` | on (client) | `=0/false/no/off` skips network fetch (cached/baseline only) |
| `SHADOWLINK_GRACEFUL_DRAIN` | **ON since 2026-05-20 (Phase 3)** | HTTP/2 GOAWAY-style slot draining with uniform-cells pool: active streams survive rotation, any free cell in the 2*poolSize slice serves as drain replacement, storm brake gates on readyCapacity. `=0`/`false`/`no`/`off` is the emergency opt-out → legacy hard-rotation path. Three canaries showed natural-finish ratio 53%, 0 capacity-floor defers, 0 reader-exit regressions. |
| `SHADOWLINK_DRAIN_HARD_CAP` | 90s | `time.Duration` (e.g. `"90s"`, `"2m"`): max time a slot can stay in `slotDraining` before forced teardown. Only consulted when `SHADOWLINK_GRACEFUL_DRAIN` is on. Tune in field without redeploy. |

### Metrics added

```
shadowlink_bypass_cidr_match_total
shadowlink_bypass_cidr_miss_total
shadowlink_first_stream_ms (gauge ms)
shadowlink_pool_warmup_ms (gauge ms)
shadowlink_handshake_decoy_received_total
shadowlink_socks5_coalesce_grouped_total
shadowlink_socks5_coalesce_groups_total

shadowlink_ratelimit_burst_consumed_total{path}     # ws_upgrade|handshake|data
shadowlink_ratelimit_burst_rejected_total{path}
shadowlink_ratelimit_clientid_exempted_total
shadowlink_ratelimit_clientid_softlimit_rejected_total
```

### Rollback

Per phase см. spec §11.

### References

- Spec: `shadowlink/docs/superpowers/specs/2026-05-02-shadowlink-bypass-and-coldstart-design.md`
- Plan: `docs/superpowers/plans/2026-05-02-shadowlink-bypass-and-coldstart.md`

---

## Rotation Budget Honesty — P0 шаг 4 (2026-08-07)

Полевой день на одном AS: три сессии, пять исправленных дефектов. Общая нить —
**механизмы существовали, логи о них рассказывали, но рассказывали неправду**
(класс H-15). Ни один из пяти не был найден чтением кода: все всплыли при
сверке лога с арифметикой.

Полный разбор с числами — `docs/audit/2026-07-25-round18/FIELD-CHECKS.md`,
раздел «Результаты полевых замеров 2026-08-07».

### Status

- **`worstCaseTeardown()`** (`client/ws_pool.go`) — единственный источник истины
  для бюджета: `base + stagger + sweep + defer + tear`. Прежняя формула в
  `stats.go` (`adaptedAge + stickyMaxDrainAge`) занижала результат в 1.6 раза и
  была верна лишь по совпадению настроек `hard_cap == sticky == 15s`.
- **`staggerSpan()`** — верхняя граница вклада сетки (`cap + step/2`).
- **`ageCutFloor()`** — вынесен из `isAgeCut`, чтобы порог классификации
  age-cut имел один источник; его же спрашивает инференс.
- **`slotobs.InferWithMinAge(minAgeMs)`** — отсев доцензурных наблюдений.
  `Infer()` сохранён как `InferWithMinAge(0)` (прежнее поведение).
- **`slotobs.Verdict.AgeMinMs`** — минимум по ОЧИЩЕННОЙ выборке;
  `Summary.AgeMin` — по сырой. Бюджет сравнивается только с первым.
- **`RejectionStats.TooYoung`** — новый счётчик отсева.
- **Лог `slot death inference`** пополнен: `stagger_span`,
  `effective_max_age_max`, `sweep_tick`, `defer_backoff`, `teardown_cap`,
  `age_min_clean_ms`, `margin_to_age_min`, `rejected_too_young`.
- **WARN `rotation budget exceeded`** — при отрицательном запасе. Молчащий
  сломанный бюджет — та же болезнь H-15.
- **WARN `sticky drain backstop is UNREACHABLE`** — в конструкторе пула при
  `sticky <= hard_cap`. Настройка НЕ подменяется молча: говорим вслух,
  поведение оставляем как настроено.

### Конфигурация (`.bat`, вне репозитория — в `.gitignore`)

| ключ | было | стало | почему |
|---|---|---|---|
| `SHADOWLINK_STICKY_MAX_DRAIN_AGE` | 15s | **25s** | при равенстве с `hard_cap` ветка продления недостижима |
| `SHADOWLINK_STAGGER_STEP` | 6s (дефолт) | **1s** | лестница должна укладываться в cap без клампа |
| `SHADOWLINK_STAGGER_OFFSET_CAP` | 45s (дефолт) | **15s** | при 16 ячейках cap=45s склеивал idx 8..15 в одно значение |

### Metrics

- `no free cell`: **9 → 0** за сопоставимую сессию — дефицит ячеек был
  следствием синхронности ротаций, а не размера пула.
- Тройные пачки ротаций в одну секунду: **1 → 0**.
- `sticky_active`: **0 → до 4** — механизм заработал впервые.
- Естественные завершения дренажа: 61 против 38 sticky-teardown.
- `decrypt_fails=0`, `meltdowns_1m=0`, `dead=0` во всех трёх сессиях.

### Rollback

- Правки в коде — только наблюдаемость и очистка выборки; поведение ротации не
  менялось. Откат не требуется, но безопасен: `InferWithMinAge(0)` возвращает
  прежнее поведение фильтра.
- Конфиг: вернуть `STAGGER_STEP=6s`, `STAGGER_OFFSET_CAP=45s`,
  `STICKY_MAX_DRAIN_AGE=15s` в `.bat`. ⚠ Возврат sticky к 15s снова сделает
  механизм недостижимым — тест `TestStickyDrainBudget_HardCapNotBelowSticky`
  станет красным намеренно.

### Открытое

Бюджет **всё ещё отрицательный**: 141.5 s расчётных против `age_min` ~82 s.
Доминирует `drainRevertBackoff=30s`. Шаги «снизить teardown» и «снизить
`thresholdSafetyFraction` 0.8 → 0.55» посчитаны и **отвергнуты**: вместе дают
111.4 s (запас −29 s) ценой ~1250 conn/час, то есть лечат не то слагаемое.
Следующая цель — устранить причину `no free cell` (сессия 3 показала 0, нужна
проверка устойчивости) и `drainTargetOverAged`, который берёт сконфигурированный
порог 150 s при смертях на 82–126 s, отчего tier-2 эвикция, похоже, недостижима.

### References

- Тесты: `client/rotation_budget_test.go`, `client/slotobs/infer_test.go`,
  `client/sticky_drain_budget_test.go`
- Коммиты: `fad8bf4` (формула бюджета), `fff6f4f` (сверка доков с продом),
  `7519617` (очистка выборки, отсрочка, lockstep)

---

## Windows-классификатор, фантомный счётчик, наблюдаемость отказа (2026-08-11)

Замер 3ч38м (лог `%TEMP%\nixavpn-DEBUG-20260811-145918.log`, 5.4 МБ) вскрыл
четыре дефекта. Три из них — про то, что контур **молчит или врёт**, а не про
поведение цензора.

### Status

**1. `classifyWSReadError` не знал Windows-формулировок (cfbee55).**
WSAETIMEDOUT приходит как `wsarecv: A connection attempt failed because the
connected party did not properly respond`, без подстроки `i/o timeout`, и падал
в `other`. `filterNoise` отсеивает `io_timeout`, но не `other`.

Цена: origin упал в 15:48 на ~80 с; 6 инцидентных смертей возрастом 55–79 с
(выше `ageCutMinAge`=45 с) прошли в чистую выборку, p10 упал 84.0 → 59.7 с,
адаптер сжал порог **66 → 47 с и держал 2ч48м**. Восстановиться структурно не
мог: кольцо `slotobs` = 512 при 37 смертях не проворачивается. Ротация выросла
533 → 641 conn/час (+20%) — counting-сигнал от сетевого сбоя.
Добавлен и WSAECONNRESET (`forcibly closed by the remote host`) → `reset_by_peer`:
без него сигнал RST-инъекции на Windows недостижим в принципе.

**2. Фантомный счётчик стримов (a223cb9).** `slot.streams` держит привязки,
которых нет в `streamMap` → закрыты обе ранние ветки выхода `drainWatchdog`
(`streams==0` ложно; `allStreamsIdle` даёт `found && allIdle`=false при пустой
карте) → слот всегда доезжает до sticky-предела.

Поле: **408 из 431** sticky-teardown с расхождением, **396 ровно по 25 с**;
natural finish — **0 из 158**. Есть во всех пяти прогонах с 08-07. Правка
sticky 15→25 с (2026-08-07) баг не создала, а удвоила его цену.

Починено ПОСЛЕДСТВИЕ: рвать по карте (ground truth), а не по счётчику.
⚠ **Причина утечки декремента НЕ найдена** — нужен `-race` на сервере.

**3. Полный отказ пула при `meltdowns_1m=0` (c6c7946).** В 15:48:49 `alive=0`,
`active_streams=0`, 45 отказов `no ready slots`, 24 стрима задето — ни один
счётчик не показал. `recordSlotDeath` зовётся только для `deathCauseNatural`, а
6 из 8 смертей классифицированы как age_cut. Пропуск age_cut в кулдауне
**верен** (в этом инциденте пауза бы навредила) — добавлено отдельное поле
наблюдаемости `slot_deaths_1m`, `recentDeaths` не тронут.

**4. Backoff переспал восстановление (c6c7946).** Origin вернулся к 15:49:19,
слоты 2 и 11 досиживали attempt=3 (60 с) лишние ~50 с по здоровой сети.
Broadcast «сеть вернулась» на успешный connect.

### Правки по ревью (94bbad5)

- **CRITICAL:** предикат фантома рвал слот в окне `AssignStream` (inc счётчика
  идёт ПЕРЕД `streamMap.Store`, spec §2.5). Живой стрим был бы порван до
  публикации, канал не закрыт, соединение повисло бы до таймаута. Требуется
  **два наблюдения подряд**: утечка необратима, окно inc→Store — наносекунды.
- `attempt = -1` возвращал запрещённый 2026-05-18 цикл на rate-limit через
  новый вход (соседний слот будит зажатого). Гейт `lastWasRateLimited`.
- `signalNetworkRevival` не звался из `connectReserveSlot` — половина успехов.
- `finishPhantom` как отдельный исход: иначе 408 событий переехали бы в
  `DrainNaturalFinishTotal` и дашборд «улучшился» бы без изменения реальности.

### Metrics

Честные времена жизни слотов (n=2215, пары `reader started` → конец, **без
цензуры** `slotobs`):

```
до 15:48:51 (порог 66с): n=425  p10 69 p50 79 p90 89 max 113
после (порог 47с):       n=1790 p10 49 p50 54 p90 59 max 109
```

Чистая выборка резов (только `close 1006`, n=23): p10 83.99 / p50 92.8 /
p90 102.7 — **независимо подтверждает окно 84–118 с** замера 2026-08-07.

Фактических пробоев бюджета — **ноль** за 3ч38м; дефицит остаётся структурным
и терпимым (вердикт 2026-08-10 в силе). FLOWCTL-ack timeout: 16, все на
reserve-слотах, с нагрузкой не коррелирует.

Новая метрика `shadowlink_drain_phantom_counter_total` — сторож: если после
починки утечки декремента она не упадёт до нуля, починили не то.

### Rollback

Все четыре коммита независимы и откатываются по отдельности. Поведение ротации
не менялось ни одним из них — тайминговые константы не тронуты. Откат cfbee55
вернёт сжатие порога после любого сетевого сбоя; откат a223cb9 вернёт 25 с
удержания ячейки на каждом фантоме.

### Открытое

- **Причина утечки `slot.streams`** — подозрительна связка миграции с
  `e.slotIdx`, по логу не подтверждено. Требует `-race` на сервере
  (Windows-dev гонки не ловит, hard rule 6).
- **Окно `slotobs` по давности, а не только по ёмкости** (512 при 37 смертях за
  прогон = кольцо не проворачивается). Константу давности по одному прогону не
  вывести. После cfbee55 острота снята: инцидентные смерти теперь отсеиваются.
- **Фиксы в поле не проверены** — клиент пересобран, прогона после сборки не
  было. Что смотреть: `applied_max_slot_age` не должен сваливаться к 47 с после
  сбоя (ожидаемо ~67 с), `drain_duration=25s` должно почти исчезнуть,
  `slot_deaths_1m` — показывать провал, когда он есть.

### References

- Тесты: `client/ws_pool_drain_phantom_test.go`,
  `client/ws_pool_reconnect_revival_test.go`,
  `client/ws_pool_deaths_observed_test.go`, `client/ws_pool_anomaly_test.go`
- Коммиты: `cfbee55` (классификатор), `a223cb9` (фантом), `c6c7946`
  (наблюдаемость + revival), `94bbad5` (правки по ревью)

---

## Фаза свипа, hazard по экспозиции, capacity-floor (2026-08-14)

Независимая проверка (Fable) разбора от 08-13 по первичным логам, затем ревью
самой реализации тем же агентом. Реконструкция 622 ротаций воспроизведена бин в
бин. Исходный вопрос («срезать ли `STAGGER_OFFSET_CAP` 15s → 10s») снят: правка
**no-op** при `step=1s`. Первая реализация фазовой правки **откачена в тот же
день** — ревью показало, что она не работает. Полный разбор —
`docs/plans/2026-08-14-post-fable-fixes.md`.

### Status

- **`rotationWatchdogTick` 5s → 500ms** — период свипа и есть квант фазы новых
  TLS-соединений на wire. Замер `nixavpn-DEBUG-20260813-153638`: все 588
  age-ротаций в одной фазе 5s-сетки (σ 0.0001s, дрейфа за 2ч нет), 92.2%
  TCP-connect'ов в одном 1s-окне. Комментарий к `slotStaggerOffset` про
  размазанный FFT-пик описывал механизм, который не исполнялся: тот джиттер
  правит ПОРОГ, а порог сравнивается с возрастом только на тике. После срезки
  амплитуда джиттера (±0.5s при step=1s) впервые сравнима с квантом сетки.
- ⚠ **`SHADOWLINK_SWEEP_PHASE_JITTER` — заведён и УДАЛЁН 2026-08-14.** Отсрочка
  `uniform[0, 4s)` через `nextDrainAttemptNs` не размазывала фазу: единственный
  читатель этого поля — сам свип, а он просыпается по тому же тикеру, поэтому
  отсрочка короче тика переносила дренаж ровно на следующий тик, в ту же фазу, с
  вероятностью 1. Ручка была `bool`, замаскированный под `time.Duration` (любое
  значение из `(0, tick]` давало идентичное поведение), и платила полным тиком
  возраста: ячейки 5-9 уходили с 79.6s на 84.6s, то есть **выше p10 резов 84.4s**.
  Не воскрешать без замера.
- **`sweep` в бюджете = 2×tick**, а не 1×. Тик расходуется дважды: обнаружение
  перезревания (перешагнул порог сразу после тика) и повторная попытка после
  отсрочки гейта — прочитать её может только свип. Прежняя формула была занижена
  ровно на период; это H-15 с другой стороны, поэтому исправлено вместе со
  срезкой, а не отложено.
- **`SHADOWLINK_READY_CAPACITY_FLOOR_FRACTION`** (новый, дефолт 0.75 —
  **не изменён**) — выведен ради A/B. 3 реза из 4 в прогоне следуют за отложкой
  этого гейта в пределах 7s (RR ×21, p ≈ 1.5e-4, n=3). Причина: порог 75→70s
  сдвинул рабочую точку пула РОВНО на пол (`alive=6` при `floor=6`). Применённая
  доля теперь логируется (`ready_capacity`, `ready_capacity_floor`,
  `ready_capacity_floor_fraction`) — без этого A/B был неподтверждаем, т.к.
  `envFloatDefault` молча отдаёт дефолт на мусор вида `0,5`.
- **`HazardBand.RateByExposure()` + `ExposureMs` + `RingSaturated`** — прежний
  `Rate()` занижал вдвое (actuarial-вес 1/2 неверен, когда цензура у нижней
  кромки: плановые проживают в полосе 0.2s, а не 2.5s). Обе формы печатаются
  рядом. ⚠ `RateByExposure` не смещена ЦЕНЗУРИРОВАНИЕМ, но смещается насыщением
  ринга — там обрезается знаменатель.
- **`PlannedCapacity` = 4096** (было: ёмкость ринга резов, 512). Обоснование
  «~512 = several hours» верно для резов (2-4/час), но плановых 300+/час, и ринг
  переполнялся за ~1.7ч: в PROBE 1256 плановых при 512 → hazard делил числитель
  за весь прогон на знаменатель за последние 512 записей, завышение ×2.06. То же
  обрезание смещало `cut_share_ring` (0.0154 против истинных 0.0107).
- **Лог:** `sweep_tick` → **`sweep_budget`** (величина = 2×tick, чистый тик
  печатается рядом). Новые поля hazard-строки: `exposure_s`, `rate_exp`,
  `p_pass`, `rate_act`, `ring_saturated`.
- **Прод-настройки `.bat` не менялись**: `MAX_SLOT_AGE=70s` как было.

### Rollback

1. Тик свипа: вернуть `rotationWatchdogTick = 5 * time.Second`. Это константа без
   env — правка требует пересборки намеренно: величина влияет на фазу на wire, то
   есть на наблюдаемость клиента для ТСПУ, и менять её «на прогон» нельзя.
2. Пол storm-brake: не задавать env → константа 0.75, как до правки.
3. Hazard: `rate_act` в логе — прежняя величина, сравнимость со старыми логами
   сохранена; удалять её нельзя, пока не пересчитаны исторические выводы.
4. `PlannedCapacity`: вернуть к `len(r.buf)` — но тогда вернётся и смещение ×2.06,
   поэтому только вместе с отказом от hazard-выводов.

### Metrics

| Величина | До | После |
|---|---|---|
| Фаза age-ротаций (концентрация в модальном 1s-окне) | 92.2% | цель <40%, **нужен прогон** |
| `worstCaseTeardown()` прод | 145.5s (при 1×tick=5s) | **141.5s** (2×tick=1s) |
| hazard 80–85s, `rate_exp` | — | **14.4e⁻³ 1/с** |
| hazard 80–85s, `p_pass` (проход полосы) | `rate_act` 3.37% | **6.94%** |
| `cut_share_ring` при 740 плановых | 0.0154 (обрезка) | **0.0107** (= lifetime) |
| Экспозиция ниже 80s / резов | 52 808s / **0** | не изменилось (замер, не правка) |

⚠ Не путать единицы: `2.1%` = `Cut/Reached` (доля на ВХОД в полосу при экспозиции
0.2s) — не сравнима с `p_pass 6.94%`. Подмена этих величин уже давала неверный
вывод; см. разбор.

### References

- `docs/plans/2026-08-14-post-fable-fixes.md` — разбор, A/B-критерии, что открыто
- `CLAUDE.md` правило 9 (причина двух режимов — квантование тиком; фаза лечится
  периодом тикера) и правило 10 (cap — no-op при `(2·poolSize−1)·step ≤ cap`)
- `client/ws_pool_sweep_phase_test.go`, `client/slotobs/planned_test.go`

---

## Утечка ячеек, фаза через Timer, наблюдаемость бюджета (2026-08-14, вечер)

Первый полевой прогон после утренних правок (`nixavpn-DEBUG-20260814-115514.log`,
2ч57м) + независимый анализ. Резы обнулились (0 против 4), экспозиция в опасной
полосе упала 2.6-5.7x. Но анализ нашёл три вещи, две из которых опровергли мои
собственные выводы. Разбор — `docs/plans/2026-08-14-run2-fixes.md`.

### Status

- **Утечка ячеек в reconnect/recycle ЗАКРЫТА** (первопричина резов базового
  прогона). `placeholder freed` → `reconnecting slot N` → дренаж забрал ту же
  ячейку → recycle guard делал голый `return` → ячейка терялась НАВСЕГДА, потому
  что периодического healer'а ёмкости в пуле нет. В поле: `empty` 8→9→10→11,
  `mean alive` 7.21→5.80 за 2ч. Теперь guard отказывается от ЯЧЕЙКИ, но
  восполняет ЁМКОСТЬ на свободной (`claimFreeCellForHealing`, предел
  `maxHealingRetargets=3`, счётчики `healing_retargets_total` /
  `healing_gave_up_total`). Лечение УСЛОВНО — только при недостаче живых слотов:
  лишнее TLS к origin это P0.
  ⚠ **Гонка «два обрыва выберут одну ячейку» оценивалась неверно** (ревью 08-14).
  Комментарий у `claimFreeCellForHealing` утверждал: «безвредно, connectSlot пишет
  под reserveMu, второй перезапишет первого, лишним будет одно соединение».
  Перезапись ЖИВОЙ ячейки стоит дороже: старый transport не закроет никто (все
  `Close()` идут через `slotAt(idx)`, т.е. уже по новому указателю), старый
  `slotReader` не выйдет (`shouldExitReader` сравнивает `generation` своего
  объекта, а бампается `generation` нового), и этот ридер на своей ошибке чтения
  позовёт `handleSlotDeath` **по индексу**, убив свежий слот; `slot.streams`
  старого объекта навсегда уйдёт из `readyCapacity`. Закрыто у писателя:
  `connectSlot` проверяет ячейку через `cellIsOverwritable` под тем же
  `reserveMu` и возвращает `ErrCellOccupied` для `slotReady`/`slotDraining`.
  Заодно закрыты два пути, где гарантии не давал никто изначально —
  повторный `Connect` fan-out и `legacyRotateOneSlot`. `ErrCellOccupied` не
  считается отказом origin ни в `reconnectLoopInner`, ни в `connectReserveSlot`.
- **Диагноз capacity floor ОПРОВЕРГНУТ хронологией.** Утверждение «порог 75→70s
  посадил пул на пол» неверно: до первой потери ячейки (15:42:12) гейт не
  срабатывал ни разу, первая отложка 15:44:32, все 22 при `ready=5`, а `ready=5`
  достижимо только после потери двух ячеек. Настоящая цепочка: **утечка → alive до
  пола → отложка → +возраст → рез**. A/B по доле обесценен: критерий
  `capacity_floor_deferred_total → 0` выполняется сам (в прогоне уже 0 при
  неизменной доле 0.75). Понижать долю нельзя — замаскирует остаточную утечку.
- **Фаза: `Ticker` → `Timer` с перевзводом `tick + uniform[0, tick)`.** Срезка
  периода 5s→500ms убила линию 0.2Гц (vector strength 1.0000 → 0.0096), но пик
  ПЕРЕЕХАЛ на 2Гц (R=0.8657 на периоде 500ms; по `reader started` 0.598 → 0.553,
  то есть не изменился). Причина не в величине периода, а в его ПОСТОЯНСТВЕ.
  Джиттер сэмплируется заново каждый взвод (`nextWatchdogWakeup()` — вынесен
  функцией ревью 08-14, потому что тест держал СВОЮ копию формулы и на снятие
  джиттера в цикле не отреагировал бы).
  ⚠ **Развязан момент нового СОЕДИНЕНИЯ, но не момент ЗАКРЫТИЯ** (ревью 08-14).
  `startDrain` зовётся из свипа и сразу спавнит `connectReserveSlot`, поэтому
  `reader started` едет на джиттерованном расписании. Фактический teardown делает
  `drainWatchdog` по своему `time.NewTicker(drainPollInterval=500ms)`
  (`ws_pool_drain.go:805`) — он остался жёстким, и на wire живёт вторая сетка 2Гц
  по close. Замер R=0.8657 брался «по моменту дренажа», т.е. по ней, и от этой
  правки упасть не обязан. «Решётки не остаётся» было сильнее данных.
  ⚠ Мой критерий «доля в модальном 1s-окне сетки 5s» (100% → 21.4%) был
  ТАВТОЛОГИЧЕН: падает автоматически при любом тике <1s, то есть измеряет ручку,
  а не наблюдаемость. Правильный критерий — **R < 0.2 по `reader started`**.
- **`sweep` в бюджете = `sweepWorstCase()` = 4 × tick.** Два пробуждения по
  `tick + jitter`. Формула ошибалась дважды за день: `1×tick` (не учтено второе
  пробуждение после отсрочки гейта) → `2×tick` (не учтён джиттер).
  `worstCaseTeardown()` = 142.5s.
- **Гейт наблюдаемости снят.** `worst_case_teardown` и слагаемые жили только в
  строке `slot death inference` (выходит при `samples >= 12`). Резов ноль →
  строка молчала 3 часа → правка бюджета была НЕПРОВЕРЯЕМА замером. Бюджет
  считается из конфигурации и от выборки не зависит; теперь печатается и в ветке
  нехватки выборки, с `margin_to_age_min="n/a"` (он выборку требует).

### Rollback

1. Лечение ёмкости: убрать ветку `claimFreeCellForHealing` в `reconnectLoopInner`
   — вернётся утечка ячеек, диагностируемая по монотонному росту `empty`.
2. Фаза: `Timer` → `time.NewTicker(rotationWatchdogTick)` (и удалить
   `nextWatchdogWakeup`) — вернётся решётка на 2Гц по новым соединениям.
   Величину периода при этом менять не нужно.
4. Условная установка ячейки: убрать проверку `cellIsOverwritable` в
   `connectSlot` и ветки `ErrCellOccupied` у двух вызывающих — вернётся риск
   осиротить живой transport/ридер в микроокне лечения.
3. Бюджет в ветке нехватки выборки: удалить блок `budget_*` — вернётся
   непроверяемость.

### Metrics

| Величина | База 08-13 | Прогон 08-14 | После правок |
|---|---|---|---|
| резы | 4 (1.96/ч) | **0** | — (нужен прогон) |
| экспозиция >82s | 109.8 с/ч | **41.6 с/ч** | — |
| `R` на периоде тика (`reader started`) | 0.598 | 0.553 | цель **<0.2** |
| `worst_case_teardown` | 145.5s | 141.5s | **142.5s** |
| `mean alive` | 7.21 → 5.80 (утечка) | 7.95 | цель: без просадки |
| conn/ч на живую ячейку | 48.0 | 48.8 | — |

⚠ Ноль резов — слабое доказательство: P(0|2.2 ожидаемых) = 11%. Значима
экспозиция, не нулевая цифра.

### References

- `docs/plans/2026-08-14-run2-fixes.md` — замер, что опровергнуто, что открыто
- `CLAUDE.md` правила 9 (фаза, бюджет), 10 (cap), **11 (утечка ячеек)**
- `client/ws_pool_drain_test.go`: `TestReconnectLoop_RecycleHealsCapacity`,
  `TestReconnectLoop_RecycleNoHealWhenPoolFull`,
  `TestClaimFreeCellForHealing_CountsOnlyLiveStates`,
  `TestConnectSlot_RefusesToOverwriteLiveCell`
- `client/ws_pool_sweep_phase_test.go`: `TestRotationWatchdogLoop_WakeupsAreNotOnAGrid`,
  `TestSweepWorstCase_CoversJitteredWakeups`

---

## Замер прогона 161915: фаза развязана целиком, sticky остался один (2026-08-14)

Полевой прогон 4ч после a0dfe86 + f2d577a. Все четыре правки подтверждены замером;
ДВА прогноза предыдущей секции оказались неверны в свою пользу. Разбор —
`docs/plans/2026-08-14-run2-fixes.md`.

### Status

- **Фаза развязана ЦЕЛИКОМ, включая момент close.** Прогноз «развязано наполовину,
  для close нужна отдельная правка drainPollInterval» ОПРОВЕРГНУТ. R на уровне шума
  (1/√n=0.025) по всем событиям: `reader started` 0.0330, `drain started` 0.0464,
  close 0.0447 — против 0.5892 / 0.9541 / 0.9655 в базе. Слепой скан 0.05-6.0s
  шагом 5ms: max R=0.063, линий нет вовсе.
  **Механизм — ЯКОРЬ**: сетка `drainPollInterval` жива на 100% относительно старта
  дренажа (R((close−drain_start) mod 500ms)=1.0000, 1575/1575 в одном 50ms-бине;
  на подвыборке многотиковых дренажей delta>0.75s, n=208 — тоже 1.0000, delta
  кратна 500ms с остатком <=4ms, что и доказывает тикер: 87% дренажей закрываются
  на первом тике и дают delta=0.500s константой, по которой R=1.0 тривиален),
  но её фаза наследуется от `startDrain`, а тот приходит из джиттерованного свипа.
  → Правка `drainPollInterval` СНЯТА как ненужная. Это зависимость, а не свобода:
  возврат свипа к time.NewTicker немедленно проявит решётку в close без правок в
  дренаже (наблюдалось в прогоне 115514: R=0.8933).
- **Утечка ячеек вылечена, доказано срабатыванием.** `healing_retargets_total=2`,
  `healing_gave_up_total=0`, `short-circuited=0` (в базе 2 — те и теряли ячейки).
  alive по квартилям: база 6.97→6.49→5.92→5.87 (деградация), новый
  7.92→7.97→7.93→7.96 (плоско 4ч, `alive<7` в 1 снимке из 481).
- **Резы: 0 за 4 часа** (база 1.97/ч). `capacity_floor_deferred=0`, балансы
  1551/1551/1551, `decrypt_fails=0`, 0 ERROR.
- **Наблюдаемость бюджета работает**: `worst_case_teardown=2m22.5s` печатается 16
  раз при `samples=0`, формула сходится точно (70+15.5+2+30+25). `ring_saturated=false`.
- **НОВОЕ: sticky — главный источник хвоста, но НЕ единственный.** 77% перебега
  >82s (196.8 из 254.0s), остальные 23% (57.3s) — natural finish. Соединений >85s
  всего 17: sticky 12 (max 102.6s), natural 5 (max 95.0s). Все 50 sticky-teardown —
  `age_backstop` и `drain_duration=25s` РОВНО, то есть каждый упёрся в
  stickyMaxDrainAge. Добавлены `slot_age` во ВСЕ ветки teardown (drain_duration в
  ветке age_backstop константа и о риске молчит) и счётчик
  `age_exposure_over_threshold_ms`, накапливаемый на общем пути `tearDown`
  (порог 82s: плановые массово идут через 80.2s и забили бы счётчик штатной
  работой). Константу НЕ трогали — 0 резов за 4ч.

  ⚠ **Ревизия по итогам независимой перепроверки лога (n=1575).** Две правки:
  (1) накопление счётчика перенесено из `emitStickyTeardownLog` на общий путь —
  в sticky-ветке он видел 77% перебега и недосчитывал 23% в безопасную сторону,
  причём слепая зона растёт вниз по порогу (при 80s sticky даёт уже 66%);
  (2) снято утверждение «при 49.2 с/ч ожидается ~1 рез за 4ч»: 49.2 с/ч — перебег
  за **85s**, за 82s он 63.4 с/ч, и произведение на `rate_exp` даёт **3.7**
  ожидаемых реза, а не 1. При наблюдённых 0 модель замером ОТВЕРГАЕТСЯ; счётчик
  читать как тренд, а не как прогноз числа резов.

### Rollback

1. `slot_age` / `age_exposure_over_threshold_ms` — только наблюдаемость, поведение
   не меняют; удаление безопасно, но вернёт слепоту к главному оставшемуся риску.
2. `ageExposureThreshold` — порог НАБЛЮДЕНИЯ, менять можно без замера, но
   исторические значения счётчика станут несравнимыми (поэтому порог печатается
   рядом со счётчиком — в health-логе и как отдельная Prom-gauge).
3. Накопление на общем пути (`accrueAgeExposure`) откатывать в sticky-ветку
   нельзя: 23% перебега станут невидимы. Сторож —
   `TestAgeExposure_AccruedOnAllTeardownPaths`.

### Metrics

| Величина | База 08-13 | Утро 08-14 | Прогон 161915 |
|---|---|---|---|
| резы | 4 (1.97/ч) | 0 | **0 за 4ч** |
| R @0.5s (close) | 0.9655 | 0.8933 | **0.0447** |
| mean alive | 6.31 (деград.) | 7.96 | **7.95 (плоско)** |
| экспозиция >82s | 109.6 с/ч | 41.5 с/ч | 63.4 с/ч |
| из неё sticky | 23.0 с | 108.8 с | **196.8 с (77%)** |
| из неё natural finish | — | — | 57.3 с (23%) |
| conn/ч на живую ячейку | 48.3 | 48.8 | 49.4 |

### References

- `docs/plans/2026-08-14-run2-fixes.md` — полный разбор, что закрыто, что открыто
- `CLAUDE.md` правило 9 (фаза + якорь), 11 (утечка), **12 (sticky)**
- `client/sticky_stream_test.go`: `TestAgeExposure_CountsOnlyOverThreshold`,
  `TestAgeExposureThreshold_AbovePlannedRotationBand`,
  `TestAgeExposure_AccruedOnAllTeardownPaths`
- `client/ws_pool_sweep_phase_test.go`:
  `TestRotationWatchdogLoop_UsesJitteredTimerNotTicker` — сторож якоря фазы

---

## DoH: резервный апстрим, маршрутные сторожа, удаление ECH (2026-08-26)

### Status

Выпущено в **v0.2.1**. Повод — августовская волна: РКН рвёт DoH/DoT к Cloudflare
и Google на TLS-хендшейке (`ECONNRESET` / тишина после ClientHello; замеры
bypassblock 21.08, жалобы с 22.08 — Ростелеком, Дом.ру, Таттелеком, SkyNet).
Позиция оспорена (главред Runet: CF и 8.8.8.8 режут давно, роста сбоев нет), но
проверка кода вскрыла настоящую хрупкость независимо от новизны события.

**Data path прода волной НЕ затронут структурно.** При `origin=` клиент дайлит
голый IP, `CDNDomain` обнуляется, DNS в data path отсутствует
(`engine/engine.go:223-234`: «there is no DNS for the data path»). Затронута была
только DoH-нога split-DNS в TUN-режиме.

### Что сделано

1. **Резервный DoH-апстрим** — AdGuard unfiltered `94.140.14.140`. Выбран
   ЗАМЕРОМ, не репутацией: живой дозвон с нашим ALPN (`http/1.1`,
   `ForceAttemptHTTP2:false`) дал Quad9 → **HTTP 505**, AdGuard и CF → 200.
   Переход на HTTP/2 запрещён hard rule 4. `1.0.0.1` отвергнут явно: в
   августовской блокировке назван вместе с `1.1.1.1` — второй edge лечит аварию
   узла, а не блок оператора.
2. **Один ретрай**, только на ТРАНСПОРТНЫХ отказах. Валидный DNS-ответ любого
   Rcode (NXDOMAIN/NODATA) — успех уровня транспорта, ретраю не подлежит.
   Тайминги НЕ менялись (hard rule 8): две попытки по 3 с не влезают в overall
   4 с, поэтому попытки делят ОСТАТОК бюджета (`dohAttemptContext`).
3. **Yandex-фолбэк для не-A** (MX/TXT/SRV/PTR/NS/SOA/CNAME). HTTPS/SVCB (type 65)
   — **fail-closed**: защиты A-пути (`yandexIsRU`, `containsStubIP`) работают
   через `a4Set`, то есть по `*dns.A`; у type-65 `ipv4hint` лежит в SvcParam,
   stub-фильтр его не видит, а подменённый `ech=` снял бы ECH.
4. **Guard в `BypassDialer.route()`** — пиннутые DoH-апстримы короткозамыкаются
   на туннель ДО опроса trie. Закрывает увод через `AdminOverride.Adds`
   (фетчится с админ-сервера). Не Exclude в `Load`: `route()` — единственная
   точка решения для tun2socks (TCP и UDP), покрывает `Resolved` любого
   происхождения и не трогает `SnapshotPrefixes` (allow-правила leakguard).
5. **Удалена мёртвая ECH-ветка** (резолв `ECHConfigList` из DNS HTTPS-записи).
   Исполнялась только при `cdn=` + `ech=1` БЕЗ `origin=`/`sni=` — CDN-режим,
   запрещённый hard rule 1; нигде не сконфигурирована; результат в TLS не
   применялся (MVP-заглушка). GREASE ECH из Chrome-профиля НЕ тронут. Формат
   `sl://` совместим: `ech=1` принимается и игнорируется.

### Ключевой урок: дефект НА СТЫКЕ двух правок

Пункты 1 и 4 делались параллельно, каждый корректен и полон в своих границах.
Но guard сравнивал адрес с ОДНОЙ константой, а апстримов стало два — **резерв
остался незащищённым**. Скверно вдвойне из-за момента: резерв дайлится ровно
тогда, когда основной уже заблокирован.

Поштучная приёмка (чтение диффов + проверка власти порчей) это НЕ поймала.
Нашёл сторонний ревьюер, запущенный по объединённому диапазону после слияния.

→ После слияния параллельных правок нужен ОТДЕЛЬНЫЙ проход по
`git log -p <base>..HEAD`, а не сумма приёмок. Красный флаг класса: одна правка
обобщает сущность (один → список), другая защищает её частный случай.

### Комментарий врал о механизме

`ech.go:25-26` утверждал «routed through the tunnel by BypassDialer». Неверно:
дайлер — голый `net.Dialer` (`utls_http.go buildUTLSHTTPClientCommon`), в
туннель пакет попадает ТАБЛИЦЕЙ МАРШРУТОВ ОС (нет /32 escape + split 0/1+128/1
+ /16-sweep пропущен при origin-pin), и только в TUN-режиме. Это привело к
неверной формулировке в разборе. Комментарий переписан на точный.
Та же болезнь: `DoHUpstreams()` называл резервом Quad9 (отвергнут замером),
`upstream.go` ссылался на несуществующую `dohAttemptBudget`.

### Сторожа

Защита DoH-маршрута **эмерджентна** — свойство трёх независимых решений, ни одно
не документировано как «это защищает DoH». Поэтому:

- `TestDoHServerIP_HasNoEscapeRoute` — /32, /16-sweep (через `coversIP`: sweep не
  называет IP по имени), дрейф самой константы через `client.DoHServerIP()`;
- `TestDoHUpstreams_HaveNoEscapeRoute` — итерирует ВЕСЬ список апстримов;
- `TestBuildEscapePlan_YandexAlwaysEscapes` — ОБРАТНЫЙ знак: Yandex обязан иметь
  /32 (plain UDP direct by design), DoH-IP не должен иметь ни одного;
- `TestDoHUpstreams_AdminOverrideCannotExposeAny` — обе формы override (/24, /32)
  для каждого апстрима;
- `TestDoHUpstreams_AllPinnedInBypassroute` — про ПОЛНОТУ: третий апстрим,
  добавленный в `DoHUpstreams()` но не пиннутый в bypassroute, краснит его.
  Поимённая сверка констант пропустила бы — ровно как исходный guard пропустил
  второй апстрим;
- `mobile/deps_test.go` — `client/dnsproxy` в forbidden: у мобильного фасада нет
  split-маршрутов (TUN поднимает платформа, `SystemVPN=false`), поэтому
  форвардер, приехавший молча, слал бы открытый ClientHello с физического NIC.

Власть КАЖДОГО проверена порчей. Важно: порчу проверять ПО СУЩЕСТВУ (guard
читает только `[0]`), а не по форме (изъять элемент) — второе краснеет по
проверке длины и защиту не доказывает.

### Metrics (полевой прогон 114426, 28 мин, TUN + принудительный отказ CF)

| Величина | Значение |
|---|---|
| **Резерв спас запрос** | **да** — CF `context deadline exceeded` → adguard за 578 мс |
| SERVFAIL | **0** |
| Арбитражи DNS | 226 (214 foreign, **9 censored**, 3 yandex) |
| Резы слотов | **0** на 178 плановых ротаций |
| alive / dead / meltdowns | 8 / 0 / 0 |
| Паники, fatal | 0 |
| Следы ECH в логе | 0 |
| Утечка ячеек (`healing_retargets`) | 0 |

⚠ Прогон КОРОТКИЙ (28 мин): отвечает на «сломали ли» и «работает ли резерв», но
не на хвост возрастов под нагрузкой. Отказ CF вызван локальным firewall-правилом,
а не ТСПУ — то есть проверена достижимость AdGuard из сети разработчика, НЕ из
абонентской сети РФ.

### Открыто

- cold-start и `NewDoHKeepAliveClient` — на `1.1.1.1` без ретрая;
- `TestDoHResolver_RetryRespectsCallerDeadline` почти тавтологичен: транспорт
  отдаёт ошибку мгновенно, деление бюджета не проверяется;
- `tcbit_test.go:120` флейкует на Windows (исчерпание эфемерных портов) — не
  наше, но мешает CI;
- достижимость AdGuard из РФ не замерена.

### References

- Коммиты `4a82292`, `6b1dc22`, `4b14ac1`, `ce51f6b`, `2c17650`, `c8744cb`
- Тег `v0.2.1`
- CLAUDE.md hard rule 1 (DIRECT), 4 (nginx/HTTP-2), 8 (тайминги)

---

## Фаза: разбор внешнего ревью интеграции (2026-08-31, v0.3.0)

**Повод.** Команда клиента NixaVPN интегрировала протокол в приложение под
macOS/iOS и прислала разбор с полевыми замерами
(`ShadowLink-Protocol-Review-2026-08-31.md`). Из 12 проверяемых утверждений
7 подтвердились, 2 оказались неверны, 3 — частично.

### Главное: пуловый UDP был сломан

`proxy/socks5/udp.go` и `inprocess.go` шифровали кадр `cl.Session()` —
глобальной сессией начального handshake, — тогда как в WS-пуле **каждый слот
делает свой handshake и имеет свои ключи**. Сервер разрешает сессию один раз на
апгрейде (`server/websocket.go:159`) и расшифровывает все последующие кадры
только сессией этого слота, поэтому кадр с чужим ключом отбрасывался через
`continue` (`websocket.go:917-919`) — **без строки лога и без метрики**.

| | |
|---|---|
| Симптом у интегратора | UDP ASSOCIATE висел до обрыва, **ноль** разрешений DNS; TCP через тот же пул работал |
| Почему дожило до поля | в режиме single-WS дефект не воспроизводится, а сквозного теста UDP через пул не было (стабы не имеют per-slot сессий) |
| Кого задевало | мобильный фасад — всегда (`WSPool: true` жёстко, `mobile/config.go:196`); десктопный TUN — тоже (`inprocess.go`) |
| A/B на живом pl1 | с дефектом — `i/o timeout`, без ответа; с правкой — валидный DNS-ответ, `ANCOUNT=2` |

Правка: `AssignStream` до резолва сессии → `client.StreamSession` →
`client.StreamWrite`, причём сессия резолвится **на каждую датаграмму**, иначе
она устареет при миграции стрима между слотами.

### Наблюдаемость (следствие того же дефекта)

Молчаливый отброс кадров был невидим и в логах, и в метриках. Добавлены
`ws_frames_discarded_total{reason=undecryptable|replayed}` и
`ws_first_frame_auth_rejected_total`; серии присутствуют при нуле, иначе алерт
«> 0» никогда не вычисляется. Логировать эти ветки нельзя — атакующий забил бы
диск.

### Три комментария описывали механизмы, которых нет

1. `client/transport.go` обосновывал `InsecureSkipVerify` «пином X25519-ключа
   сервера». **Пина нет** — `HandshakeClientState.ServerPub` хранится и никогда
   не сравнивается, подписи над ServerHello тоже нет. Реально сервер
   аутентифицируется тем, что только владелец статического ключа расшифрует
   `clientID`, который входит в HKDF-info; клиент это проверяет, открывая
   `EncryptedSessionToken`. Прочность = секретность `clientID`, долговременного
   общего секрета **без ротации в протоколе**. Сторож — `core/server_auth_test.go`.
2. `Rekey`/`RekeyNeeded` обещали «раз в час либо при `sendSeq` → 2^32», но вне
   тестов не вызываются. Ключи меняются ротацией слотов; гейт переполнения
   `sendSeq` не проверяет **никто**. Включение блокировано C13.
3. `handleControl` говорил «Control chunks handle rekeying» — заглушка над
   keepalive.

### Логи и утечка секрета

8 per-stream строк понижены Info→Debug (по 2 на CONNECT — это и был весь объём,
а не периодика пула, как решил интегратор). `clientID` больше не пишется в лог
целиком: он одновременно секрет HKDF и ключ авторизации, а
`slog.Info("management: client added", …)` отправлял его в log shipping. Замена —
усечённый SHA-256: корреляция added↔removed сохраняется, вход не восстановим
(префикс не годился — прод-формат `u42:d1` слишком короток).

### Дефект деплоя, найденный при развёртывании этой же фазы

`build-server.sh` печатал `/usr/local/bin/shadowlink-server`, а systemd на pl1
запускает **`/opt/shadowlink/shadowlink-server`**. Деплой обновил копию, которую
никто не запускает, и **все обычные проверки прошли**: scp успешен,
`is-active` → active, логи чистые, md5 на «обновлённом» пути совпал. Прод
работал на сборке от 10 августа. Поймано только по отсутствию новых метрик в
`/metrics`. Скрипт теперь читает путь из `ExecStart`; приёмка — md5 по этому
пути плюс сквозной трафик.

### Что осталось НЕ измеренным (и почему прежний вывод снят)

В `ExecStart` на pl1 стоит `-flow-max-window 4194304`, то есть серверный потолок
**4 МиБ**, а не дефолтный 1 МиБ. Поэтому объяснение замера интегратора через
«сравнили 1 МиБ с 1 МиБ» **не держится**: связывал клиентский 1 МиБ, и подъём
`SHADOWLINK_FLOW_WINDOW` до 6 МиБ должен был дать эффективные 4 МиБ. Роль окна
остаётся **не измеренной**, а не опровергнутой. Согласованное значение читать из
FLOWCTL-ack, а не из конфигов сторон.

Прочее открытое: параллельные потоки (одиночное наблюдение интегратора —
4 загрузки дали 10.3 Мбит/с против 46.4 у одной, повторить не удалось);
метрика доли Chrome 133; ротация `clientID` в протоколе.

### Новое

`tools/facade-probe` — поднимает мобильный фасад ровно как нативка
(`NewConfig → NewSession → SetEventHandler → Start`) и держит SOCKS5 открытым.
Отвечает за минуту на вопрос «ключ протух или клиент сломался». Юнит-тесты этого
не покрывают: `mobile.Session` имеет seam `newEngine`, который тесты подменяют
фейком, поэтому реальный движок в `go test ./mobile/` не стартует ни разу.
`flow_max_window` теперь настраивается через YAML (был недостижим: прод идёт
`-config` без флагов, а `main.go` затирал YAML безусловно).

### References

- Коммиты `14f47bd`, `65e6540`, `1cc1d18`, `0cae455`, `2775257`, `94010c3`,
  `d89ac4f`, `9d0709b`
- Тег `v0.3.0`
- CLAUDE.md hard rule 5 (единственная копия — дополнено про путь на сервере),
  hard rule 9 (оговорка про `udp_polls = 0`)

### Приёмочный прогон 2026-08-31 (после v0.3.0)

Короткий прогон `connect-vpn-DEBUG.bat` (`-system-vpn`, 4 мин 17 с) — проверка
«не сломано ли», не замер.

| Величина | Значение |
|---|---|
| Паники, fatal | **0** |
| `no session for stream` (новая строка правки UDP) | **0** — `AssignStream` срабатывает |
| `decrypt_fails` | **0** |
| socks_connects | 267 |
| Трафик | 305 МБ uplink / 242 МБ downlink |
| Резы слотов | 4, возрасты **91.4 / 92.5 / 100.7 / 101.6 с** — прежнее окно, ось возраста |
| keepalive `slots` | 8…13, то есть дренируемые слоты охвачены |
| `healing_retargets_total` | 3 при `empty=4` — холодный старт, пул ещё разворачивался |

⚠ Прогон **не проверяет главного — UDP через пул**: `-system-vpn` гонит трафик
через tun2socks, и UDP-ветка (`inprocess.go`) задействуется только если
приложение реально шлёт UDP (QUIC/HTTP-3). Чистая проверка UDP — A/B через
`tools/facade-probe` (см. выше в этой фазе).
⚠ `alive=10` при `poolSize=8` и `empty=4` — артефакт холодного старта на
4-минутном прогоне, не утечка ячеек. Для суждения об утечке нужен прогон часами
(hard rule 11).

## Фаза: разбор дополнения к внешнему ревью (2026-09-01)

Команда клиента прислала дополнение к разбору 2026-08-31: правки v0.3.0
подтверждены полем (UDP 8/8 за 0.31 с), обвал на параллельных потоках **снят
ими самими** как артефакт источника раздачи (403 на крупные файлы). Осталось
два открытых вопроса, и по обоим причина оказалась **на нашей стороне**.

### 1. «UDP через sing-box 33 %» — дефект наш, а не sing-box

Их формулировка: прямой ASSOCIATE 8/8, через sing-box 242/485 (33 %), «есть ли
догадка, как sing-box держит ASSOCIATE-сессии». Догадка не понадобилась —
механизм читается в коде.

`proxy/socks5/udp.go` пиннил **полный адрес** первой датаграммы (IP + порт) и
слал туда **все** ответы, принимая при этом uplink с **любого** порта того же
IP. Клиент, мультиплексирующий несколько UDP-потоков через одну ассоциацию с
разных source-портов (sing-box — один сокет на запрос в полёте), получал ответы
только на первый поток.

⚠ **Ключевой урок: ручная проверка структурно не способна поймать этот дефект.**
У одиночного сокета пин и реальный отправитель совпадают, поэтому «8/8 руками»
было не опровержением, а **следствием метода проверки**. Дефект жил ровно в
зазоре между тем, как проверяем мы, и тем, как пользуется реальный клиент.

**Правка** (оба пути — WS и poll, второй живой в трёх конфигурациях, hard rule 8):
`udpSenderSet` маршрутизирует ответ **по адресу назначения**, а не «последнему
заговорившему». Выбор не косметический: «последний побеждает» прошёл бы
двухсокетный тест и всё равно путал бы ответы при чередовании — тот же класс
дефекта уровнем ниже. Граница безопасности не тронута: чужой source IP
по-прежнему отвергается (H4).

Попутно, тем же разбором, ещё три дефекта жизненного цикла:
1. `conn.Read(waitBuf)` считал **любой байт** в контрольном TCP концом
   ассоциации, возврат не проверялся → клиент с keepalive рвал себе релей.
   RFC 1928 завершает ассоциацию по **закрытию**. Теперь `waitForControlClose`.
2. `REP=0x00` уходил **до** проверки сессии → клиент считал ассоциацию живой над
   мёртвым релеем и ждал собственного таймаута вместо фейловера. Теперь ответ
   пишется последним, когда релей действительно пригоден.
3. Все отбросы на UDP-пути были **молчаливыми** — ни лога, ни счётчика.

### 2. Наблюдаемость: почему 33 % были невидимы с нашей стороны

Единственная UDP-смежная метрика — серверный
`shadowlink_ws_frames_discarded_total` — **молчит по построению** для датаграммы,
отброшенной до того, как она вообще запечатана. Снято с прода в момент разбора:
`undecryptable` = 20, `replayed` = 0 за 26.4 ч — то есть чисто, и это верно, но
об UDP не говорит ничего.

Добавлены `udpDropCounters` (7 причин) + агрегат
`shadowlink_udp_datagrams_dropped_total` в клиентском Prometheus + поле
`udp_drop_reasons` в строке статистики, **только когда ненулевое** (их §2.6 —
1.9 млн строк за сутки; постоянный «0» стоит объёма и читается как здоровье).
Логировать ветки нельзя — забьют диск; это тот же вывод, к которому пришли на
сервере для undecryptable.

Связь `proxy/socks5` → `client.Stats` сделана записью из `Add()` и хуком
`SetUDPDropReporter` (обратного импорта быть не может), и **прикрыта сторожем** —
такая связь рвётся молча.

### 3. Потолок на поток: наблюдение верное, объяснение — нет

Их вывод «стрим привязан к одному слоту = одному TCP, одиночный TCP через 241 мс
столько и даёт, значит не дефект, а свойство схемы» — **неверен**:

- потолок задаёт **клиентское окно 1 МиБ** (`ws_pool.go`): 1 МиБ / 0.241 с =
  **34.8 Мбит/с**; наблюдаемые 23 — 66 % от него, остаток съедает возврат
  кредитов;
- 187 Мбит/с на 8 потоках = **23.4 Мбит/с на поток**: при восьмикратной нагрузке
  на общий тракт поток не теряет ничего, то есть общего окна уровня
  сессии/слота/TLS на этой скорости нет — ограничение строго на поток.

⚠ Первая редакция содержала «одиночный TCP дал бы ~199 Мбит/с, на порядок
больше» — **снято как сильнее данных**, дважды. (1) 199 Мбит/с при 241 мс
требует приёмного буфера ~5.7 МиБ; это автотюненный максимум, а не «обычный
`tcp_rmem`» (дефолт Linux — 128 КиБ), и клиент у них вообще macOS/iOS, где мы
буфер не мерили. (2) 199/23 = 8.6×, что не «порядок». Вывод (BDP не
ограничитель) верен, но держится он на линейности их собственных замеров, а не
на подставленной константе. Тот же класс ошибки, что и «8 × 23 ≈ 187»: 8 × 23 =
184, и записывать надо было деление 187/8, которое ничего не округляет.

⚠ Почему **оба** их замера с окном дали шум: согласование берёт
`min(client, server)` (`server/stream_credit.go`), поэтому серверный
`-flow-max-window 4194304` на pl1 потолок не поднимает, пока клиент просит 1 МиБ.

⚠ И ручки у них физически не было: единственный вход — `os.Getenv`
(`stream_flow.go`), а в `mobile/` и `engine/` окна не было ни одного упоминания.
В extension на iOS env выставить нечем. Добавлены `WSPoolConfig.FlowWindow` →
`engine.Config.FlowWindow` → `mobile.Config.FlowWindowKB` (килобайты: gobind не
переносит uint64), env остаётся fallback'ом.

### 4. Стенд, который поймал бы это раньше

`tools/facade-probe -check-udp` резолвит несколько имён через **одну** ассоциацию,
каждое со **своего** сокета, и печатает результат по портам. Одиночный сокет
измеряет не тот класс отказов, который дошёл до поля.

**Проверено на живом проде (104.222.177.67), A/B:**

| Конфигурация | Результат |
|---|---|
| с правкой | **4/4** с четырёх разных портов, TCP тоже OK |
| дефект возвращён | **1/4** — отвечает только первый сокет, счётчики отбросов МОЛЧАТ |

Подтверждены две вещи: дефект реален и правка его снимает.

⚠ **Строка «дефект возвращён» исправлена при ревью 2026-09-01; было «0/4 и
`udp_drop_reasons="no_client_yet=4"`», и это неверно по обоим числам.**
Перепроверено воспроизведением ИСХОДНОГО дефекта (пин полного адреса первой
датаграммы, `lastAddr` через `CompareAndSwap` вместо `Store`) на паттерне самого
стенда — последовательные сокеты, каждый закрывается после своего запроса:

- получается **1/4**, а не 0/4: первый сокет — тот самый, на чей порт стоит пин,
  и свой ответ он получает. Эта единица и есть причина, по которой одиночная
  ручная проверка давала 8/8;
- `udp_drop_reasons` при этом **пуст**. `no_client_yet` инкрементится только
  когда `replyTo` вернул nil, то есть клиент не прислал ничего; при дефекте
  отправитель записан — просто не тот, и `WriteToUDP` на закрытый loopback-порт
  ошибки не даёт, поэтому `unroutable_reply` тоже молчит.

Отсюда вывод, который стоит держать рядом с самими счётчиками: **новая
наблюдаемость этот конкретный дефект НЕ поймала бы**. «Ответ ушёл не тому, но
кому-то» отбросом не является ни на одной ветке. Ловит его только стенд с
несколькими портами. Первая редакция записи приписывала счётчикам заслугу,
которой у них нет, — тот же класс ошибки, что «формулировка сильнее данных».

### Власть сторожей проверена порчей

Все четыре UDP-сторожа и оба сторожа окна прогнаны с **намеренно возвращённым**
дефектом — краснеют; после восстановления зелено. Зелёный сторож сам по себе
ничего не доказывает.

### Что НЕ сделано и почему

- **Причина «33 % именно у sing-box» полем не подтверждена нами** — мы
  воспроизвели механизм и класс отказа, но их прогон с sing-box после правки
  ещё не сделан. Просьба к ним: повторить и вернуть `udp_drop_reasons`.
- Демультиплексирования по адресу назначения на уровне **стрима** нет: вся
  ассоциация по-прежнему идёт одним `streamID`, серверный flow-ключ —
  `(sessionID, streamID)`. Маршрутизация ответов чинится на клиенте, но одна
  ассоциация = один стрим = один слот.
- Асимметрия таймаутов (клиент 120 с / сервер 60 с) и отсутствие `CloseStream`
  при снятии ассоциации — **не тронуты**, замера вреда нет.
- Влияние окна на скорость **нами не измерено**: ручка добавлена, число не
  проверено. Мерить им, у них RTT 241 мс.

### Артефакты

- `proxy/socks5/udp.go`, `udp_drops.go`, `client/stats.go`, `client/ws_pool.go`,
  `engine/config.go`, `engine/engine.go`, `mobile/config.go`,
  `tools/facade-probe/udpcheck.go`
- Сторожа: `udp_pool_multiport_test.go`, `udp_pool_lifecycle_test.go`,
  `udp_drops_test.go`, `client/flow_window_config_test.go`,
  `mobile/flow_window_test.go`
- `docs/integration/mobile-sdk.md` §4.5, §8.1.1, §8.1.2
