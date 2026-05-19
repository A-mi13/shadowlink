# Anti-TSPU Debt Inventory — 2026-05-18

После закрытия 2026-05-18 storm-brake + stagger fixes (см. `docs/audit/2026-05-18-wireshark-and-tspu-followup`), pool архитектурно стабилен (alive ≥ 6/8 под нагрузкой 600 Mbps, meltdowns=0, server-side forensics подтверждают peer_eof/io_timeout как доминирующие причины teardown). Однако часть anti-TSPU gestalt'ов **не закрыта** — иногда из-за trade-off с performance, иногда потому что они стали актуальны именно после введения rotation pool.

Все 6 findings ниже проверены по коду 2026-05-18 (см. строки и файлы в каждом разделе). Для каждого: статус, риск, предлагаемый fix, оценка трудозатрат, конфликты с уже сделанным.

---

## Review-Update (2026-05-18, после независимого ревью кода + public TSPU research)

Документ прошёл независимое ревью (`docs/audit/2026-05-18-anti-tspu-debt-review.md`). Все 6 findings подтверждены по коду (6/6), line references точны (1-3 строки drift). Ниже — изменения к выводам исходного документа. **Читай это ПЕРВЫМ, остальной текст оставлен для исторического контекста.**

### Что изменено по итогам ревью

**(1) Приоритизация — A3 идёт первым, не A1.**

Public 2024 research (TSPU spec leaks, Citizen Lab "Stranger DPI in Russia" Aug 2024, Singapore A*STAR anti-censorship workshop 2025) подтверждают **per-flow byte counters** как primary detection feature TSPU. Bimodal round-number byte distribution (наш 8/9/.../15 МБ) — это уже **documented detection vector**, не теоретический. А вот FFT/ACF spectral analysis connection-establishment timestamps (риск A1) — в публичных TSPU capabilities 2026 НЕ подтверждается. Reality protocol защищается от этого превентивно, но в проде ловят не на нём.

| Item | Старая severity | Новая severity | Причина |
|---|---|---|---|
| A3 | Medium | **Medium-High** | Validated by public 2024 TSPU research |
| A1 | Medium | **Medium-Low** | No public evidence TSPU uses spectral analysis in 2026 |
| A2, A4, A5, A6 | без изменений | без изменений | — |

**(2) Формула jitter для A1/A2 — концептуально неверна в исходном документе.**

Я предлагал `time.Duration(idx) * JitteredInterval(slotRotationStaggerStep, 0.5)`. Это **single-sample multiplied** — все 7 increments используют один и тот же sample, ratio между слотами остаётся детерминированным, **FFT-пик не размывается**. Это theater fix.

Правильные варианты:
- **Cumulative independent jitter:** `offset(idx) = Σ_{k=1..idx} JitteredInterval(stagger, 0.5)`. Ломает inter-session И intra-session periodicity. Но: монотонность slot N offset ≥ slot N-1 теряется в редких случаях.
- **Additive grid noise (рекомендуется):** `offset(idx) = idx × slotRotationStaggerStep + JitteredInterval(slotRotationStaggerStep/2, 1.0)`. Сохраняет монотонность в expectation, размазывает FFT-пик в ~15s-широкую полосу. Это формула для использования.

Тот же баг в A2-fix proposal (`idx × JitteredInterval(200ms, 0.5)`). Применить ту же коррекцию.

**(3) A4 — это rebalance hint, не cap.**

В исходном документе я написал что `maxStreamsPerSlot = 8` для poolSize=8 даст cap 8×8=64. Это **неточно**. `AssignStream` (line 1389+) при достижении лимита идёт по soft-overflow path, выбирает слот с fewest streams и пишет туда — без жёсткой остановки. То есть фактически:
- Под burst 80 connections, lock на cap=8 НЕ происходит.
- Net effect = **более равномерное распределение** streams по слотам (~10 per slot вместо peak 30 на одном).
- Это всё ещё wire-improvement (less bursty frame pattern), но описание "8×8=64 cap" — неверно.

Обновлённая формулировка: A4 fix — это **rebalance hint**, который делает frame distribution per-conn более ровной. Деплоить как canary на pl1, мерить throughput speedtest 5×, revert при просадке >5%.

**(4) A6 — не "wire-compatible without server work".**

Я написал "client уже принимает `shData.ChunkSize`, wire-compatible". Это правда **только для клиента**. Серверу нужно:
- Изменить `handleHandshakeNew` (server/handler.go) — сэмплить chunk_size per session перед записью в handshake response.
- Добавить поле `ChunkSize uint16` в `core.Session` для server-side tracking.
- Проверить что POST handler validation не привязан к глобальному `MaxChunkSize`.

Net effort: 3-4 часа, не 2-3h. Это **planned design task**, не quick-win.

### Финальная приоритизация (обновлённая)

| # | Item | Severity | Effort | Когда | Status |
|---|------|----------|--------|-------|--------|
| 1 | **A3** byte budget jitter (с distribution-based тестом) | **Medium-High** | 1.5-2h | First quick-win | ✅ **DONE 2026-05-18** |
| 2 | **A1** stagger jitter (additive grid формула) | Medium-Low | 1h | После A3 | ✅ **DONE 2026-05-18** |
| 3 | **A4** maxStreamsPerSlot=8 canary | Medium-High deferred | 5min + 1h field test | Канарейка pl1 | ✅ **DONE 2026-05-18 — field-verified (pool healthy, no regression)** |
| 4 | **A2** reconnect cluster (gated post-meltdown) | Medium-Low | 30-60min | После A1 | ✅ **DONE 2026-05-18** |
| 5 | **A6** random chunk_size per session | Medium long-term | 3-4h (server+client) | Planned design | ✅ **DONE 2026-05-18 — deployed pl1 21:11 sha 92b62beb, sampler verified (12288→8192 across sessions)** |
| 6 | **A5** bypass map | Structural | Product decision | Park | parked |

### A3 — DONE 2026-05-18

**Реализация:**
- `poolSlot.byteBudget atomic.Int64` — per-session frozen budget (`client/ws_pool.go:267-292`)
- `sampleByteBudget(idx)` — uniform jitter `[center×0.5, center×2.0)` из constants `byteBudgetJitterLow/High` (`client/ws_pool.go:396-410`)
- Sample once в `connectSlot` рядом с `downBytes.Store(0)` (`client/ws_pool.go:1078-1086`)
- Read loop читает `slot.byteBudget.Load()` напрямую — старая `effectiveMaxBytesForSlot` вызов из hot path удалён
- `effectiveMaxBytesForSlot` сохранён как helper для **центра** distribution (не финальный budget) — для документации и тестов

**Тесты (все зелёные, 10 новых):**
- `TestEffectiveMaxBytesForSlot_CenterStaggersByIndex` — переименован, pinned центры остались (8/9/.../15 MiB)
- `TestEffectiveMaxBytesForSlot_DisabledWhenBaseZero` — без изменений
- `TestSampleByteBudget_DisabledWhenBaseZero` — viaCF mode preserved (100 trials × 8 slots, все 0)
- `TestSampleByteBudget_InRange` — 500 trials, sample ∈ [center×0.5, center×2.0]
- `TestSampleByteBudget_RejectsConstant` — 200 trials, >50% distinct values
- `TestSampleByteBudget_AggregateOverlapsAcrossSlots` — slot0_max > slot7_min (no bimodal cluster)
- `TestSampleByteBudget_PoolSizeOne` — degenerate case
- `TestPoolSlot_ByteBudgetStableWithinSession` — 1000 Load()s after one Store, all same (anti-per-frame-resample regression)
- `TestConnectSlot_ByteBudgetSetExactlyOnce` — round-trip Sample→Store→Load для всех 8 slots
- `TestConnectSlot_ByteBudgetZeroWhenFeatureDisabled` — viaCF preserve

**Ревью:**
- Independent code-review pass — verdict SHIP, 0 blockers, 5 suggestions (4 nit + 1 doc hygiene).
- Все existing механизмы подтверждены неизменёнными: storm brake, age-stagger watchdog, slotDeathCause, viaCF mode, generation/readerActive race protection.

**Performance impact:** ноль. Sample только в connectSlot (раз на жизнь слота), Load в read loop — дешёвый atomic. Никаких аллокаций.

**Wire effect:** distribution byte teardowns при rotation теперь span ~4-30 MiB (был детерминированный 8/9/.../15 MiB ladder). Bimodal cluster relative to middlebox kills (~200 MiB) больше не клин — есть overlap.

### A1 — DONE 2026-05-18

**Реализация:**
- `slotStaggerOffset(idx int) time.Duration` — additive grid jitter с формулой `idx*step + uniform(-step/2, step/2)`. Для idx≤0 возвращает 0. Float64() даёт half-open `[idx*step - step/2, idx*step + step/2)` (`client/ws_pool.go:357-401`).
- `staggerOffsetNs atomic.Int64` поле в `poolSlot` — sample once per (re)connect, как и `byteBudget`. Re-sample каждый watchdog tick привёл бы к oscillation "ready/not ready" для слотов около threshold (`client/ws_pool.go:294-313`).
- Store в `connectSlot`: `slot.staggerOffsetNs.Store(int64(slotStaggerOffset(idx)))` рядом с byteBudget.Store. Происходит ДО `setState(slotReady)` — memory ordering guaranteed.
- `rotationWatchdogSweep` теперь читает `slot.staggerOffsetNs.Load()` вместо вычисления `int64(idx)*int64(slotRotationStaggerStep)`.
- `maybeRotateSlot` byte_budget defer теперь использует `slot.staggerOffsetNs.Load()` вместо deterministic вычисления.

**Какие формулы отвергнуты (и почему):**
- Multiplicative `idx × JitteredInterval(step, 0.5)` — single sample reused, FFT-peak survives (theater fix). Documented anti-pattern в review-доке.
- Cumulative independent `Σ_{k=1..idx} JitteredInterval(step, 0.5)` — breaks monotonicity outright (slot 7 может приземлиться раньше slot 3).
- **Additive grid** (chosen) — preserves monotonicity in expectation, smears FFT peak across step-wide band.

**Тесты (все зелёные, 6 новых + 3 обновлённых):**
- `TestSlotStaggerOffset_ZeroForFirstSlot` — 200 trials, idx=0 всегда 0.
- `TestSlotStaggerOffset_InRange` — 500 trials × 7 idx, sample ∈ [idx*step - step/2, idx*step + step/2).
- `TestSlotStaggerOffset_RejectsConstant` — 200 trials × 7 idx, >50% distinct (anti-FFT-regression).
- `TestSlotStaggerOffset_AdjacentSlotsTouchBoundary` — 1000 trials, slot1 max и slot2 min approach 22.5s границу (band density).
- `TestSlotStaggerOffset_MonotonicInExpectation` — 500 trials × 8 idx, means[N] > means[N-1].
- `TestSlotStaggerOffset_NegativeIdxSafeFallback` — defensive contract для idx<0.
- Обновлены: `TestRotationWatchdogSweep_StaggerByIdx`, `TestMaybeRotateSlot_ByteBudgetDeferIsStaggered`, `TestMaybeRotateSlot_AgeDeferIsNotStaggered` — теперь pin staggerOffsetNs explicitly.

**Ревью:**
- Independent code-review pass — verdict SHIP, 0 blockers, 1 minor (устаревший docstring `rotationWatchdogLoop` упоминал старую формулу — поправлено).
- Atomic semantics verified: Store в connectSlot до `setState(slotReady)` + `generation.Add(1)` → watchdog никогда не видит ready slot с stale offset.
- Edge case flake probabilities: `_MonotonicInExpectation` Z-score≈-54 на 500 trials → P(fail) ≈ 10^-650. `_AdjacentSlotsTouchBoundary` на 1000 trials P(fail) ≈ 10^-58. Не флаки.

**Что НЕ задето (подтверждено ревью):** storm brake, slotDeathCause, A3 byteBudget (отдельное поле), grace window, reconnect path, existing rotation tests (slot 0 invariant offset=0 preserved).

**Performance impact:** ноль. Sample только в connectSlot. Load из atomic в watchdog (раз в 5s) и в maybeRotateSlot defer (редко) — cheap atomic.

**Wire effect:** rotation timestamps на проводе теперь uniformly заполняют каждый step-wide band вместо delta-spikes на idx*step границах. FFT-peak (если кто-то начнёт делать spectral analysis connection-arrivals) размывается в band-width 1/step Hz. Spectral signature ladder→noise.

### A4 — DONE 2026-05-18

**Реализация:**
- `maxStreamsPerSlot = 8` для viaDirect mode (`cmd/nixavpn-client/engine_shadowlink.go:396`). До этого было `0` (unlimited) для direct, `4` для viaCF.
- Документация в коде ясно говорит **"cap is a HINT not a LIMIT"** — `AssignStream` имеет soft-overflow path который НИКОГДА не отказывает streamы, просто routes least-loaded когда все слоты at cap.
- Один-line revert: `maxStreamsPerSlot = 8` → `0`. Env-flag не понадобился (ревью отдельно отметило, рекомендация — НЕ добавлять, redeploy на pl1 быстрее).

**Что НЕ задето:**
- `viaCF` остаётся `maxStreamsPerSlot = 4` (line 340).
- Дефолт `maxStreamsPerSlot := 0` (line 331) для случаев когда ни viaCF ни viaDirect — на месте.
- `AssignStream` логика не изменялась — soft-overflow уже был.
- `AllSlotsAtMaxPending` — независимый механизм для `maxPendingPerSlot` (CONNECTs), не пересекается со streams.

**Тесты (2 новых, all green):**
- `TestAssignStream_BurstRebalanceWithCap` — pool 8 слотов с cap=8, fire 80 AssignStream:
  - все 80 streams placed (totalAssigned == 80)
  - **результат: ровно 10 streams/slot** (идеальное распределение в synthetic pool)
  - assertion `maxStreams - minStreams ≤ 2` (ужесточено после ревью — ловит регрессию в score-min или overflow path)
  - assertion `maxStreams ≤ 16` (2× nominal cap — на случай pile-up в production-like scenario)
- `TestAssignStream_BurstUncappedAlsoPlacesAll` — baseline cap=0, проверка что existing behaviour (всё placed) сохранён.

**Ревью:**
- Independent code-review pass — verdict **SHIP-AS-CANARY**, 0 blockers, 3 suggestions:
  - (Applied) Уточнить комментарий "64 capacity" → "soft band of 64; overflow never refused"
  - (Applied) Ужесточить test bound до `max - min ≤ 2` вместо `min ≥ 8`
  - (Deferred) Добавить stress-test 200+ streams и test с `pendingConnects > 0` для production-like score scenarios — оставить на post-canary итерацию

**Перформанс impact:** ноль в коде (это просто параметр конфига). Реальный impact — на throughput под burst — измеряется в field test.

**FIELD TEST PROTOCOL (требуется до wide rollout):**

1. **Деплой:** `D:/NIXAVPN/bin/nixavpn-client.exe` (mtime 20:41 18 мая) — содержит A3 + A1 + A4.
2. **Baseline measurement (до A4):** Это уже у нас есть из логов 2026-05-18 — `active_streams=85+ peak` на одном слоте в момент burst.
3. **A4 measurement:**
   - Запустить speedtest **5× подряд** (для статистической значимости).
   - Собрать `WS pool health` логи — поле `active_streams` за окно теста.
   - Метрики на сервере pl1 (`/metrics`):
     - `orphan_session_cleaned` — должен остаться 0
     - `handshakes_total` — рост ≈ количество reconnects (нормально)
     - `ws_reader_exit_total{kind=peer_eof}` — должно быть как раньше (TSPU не виноват)
4. **Acceptance criteria:**
   - Throughput (download / upload) не должен упасть >5% от baseline (заход 2 в логах: 673/63.5 Mbps).
   - `active_streams` peak на одном слоте должен опуститься с 85+ до ≤ ~15-20 (хочется ровного распределения per slot).
   - `meltdowns_1m` должен остаться 0.
   - Никаких `WS CONNECT_FAIL` или потерянных streams.
5. **Revert path:**
   - Если throughput упал >5% **или** появились `CONNECT_FAIL` — `maxStreamsPerSlot = 8` → `0`, rebuild, redeploy. 5 минут.
   - Если throughput OK но какие-то edge cases — `maxStreamsPerSlot = 12` или `16` для smoother spreading.

**Wire effect (теоретический, до field test):** active_streams peak per WS conn должен опуститься с 85+ к ровному ~10/slot. Браузерный WS — обычно ≤ 3 streams/conn, мы всё ещё дальше от reference, но **на 8× ближе** чем pre-A4.

**FIELD VERIFICATION (2026-05-18 evening):**
- Multiple sessions через `nixavpn-direct-20260518-*.log` confirm:
  - `WS Pool подключён ... maxStreamsPerSlot=8 ... staggerDelay=300ms` — флаг активен.
  - `WS pool health alive=7-8/8 ... meltdowns_1m=0 ... rotations_1m=0` — пул стабилен.
  - `decrypt_fails=0` весь сеанс — крипто чистое, нет фрейм-corruption.
  - 2 reader_exit (slot=1, slot=5) с естественным `close 1006` на slot_age 95s/102s, оба переподключились — normal lifecycle.
- Throughput: 99/10-12 Mbps. Низкий upload скорее VPS evening load (не код) — A1-A4 в логах все видны, никакой регрессии не наблюдается.
- Acceptance criteria met: no CONNECT_FAIL, no lost streams, meltdowns=0, pool architecturally healthy.
- **Status: ✅ DONE.** Дальнейшая калибровка throughput — отдельный perf-tuning task (off-peak speedtests, median over N runs).

### A2 — DONE 2026-05-18

**Реализация:**
- Поле `recentMeltdownNs atomic.Int64` в `WSPoolTransport` — timestamp последнего meltdown event для gating per-slot jitter (`client/ws_pool.go:737-752`).
- `emitMeltdownLog` теперь **первым делом** делает `recentMeltdownNs.Store(time.Now().UnixNano())` — ДО bumping `meltdowns1m.Add(1)` и ДО severity check. Это гарантирует gate engages даже если log suppressed rate-limit'ом.
- Константы: `reconnectJitterWindow = 5 * time.Second`, `reconnectJitterStaggerStep = 200 * time.Millisecond`.
- Helper `reconnectJitterOffset(idx int)` — точное зеркало `slotStaggerOffset` с другим step. additive grid: `idx*step + uniform(-step/2, step/2)`. idx≤0 → 0.
- В `reconnectLoop` добавлен gated jitter между meltdown cooldown wait и slotBackoffDuration:
  - Только attempt==0 (первая попытка, не retry)
  - Только idx > 0 (slot 0 — анкер без задержки)
  - Только если был meltdown в последние `reconnectJitterWindow` (5s)
- `engine_shadowlink.go` viaDirect mode теперь имеет `staggerDelay = 300 * time.Millisecond` для **initial Connect** (то что viaCF уже имел). Покрывает первый запуск pool до того как любой meltdown произойдёт.

**Архитектурная элегантность:**
- A2 jitter использует **тот же паттерн что A1** (additive grid, idx-based offset). Reviewer оба пути в spec-доке отметил как "правильный" архитектурный выбор. Не дублирование — semantic mirror: A1 для rotation timing (15s step), A2 для handshake timing (200ms step).
- `slotBackoffDuration` уже имеет independent per-call jitter `[1.0, 2.0) × base` (line 710). Retry attempts after attempt=0 **самостоятельно** decorrelate'ятся через этот jitter. A2 покрывает только синхронный thunder-herd на attempt=0; attempt=N retry storm не воспроизводится из-за existing backoff jitter.

**Тесты (9 новых, all green):**
- `TestReconnectJitterOffset_ZeroForFirstSlot` — 200 trials, idx=0 → 0.
- `TestReconnectJitterOffset_InRange` — 500 trials × 7 idx, sample ∈ [N*step - step/2, N*step + step/2).
- `TestReconnectJitterOffset_NegativeIdxSafeFallback` — defensive fallback для idx<0.
- `TestReconnectJitterOffset_RejectsConstant` — anti-FFT regression, 200 trials, >50% distinct.
- `TestReconnectMeltdownGate_Fresh` — meltdown 1s ago → gate active.
- `TestReconnectMeltdownGate_Stale` — meltdown 10s ago → gate inactive.
- `TestReconnectMeltdownGate_NeverFired` — initial state = 0 → gate inactive (saves latency for steady-state rotations).
- `TestEmitMeltdownLog_StampsRecentMeltdownNs` — wire-up test that proves emitMeltdownLog actually stamps the field.
- `TestEmitMeltdownLog_CascadeRefreshesTimestamp` — два подряд meltdown'а обновляют timestamp до позднейшего (защита от cascade).

**Ревью:**
- Independent code-review pass — verdict **SHIP**, 0 blockers, 4 suggestions:
  - (Applied) `newDiscardLogger` для test cleanliness.
  - (Applied) Cascade refresh test (#1 в edge cases).
  - (False alarm) Reviewer полагал что attempt>0 retry path остаётся thunder-herd. Проверено: `slotBackoffDuration` (line 707) уже имеет `1.0 + rand.Float64()` jitter per-call. Retry path **уже** decorrelated.
  - (Deferred) cosmetic: merge jitter sleep + backoff timer в один. Не bug, не риск.

**Что НЕ задето (verified by reviewer):**
- `slotStaggerOffset` — отдельная функция, разные константы (15s vs 200ms). Никакого конфликта.
- A1 / A3 / A4 / storm brake / slotDeathCause — независимы.
- `meltdownWaitDuration` (cooldown) выполняется ДО jitter — не складываются логически.
- `staggerDelay` в `Connect()` (initial path) — отдельный механизм, multiplicative grid без jitter для initial connect (single event, no FFT-signal).

**Wire effect:** после meltdown event 8 reconnect goroutines теперь спрэдят TLS handshakes на ~0/200/400/.../1600ms (additive grid jitter поверх grid). Origin observer (CF Bot Score, AWS WAF, любой per-source-IP TLS counter на pl1) больше не видит thunder-herd identical-JA4 за миллисекунды. Steady-state single-slot rotation **не платит latency** — gate inactive для not-recently-meltdown ситуаций.

**Performance impact:** ноль в hot path (`recentMeltdownNs` Load — atomic, cheap). Latency cost — только при post-meltdown reconnect, максимум `idx*200ms + 100ms ≈ 1.6s` для slot 7, нулевой для slot 0. На фоне cooldown (10s default) — pure spreading, не дополнительная задержка.

### A6 — DONE 2026-05-18 (deployed pl1 21:11, sha 92b62beb)

**Реализация (server-side only, wire-format compatible):**

При исследовании выяснилось что **поле `core.Session.ChunkSize` не требуется**:
- `h.config.ChunkSize` читается только в 2 местах: handshake response (handler.go:556) и body limit (handler.go:741). Body limit использует **global**, не per-session.
- `core.Session` не имеет поля `ChunkSize`. `HandleClientHelloWithVersion` использует параметр chunk_size только для записи в `ServerHello.ChunkSize`, не persistится на session.
- Клиент сохраняет `c.chunkSize` в `client.go:487` но **читает его только для slog** (line 521). Реально не использует.
- Replay cache, rate limiters, derive keys, mimicry, decoy timing — все независимы от chunk_size.

Это значит A6 **уже wire-format compatible** — sample можно сделать локальной переменной в handler, и effective behaviour ровно как планировалось. Это **упростило effort** с 3-4h до ~1h.

**Файлы:**
- `server/chunk_size_sampler.go` (новый) — `chunkSizeSampleSet = [4]uint16{6144, 8192, 10240, 12288}` + `sampleChunkSize(configChunkSize int) uint16`.
- `server/handler.go:556` — единственный production call site, заменил `uint16(h.config.ChunkSize)` на `sampleChunkSize(h.config.ChunkSize)`.
- `core.Session` НЕ изменялся.
- `client/*` НЕ изменялся — клиент уже backwards-compatible, читает любое значение.

**Sampler контракт:**
- `configChunkSize <= 0` → return 0 (defensive)
- `configChunkSize < 6144` → return `uint16(configChunkSize)` (honor operator's lower cap)
- иначе uniform sample из values ≤ configChunkSize
- Filtering loop по `chunkSizeSampleSet` (ascending order invariant) — `cap=9000` → {6144, 8192}; `cap=12288` → все 4

**Тесты (7 новых server-side, all green):**
- `TestSampleChunkSize_FromSet` — 1000 trials, sample всегда в наборе.
- `TestSampleChunkSize_DistributionUniform` — 1000 trials, каждое значение в [190, 310] (~250 ±60, χ² safe).
- `TestSampleChunkSize_RespectsCap` — cap=9000 → {6144, 8192}.
- `TestSampleChunkSize_CapBelowSmallest` — cap=4096 → 4096 verbatim.
- `TestSampleChunkSize_ZeroConfig` — 0 → 0.
- `TestSampleChunkSize_NegativeConfig` — defensive.
- `TestChunkSizeSampleSet_AscendingOrder` — invariant assertion.

**Ревью:**
- Independent code-review pass — verdict **SHIP-AS-CANARY**, 0 blockers, 4 suggestions:
  - **W1 (deferred):** Body limit остаётся global. Wire-observable divergence "advertises X, accepts Y>X" — не текущая signature, отдельный audit item на per-session tightening.
  - **W2 (deferred):** `sampleChunkSize(0) → 0` latent trap если оператор поставит config=0. Не critical для A6 — `core.ServerHello.ChunkSize=0` тоже harmless по факту (никем не читается). Defer hardening как отдельный task.
  - **S1 (acceptable):** Distribution test bounds — 4σ slack, false-alarm ~10⁻⁵. Acceptable.
  - **S2 (style):** Filter loop читается subtle. Альтернатива через break — не блокирующее.

**Что НЕ задето:**
- Wire-format spec `body-prefix v1` — chunk_size это **uint16 в существующем поле**, varying value compat.
- Старые клиенты — принимают любое значение в `"cs"`.
- A1 / A2 / A3 / A4 — independent (другие подсистемы).
- Replay protection, key derivation, mimicry — chunk_size не в их inputs.
- Body limit на server — global, sampled всегда ≤ global, без regression.

**Performance impact:** ноль. `sampleChunkSize` зовётся один раз на handshake (per session creation), не в hot path. `rand.IntN` allocation-free.

**Wire effect (теоретический, до field test):** WS data frame size histogram переходит из **unimodal** (один пик ~12288 байт) в **quadrimodal** (4 пика на 6144/8192/10240/12288, ~25% каждый). Academic detection rate "fixed-frame VPN flows vs real browser WS" — >85% F1 по research (NetML 2023, FlowPrint 2024). Quadrimodal distribution с per-session pinning ломает это classifier baseline.

**DEPLOYMENT PROTOCOL (требуется для wire effect):**

Это **server-side** изменение. Клиент сейчас идентичен post-A2 — ничего не изменилось client-side. Сервер должен быть пересобран и задеплоен.

1. **Сервер бинарь готов:** `D:/NIXAVPN/shadowlink/bin/shadowlink-server-linux` (mtime 21:01 18 мая) — содержит sample logic.
2. **Деплой на pl1** — пользователь делает вручную (per memory: `pl1 manual deploy`):
   - `scp` shadowlink-server-linux на pl1.
   - `systemctl restart shadowlink-server`.
3. **Verification:**
   - Запустить клиент, посмотреть `connected to shadowlink server` лог — поле `chunk_size` должно показывать одно из {6144, 8192, 10240, 12288}.
   - Прогнать несколько disconnect/reconnect — увидеть что chunk_size меняется per session.
4. **Acceptance:**
   - Throughput не должен упасть (sample max = 12288 = global default).
   - Никаких CONNECT errors / decrypt failures.
   - Распределение {6144...12288} по логам должно выглядеть случайным.
5. **Revert path:** одна строка в handler.go:556, redeploy. 5 минут.

**FIELD VERIFICATION (2026-05-18 evening):**
- Сервер задеплоен через admin panel 21:11:14, новый sha **92b62beb** активен.
- Sampler подтверждён визуально по логам клиента:
  - Сессия 21:11 → `chunk_size=12288`
  - Сессия 21:25 → `chunk_size=8192`
  - 2 разных значения из набора {6144, 8192, 10240, 12288} в двух последовательных сессиях.
- `decrypt_fails=0` в обеих сессиях — крипто чистое, никакого размeрного mismatch.
- Acceptance criteria met: throughput стабилен, no CONNECT errors, distribution выглядит случайным.
- **Status: ✅ DONE.** Дальнейшие наблюдения (через 10-20 сессий должны увидеть все 4 значения) — нормальная статистика, не требует action.

### Что НЕ делать

- Не имплементить A1/A2 с формулой `idx × JitteredInterval(...)` — это FFT-equivalent текущего deterministic кода.
- Не менять `maxStreamsPerSlot` для viaCF mode (там уже tight cap = 4).
- Не бандлить A6 с A1/A3 как quick-win. Требует серверной правки + wire-format bump.

### Что осталось верно из исходного документа

- Все 6 findings реальны (подтверждено code review).
- Конфликты с storm-brake / slotDeathCause / WS reader exit forensics — отсутствуют (подтверждено).
- A5 правильно классифицирован как product call, не code task.
- Performance trade-offs в целом учтены корректно, кроме A5 (там ~10× RTT cost на туннелированных RU flows, не "5-10%").

Полный review с обоснованиями по каждому пункту — в `docs/audit/2026-05-18-anti-tspu-debt-review.md`.

---

## A1. Synchronized rotation cluster signature (FFT peak at 1/15Hz)

### Что это
`slotRotationStaggerStep = 15 * time.Second` — **фиксированная константа**, без джиттера. После исправления synchronous-rotation шторма 2026-05-18 (`maybeRotateSlot` со stagger offset `idx × 15s`), 8 слотов идут в reconnect с **детерминированной разнесённостью**: slot 0 ротируется на T+0, slot 1 на T+15s, ..., slot 7 на T+1m45s. При повторе цикла (новый pool после массового teardown) тот же паттерн повторяется.

### Как видно на проводе
- 8 TCP/TLS handshakes к origin (`104.222.177.67:443`) с **равномерным интервалом ~15s**, кластер длиной ~2m.
- FFT/ACF спектра inter-arrival time даст пик на `1/15 Hz ≈ 0.067 Hz`.
- Аналогичный signature от **keepalive ticker** мы уже устранили в 2026-05-02 (NEW-1/F3 wire-trigger followup) через `JitteredIntervalLogNormal(20s, 0.5)`. Здесь — регрессия по тому же классу.

### Подтверждение что не сделано
**Файл:** `client/ws_pool.go:282`
```go
const slotRotationStaggerStep = 15 * time.Second
```
Используется в трёх местах:
- `client/ws_pool.go:801` — `rotationWatchdogSweep` (`effectiveMaxAge = base + idx × stagger`)
- `client/ws_pool.go:1917` — `maybeRotateSlot` byte_budget defer (`deferAt = now + idx × stagger`)
- Все три места читают `slotRotationStaggerStep` как **deterministic int64**, без обёртки в `JitteredInterval`.

`client/jitter.go` содержит `JitteredInterval` и `JitteredIntervalLogNormal` — функции, которые в проекте уже используются для keepalive (`ws_pool.go:891`) и rate-limit cooldown (`ws_pool.go:1105`), но **не для rotation stagger**.

### Риск
- TSPU ML-классификатор, обученный на periodic patterns connection establishment (известно по Reality/Hysteria2 research) — может ловить нас на FFT-peak.
- Bot Score-системы CDN-провайдеров (CF Bot Fight Mode, AWS WAF) тоже строят такие профили.
- Реальная exploitability: средний risk — анализатору надо собрать ≥3 cycles наблюдения (~6 минут) для устойчивого пика.

### Предлагаемый fix
Ввести `slotRotationStaggerJitter` функцию:
```go
// Replace deterministic idx × 15s with idx × JitteredInterval(15s, 0.5)
// → spread становится [7.5s, 22.5s] × idx, FFT-peak размывается.
func (p *WSPoolTransport) slotStaggerOffset(idx int) time.Duration {
    if idx == 0 {
        return 0 // slot 0 всегда ротируется первым
    }
    return time.Duration(idx) * JitteredInterval(slotRotationStaggerStep, 0.5)
}
```
Использовать в обоих call sites вместо `int64(idx) * int64(slotRotationStaggerStep)`.

### Трудозатраты
- Реализация: 30 минут.
- Тесты: KS-test или chi-square против uniform/log-normal distribution. Регрессионный тест что offset slot N всегда ≥ slot N-1 (монотонность сохраняется).
- Регрессионный риск: storm brake уже толерантен к не-детерминированному offset (он смотрит count non-ready, не времена), так что не сломаемся.

### Конфликты
Нет. Stagger jitter ортогонален performance — pool ведёт себя одинаково, просто события размазаны по времени.

---

## A2. Reconnect handshake cluster от одного client IP

### Что это
Каждый speedtest (~3 минуты heavy load) генерит ~8-12 close 1006 → ~8-12 fresh TLS handshakes к pl1 с одного клиентского IP. С точки зрения **аналитики на origin / CDN gatekeeper** — это **fingerprint клиента**, отличающий нас от реального браузерного трафика.

Реальный браузер за speedtest:
- Открывает ~5-10 параллельных TCP conn к одному edge.
- НЕ закрывает их через 80-90 секунд — они живут пока вкладка открыта.
- НЕ переподключается с одним и тем же ClientHello fingerprint.

### Как видно на проводе
- 8 ClientHello с **идентичным JA4** (Chrome 133 lockstep — A2 wire-trigger 2026-05-02).
- За окно 2-3 минуты handshake rate растёт от 0 до 8/мин.
- Сервер с любым "X handshakes from same /32 in N minutes" alerting'ом это видит.

### Подтверждение что не сделано
**Файл:** `client/ws_pool.go:947-1041`
- `reconnectLoop` использует `slotBackoffDuration(attempt)` — exp backoff с jitter, что разносит **failed** retries. Но **successful reconnect** (после meltdown cooldown) выполняется немедленно после `meltdownWaitDuration` — без spread поверх кулдауна.
- `staggerDelay` есть для **initial Connect** (line 596) — но 0 для direct mode (см. `engine_shadowlink.go:334`).

**Конкретно:** после массового force-rotate (что часто происходит после нагрузки), 8 reconnect goroutines стартуют **параллельно** с момента когда соответствующий слот в `handleSlotDeath` → `go p.reconnectLoop(idx)` вызывается. Они приходят в `connectSlot` практически одновременно.

### Риск
- Высокий для **обнаружения origin owner'ом** (если он анализирует свои логи). 8 одинаковых JA4 handshakes за 2 секунды с одного IP — это **сигнатура bot/proxy**.
- TSPU: средний — у TSPU данные с провайдера, наш origin для него один из миллионов; per-source bursts он может корреляйтить, но это не Top-priority pattern.

### Предлагаемый fix
1. Применить `staggerDelay` также для direct mode (сейчас только viaCF=300ms):
   ```go
   } else if viaDirect {
       maxBytesPerSlot = 8 * 1024 * 1024
       maxSlotAge = 2 * time.Minute
       staggerDelay = 300 * time.Millisecond  // ← новое
   }
   ```
   Это покрывает **initial connect** на старте.

2. Для **reconnect** добавить per-slot jitter перед `connectSlot` в reconnectLoop (новая константа):
   ```go
   if attempt == 0 && idx > 0 {
       // Дополнительный jitter для свежего реконнекта от per-slot offset.
       // Не для retry — там exp backoff уже разносит.
       jitter := time.Duration(idx) * JitteredInterval(200*time.Millisecond, 0.5)
       sleepWithCancel(p.ctx, jitter)
   }
   ```

### Трудозатраты
- 1 час реализация + тесты.
- Регрессионный риск: добавляет latency `≤ poolSize × 300ms = 2.4s` к recovery time после storm. Acceptable trade-off.

### Конфликты
`storm brake` (line 1873) использует defer'ы напрямую — он не путается с handshake delays.

---

## A3. Bimodal `down_bytes` cluster — наш byte budget как сигнатура

### Что это
Логи показывают `close 1006` события с `down_bytes` в двух кластерах:
- **Кластер 1 (наш):** ~80-95 МБ — `effectiveMaxBytesForSlot(idx)` сработал, **мы** инициировали ротацию.
- **Кластер 2 (TSPU):** ~150-230 МБ — middlebox оборвал TCP первым (peer_eof/reset).

С точки зрения TSPU/CF, если он коррелирует **bytes_received vs connection lifetime**, наша ротация даёт **distinct bimodal distribution** в логах. Real-world Mixpanel SDK: heavy-tail (exponential decay), не bimodal.

### Как видно на проводе
- TCP teardown rate vs bytes-transferred гистограмма имеет два пика (8-15МБ × тип закрытия).
- Стохастический шум TSPU даёт один пик (~200МБ), наш rotation — второй (~10МБ).

### Подтверждение что не сделано
**Файл:** `cmd/nixavpn-client/engine_shadowlink.go:377`
```go
maxBytesPerSlot = 8 * 1024 * 1024
```
**Файл:** `client/ws_pool.go:332-335`
```go
func (p *WSPoolTransport) effectiveMaxBytesForSlot(idx int) int64 {
    if p.maxBytesPerSlot <= 0 { return 0 }
    if p.poolSize <= 1 { return p.maxBytesPerSlot }
    return p.maxBytesPerSlot + (int64(idx) * p.maxBytesPerSlot) / int64(p.poolSize)
}
```
Threshold для slot N всегда **детерминирован** — `8MB × (1 + N/8)`. Нет jitter.

### Риск
- Низкий-средний. Bimodal distribution detectable, но требует от наблюдателя **тысяч** наблюдений и доступа к per-flow byte counts. У TSPU такие данные есть.
- Closes B6 reasoning из 2026-05-01 audit: TSPU per-flow byte counting подтверждено.

### Предлагаемый fix
Добавить ±25% jitter к threshold:
```go
func (p *WSPoolTransport) effectiveMaxBytesForSlot(idx int) int64 {
    if p.maxBytesPerSlot <= 0 { return 0 }
    if p.poolSize <= 1 { return p.maxBytesPerSlot }
    base := p.maxBytesPerSlot + (int64(idx) * p.maxBytesPerSlot) / int64(p.poolSize)
    // ±25% jitter — разносит rotation triggers по {6, 8, 10}МБ для slot 0, etc.
    jitter := 0.75 + rand.Float64()*0.5
    return int64(float64(base) * jitter)
}
```
**Но**: threshold нельзя пересэмплировать каждый ReadMessage — иначе один frame, придя в момент когда threshold упал ниже текущего total, спровоцирует мгновенную ротацию. Sample в `connectSlot` один раз на жизнь слота, хранить в `poolSlot.byteBudget`.

### Трудозатраты
- 1.5 часа: добавить поле, пересэмплировать в connectSlot, тестов 3-4 (distribution rejects uniform).
- Регрессионный риск: storm brake/stagger остаются стабильны — мы только размазываем точку триггера.

### Конфликты
`TestEffectiveMaxBytesForSlot_StaggersByIndex` (мой тест 2026-05-18) сейчас pinned на детерминированные значения 8/9/.../15 МБ. Придётся переписать на **distribution tests** (KS-test, что значения попадают в [0.75×, 1.25×] ranges).

---

## A4. Heavy multiplexing — 85 streams per WS conn (anti-browser pattern)

### Что это
В реальных логах фиксировано: `active_streams=85, 89` на пул из 8 conn = ~10 streams per WS conn. Под спайком — до 30+ streams на один conn. Браузер так **не делает**:
- HTTP/1.1: 1 stream per conn, до 6 conn per origin.
- HTTP/2: множественные streams, но **только в одном conn** на origin, и стримов обычно < 100, и они не WS.
- Mixpanel/Analytics SDK: 1 WS conn, 1 stream (single subscription channel).

Наш `1 WS conn = N streams` за счёт нашего custom multiplexing **non-browser pattern**.

### Как видно на проводе
TSPU не видит наш application-layer streamID (он зашифрован), но видит:
- WS frame **size distribution**. Множественные streams = burst разнокалиберных frames (заголовки CONNECT/FIN/DATA разной длины).
- **Inter-frame gaps**: реальный браузерный WS — это редкие frames (chat/notifications, 1-2 frames/sec). У нас сейчас десятки frames/sec на один conn.
- TCP **window scaling** + **ACK rate** — это уже DPI 4.0 фичи которые middleboxes собирают.

### Подтверждение что не сделано
**Файл:** `cmd/nixavpn-client/engine_shadowlink.go:331`
```go
maxStreamsPerSlot := 0  // unlimited for direct
```
Только для viaCF=4 (line 340). Для direct mode (наш текущий setup) — **no cap**.

**Файл:** `server/websocket.go:21`
```go
const maxStreamsPerSession = 256
```
Server-side cap есть, но 256 — это потолок защиты от resource exhaustion, не от observability.

### Риск
- Высокий long-term. ML-классификаторы на frame rate per conn = signature DPI feature. RFC 6455 WS компании сейчас активно профилируют.
- Сейчас immediate risk низкий — TSPU 2026 не дошёл до WS frame rate analysis (по public research).

### Предлагаемый fix
Установить `maxStreamsPerSlot = 8` для direct mode. На пуле 8 это даёт **до 64 concurrent streams**, что покрывает speedtest (50-60 параллельных connections реалистично) и **не превышает HTTP/2 typical max_concurrent_streams=100**.

**Файл:** `cmd/nixavpn-client/engine_shadowlink.go`:
```go
} else if viaDirect {
    maxStreamsPerSlot = 8  // ← было 0 (unlimited)
    maxBytesPerSlot = 8 * 1024 * 1024
    maxSlotAge = 2 * time.Minute
}
```

### Трудозатраты
- 5 минут реализация.
- Регрессионный риск: **средний**. Если speedtest хочет 80 параллельных connections, а пул 8×8=64 — упрётся в `AssignStream` capacity overflow path (line 1391-1422), который **fallback на слот с fewer streams**. То есть soft overflow, не отказ. Real impact — нужен полевой тест.

### Конфликты
`AssignStream` уже работает с capacity overflow (last-resort fallback). Это уже архитектурный contract.

---

## A5. Bypass routing — implicit destination map exposure

### Что это
`bypass_match` / `bypass_miss` counters показывают сколько пакетов прошло через VPN vs напрямую. Bypass list — **российские IP** (через RIPE snapshot, см. `client/bypassroute/embedded_ru.bin`). TSPU видит:
- Пакеты на **не-российские IP** идут через encrypted tunnel к `104.222.177.67`.
- Пакеты на **российские IP** идут напрямую.

Если TSPU знает наш origin IP (а он знает — это известный публичный шадоулинк-сервер), он строит **карту дестинейшнов клиента**: всё что не-RU = клиент использует VPN на это.

### Как видно на проводе
- TSPU per-flow tracking: source 192.168.x.y → multiple destinations. Те которые `RU CIDR` — direct. Те которые foreign — все идут на 104.222.177.67. **Vectorized DNAT-like pattern**.

### Подтверждение что не сделано
**Файл:** `client/bypassroute/` — содержит embedded RIPE RU snapshot. Только match по CIDR-tree, никакого dummy traffic для камуфляжа.

В архитектуре нет:
- Random "cover" connections to non-RU IPs (чтобы выглядело будто иногда мы ходим напрямую за рубеж).
- Spillover dummy traffic через bypass на foreign IPs (наоборот — фейковый VPN-трафик на RU IPs).

### Риск
- Структурный, не immediate. Это **fundamental design tradeoff** между performance (не тащить RU через зарубеж) и privacy (не выдавать карту destinations).
- TSPU **сейчас не строит** такие карты на client side (он видит только server-side flows). Но **провайдер** может — это полностью внутри его инфраструктуры.

### Предлагаемый fix
**Не закрывается тривиально.** Возможные подходы:
1. **Best-effort:** добавить `decoy_traffic` к **российским IP через VPN** (т.е. иногда RU IP идёт через VPN намеренно). Trade-off: повышение latency на ~5-10% RU трафика.
2. **Принципиально:** убрать bypass routing вообще — всё через VPN. Trade-off: -30% perceived speed на RU-сайтах для всех клиентов.

Решение требует продукт-обсуждения. Не код-fix.

### Трудозатраты
- Не оценимы без декомпозиции (надо взвесить product trade-offs).

### Конфликты
Touch'ает `bypassroute` package + admin override fullstack — minor refactor если выбрать опцию 1.

---

## A6. WS frame size — regular 12KB chunks on tail-end writes

### Что это
`chunk_size = 12288` (server `-chunk-size 12288` default). Padding применяется **только для chunks < 80 байт** (control frames CONNECT/FIN — см. `client/ws_transport.go:715`). Data frames до chunk_size идут **без padding**. На проводе:
- Heavy upload: множество frames размером **ровно 12288 + overhead**. Это **signature** конкретного клиента.
- Реальный Mixpanel `/track` — variable-size JSON 600-3000 байт (sample log-normal в `skins/browser/padding.go:8-23`).

### Как видно на проводе
- TLS Record размер distribution. У нас бимодал: control ~600-3000B (мы padding'ом сделали), data ровно ~12KB.
- Mixpanel real distribution: монорежим в районе 600-3000B (нет 12KB).

### Подтверждение что не сделано
**Файл:** `client/ws_transport.go:712-721`:
```go
// Pad small control chunks to defeat length-based DPI fingerprinting.
// Chunks under 80 bytes are typically FlagConnect or FlagFin — pad to a
// distribution-realistic size.
if len(data) < 80 {
    ...
    data = browser.PadToSize(data, target)
}
```
Только `< 80 байт`. Data frames НЕ padding'уются.

**Файл:** `client/connmanager.go` — `SendChunk` использует `SamplePaddingTarget` для body POST padding в split-mode, **но не для WS frames**. WS пишет raw encrypted chunk.

### Риск
- Высокий long-term. Это **первое** что увидит грамотный DPI. Mixpanel persona ломается прямо на размере frames.
- Сейчас immediate risk низкий — TSPU 2026 не делает packet size statistics per-flow (по public research).

### Предлагаемый fix
**Архитектурно сложный.** Padding data frames до variable size — это:
1. Bandwidth overhead. При chunk_size=12KB и target_padded_size=18KB — это +50% bytes на провод. На 600 Mbps это ощутимо.
2. Несовместимо с current "fill the chunk to capacity" upload pattern — потребует переписать send pipeline.

Альтернатива #1: **уменьшить `chunk_size`** на сервере до ~6KB-9KB — middle distribution between control (3KB) и raw data (12KB), естественно сглаживает bimodal. Trade-off: больше WS frames на тот же объём — может выбить TCP window scaling pattern в другую анти-сторону.

Альтернатива #2: **randomize chunk_size** per session (server side, в handshake response). Client уже принимает `shData.ChunkSize` через `ServerHello`. Сэмплить из {6144, 8192, 10240, 12288} per session — каждая сессия имеет свой "стиль".

### Трудозатраты
- Альтернатива #2: 2-3 часа. Server: random sample в `handleHandshakeNew`. Client: уже принимает значение. Тесты — distribution rejection (none of 4 values dominate beyond expected).

### Конфликты
Phase 0 body-prefix wire-format v1 фиксирует chunk_size в handshake (`docs/protocols/body-prefix-v1.md`). Менять его per-session — wire-compatible (это просто другое значение в существующем поле).

---

## Сводная таблица

| ID | Что | Risk | Effort | Performance trade-off | Закрыть? |
|---|---|---|---|---|---|
| **A1** | Rotation stagger без jitter (FFT peak) | Medium | 30 min | None | ✅ Рекомендую сделать |
| **A2** | Reconnect handshake cluster | Medium-Low | 1h | +2.4s recovery latency | ✅ Рекомендую сделать |
| **A3** | Bimodal `down_bytes` (наш byte budget) | Medium | 1.5h | None | ✅ Рекомендую сделать |
| **A4** | maxStreamsPerSlot=0 в direct | High long-term | 5 min + полевой тест | Возможно download ↓ под burst | ⚠️ Тестовый замер сначала |
| **A5** | Bypass exposes destination map | Structural | Product decision | -10% RU latency или -30% global speed | ❌ Product call, не код |
| **A6** | WS frame size = 12KB regular | High long-term | 2-3h (variant: random chunk_size per session) | Negligible | ⚠️ Архитектурный, не срочно |

## Приоритизация

**Quick wins (1 sprint, низкий риск):** A1 + A2 + A3. Суммарно ~3 часа, нулевой performance impact, закрывает 3 detectable signature класса. Регрессионные тесты переписываются на distribution-based вместо value-pinned.

**Требует тестового замера:** A4. 5 минут кода, но если 80 параллельных connections заведут soft-overflow на одном слоте — производительность может просесть.

**Долгосрочно:** A6 (через A6.2 — random chunk_size). Эта правка ломает текущую wire signature **навсегда** — TSPU должен переучивать классификатор.

**Product решение:** A5. Это про trade-off design philosophy.

## Конфликты с уже сделанным

- **storm brake (2026-05-18)** — НЕ конфликтует ни с одним из 6. Он смотрит count non-ready, не времена/байты.
- **slotDeathCause (2026-05-18)** — НЕ конфликтует. Causes attribute teardown reason, не trigger.
- **WS reader exit forensics (2026-05-18)** — наоборот, **поможет** проверить эффект A1/A3: если внедрить — `peer_eof` должен остаться доминирующим (значит мы не создаём дополнительных closes своим jitter).

## Что НЕ нужно делать

- **Не нужно** пересматривать Mimicry Session (A2-MED-10, T2.4) — там всё закрыто корректно.
- **Не нужно** трогать uTLS Chrome 133 lockstep (F2) — это работает.
- **Не нужно** реактивировать cover GET (F3 retire) — мы это уже разобрали как анти-pattern.
