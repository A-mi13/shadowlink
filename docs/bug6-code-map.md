# Bug #6 — карта актуального кода (verified 2026-05-29, после Bug #5)

Прочитано из первоисточника. Все факты с file:line из `D:\NIXAVPN\shadowlink\client\`.

## Два триггера ротации (подтверждено ровно 2)

### Триггер 1 — age-rotation
- `ws_pool.go:1276` `rotationWatchdogSweep()` — pool-level goroutine, тикает независимо от трафика.
- `ws_pool.go:1296-1298` условие: `nowNs - started >= maxSlotAge + slot.staggerOffsetNs`.
- `ws_pool.go:1300-1301` graceful path: `p.startDrain(p.client, idx, "age")`.
- `ws_pool.go:1302-1309` legacy path: `maybeRotateSlot(...,"age",...)` — НЕ graceful, уже умеет дефер `slotRotationGraceWithActiveStreams`.

### Триггер 2 — byte_budget-rotation
- `ws_pool.go:2521` `budget := slot.byteBudget.Load()` в `slotReaderWithClient` (на приёме данных).
- `ws_pool.go:2525` `total := slot.downBytes.Add(int64(len(data)))`.
- `ws_pool.go:2532` условие: `total >= budget && byteBudgetRotationAllowed(time.Since(slotStart), p.byteBudgetMinInterval)`.
- `ws_pool.go:2547` graceful path: `p.startDrain(cl, idx, "byte_budget")` + `slot.downBytes.Store(0)` + `continue` (reader продолжает читать downlink!).
- `ws_pool.go:2551` legacy path: `maybeRotateSlot(...,"byte_budget",...)`.
- `byteBudgetRotationAllowed` (Bug #4 rate-floor): `slotAge >= minInterval || minInterval <= 0`.

**ВАЖНО:** оба graceful-триггера вызывают `startDrain` БЕЗ проверки активности стримов. Это точки дефера.

## drainWatchdog + hard-cap (ГЛАВНОЕ ОТКРЫТИЕ)

- `ws_pool_drain.go:557` `drainWatchdog(cl, oldIdx, oldSlot, drainStart, reason)`.
- `:565` ticker = `drainPollInterval`; `:567` `deadline := time.NewTimer(p.drainHardCap)` (default 90s).
- Три причины завершения (`finishCause`): `finishStreamsZero`, `finishIdle`, `finishHardCap`.
- `:628-630` `case <-deadline.C: tearDown(finishHardCap)` — **АБСОЛЮТНЫЙ ПОТОЛОК.** Срабатывает даже если стрим АКТИВЕН.
- `:631-640` `case <-ticker.C`: если `streams==0` → finishStreamsZero; если `idleEnabled && allStreamsIdle(...)` → finishIdle.
- `:637` idle-логика УЖЕ использует `allStreamsIdle` (per-stream lastWriteNs). То есть слот с активным стримом по idle НЕ рвётся — но `deadline.C` (hard-cap) рвёт его поверх idle.

**Вывод:** детекция активности УЖЕ работает в idle-ветке. Bug #6 = hard-cap `deadline` игнорирует активность. Чинить надо именно потолок, а не добавлять детекцию.

## allStreamsIdle (готовый детектор)
- `stream_entry.go:122` `func allStreamsIdle(p *WSPoolTransport, slotIdx int, threshold time.Duration, now time.Time) bool`.
- Поле времени: `streamEntry.lastWriteNs atomic.Int64` (`stream_entry.go:20`).
- Early-exit на первом активном стриме. `found && allIdle`.
- Стампинг lastWriteNs: `ws_pool.go:2601` в slotReader ПОСЛЕ stale-frame check (только для своего slotIdx). При создании — `newStreamEntry` (`stream_entry.go:28`).

## poolSlot поля (drain/rotation/activity)
- `streams atomic.Int32` — счётчик активных стримов на слоте.
- `downBytes atomic.Int64`, `byteBudget atomic.Int64`.
- `startedAtNs atomic.Int64`, `staggerOffsetNs atomic.Int64`.
- `nextDrainAttemptNs atomic.Int64` — drain backoff (storm brake).
- `generation atomic` — bump перед handleSlotDeath (reader exit via shouldExitReader).
- состояния: slotReady / slotDead / slotConnecting / slotDraining / nil(empty).

## drainStreamSnapshot (диагностика)
- `stream_entry.go:35-94` `snapshotDrainStreams` — total / idleAge30sCount / activeCount / max/minStreamAgeMs. idle threshold = 30_000ms.

## Метрики drain (stats.go)
- `DrainNaturalFinishTotal`, `DrainIdleFinishTotal`, `DrainHardCapTotal`, `DrainDurationSeconds` (Observe), `DrainForceEvictedTotal`, `StaleFrameDroppedTotal`, `SnapshotNegativeAgeTotal`.
- `bumpRotations1m()` — rolling 1-min счётчик (health logs).

## readyCapacity / storm brake
- `nextDrainAttemptNs` гейтит повторные попытки drain (backoff).
- startDrain имеет revert если нет reserve (storm brake) — слот остаётся slotReady.
- poolStateCounts инвариант: alive+dead+connecting+draining+empty == 2*poolSize.

## РАСХОЖДЕНИЯ С bug6-design.md (черновик)
1. **Черновик предлагает добавить allStreamsIdle перед startDrain.** Реальность: allStreamsIdle УЖЕ в drainWatchdog idle-ветке (:637). Дефер ПЕРЕД startDrain — это другое (предотвратить вход в drain вообще), а реальная поломка — hard-cap `deadline` поверх уже работающей idle-детекции.
2. **Номера строк сдвинуты:** byte_budget call на :2547 (не :2532, на :2532 условие); age call на :1301 (не :1300).
3. **Черновик не различает «дефер входа в drain» vs «продление/снятие hard-cap».** Это две разные точки с разным эффектом на скрытность — главная развилка дизайна.
4. **`maybeRotateSlot` (legacy non-graceful) уже умеет дефер активных стримов** (`slotRotationGraceWithActiveStreams`) — но graceful-путь (production, ON) этого не делает на входе.
