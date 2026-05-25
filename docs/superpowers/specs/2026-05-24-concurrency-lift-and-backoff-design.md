# WS Pool Concurrency Lift + Reserve-Slot Backoff

**Status:** design ready for review (2026-05-24 evening)
**Driver canary:** `/tmp/nixavpn-graceful-drain-20260524-163239.log` (4h3m, 2026-05-24 16:32-20:36)
**Analysis:** `D:\NIXAVPN\docs\canary-2026-05-24-post-fix-analysis.md`
**Predecessor spec:** `2026-05-24-drain-diagnostics-counter-split-design.md` (counter split visibility fix that made this diagnosis possible)

## Problem statement

Канарейка 2026-05-24-evening (4h3m) с включёнными diagnostic counters показала
два конкретных архитектурных факта:

1. **100% storm-brake defers пришлись на inflight cap gate** — `InflightCapDeferredTotal=12497` vs `CapacityFloorDeferredTotal=0`. Пул провёл **77% времени** в `inflight_drains=2` saturation (это и есть текущий `maxConcurrentDrains` при poolSize=6 = `ceil(6 * 0.25) = 2`).

2. **24 TIME_WAIT exhaustion events** — Windows TCP ephemeral port exhaustion при reserve-slot connect к `104.222.177.67:443`. Распределено равномерно по 4h. Возникает потому что `connectReserveSlot` при failure запускает `go p.reconnectLoop(newIdx)` **без задержки** — busy-retry loop на том же endpoint'е держит socket в TIME_WAIT.

Hard cap reached % (46%) — это **симптом, не первопричина.** Drain scheduler хочет ротировать слот, упирается в inflight cap, defer'ит, стрим живёт дольше, накапливает age, режется по hard-cap ceiling.

## Goals

1. **Развязать два knob'а** (`maxConcurrentDrains` и `readyCapacityFloor`) которые сейчас derive'ятся из одной константы `rotationStormBrakeFraction = 0.25`. Архитектурно это две разные защиты с разными trigger conditions — склейка через одну const артефакт исторического дизайна.

2. **Поднять `maxConcurrentDrainsFraction` с 0.25 до 0.5** → при poolSize=6 даст `maxConcurrentDrains=3` (вместо 2). Сохранить `readyCapacityFloor=4` неизменным (capacity floor gate не срабатывал ни разу за 4h — нет данных оправдывающих его движение).

3. **Exponential backoff на `connectReserveSlot` failure** — per-cell counter + `0.5s → 1s → 2s → ... → 30s` cap, ±20% jitter, сброс на успешный connect. Защита от TIME_WAIT шторма при cascade failures, особенно важно потому что P0 (выше) поднимет concurrency и без backoff'а даст регресс по TIME_WAIT.

   **TIME_WAIT hypothesis (opus review M1):** Windows TIME_WAIT default 120-240s (`TcpTimedWaitDelay`). Backoff 500ms-30s **не очищает** TIME_WAIT slots — каждый reconnect всё равно открывает новый ephemeral port. Backoff лечит **rate of new socket creation**, не **socket lifecycle**. Эффекты:
   - При single failure: 500ms wait → новый ephemeral port → consumes pool. Backoff помогает только если другой cell освободит port раньше.
   - При cascade failure (наш сценарий): exp backoff разносит reconnects во времени → cumulative rate of new sockets падает кратно (с potential 10 reconnects/sec до ~1-2/sec) → ephemeral pool успевает recover.
   - **Это частичное решение.** Полное (Windows-specific) — `SO_REUSEADDR` на dial socket'е или Registry tweak `TcpTimedWaitDelay 240→30s`. Spec не включает их потому что (a) `SO_REUSEADDR` требует encrypted dial flow rewrite, (b) Registry — пользовательская OS-настройка, не код.
   - **Acceptance criterion #8 (TIME_WAIT errors → 5-10/4h) — гипотеза, не математическая гарантия.** Если после P0+P2 показатель не упадёт ниже 15-20/4h → принять SO_REUSEADDR как Phase 2 follow-up. Если упадёт ниже 5 — гипотеза подтверждена.

## Non-goals

- Менять `SHADOWLINK_DRAIN_HARD_CAP` (90s) — после проверки P0+P2 на канарейке
- Менять `poolSize` (6) — не нужно если concurrency lift разрулит inflight gate
- Менять `readyCapacityFloorFraction` — 0 defers за 4h означает «не трогать»
- Wire-format / server-side изменения — none
- Histogram `drain_natural_finish_duration` — отдельная задача
- Leakguard `0xc000013a` shutdown race — отдельный bugfix

## Design

### 1. Knob decoupling

**Файл:** `shadowlink/client/ws_pool.go`

**Удалить:**
```go
const rotationStormBrakeFraction = 0.25
```

**Добавить (на том же месте):**

```go
// maxConcurrentDrainsFraction — fraction of poolSize that defines the
// maximum number of concurrent in-flight drains. Inflight cap for the
// drain scheduler's storm-brake. Raised 2026-05-24 from 0.25 (=2 drains
// at poolSize=6) to 0.5 (=3 drains) because canary 2026-05-24-evening
// showed 100% of storm-brake defers landing on the inflight gate and 0%
// on the capacity-floor gate (12497 vs 0 over 4h3m). The pool spent 77%
// of its time at inflight=2 saturation — drains queued behind the cap,
// streams accumulated age, then hit the 90s hard-cap ceiling. Raising
// the cap allows the scheduler to dispatch drains promptly.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff).
const maxConcurrentDrainsFraction = 0.5

// readyCapacityFloorFraction — fraction of poolSize that must be in
// slotReady state before storm-brake permits a new drain. Catastrophic-
// state gate: when ready slots fall below this floor, the pool is losing
// slots faster than reconnectLoop heals — defer drains so reconnects can
// catch up.
//
// Decoupled 2026-05-24 from maxConcurrentDrainsFraction (previously both
// derived from a single rotationStormBrakeFraction=0.25 constant). The
// canary 2026-05-24-evening proved this gate never triggers in steady
// state (0 defers over 4h), so it's set independently of the inflight
// cap. Value 0.75 preserves the prior floor at poolSize=6 (was floor=4,
// stays floor=4) — purely decoupling, no behavior change for the
// capacity-floor branch.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff).
const readyCapacityFloorFraction = 0.75
```

**Patch `readyCapacityFloor()`:**

```go
func (p *WSPoolTransport) readyCapacityFloor() int {
	floor := int(math.Floor(float64(p.poolSize) * readyCapacityFloorFraction))
	if floor < 1 {
		floor = 1
	}
	if floor >= p.poolSize {
		floor = p.poolSize - 1 // never block all drains
	}
	return floor
}
```

**Patch `maxConcurrentDrains()`:**

```go
func (p *WSPoolTransport) maxConcurrentDrains() int {
	mcd := int(math.Ceil(float64(p.poolSize) * maxConcurrentDrainsFraction))
	if mcd < 1 {
		mcd = 1
	}
	if mcd >= p.poolSize {
		mcd = p.poolSize - 1 // never block all drains; preserve floor >= 1
	}
	return mcd
}
```

**Invariant note:** при poolSize=6 → `maxConcurrentDrains=3`, `readyCapacityFloor=4`. Сумма `mcd+floor=7` **больше** poolSize=6. Раньше это было запрещено invariant'ом `floor = poolSize - mcd`. Теперь — допустимо. Два gate'а проверяют **разные условия** (inflight count vs ready count) и логически не конфликтуют: один защищает от scheduler overload, другой — от cascade slot deaths.

**Degenerate state analysis (opus review M2):** при максимальной нагрузке pool может оказаться в состоянии `inflight_drains=3, draining=3, ready=poolSize-3=3`. Это **ниже floor=4** → дальнейшие drains будут defer'иться на **обоих** gates (inflight cap И capacity floor). Это **корректное и желаемое** поведение — оба защитных механизма работают совместно:
- Inflight gate говорит "уже 3 в полёте, хватит"
- Capacity floor говорит "ready капитально упал, не разгоняй"
- DrainWatchdog для каждого draining slot eventually завершит drain (natural finish or hard cap) → ready вернётся → один из gate'ов разрешит следующий drain

Pool не залипнет: idle-finish path в drainWatchdog снижает streams без увеличения ready (slot всё ещё в slotDraining), но **hard cap 90s** гарантирует teardown → cell освобождается → reconnectLoop возвращает new slot в slotReady → ready++. Worst-case latency для recovery = 90s, ограничена hard_cap.

Это **expected behavior under cascade**, не баг decoupling. Декаплинг просто делает оба gate'а независимо тюнаемыми.

### 2. Reserve-slot exponential backoff

**Counter placement:** на pool-level array indexed by cell index, NOT per-`poolSlot`. Lifetime = pool lifetime (не slot lifetime), потому что cell может быть recycled (`p.slots[i] = nil` → следующий `claimFreeSlot` создаёт fresh `poolSlot` с counter=0). При cascade failure это даёт busy-retry — fresh slot всегда начинает с 500ms backoff. Хранение counter на pool level закрывает этот baseline race (опус-ревью H2, 2026-05-24).

**Файл:** `shadowlink/client/ws_pool.go` (struct `WSPoolTransport`)

Добавить поле рядом с `lastInflightCapLogNs` (созданным в предыдущей спеке):

```go
// reserveConnectFailures — per-cell consecutive-failure counter for
// connectReserveSlot. Indexed by cell index (0..2*poolSize-1). Reset
// to 0 on successful connect. Lives on the pool (not the poolSlot)
// because cells get recycled — placing the counter on poolSlot would
// reset it to zero each time a fresh slot replaces a failed one,
// defeating the backoff under cascade failures.
//
// Slice size: 2 * poolSize (matches the slots slice). Pre-allocated in
// NewWSPoolTransport so connectReserveSlot can do lock-free atomic
// Add/Store/Load on a stable address.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff) §2.
reserveConnectFailures []atomic.Int32
```

Инициализация в `NewWSPoolTransport` (рядом с `slots = make(...)`):

```go
p.reserveConnectFailures = make([]atomic.Int32, 2*poolSize)
```

(Точная строка определяется при имплементации — прочитать NewWSPoolTransport и поставить инициализацию рядом с `p.slots = make(...)`.)

**Файл:** `shadowlink/client/ws_pool_drain.go` (const block)

Добавить:

```go
// reserveConnectInitialBackoff — first delay after connectReserveSlot
// fails, before spawning reconnectLoop. Doubled on each consecutive
// failure up to reserveConnectMaxBackoff. Spec 2026-05-24.
reserveConnectInitialBackoff = 500 * time.Millisecond

// reserveConnectMaxBackoff — ceiling for connectReserveSlot exponential
// backoff. Equal to drainRevertBackoff (30s) for symmetry with the
// existing "slice full" retry timeline. Spec 2026-05-24.
reserveConnectMaxBackoff = 30 * time.Second

// reserveConnectBackoffJitterFraction — ±20% jitter applied to the
// computed backoff to avoid thundering herd when multiple slots fail
// simultaneously (e.g. cascade TIME_WAIT exhaustion under upload load).
// Spec 2026-05-24.
reserveConnectBackoffJitterFraction = 0.2
```

**Файл:** `shadowlink/client/ws_pool_drain.go` (helper)

```go
// computeReserveBackoff returns an exponential backoff delay for the
// connectReserveSlot retry path, capped at reserveConnectMaxBackoff and
// jittered ±20% to break synchrony across slots.
//
// failures: consecutive failure count for this slot (1-based — 1 means
// "first failure", 2 means "second failure", etc.). Caller passes the
// value AFTER incrementing the counter, so failures=1 produces the
// initial backoff (500ms ± jitter), failures=2 produces 1s ± jitter,
// and so on, doubling until the 30s ceiling.
//
// The rng parameter returns float64 in [0.0, 1.0); production passes
// rand.Float64 (math/rand/v2). Tests pass a deterministic function to
// pin the jitter value.
//
// Spec 2026-05-24 (concurrency-lift-and-backoff) §3.
func computeReserveBackoff(failures int32, rng func() float64) time.Duration {
	if failures < 1 {
		failures = 1
	}
	// Cap shift to avoid int overflow at high failure counts.
	const maxShift = 30
	shift := failures - 1
	if shift > maxShift {
		shift = maxShift
	}
	delay := reserveConnectInitialBackoff << shift
	if delay > reserveConnectMaxBackoff || delay <= 0 {
		delay = reserveConnectMaxBackoff
	}
	// Apply ±20% jitter. rng returns [0.0, 1.0); map to [-0.2, +0.2].
	jitterFrac := (rng() - 0.5) * 2 * reserveConnectBackoffJitterFraction
	jittered := time.Duration(float64(delay) * (1.0 + jitterFrac))
	if jittered < 0 {
		jittered = 0
	}
	return jittered
}
```

**Файл:** `shadowlink/client/ws_pool_drain.go` (rewrite `connectReserveSlot`)

```go
func (p *WSPoolTransport) connectReserveSlot(cl *Client, newIdx, oldIdx int) {
	if newIdx < 0 || newIdx >= len(p.slots) {
		return
	}

	var err error
	if connectSlotForTest != nil {
		err = connectSlotForTest()
	} else {
		err = p.connectSlot(p.ctx, newIdx)
	}

	if err != nil {
		// Counter on pool level (indexed by cell), not on poolSlot —
		// survives cell recycle. Atomic Add is race-safe under concurrent
		// connectReserveSlot calls; pool-level array avoids the per-slot
		// "fresh poolSlot → counter=0 → busy retry" trap under cascade
		// failures. (Opus review H2.)
		failures := p.reserveConnectFailures[newIdx].Add(1)
		Stats.ReserveConnectFailuresTotal.Add(1)

		p.reserveMu.Lock()
		if p.slots[newIdx] != nil && p.slots[newIdx].getState() != slotReady {
			p.slots[newIdx] = nil // free for next claim
		}
		p.reserveMu.Unlock()

		backoff := computeReserveBackoff(failures, rand.Float64)
		p.log.Warn("WS pool reserve slot connect failed — placeholder freed",
			"slot", newIdx, "for_drain_of", oldIdx,
			"err", err,
			"consecutive_failures", failures,
			"reconnect_backoff", backoff.Truncate(time.Millisecond))

		go func() {
			select {
			case <-p.ctx.Done():
				return
			case <-time.After(backoff):
			}
			p.reconnectLoop(newIdx)
		}()
		return
	}

	// Success — reset the failure counter for this cell. Pool-level
	// storage means this reset persists across cell recycle.
	p.reserveConnectFailures[newIdx].Store(0)
	go p.slotReader(newIdx)
}
```

**Counter lifecycle:** counter живёт per-cell. Когда cell освобождается (`p.slots[newIdx] = nil`), counter теряется со слотом. Следующий `claimFreeSlot` создаёт новый `poolSlot` с counter=0. Это корректно — backoff bounded by per-attempt history, не глобальный.

### 3. Stats counter for monitoring + stale-reference cleanup

**Stale reference cleanup (opus review H1):** в `client/stats.go` есть Prom HELP text который ссылается на удаляемую `rotationStormBrakeFraction`:

```
shadowlink_slot_drain_capacity_floor_deferred_total ... readyCapacity < poolSize * rotationStormBrakeFraction
```

Найти все упоминания удаляемой const через `grep -rn "rotationStormBrakeFraction" shadowlink/client/`. Обновить найденные HELP-texts и комментарии на `readyCapacityFloorFraction` (для capacity-floor Prom HELP) или `maxConcurrentDrainsFraction` (если упоминается inflight cap). Также в `client/stats.go::CapacityFloorDeferredTotal` doc-comment (~line 243) — обновить ссылку.

**Добавить в struct** (рядом с `DrainForceEvictedActiveTotal`):

```go
// ReserveConnectFailuresTotal — cumulative count of connectReserveSlot
// failures (across all cells). High rate suggests TIME_WAIT exhaustion
// or origin endpoint instability — investigate before raising
// maxConcurrentDrainsFraction further. Spec 2026-05-24
// (concurrency-lift-and-backoff).
ReserveConnectFailuresTotal atomic.Uint64
```

Prometheus exposition:

```go
fmt.Fprintf(w, "# HELP shadowlink_reserve_connect_failures_total Cumulative count of connectReserveSlot failures across all cells\n")
fmt.Fprintf(w, "# TYPE shadowlink_reserve_connect_failures_total counter\n")
fmt.Fprintf(w, "shadowlink_reserve_connect_failures_total %d\n", Stats.ReserveConnectFailuresTotal.Load())
```

## Testing

Все новые тесты — в `shadowlink/client/ws_pool_drain_logging_test.go` или новом `ws_pool_reserve_backoff_test.go` (выбрать при имплементации по размеру файла).

### Knob decoupling tests

1. **`TestMaxConcurrentDrains_NewValueAfterLift_2026_05_24`** — table test для poolSize ∈ {1, 4, 6, 8} с ожидаемыми значениями 1, 2, 3, 4.
2. **`TestReadyCapacityFloor_UnchangedAfterDecouple_2026_05_24`** — table test для poolSize ∈ {1, 4, 6, 8} с ожидаемыми значениями 1, 3, 4, 6 (значение 4 при poolSize=6 совпадает с pre-decouple для регрессии).
3. **`TestKnobs_AreIndependent_2026_05_24`** — assert что `mcd + floor > poolSize` при poolSize=6 (фингерпринт что decoupling действительно произошёл).
4. Существующий `TestReadyCapacityFloor_DerivedFromPoolSize` (table) — обновить ожидаемые значения если они изменились (нужно проверить точные числа при имплементации).

### computeReserveBackoff tests

5. **`TestComputeReserveBackoff_FirstFailure`** — `failures=1, rng=0.5 (no jitter)` → `500ms` exact.
6. **`TestComputeReserveBackoff_DoublesEachFailure`** — table: failures=1..6 без jitter → 500ms / 1s / 2s / 4s / 8s / 16s.
7. **`TestComputeReserveBackoff_CapsAtMax`** — failures ∈ {7, 10, 100, 1000, 1<<20} → ровно `reserveConnectMaxBackoff=30s`.
8. **`TestComputeReserveBackoff_JitterBounds`** — `rng=0.0` → `0.8 * initialBackoff`, `rng=0.999...` → `1.2 * initialBackoff` (slop 1µs).
9. **`TestComputeReserveBackoff_GuardsZeroFailures`** — failures ∈ {0, -1, -100} → возвращает `reserveConnectInitialBackoff`.

### Counter-reset invariant

10. **`TestConnectReserveSlot_ResetsFailureCounterOnSuccess`** — pre-load `p.reserveConnectFailures[0].Store(5)`, инсталлировать `connectSlotForTest = func() error { return nil }`, вызвать `p.connectReserveSlot(...)` напрямую, проверить что `p.reserveConnectFailures[0].Load() == 0`. Это **реально проверяет business logic** через `connectSlotForTest` hook (он уже используется в тестах, например `TestStartDrain_InflightCounterCaps`), а не тавтологически вызывает `.Store(0)` сам по себе (opus review M3).

11. **`TestConnectReserveSlot_IncrementsFailureCounterOnFailure`** — pre-load 0, инсталлировать `connectSlotForTest = func() error { return errors.New("simulated") }`, вызвать `p.connectReserveSlot(...)`, проверить что `p.reserveConnectFailures[0].Load() == 1`. После повторного вызова — `== 2`. Подтверждает что counter растёт под pool-level array, переживает per-call invocations.

12. **`TestConnectReserveSlot_PoolLevelCounterSurvivesSlotRecycle`** — pre-load 3 в `p.reserveConnectFailures[0]`. Через `connectSlotForTest` сэмулировать failure → cell стал nil → создать новый `poolSlot{index:0}` через `claimFreeSlot` → пройти ещё одну failed connectReserveSlot → проверить counter == 5 (не 1!). Это **regression guard** для opus review H2 — counter живёт на pool, не на slot.

### Race detector

Запустить полный client suite под `-race -count=3` на CI Linux. Critical paths: `reserveConnectFailures[idx].Add/Store/Load` под concurrent `connectReserveSlot` calls.

### Acceptance pre-merge greps (opus review M4)

Перед merge выполнить grep'ы на остатки удалённой const и magic number:

```bash
# Должен вернуть только docs/ (snapshot in time), НЕ client/*.go
grep -rn "rotationStormBrakeFraction" shadowlink/

# Должен вернуть только тесты которые осознанно используют 0.25 для других целей (не storm-brake)
grep -rn "0\.25" shadowlink/client/*_test.go shadowlink/client/*.go | grep -v "// "
```

Если grep #1 находит matches в `client/*.go` — это leftover reference, fix перед merge. Grep #2 контролирует что magic number 0.25 не используется где-то ещё в storm-brake контексте.

## Breaking changes

| Removed | Added | Migration |
|---|---|---|
| `rotationStormBrakeFraction` const | `maxConcurrentDrainsFraction = 0.5`, `readyCapacityFloorFraction = 0.75` | None — internal const. Historical specs (2026-05-02, 2026-05-20, 2026-05-23) treated as archive snapshots — not updated. |
| — | `Stats.ReserveConnectFailuresTotal` counter | None — new monitoring counter. |
| — | Prom `shadowlink_reserve_connect_failures_total` | None — auto-picked up by `shadowlink-metrics-dump-linux`. |
| — | `WSPoolTransport.reserveConnectFailures []atomic.Int32` slice (size 2*poolSize) | None — internal field, allocated in NewWSPoolTransport, zero-init semantically correct. |

**Wire-format:** none. **Server-side:** не изменяется.

**Поведение runtime:**

1. При poolSize=6 `maxConcurrentDrains` был 2, стал 3. Pool обслуживает больше параллельных drain'ов.
2. `connectReserveSlot` failure теперь триггерит exp backoff перед reconnectLoop. Single failure: задержка +~500ms. Cascade failures: до 30s ceiling per cell.
3. WARN log на reserve-slot connect failure теперь содержит `consecutive_failures` и `reconnect_backoff` — диагностика per-cell.

## Acceptance criteria

После деплоя + 2-3h канарейки должно быть видно:

1. **`maxConcurrentDrains() = 3`** — pool достигает `inflight_drains=3` в нескольких health snapshot строках (не всегда 2)
2. **`inflight_cap_deferred_total`** ~4000-6000 за 4h (vs 12497 baseline)
3. **`capacity_floor_deferred_total`** остаётся **0** (decoupling без change-of-behavior validated)
4. **Hard cap reached %** ~25-30% (vs 46%)
5. **WARN hard cap** ~2-3 (vs 10)
6. **`shadowlink_reserve_connect_failures_total`** > 0 в Prom выводе — counter active
7. **Reserve-slot connect failures clustering** прекращён — WARN строки с `consecutive_failures=1..3`, никаких длинных серий
8. **TIME_WAIT exhaustion errors** (`Only one usage of each socket address`) — гипотеза: снизятся с 24/4h до **≤ 15/4h** (улучшение есть, но возможно не до zero). Если показатель остаётся ≥ 20/4h → принять `SO_REUSEADDR` или Registry tweak как Phase 2 follow-up (см. §Problem statement TIME_WAIT hypothesis).

При выполнении criteria канарейка обоснованно подтверждает архитектурное решение.

## Files affected

| File | Type of change | ~LOC |
|---|---|---:|
| `shadowlink/client/ws_pool.go` | Knob decoupling (2 const + 2 function rewrites) + pool-level `reserveConnectFailures []atomic.Int32` field + init in NewWSPoolTransport | ~55 |
| `shadowlink/client/ws_pool_drain.go` | 3 const + `computeReserveBackoff` helper + rewrite `connectReserveSlot` (pool-level counter access) | ~70 |
| `shadowlink/client/stats.go` | `ReserveConnectFailuresTotal` + Prom exposition + **update stale `rotationStormBrakeFraction` references in HELP/comments** (~2 places) | ~18 |
| `shadowlink/client/ws_pool_drain_logging_test.go` (or new `ws_pool_reserve_backoff_test.go`) | 12 unit tests (5 backoff math + 3 knob tables + 3 connectReserveSlot via test-hook + 1 pool-level-counter survives recycle) | ~190 |
| `shadowlink/client/ws_pool_drain_test.go` | Update `TestReadyCapacityFloor_DerivedFromPoolSize` table | ~15 |
| `shadowlink/client/ws_pool_test.go` | Possible regression test updates if any reference `rotationStormBrakeFraction` | ~10 |

**Total: ~360 LOC, ~205 in tests.**

Один пересбор бинарей (7 штук: 2 Windows + 1 Linux client + 1 Mac ARM64 + 1 Linux server + 1 Linux metrics-dump + 1 cf-scanner).

## References

- Driver canary log: `/tmp/nixavpn-graceful-drain-20260524-163239.log`
- Canary analysis: `D:\NIXAVPN\docs\canary-2026-05-24-post-fix-analysis.md`
- Predecessor diagnostic spec: `shadowlink/docs/superpowers/specs/2026-05-24-drain-diagnostics-counter-split-design.md`
- Storm-brake original design: `shadowlink/docs/superpowers/specs/2026-05-20-ws-pool-uniform-cells-design.md`
- Code touch points:
  - `shadowlink/client/ws_pool.go::rotationStormBrakeFraction` (line ~498, removed)
  - `shadowlink/client/ws_pool.go::readyCapacityFloor` (line ~600)
  - `shadowlink/client/ws_pool.go::maxConcurrentDrains` (line ~613)
  - `shadowlink/client/ws_pool_drain.go::connectReserveSlot` (line ~435)
- TIME_WAIT issue manifest: `tunnel/tcp.go:34` warnings in canary log (24 events over 4h)
