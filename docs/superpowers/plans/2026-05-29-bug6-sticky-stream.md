# Bug #6 Sticky Stream — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Большая закачка (>90s) переживает ротацию WS-слота — `drainWatchdog` перестаёт рвать активный стрим вслепую по hard-cap, продлевая дренаж под защитой двух backstop-предохранителей и динамического cap.

**Architecture:** Чиним одну ветку `case <-deadline.C` в `drainWatchdog` (`ws_pool_drain.go`): вместо слепого `tearDown(finishHardCap)` принимаем осознанное решение — если стрим активен (`!allStreamsIdle`), не достигнут возрастной (10m) и объёмный (256MiB на TCP) предел, и есть динамическая sticky-квота (readyCapacity > floor, ≤ poolSize/2 слотов), то продлеваем дренаж (`deadline.Reset(5s)`); иначе teardown. Reader-путь byte_budget НЕ трогаем (урок B1). Параметры — типизированные поля `WSPoolConfig`. Sticky-учёт через `*poolSlot.isSticky` (CAS) + глобальный `WSPoolTransport.stickyDrainCount`; helpers работают по захваченному указателю слота, не по индексу (урок H2 cross-recycle).

**Tech Stack:** Go 1.x, `sync/atomic`, hand-rolled atomic metrics (`client/stats.go` — проект НЕ использует prometheus/client_golang), `testing` + `-race`.

**Спека:** `docs/superpowers/specs/2026-05-29-bug6-sticky-stream-design.md` (v2).
**Карта кода:** `docs/bug6-code-map.md`. **Ревью:** `docs/bug6-spec-review-opus-v2.md`.

**ВАЖНО про -race:** проект требует `-race` для concurrent-тестов (CLAUDE.md «Race Detector»), но Windows dev-хост без gcc падает в plain `go test`. Команды ниже дают `-race` вариант; если gcc нет — запускать без `-race`, но Task 6/8 (cross-recycle, клинч) ОБЯЗАТЕЛЬНО прогнать под `-race` на Linux/CI перед мержем.

---

## File Structure

| Файл | Ответственность | Изменение |
|---|---|---|
| `client/ws_pool.go` | поля cfg + дефолты + поля transport/slot + helpers | Modify |
| `client/ws_pool_drain.go` | ветка `deadline.C`, finishCause, defer releaseSticky, sticky_outcome в логах | Modify |
| `client/stats.go` | 5 sticky-метрик | Modify |
| `cmd/nixavpn-client/engine_shadowlink.go` | заполнение 3 полей cfg из env | Modify |
| `client/sticky_stream_test.go` | все sticky-тесты | Create |

**Reader-путь byte_budget (`ws_pool.go:2521-2554`) НЕ трогаем.** Сервер НЕ трогаем. Провод НЕ меняется.

---

### Task 1: WSPoolConfig — 3 новых поля + дефолты в конструкторе

**Files:**
- Modify: `client/ws_pool.go` (WSPoolConfig struct ~`:1078`, NewWSPoolTransport defaults ~`:1116`, struct literal ~`:1141`, WSPoolTransport fields ~`:851`)

- [ ] **Step 1: Добавить поля в WSPoolConfig** (после `DrainIdleStreamsMax int32`, перед закрывающей `}` на `:1078`)

```go
	// ── Bug #6 sticky stream (adaptive backstop) ──
	// StickyMaxDrainAge: макс. время, которое активный стрим переживает дренаж
	// (от старта дренажа, монотонные часы). 0 → default 10m. <=0 после клампа
	// невозможно (см. NewWSPoolTransport); kill switch — отрицательное cfg-значение
	// до клампа → 0 → деградация в слепой hard-cap (pre-Bug#6).
	StickyMaxDrainAge time.Duration

	// StickyMaxTotalBytes: анти-TSPU потолок на текущем отрезке TCP (downBytes).
	// 0 → default 256 MiB. Рвём активный стрим если TCP прокачал столько —
	// per-flow byte counter detection vector (ws_pool.go byteBudget docstring).
	StickyMaxTotalBytes int64

	// StickyMaxSlots: статический потолок одновременно sticky-слотов. 0 → авто
	// (poolSize/2). <0 → sticky запрещён (cap=0). Фактический cap ещё и
	// динамический — гейтится readyCapacity (см. stickyQuotaAvailable).
	StickyMaxSlots int
```

- [ ] **Step 2: Добавить поля в WSPoolTransport struct** (после `drainIdleStreamsMax int32` на `:859`)

```go
	// ── Bug #6 sticky stream (adaptive backstop) ──
	stickyMaxDrainAge   time.Duration // от старta дренажа; 0 = sticky выключен
	stickyMaxTotalBytes int64         // анти-TSPU потолок на TCP
	stickyMaxSlots      int           // статический потолок (0=авто poolSize/2, <0=выкл)
	stickyDrainCount    atomic.Int32  // слотов СЕЙЧАС в sticky-продлении (глобальный)
```

- [ ] **Step 3: Добавить дефолты в NewWSPoolTransport** (после блока `drainIdleStreamsMax` ~`:1119`, перед `byteBudgetMinInterval`)

```go
	// Bug #6 sticky stream defaults. StickyMaxDrainAge<=0 is the kill switch:
	// the deadline branch degrades to the legacy blind hard-cap teardown.
	stickyMaxDrainAge := cfg.StickyMaxDrainAge
	if stickyMaxDrainAge == 0 {
		stickyMaxDrainAge = 10 * time.Minute
	}
	// negative stays negative → sticky disabled (kill switch).
	stickyMaxTotalBytes := cfg.StickyMaxTotalBytes
	if stickyMaxTotalBytes <= 0 {
		stickyMaxTotalBytes = 256 * 1024 * 1024 // 256 MiB
	}
```

- [ ] **Step 4: Добавить поля в struct literal** (после `drainIdleStreamsMax: drainIdleStreamsMax,` на `:1141`)

```go
		stickyMaxDrainAge:   stickyMaxDrainAge,
		stickyMaxTotalBytes: stickyMaxTotalBytes,
		stickyMaxSlots:      cfg.StickyMaxSlots,
```

- [ ] **Step 5: Сборка проходит**

Run: `cd /d/NIXAVPN/shadowlink && go build ./client/`
Expected: успех (поля добавлены, нигде ещё не используются — ОК для Go, поля структуры).

- [ ] **Step 6: Commit**

```bash
git add client/ws_pool.go
git commit -m "feat(shadowlink): Bug #6 — WSPoolConfig sticky stream fields + defaults"
```

---

### Task 2: poolSlot.isSticky + effectiveStickyMaxSlots helper

**Files:**
- Modify: `client/ws_pool.go` (poolSlot struct ~`:329`, helper рядом с readyCapacityFloor ~`:633`)
- Test: `client/sticky_stream_test.go` (Create)

- [ ] **Step 1: Написать падающий тест на effectiveStickyMaxSlots**

```go
package client

import "testing"

func TestEffectiveStickyMaxSlots(t *testing.T) {
	cases := []struct {
		name       string
		poolSize   int
		cfgMax     int
		wantResult int
	}{
		{"auto half of 6", 6, 0, 3},
		{"auto half of 8", 8, 0, 4},
		{"auto poolSize 2 → min 1", 2, 0, 1},
		{"auto odd 5 → 2", 5, 0, 2},
		{"explicit 1", 6, 1, 1},
		{"explicit cap above half", 6, 5, 5},
		{"negative → disabled (0)", 6, -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &WSPoolTransport{poolSize: tc.poolSize, stickyMaxSlots: tc.cfgMax}
			if got := p.effectiveStickyMaxSlots(); got != tc.wantResult {
				t.Errorf("poolSize=%d cfgMax=%d: got %d, want %d",
					tc.poolSize, tc.cfgMax, got, tc.wantResult)
			}
		})
	}
}
```

- [ ] **Step 2: Запустить тест — убедиться что падает**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run TestEffectiveStickyMaxSlots -v`
Expected: FAIL — `p.effectiveStickyMaxSlots undefined`.

- [ ] **Step 3: Добавить поле isSticky в poolSlot** (после `nextDrainAttemptNs atomic.Int64` на `:329`, перед закрывающей `}`)

```go
	// isSticky marks that THIS slot's drainWatchdog currently holds a sticky
	// extension slot in the pool-wide stickyDrainCount (Bug #6). Set via
	// markSticky (CAS false→true, increments count once), cleared via
	// releaseSticky (Swap, decrements once). Lives on poolSlot (not keyed by
	// index) so a recycled cell's NEW *poolSlot starts with isSticky=false
	// (zero value) and the OLD watchdog's deferred releaseSticky operates on
	// its OWN captured *poolSlot — no cross-recycle counter desync (spec H2).
	isSticky atomic.Bool
```

- [ ] **Step 4: Добавить helper effectiveStickyMaxSlots** (после `readyCapacityFloor` на `:633`)

```go
// effectiveStickyMaxSlots is the static ceiling on concurrently-sticky slots
// (Bug #6). 0 (config) → auto = poolSize/2 (min 1). <0 → 0 (sticky disabled).
// The ACTUAL cap is further gated dynamically by readyCapacity in
// stickyQuotaAvailable — this is only the upper bound.
func (p *WSPoolTransport) effectiveStickyMaxSlots() int {
	if p.stickyMaxSlots > 0 {
		return p.stickyMaxSlots
	}
	if p.stickyMaxSlots < 0 {
		return 0
	}
	half := p.poolSize / 2
	if half < 1 {
		half = 1
	}
	return half
}
```

- [ ] **Step 5: Запустить тест — проходит**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run TestEffectiveStickyMaxSlots -v`
Expected: PASS (все 7 кейсов).

- [ ] **Step 6: Commit**

```bash
git add client/ws_pool.go client/sticky_stream_test.go
git commit -m "feat(shadowlink): Bug #6 — poolSlot.isSticky + effectiveStickyMaxSlots"
```

---

### Task 3: markSticky / releaseSticky / stickyQuotaAvailable helpers

**Files:**
- Modify: `client/ws_pool.go` (после effectiveStickyMaxSlots)
- Test: `client/sticky_stream_test.go`

- [ ] **Step 1: Написать падающий тест на markSticky/releaseSticky идемпотентность**

```go
func TestStickyMarkReleaseIdempotent(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	slot := &poolSlot{index: 0}

	// markSticky дважды → счётчик +1 ровно один раз (CAS гейт).
	p.markSticky(slot)
	p.markSticky(slot)
	if got := p.stickyDrainCount.Load(); got != 1 {
		t.Fatalf("after 2× markSticky: count=%d, want 1", got)
	}
	if !slot.isSticky.Load() {
		t.Fatal("isSticky should be true after markSticky")
	}

	// releaseSticky дважды → счётчик -1 ровно один раз (Swap гейт).
	p.releaseSticky(slot)
	p.releaseSticky(slot)
	if got := p.stickyDrainCount.Load(); got != 0 {
		t.Fatalf("after 2× releaseSticky: count=%d, want 0", got)
	}
	if slot.isSticky.Load() {
		t.Fatal("isSticky should be false after releaseSticky")
	}
}

func TestStickyQuotaAvailable(t *testing.T) {
	// readyCapacity для теста: все слоты slotReady → readyCapacity=poolSize.
	newReadyPool := func(size, cfgMax int) *WSPoolTransport {
		p := &WSPoolTransport{poolSize: size, stickyMaxSlots: cfgMax}
		p.slots = make([]*poolSlot, 2*size)
		for i := 0; i < size; i++ {
			s := &poolSlot{index: i}
			s.state.Store(int32(slotReady))
			p.slots[i] = s
		}
		return p
	}

	t.Run("already sticky → always allowed", func(t *testing.T) {
		p := newReadyPool(6, 0)
		s := &poolSlot{index: 0}
		s.isSticky.Store(true)
		if !p.stickyQuotaAvailable(s) {
			t.Fatal("already-sticky slot must always be allowed to extend")
		}
	})

	t.Run("under cap + healthy capacity → allowed", func(t *testing.T) {
		p := newReadyPool(6, 0) // cap=3, readyCapacity=6, floor≈3
		s := &poolSlot{index: 0}
		if !p.stickyQuotaAvailable(s) {
			t.Fatal("fresh slot under cap with healthy capacity should be allowed")
		}
	})

	t.Run("at static cap → denied", func(t *testing.T) {
		p := newReadyPool(6, 0) // cap=3
		p.stickyDrainCount.Store(3)
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("at static cap, new sticky must be denied")
		}
	})

	t.Run("capacity at floor → denied", func(t *testing.T) {
		p := newReadyPool(6, 0)
		// сбросить все slotReady кроме floor → readyCapacity<=floor
		for i := 0; i < 6; i++ {
			p.slots[i].state.Store(int32(slotDraining))
		}
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("at/below capacity floor, new sticky must be denied")
		}
	})

	t.Run("disabled cap (cfgMax<0) → denied", func(t *testing.T) {
		p := newReadyPool(6, -1) // effective cap=0
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("cfgMax<0 disables sticky → denied")
		}
	})
}
```

- [ ] **Step 2: Запустить — падает**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run 'TestStickyMarkReleaseIdempotent|TestStickyQuotaAvailable' -v`
Expected: FAIL — `p.markSticky undefined`, `p.stickyQuotaAvailable undefined`.

- [ ] **Step 3: Реализовать три helper'а** (после effectiveStickyMaxSlots)

```go
// markSticky records that slot's watchdog holds a sticky extension. CAS gate
// makes the pool-wide stickyDrainCount increment exactly once per slot,
// regardless of how many times the deadline branch extends (Bug #6, spec §4).
// Operates on the CAPTURED *poolSlot — never via p.slots[idx] — so a recycled
// cell cannot make this collide with another slot's accounting (spec H2).
func (p *WSPoolTransport) markSticky(slot *poolSlot) {
	if slot.isSticky.CompareAndSwap(false, true) {
		p.stickyDrainCount.Add(1)
	}
}

// releaseSticky frees slot's sticky extension. Idempotent: Swap returns the
// prior value, so a second call (panic + defer, double teardown path) does
// NOT double-decrement. Operates on the captured *poolSlot (spec H2).
func (p *WSPoolTransport) releaseSticky(slot *poolSlot) {
	if slot.isSticky.Swap(false) {
		p.stickyDrainCount.Add(-1)
	}
}

// stickyQuotaAvailable reports whether slot may (continue to) hold a sticky
// extension. Already-sticky slots always pass (we extend, not re-acquire).
// Fresh slots gate on BOTH the static cap (effectiveStickyMaxSlots) AND a
// dynamic capacity check: holding one more slot in slotDraining must not push
// readyCapacity to/below the storm-brake floor — otherwise the pool could
// clinch and stop rotating entirely (spec H4). The dynamic gate is
// deliberately conservative (fail-safe toward rotation).
func (p *WSPoolTransport) stickyQuotaAvailable(slot *poolSlot) bool {
	if slot.isSticky.Load() {
		return true
	}
	max := p.effectiveStickyMaxSlots()
	if p.stickyDrainCount.Load() >= int32(max) {
		return false
	}
	if p.readyCapacity() <= p.readyCapacityFloor() {
		return false
	}
	return true
}
```

- [ ] **Step 4: Запустить — проходит**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run 'TestStickyMarkReleaseIdempotent|TestStickyQuotaAvailable' -v`
Expected: PASS (все кейсы).

- [ ] **Step 5: Commit**

```bash
git add client/ws_pool.go client/sticky_stream_test.go
git commit -m "feat(shadowlink): Bug #6 — sticky markSticky/releaseSticky/stickyQuotaAvailable helpers"
```

---

### Task 4: drainWatchdog — добавить finishCause + defer releaseSticky

**Files:**
- Modify: `client/ws_pool_drain.go` (finishCause const block ~`:572`, defer area ~`:563`, tearDown switch ~`:579`)

- [ ] **Step 1: Расширить finishCause const block** (`ws_pool_drain.go:572-577`)

Заменить:
```go
	type finishCause int
	const (
		finishStreamsZero finishCause = iota
		finishIdle
		finishHardCap
	)
```
на:
```go
	type finishCause int
	const (
		finishStreamsZero finishCause = iota
		finishIdle
		finishHardCap
		finishStickyAgeBackstop  // Bug #6: активный стрим, достигнут возрастной предел дренажа
		finishStickyBytesBackstop // Bug #6: активный стрим, достигнут объёмный предел TCP
		finishStickyQuotaDenied   // Bug #6: активный стрим, но sticky-квота/ёмкость не позволяют
	)
```

- [ ] **Step 2: Добавить defer releaseSticky** (сразу после `defer p.inflightDrains.Add(-1)` на `:563`)

```go
	// Bug #6: free this slot's sticky extension on EVERY watchdog exit path
	// (tearDown→return, ctx.Done, panic). Operates on the captured oldSlot
	// pointer — safe across cell recycle (spec H2). Idempotent if never sticky.
	defer p.releaseSticky(oldSlot)
```

- [ ] **Step 3: Расширить tearDown switch на новые причины** (внутри `tearDown` func, `:581-603`, добавить case'ы в `switch cause`)

Найти `switch cause {` (`:581`) и добавить ПОСЛЕ `case finishHardCap:` блока (после `emitHardCapLog(...)` на `:583`), перед `case finishIdle:`:

```go
		case finishStickyAgeBackstop:
			Stats.DrainStickyBackstopAgeTotal.Add(1)
			emitStickyTeardownLog(p, oldIdx, oldSlot, reason, duration, "age_backstop")
		case finishStickyBytesBackstop:
			Stats.DrainStickyBackstopBytesTotal.Add(1)
			emitStickyTeardownLog(p, oldIdx, oldSlot, reason, duration, "bytes_backstop")
		case finishStickyQuotaDenied:
			Stats.DrainStickyQuotaDeniedTotal.Add(1)
			emitStickyTeardownLog(p, oldIdx, oldSlot, reason, duration, "quota_denied")
```

(Метрики и `emitStickyTeardownLog` создаются в Task 5 — этот шаг СНАЧАЛА не скомпилируется, это ожидаемо в TDD-последовательности; Task 5 идёт сразу следом и закрывает компиляцию. Если исполнитель требует green между задачами — слить Task 4 Step 3 и Task 5 в один коммит.)

- [ ] **Step 4: Сборка (ожидаемо падает до Task 5)**

Run: `cd /d/NIXAVPN/shadowlink && go build ./client/`
Expected: FAIL — `Stats.DrainStickyBackstopAgeTotal undefined`, `emitStickyTeardownLog undefined`. Закрывается в Task 5.

- [ ] **Step 5: (без коммита — переходим к Task 5, коммит общий в Task 5 Step 6)**

---

### Task 5: Метрики + emitStickyTeardownLog

**Files:**
- Modify: `client/stats.go` (counter fields + text exporter), `client/ws_pool_drain.go` (emitStickyTeardownLog рядом с emitHardCapLog ~`:655`)

- [ ] **Step 1: Добавить counter-поля в Stats struct** (`client/stats.go`, рядом с `DrainHardCapTotal` на `:210`)

```go
	// Bug #6 sticky stream counters.
	DrainStickyExtendedTotal     atomic.Uint64 // раз продлён дренаж (стрим активен)
	DrainStickyBackstopAgeTotal  atomic.Uint64 // teardown по возрастному пределу
	DrainStickyBackstopBytesTotal atomic.Uint64 // teardown по объёмному пределу
	DrainStickyQuotaDeniedTotal  atomic.Uint64 // teardown: квота/ёмкость не позволили
```

- [ ] **Step 2: Добавить gauge-экспорт + counters в text exporter** (`client/stats.go`, рядом с `shadowlink_slot_drain_hard_cap_total` на `:595`)

```go
	fmt.Fprintf(w, "shadowlink_drain_sticky_extended_total %d\n", Stats.DrainStickyExtendedTotal.Load())
	fmt.Fprintf(w, "shadowlink_drain_sticky_backstop_age_total %d\n", Stats.DrainStickyBackstopAgeTotal.Load())
	fmt.Fprintf(w, "shadowlink_drain_sticky_backstop_bytes_total %d\n", Stats.DrainStickyBackstopBytesTotal.Load())
	fmt.Fprintf(w, "shadowlink_drain_sticky_quota_denied_total %d\n", Stats.DrainStickyQuotaDeniedTotal.Load())
```

(Замечание: `shadowlink_drain_sticky_active_slots` gauge = `p.stickyDrainCount.Load()` экспортируется там, где пул выставляет свои gauge'и — если в stats.go нет доступа к транспорту, добавить в health snapshot пула, где уже печатаются `alive/dead/draining`. Найти `emitHealthSummary` (`ws_pool.go:1358`) и добавить поле `"sticky_active", p.stickyDrainCount.Load()` в его лог-вызов. Это не Prometheus-метрика, а health-лог — достаточно для канарейки.)

- [ ] **Step 3: Реализовать emitStickyTeardownLog** (`client/ws_pool_drain.go`, после `emitHardCapLog` ~`:680`)

```go
// emitStickyTeardownLog records a Bug #6 sticky-backstop teardown: an active
// stream was finally torn down because a backstop (age/bytes) or quota gate
// fired. outcome ∈ {age_backstop, bytes_backstop, quota_denied}. Mirrors
// emitHardCapLog's diag fields so operators see WHY an active download was cut.
func emitStickyTeardownLog(p *WSPoolTransport, oldIdx int, slot *poolSlot,
	reason string, duration time.Duration, outcome string) {
	snap := snapshotDrainStreams(p, oldIdx, time.Now())
	p.log.Info("WS pool slot drain sticky backstop teardown",
		"slot", oldIdx, "reason", reason,
		"sticky_outcome", outcome,
		"remaining_streams", slot.streams.Load(),
		"down_bytes", slot.downBytes.Load(),
		"drain_duration", duration.Truncate(time.Second),
		"diag_total", snap.total,
		"diag_active_count", snap.activeCount,
		"diag_max_stream_age_ms", snap.maxStreamAgeMs,
	)
	p.bumpRotations1m()
}
```

- [ ] **Step 4: Сборка проходит (закрывает Task 4 Step 4)**

Run: `cd /d/NIXAVPN/shadowlink && go build ./client/`
Expected: успех.

- [ ] **Step 5: Тесты пакета не сломаны**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run 'TestSticky|TestEffectiveSticky' -v`
Expected: PASS (Task 2-3 тесты).

- [ ] **Step 6: Commit (Task 4 + Task 5 вместе)**

```bash
git add client/ws_pool.go client/ws_pool_drain.go client/stats.go
git commit -m "feat(shadowlink): Bug #6 — sticky finishCause, metrics, teardown log"
```

---

### Task 6: drainWatchdog deadline.C — осознанное решение (ядро фикса)

**Files:**
- Modify: `client/ws_pool_drain.go` (ветка `case <-deadline.C` `:628-630`)
- Test: `client/sticky_stream_test.go`

- [ ] **Step 1: Написать падающий тест — активный стрим переживает hard-cap, рвётся idle/backstop**

```go
import (
	"context"
	"testing"
	"time"
)

// helper: пул с одним дренируемым слотом и управляемым allStreamsIdle.
// Используем streamMap + lastWriteNs для управления idle/active.
func newDrainTestPool(t *testing.T, hardCap, idleThreshold, stickyAge time.Duration, stickyBytes int64) *WSPoolTransport {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	p := &WSPoolTransport{
		poolSize:            2,
		drainHardCap:        hardCap,
		drainIdleThreshold:  idleThreshold,
		stickyMaxDrainAge:   stickyAge,
		stickyMaxTotalBytes: stickyBytes,
		stickyMaxSlots:      0, // авто=1 при poolSize=2
		ctx:                 ctx,
		cancel:              cancel,
		log:                 testLogger(),
	}
	p.slots = make([]*poolSlot, 2*p.poolSize)
	for i := 0; i < p.poolSize; i++ {
		s := &poolSlot{index: i}
		s.state.Store(int32(slotReady))
		p.slots[i] = s
	}
	return p
}

// TestDrainWatchdog_ActiveStreamSurvivesHardCap: с активным стримом
// (lastWriteNs свежий) drainWatchdog НЕ рвёт слот на hardCap — продлевает.
// Затем при достижении stickyAge — рвёт по age backstop.
func TestDrainWatchdog_StickyAgeBackstop(t *testing.T) {
	// hardCap мал (50ms), idleThreshold 1s (стрим "активен"),
	// stickyAge 150ms (рвём через ~150ms несмотря на активность).
	p := newDrainTestPool(t, 50*time.Millisecond, 1*time.Second, 150*time.Millisecond, 1<<30)
	oldSlot := p.slots[0]
	oldSlot.state.Store(int32(slotDraining))
	oldSlot.streams.Store(1)
	// активный стрим: lastWriteNs = now (свежий, < idleThreshold).
	p.streamMap.Store(uint16(1), newStreamEntry(0))
	p.inflightDrains.Add(1) // drainWatchdog defer'ит -1

	before := Stats.DrainStickyBackstopAgeTotal.Load()
	start := time.Now()
	// drainWatchdog блокирующий — запускаем в горутине, ждём завершения.
	done := make(chan struct{})
	go func() { p.drainWatchdog(p.client, 0, oldSlot, time.Now(), "test"); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainWatchdog did not finish")
	}
	elapsed := time.Since(start)

	// Должен прожить дольше hardCap (50ms) — продлевался на активном стриме.
	if elapsed < 100*time.Millisecond {
		t.Errorf("teardown too early (%v): active stream should have survived hard cap", elapsed)
	}
	// Рвём по age backstop (≈150ms), не вечно.
	if elapsed > 1*time.Second {
		t.Errorf("teardown too late (%v): age backstop should fire ~150ms", elapsed)
	}
	if got := Stats.DrainStickyBackstopAgeTotal.Load(); got != before+1 {
		t.Errorf("DrainStickyBackstopAgeTotal: %d → %d, want +1", before, got)
	}
}
```

(ПРИМЕЧАНИЕ: `p.client` будет nil в тесте; `handleSlotDeath(nil, ...)` должен пережить nil-client при teardown — если падает, тест-пул должен подставить минимальный `*Client`. Сверить с тем, как существующие тесты `ws_pool_drain_test.go` строят пул — переиспользовать их helper-конструктор, если он есть, вместо самодельного `newDrainTestPool`. См. `ws_pool_drain_test.go:111,268` — там уже есть `NewWSPoolTransport(cl, WSPoolConfig{...})` паттерн с реальным `cl`. ПРЕДПОЧЕСТЬ его.)

- [ ] **Step 2: Запустить — падает**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run TestDrainWatchdog_StickyAgeBackstop -v`
Expected: FAIL — слот рвётся на hardCap (50ms), elapsed < 100ms (старое слепое поведение).

- [ ] **Step 3: Заменить ветку `case <-deadline.C`** (`ws_pool_drain.go:628-630`)

Заменить:
```go
		case <-deadline.C:
			tearDown(finishHardCap)
			return
```
на:
```go
		case <-deadline.C:
			// Bug #6: осознанное решение вместо слепого hard-cap teardown.
			// Sticky отключён (kill switch) → ведём себя как раньше.
			if p.stickyMaxDrainAge <= 0 {
				tearDown(finishHardCap)
				return
			}
			now := time.Now()
			idle := !idleEnabled || allStreamsIdle(p, oldIdx, idleThreshold, now)
			drainAge := now.Sub(drainStart) // монотонные часы
			drainBytes := oldSlot.downBytes.Load()
			switch {
			case idle:
				// стрим простаивает → natural-finish (НЕ hard-cap метрика, spec M5)
				tearDown(finishIdle)
				return
			case drainAge >= p.stickyMaxDrainAge:
				tearDown(finishStickyAgeBackstop)
				return
			case drainBytes >= p.stickyMaxTotalBytes:
				tearDown(finishStickyBytesBackstop)
				return
			case oldSlot.isSticky.Load() && p.readyCapacity() <= p.readyCapacityFloor():
				// уже-sticky слот при просадке ёмкости → досрочно рвём (spec H4:
				// приоритет ротация > UX одной закачки, клинч саморазрешается).
				tearDown(finishStickyQuotaDenied)
				return
			case !p.stickyQuotaAvailable(oldSlot):
				tearDown(finishStickyQuotaDenied)
				return
			default:
				// активная закачка, в пределах backstop, квота есть → продлеваем.
				p.markSticky(oldSlot)
				Stats.DrainStickyExtendedTotal.Add(1)
				deadline.Reset(stickyRecheckInterval)
			}
```

- [ ] **Step 4: Добавить константу stickyRecheckInterval** (рядом с `drainPollInterval` — найти его определение, добавить рядом)

```go
// stickyRecheckInterval is how often the deadline branch re-evaluates an
// extended (sticky) drain (Bug #6). Must be >= drainPollInterval so the
// ticker idle/streams-zero branch catches natural finish between rechecks
// (spec L3). 5s keeps lifetime overshoot small vs the 10m age backstop.
const stickyRecheckInterval = 5 * time.Second
```

(Если `drainPollInterval` < 5s — инвариант `stickyRecheckInterval >= drainPollInterval` соблюдён. Проверить значение drainPollInterval grep'ом; если оно > 5s — поднять stickyRecheckInterval до него.)

- [ ] **Step 5: Запустить — проходит**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run TestDrainWatchdog_StickyAgeBackstop -v`
Expected: PASS (elapsed ∈ [100ms, 1s], age backstop counter +1).

- [ ] **Step 6: Commit**

```bash
git add client/ws_pool_drain.go client/sticky_stream_test.go
git commit -m "feat(shadowlink): Bug #6 — drainWatchdog deadline.C adaptive backstop (core fix)"
```

---

### Task 7: Тест — idle стрим рвётся по natural-finish (не hard-cap), bytes backstop, kill switch

**Files:**
- Test: `client/sticky_stream_test.go`

- [ ] **Step 1: Написать тесты на остальные ветки switch**

```go
// idle стрим → finishIdle (natural), НЕ загрязняет hard-cap метрику (spec M5).
func TestDrainWatchdog_IdleGoesToNaturalFinish(t *testing.T) {
	p := newDrainTestPool(t, 50*time.Millisecond, 30*time.Millisecond, 10*time.Minute, 1<<30)
	oldSlot := p.slots[0]
	oldSlot.state.Store(int32(slotDraining))
	oldSlot.streams.Store(1)
	e := newStreamEntry(0)
	// стрим idle: lastWriteNs далеко в прошлом (> idleThreshold 30ms).
	e.lastWriteNs.Store(time.Now().Add(-1 * time.Second).UnixNano())
	p.streamMap.Store(uint16(1), e)
	p.inflightDrains.Add(1)

	hardCapBefore := Stats.DrainHardCapTotal.Load()
	natBefore := Stats.DrainNaturalFinishTotal.Load()
	done := make(chan struct{})
	go func() { p.drainWatchdog(p.client, 0, oldSlot, time.Now(), "test"); close(done) }()
	<-done

	if got := Stats.DrainHardCapTotal.Load(); got != hardCapBefore {
		t.Errorf("idle teardown must NOT bump DrainHardCapTotal: %d → %d", hardCapBefore, got)
	}
	if got := Stats.DrainNaturalFinishTotal.Load(); got <= natBefore {
		t.Errorf("idle teardown must bump natural-finish: %d → %d", natBefore, got)
	}
}

// объёмный backstop: активный стрим, downBytes превысил лимит → bytes backstop.
func TestDrainWatchdog_StickyBytesBackstop(t *testing.T) {
	p := newDrainTestPool(t, 30*time.Millisecond, 1*time.Second, 10*time.Minute, 1024 /*1KB лимит*/)
	oldSlot := p.slots[0]
	oldSlot.state.Store(int32(slotDraining))
	oldSlot.streams.Store(1)
	oldSlot.downBytes.Store(2048) // > 1KB лимит
	p.streamMap.Store(uint16(1), newStreamEntry(0)) // активный
	p.inflightDrains.Add(1)

	before := Stats.DrainStickyBackstopBytesTotal.Load()
	done := make(chan struct{})
	go func() { p.drainWatchdog(p.client, 0, oldSlot, time.Now(), "test"); close(done) }()
	<-done

	if got := Stats.DrainStickyBackstopBytesTotal.Load(); got != before+1 {
		t.Errorf("DrainStickyBackstopBytesTotal: %d → %d, want +1", before, got)
	}
}

// kill switch: stickyMaxDrainAge<=0 → слепой hard-cap, активный стрим рвётся сразу.
func TestDrainWatchdog_StickyKillSwitch(t *testing.T) {
	p := newDrainTestPool(t, 50*time.Millisecond, 1*time.Second, 0 /*kill*/, 1<<30)
	oldSlot := p.slots[0]
	oldSlot.state.Store(int32(slotDraining))
	oldSlot.streams.Store(1)
	p.streamMap.Store(uint16(1), newStreamEntry(0)) // активный
	p.inflightDrains.Add(1)

	before := Stats.DrainHardCapTotal.Load()
	start := time.Now()
	done := make(chan struct{})
	go func() { p.drainWatchdog(p.client, 0, oldSlot, time.Now(), "test"); close(done) }()
	<-done

	// рвётся на hardCap (~50ms), НЕ продлевается (sticky выключен).
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("kill switch: should tear down at hard cap, took %v", elapsed)
	}
	if got := Stats.DrainHardCapTotal.Load(); got != before+1 {
		t.Errorf("kill switch must bump DrainHardCapTotal: %d → %d", before, got)
	}
}
```

- [ ] **Step 2: Запустить — проходят (логика уже в Task 6)**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -run 'TestDrainWatchdog_Idle|TestDrainWatchdog_StickyBytes|TestDrainWatchdog_StickyKill' -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add client/sticky_stream_test.go
git commit -m "test(shadowlink): Bug #6 — idle natural-finish, bytes backstop, kill switch"
```

---

### Task 8: Cross-recycle гонка (H2) + клинч readyCapacity (H4) — тесты под -race

**Files:**
- Test: `client/sticky_stream_test.go`

- [ ] **Step 1: Написать тест cross-recycle (H2) — счётчик не рассинхронится**

```go
// H2: старый watchdog стал sticky, ячейка recycled под новый *poolSlot,
// старый defer releaseSticky НЕ должен трогать новый слот / врать счётчику.
func TestSticky_CrossRecycleNoDesync(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}

	oldSlot := &poolSlot{index: 0}
	newSlot := &poolSlot{index: 0} // та же ячейка idx=0, НОВЫЙ указатель

	// старый стал sticky
	p.markSticky(oldSlot)
	if p.stickyDrainCount.Load() != 1 {
		t.Fatalf("after old markSticky: count=%d want 1", p.stickyDrainCount.Load())
	}

	// recycle: новый слот той же ячейки стал sticky
	p.markSticky(newSlot)
	if p.stickyDrainCount.Load() != 2 {
		t.Fatalf("after new markSticky: count=%d want 2", p.stickyDrainCount.Load())
	}

	// старый defer releaseSticky(oldSlot) — бьёт по СВОЕЙ старой структуре
	p.releaseSticky(oldSlot)
	if p.stickyDrainCount.Load() != 1 {
		t.Fatalf("after old release: count=%d want 1 (newSlot still sticky)", p.stickyDrainCount.Load())
	}
	if !newSlot.isSticky.Load() {
		t.Fatal("newSlot must still be sticky — old release must not touch it")
	}

	// новый defer
	p.releaseSticky(newSlot)
	if p.stickyDrainCount.Load() != 0 {
		t.Fatalf("after new release: count=%d want 0", p.stickyDrainCount.Load())
	}
}

// H2 порядок переставлен: старый release РАНЬШЕ нового mark.
func TestSticky_CrossRecycleReorderedRelease(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	oldSlot := &poolSlot{index: 0}
	newSlot := &poolSlot{index: 0}
	p.markSticky(oldSlot) // count=1
	p.releaseSticky(oldSlot) // count=0
	p.markSticky(newSlot) // count=1
	if p.stickyDrainCount.Load() != 1 {
		t.Fatalf("count=%d want 1", p.stickyDrainCount.Load())
	}
}

// H2 concurrent под -race: many mark/release на разных слотах не рвут счётчик.
func TestSticky_ConcurrentMarkRelease(t *testing.T) {
	p := &WSPoolTransport{poolSize: 100, stickyMaxSlots: 1000}
	const n = 200
	slots := make([]*poolSlot, n)
	for i := range slots {
		slots[i] = &poolSlot{index: i % 100}
	}
	var wg sync.WaitGroup
	for i := range slots {
		wg.Add(1)
		go func(s *poolSlot) {
			defer wg.Done()
			p.markSticky(s)
			p.markSticky(s) // идемпотентно
			p.releaseSticky(s)
			p.releaseSticky(s) // идемпотентно
		}(slots[i])
	}
	wg.Wait()
	if got := p.stickyDrainCount.Load(); got != 0 {
		t.Fatalf("after balanced concurrent mark/release: count=%d want 0", got)
	}
}
```

- [ ] **Step 2: Написать тест клинча (H4) — оба режима reserve**

```go
// H4: при просадке readyCapacity новый sticky НЕ выдаётся (пул ротируется).
func TestSticky_NoClinch_UnhealthyCapacity(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	p.slots = make([]*poolSlot, 12)
	for i := 0; i < 6; i++ {
		s := &poolSlot{index: i}
		// только floor слотов ready, остальные draining → readyCapacity<=floor
		if i < p.readyCapacityFloor() {
			s.state.Store(int32(slotReady))
		} else {
			s.state.Store(int32(slotDraining))
		}
		p.slots[i] = s
	}
	fresh := &poolSlot{index: 0}
	if p.stickyQuotaAvailable(fresh) {
		t.Fatal("unhealthy capacity: new sticky must be denied (no clinch)")
	}
}

// H4: при здоровом reserve sticky выдаётся свободно (не ложно-отказ).
func TestSticky_HealthyCapacity_Granted(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	p.slots = make([]*poolSlot, 12)
	for i := 0; i < 6; i++ {
		s := &poolSlot{index: i}
		s.state.Store(int32(slotReady)) // все ready → readyCapacity=6 > floor
		p.slots[i] = s
	}
	fresh := &poolSlot{index: 0}
	if !p.stickyQuotaAvailable(fresh) {
		t.Fatal("healthy capacity under cap: sticky must be granted")
	}
}
```

- [ ] **Step 3: Запустить под -race (или plain если нет gcc)**

Run (Linux/CI с gcc): `cd /d/NIXAVPN/shadowlink && go test -race ./client/ -run 'TestSticky_' -v`
Run (Windows без gcc): `cd /d/NIXAVPN/shadowlink && go test ./client/ -run 'TestSticky_' -v`
Expected: PASS, без race-warnings. **Перед мержем ОБЯЗАТЕЛЬНО прогнать -race вариант на Linux/CI.**

- [ ] **Step 4: Commit**

```bash
git add client/sticky_stream_test.go
git commit -m "test(shadowlink): Bug #6 — cross-recycle (H2) + clinch (H4) under -race"
```

---

### Task 9: engine_shadowlink.go — проброс env → cfg

**Files:**
- Modify: `cmd/nixavpn-client/engine_shadowlink.go` (env-парсинг ~`:430`, WSPoolConfig literal `:450-467`)

- [ ] **Step 1: Добавить env-парсинг** (рядом с `drainIdleStreamsMax := ...` на `:440`, перед `pool := client.NewWSPoolTransport(...)`)

```go
				// Bug #6 sticky stream config (settable via env, defaults in NewWSPoolTransport).
				stickyMaxDrainAge := envDurationDefault("SHADOWLINK_STICKY_MAX_DRAIN_AGE", 10*time.Minute)
				stickyMaxTotalBytes := int64(envIntDefault("SHADOWLINK_STICKY_MAX_TOTAL_BYTES", 256*1024*1024))
				stickyMaxSlots := envIntDefault("SHADOWLINK_STICKY_MAX_SLOTS", 0)
```

(Проверить имя helper для duration — если в файле есть `envDurationDefault`, использовать его; если нет — использовать тот паттерн, что уже парсит `drainHardCap`/`drainIdleThreshold` выше в этом же блоке. Grep `drainHardCap :=` в engine_shadowlink.go и скопировать стиль.)

- [ ] **Step 2: Добавить поля в WSPoolConfig literal** (после `DrainIdleStreamsMax: drainIdleStreamsMax,` на `:466`)

```go
					StickyMaxDrainAge:   stickyMaxDrainAge,
					StickyMaxTotalBytes: stickyMaxTotalBytes,
					StickyMaxSlots:      stickyMaxSlots,
```

- [ ] **Step 3: Сборка всего бинаря**

Run: `cd /d/NIXAVPN/shadowlink && go build ./cmd/nixavpn-client/`
Expected: успех.

- [ ] **Step 4: Commit**

```bash
git add cmd/nixavpn-client/engine_shadowlink.go
git commit -m "feat(shadowlink): Bug #6 — wire sticky stream config through engine env"
```

---

### Task 10: Полный прогон + регрессия пакета + gofmt

**Files:** —

- [ ] **Step 1: Весь client-пакет зелёный**

Run: `cd /d/NIXAVPN/shadowlink && go test ./client/ -v 2>&1 | tail -40`
Expected: PASS (ни один существующий тест не сломан — особенно `ws_pool_drain_test.go` группа: idle-finish, streams-zero, hard-cap counter, NaturalFinish).

- [ ] **Step 2: -race по client + server + skins (если gcc есть)**

Run: `cd /d/NIXAVPN/shadowlink && go test -race -count=1 ./client/ ./server/ ./skins/... 2>&1 | tail -20`
Expected: PASS без race. (Windows без gcc → пропустить, отметить для CI.)

- [ ] **Step 3: Весь репозиторий собирается**

Run: `cd /d/NIXAVPN/shadowlink && go build ./...`
Expected: успех.

- [ ] **Step 4: gofmt только изменённых файлов** (НЕ `gofmt -w .` — репо имеет преэкзистентные CRLF-расхождения, см. память)

Run: `cd /d/NIXAVPN/shadowlink && gofmt -l client/ws_pool.go client/ws_pool_drain.go client/stats.go client/sticky_stream_test.go cmd/nixavpn-client/engine_shadowlink.go`
Expected: пусто (нет несформатированных). Если файл в списке — `gofmt -w <тот файл>` и пере-проверить diff что изменилось только форматирование добавленного кода.

- [ ] **Step 5: Commit (если gofmt что-то поправил)**

```bash
git add -A
git commit -m "style(shadowlink): gofmt Bug #6 sticky stream files"
```

---

## Финальные шаги ПОСЛЕ плана (НЕ в чеклисте — процесс из спеки §9)

1. **Финальное адверсариальное опус-ревью КОДА** (как Bug #5) — обязательно перед мержем.
2. Пересобрать клиентский бинарь.
3. Канарейка: замер `backstop_age + backstop_bytes + quota_denied` (остаточный хвост, §6.1) ОТДЕЛЬНО от reader-error-обрывов; разброс slot lifetime sticky vs non-sticky (§6.2).
4. Если хвост значим → решение об усилении (10m→5m, авто→poolSize/4) ПО ДАННЫМ.

---

## Self-Review (выполнено автором плана)

**Spec coverage:**
- §2.2 config поля → Task 1 ✓
- §3.1 idle-детекция (idleEnabled→sticky off) → Task 6 switch (idle case + kill switch) ✓
- §3.2 возрастной предохранитель (монотонный) → Task 6 (`now.Sub(drainStart)`) + Task 6 тест ✓
- §3.3 объёмный предохранитель (downBytes, reader не трогаем) → Task 6 (`drainBytes := oldSlot.downBytes.Load()`, reader не в scope) + Task 7 bytes-тест ✓
- §3.4 switch логика → Task 6 ✓
- §4 динамический cap + helpers + cross-recycle → Task 2,3,8 ✓
- §4 досрочное снятие при просадке → Task 6 switch case ✓
- §5 регрессионные инварианты → Task 7,8,10 ✓ (idle-finish, streams-zero — Task 10 регрессия существующих; tearDown один раз — Go select, проверяется отсутствием двойного teardown в Task 6/7)
- §6.1 метрики → Task 5 ✓
- §6.2 lifetime distribution → канарейка (вне кода, отмечено) ✓
- §7 kill switch → Task 1 (default) + Task 6 (ветка) + Task 7 тест ✓
- §8 engine wiring → Task 9 ✓

**Placeholder scan:** код-блоки полные; единственные «проверить grep» — про имена helper'ов env-парсинга и `drainPollInterval` значение (Task 6 Step 4, Task 9 Step 1) — это сверка существующего кода, не плейсхолдер логики. Тест-конструктор `newDrainTestPool` помечен «предпочесть существующий helper из ws_pool_drain_test.go с реальным cl» — указано явно.

**Type consistency:** `markSticky(*poolSlot)`/`releaseSticky(*poolSlot)`/`stickyQuotaAvailable(*poolSlot)` — всюду по указателю (Task 3,6,8). `effectiveStickyMaxSlots() int` (Task 2,3). finishCause имена (`finishStickyAgeBackstop` etc.) — Task 4 определяет, Task 6 использует, совпадают. Метрики `DrainStickyBackstopAgeTotal`/`BytesTotal`/`QuotaDeniedTotal`/`ExtendedTotal` — Task 5 определяет, Task 4/6/7 используют, совпадают. Поля cfg `StickyMaxDrainAge`/`StickyMaxTotalBytes`/`StickyMaxSlots` + transport `stickyMaxDrainAge`/`stickyMaxTotalBytes`/`stickyMaxSlots`/`stickyDrainCount` — Task 1 определяет, всюду совпадают.

**Известная зависимость задач:** Task 4 Step 3 не компилируется до Task 5 (метрики/лог) — явно отмечено, коммит общий. Все остальные задачи green-to-green.
