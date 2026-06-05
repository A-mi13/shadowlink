# Half-open drain stream leak — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) или superpowers:executing-plans для реализации task-by-task. Steps используют checkbox (`- [ ]`).

**Goal:** Устранить half-open зависание стрима (спиннер Claude) при graceful age-cut drain — (A) поздно-привязавшиеся стримы стареющего слота тоже мигрируют превентивно; (B) uplink-goroutine не виснет после закрытия downlink.

**Architecture:** (A) Перенести гейт превентивной миграции с per-slot (`slot.migrationScheduled`, однократный snapshot) на **per-stream** (`streamEntry.migrationScheduled`) — watchdog на каждом тике планирует MIGRATE каждого ещё-не-запланированного стрима aging-слота, включая появившихся после первого прохода. (B) Добавить `defer wakeUplink(conn)` в downlink-goroutine — при ЛЮБОМ её выходе разбудить uplink через `conn.CloseRead()` (интерфейс-гард + Close-фолбэк). Только клиент; сервер не меняется.

**Tech Stack:** Go, ShadowLink (`shadowlink/`, module github.com/nixavpn/shadowlink), sync.Map streamMap, atomic флаги, time.AfterFunc, memConn (in-process) + net.TCPConn (loopback).

**Spec:** `docs/superpowers/specs/2026-06-04-halfopen-drain-stream-leak-design.md` (v2, APPROVED-WITH-NITS)
**Review:** `docs/halfopen-spec-review-v2-opus-2026-06-04.md`

**Критические требования из ревью (НЕ нарушать):**
- **MEDIUM-1:** контракт возврата `scheduleSlotMigration` меняется: `true` ⇔ «запланирован ≥1 НОВЫЙ стрим на этом проходе». Переписать `TestScheduleSlotMigration_Idempotent` в тест ценности re-arm.
- **MEDIUM-2:** Range-фильтр = `slotIdx==aging && !e.migrating.Load() && e.migrationScheduled.CompareAndSwap(false,true)`. Тесты на interleaving (защищены single-winner migrating CAS — код НЕ добавлять, подтвердить тестом).
- **(B) BLOCKER-2:** одно `defer wakeUplink` в downlink-goroutine, НЕ точечные вставки.
- **(B) HIGH-1/2:** примитив = `CloseRead` с интерфейс-гардом + `Close`-фолбэк.

---

## File Structure

| Файл | Ответственность | Изменение |
|---|---|---|
| `client/stream_entry.go` | поле `migrationScheduled atomic.Bool` на streamEntry | Modify |
| `client/migrate_watchdog.go` | `scheduleSlotMigration` — гейт per-stream, Range-фильтр | Modify |
| `client/ws_pool.go` | watchdog sweep вызов (без изменений логики); `slot.migrationScheduled` — занопить/удалить | Modify |
| `client/migrate_watchdog_test.go` | переписать Idempotent → re-arm тест + interleaving | Modify |
| `proxy/socks5/tcp.go` | `wakeUplink` helper + `defer` в downlink-goroutine | Modify |
| `proxy/socks5/tcp_test.go` (или соседний) | (B) тесты: wake на выходе downlink, full-keepalive, loopback фолбэк | Modify/Create |

---

## Task 1: per-stream поле `migrationScheduled`

**Files:**
- Modify: `client/stream_entry.go` (struct streamEntry ~:18-46)

- [ ] **Step 1: Написать падающий тест**

В `client/migrate_watchdog_test.go` (или stream_entry_test.go если есть) добавить:

```go
func TestStreamEntry_MigrationScheduledDefaultsFalse(t *testing.T) {
	e := newStreamEntry(3)
	if e.migrationScheduled.Load() {
		t.Fatal("migrationScheduled must default false on fresh entry")
	}
	if !e.migrationScheduled.CompareAndSwap(false, true) {
		t.Fatal("first CAS false→true must win")
	}
	if e.migrationScheduled.CompareAndSwap(false, true) {
		t.Fatal("second CAS must lose (already true)")
	}
}
```

- [ ] **Step 2: Запустить — падает**

Run: `cd shadowlink && go test ./client/ -run TestStreamEntry_MigrationScheduledDefaultsFalse -v`
Expected: FAIL — `e.migrationScheduled undefined`.

- [ ] **Step 3: Реализовать**

В `client/stream_entry.go` в struct `streamEntry` после поля `migrating atomic.Bool` (~:45) добавить:

```go

	// migrationScheduled (half-open fix 2026-06-04, BLOCKER-1) gates preemptive
	// MIGRATE scheduling PER STREAM (replacing the old per-slot slot.migration-
	// Scheduled gate). The watchdog re-invokes scheduleSlotMigration every 5s
	// while a slot is above its migration threshold; this per-stream CAS arms
	// exactly ONE AfterFunc(migrateStream) per stream over its life on a slot,
	// so a stream that ATTACHED to the aging slot AFTER the first pass still gets
	// scheduled on a later tick (the per-slot gate left such late streams
	// unmigrated → they reached age-drain → RESUME-on-death FAIL → downlink torn,
	// uplink hung). A fresh entry from newStreamEntry has it false (zero value);
	// a rebind to a new slot installs a fresh entry, re-arming on the next slot's
	// aging.
	migrationScheduled atomic.Bool
```

(`newStreamEntry` :51 не трогаем — zero-value false корректен.)

- [ ] **Step 4: Запустить — прошёл**

Run: `cd shadowlink && go test ./client/ -run TestStreamEntry_MigrationScheduledDefaultsFalse -v && go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/client/stream_entry.go shadowlink/client/migrate_watchdog_test.go
git commit -m "feat(shadowlink): per-stream migrationScheduled flag (half-open fix A)"
```

---

## Task 2: `scheduleSlotMigration` — гейт per-stream + Range-фильтр (корень A)

**Files:**
- Modify: `client/migrate_watchdog.go` (`scheduleSlotMigration` ~:169-213)

**Цель:** убрать per-slot CAS-гейт; гейтить per-stream внутри Range (`!migrating && CAS(migrationScheduled)`). Поздние стримы покрыты, дублей таймеров нет (per-stream CAS). Новый контракт возврата: `true` ⇔ запланирован ≥1 НОВЫЙ стрим.

- [ ] **Step 1: Переписать падающий тест ценности re-arm (MEDIUM-1)**

В `client/migrate_watchdog_test.go` ЗАМЕНИТЬ `TestScheduleSlotMigration_Idempotent` (~:187-233) на:

```go
// TestScheduleSlotMigration_ReArmsLateStreams: per-stream gate (half-open fix).
// Первый проход планирует уже-привязанные стримы. Стрим, привязавшийся ПОСЛЕ
// первого прохода, получает AfterFunc на втором проходе (re-arm). Уже-
// запланированный стрим НЕ планируется повторно (per-stream CAS, нет дубля).
func TestScheduleSlotMigration_ReArmsLateStreams(t *testing.T) {
	p := &WSPoolTransport{poolSize: 2}
	p.slots = make([]*poolSlot, 2)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}
	now := time.Now().UnixNano()
	p.slots[0].startedAtNs.Store(now - int64(120*time.Second))
	p.slots[0].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now)
	p.slots[1].state.Store(int32(slotReady))

	var mu sync.Mutex
	calls := map[uint16]int{}
	p.migrateStreamHook = func(streamID uint16) {
		mu.Lock()
		calls[streamID]++
		mu.Unlock()
	}
	p.migrateSpreadOverride = 10 * time.Millisecond

	// Первый стрим привязан до первого прохода.
	p.streamMap.Store(uint16(10), newStreamEntry(0))
	if !p.scheduleSlotMigration(0, p.slots[0]) {
		t.Fatal("first pass must schedule the early stream (true = ≥1 new)")
	}
	// Второй проход БЕЗ новых стримов — 0 новых → false.
	if p.scheduleSlotMigration(0, p.slots[0]) {
		t.Fatal("pass with no NEW streams must return false")
	}
	// Поздний стрим привязался ПОСЛЕ первого прохода.
	p.streamMap.Store(uint16(11), newStreamEntry(0))
	// Следующий проход ДОЛЖЕН запланировать поздний стрим (re-arm).
	if !p.scheduleSlotMigration(0, p.slots[0]) {
		t.Fatal("late stream must be scheduled on a later pass (re-arm)")
	}

	time.Sleep(120 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls[10] != 1 {
		t.Fatalf("early stream migrated exactly once, got %d", calls[10])
	}
	if calls[11] != 1 {
		t.Fatalf("late stream migrated exactly once (re-arm), got %d", calls[11])
	}
}

// TestScheduleSlotMigration_SkipsMigratingStream (MEDIUM-2): стрим уже migrating
// → НЕ планируется повторно (Range-фильтр !migrating).
func TestScheduleSlotMigration_SkipsMigratingStream(t *testing.T) {
	p := &WSPoolTransport{poolSize: 2}
	p.slots = make([]*poolSlot, 2)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}
	now := time.Now().UnixNano()
	p.slots[0].startedAtNs.Store(now - int64(120*time.Second))
	p.slots[0].state.Store(int32(slotReady))
	p.slots[1].startedAtNs.Store(now)
	p.slots[1].state.Store(int32(slotReady))

	var mu sync.Mutex
	calls := 0
	p.migrateStreamHook = func(streamID uint16) { mu.Lock(); calls++; mu.Unlock() }
	p.migrateSpreadOverride = 10 * time.Millisecond

	e := newStreamEntry(0)
	e.migrating.Store(true) // уже в процессе миграции
	p.streamMap.Store(uint16(20), e)

	if p.scheduleSlotMigration(0, p.slots[0]) {
		t.Fatal("a migrating stream must NOT be scheduled (returns false, 0 new)")
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatalf("migrating stream must not be re-scheduled, got %d calls", calls)
	}
}
```

- [ ] **Step 2: Запустить — падает (старый тест удалён, новые не проходят)**

Run: `cd shadowlink && go test ./client/ -run 'TestScheduleSlotMigration_ReArms|TestScheduleSlotMigration_Skips' -v`
Expected: FAIL — текущая per-slot логика не re-arm'ит поздний стрим (второй непустой проход вернёт false из-за per-slot CAS) и не фильтрует migrating.

- [ ] **Step 3: Реализовать — гейт per-stream**

В `client/migrate_watchdog.go` заменить тело `scheduleSlotMigration` (~:169-213) на:

```go
func (p *WSPoolTransport) scheduleSlotMigration(agingIdx int, slot *poolSlot) bool {
	if slot == nil {
		return false
	}
	// Half-open fix (BLOCKER-1): the gate is now PER-STREAM, not per-slot. The
	// watchdog ticks every 5s while the slot is above threshold; each tick we
	// arm an AfterFunc only for streams that are not yet scheduled (per-stream
	// CAS) and not already migrating. This covers streams that attached to the
	// aging slot AFTER the first pass — the old per-slot CAS left them unmigrated.
	// Returns true if ≥1 NEW stream was scheduled on THIS pass (MEDIUM-1: the
	// return contract changed from "slot first processed" to "≥1 new scheduled").
	spread := p.effectiveMigrationSpread()
	scheduled := 0
	p.streamMap.Range(func(key, value any) bool {
		e, ok := value.(*streamEntry)
		if !ok || e.slotIdx != agingIdx {
			return true
		}
		// MEDIUM-2: skip streams already migrating (an in-flight move owns the
		// stream; arming a second AfterFunc would short-circuit on the migrating
		// CAS in migrateStream, but skip it cleanly to avoid a wasted timer).
		if e.migrating.Load() {
			return true
		}
		// Per-stream single-winner: arm exactly one AfterFunc per stream/slot life.
		if !e.migrationScheduled.CompareAndSwap(false, true) {
			return true
		}
		streamID, ok := key.(uint16)
		if !ok {
			return true
		}
		offset := sampleMigrationOffset(spread)
		time.AfterFunc(offset, func() {
			if p.migrateStreamHook != nil {
				p.migrateStreamHook(streamID)
				return
			}
			p.migrateStream(streamID)
		})
		scheduled++
		return true
	})

	if scheduled == 0 {
		return false
	}
	Stats.MigrateScheduled.Add(uint64(scheduled))
	return true
}
```

> **Примечание:** `slot.migrationScheduled` больше НЕ используется в этой функции. Параметр `slot` оставлен (сигнатура та же, вызов в ws_pool.go:1813 не меняется; `slot` используется для nil-guard). Удаление поля `slot.migrationScheduled` — Task 3.

- [ ] **Step 4: Запустить — прошёл + регресс watchdog**

Run: `cd shadowlink && go test ./client/ -run 'TestScheduleSlotMigration|TestMigrate|TestStreamEntry' -v && go build ./...`
Expected: PASS. (Если другой тест пинил per-slot `slot.migrationScheduled` напрямую — обновить его в этом же шаге; grep `migrationScheduled` по client/*_test.go.)

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/client/migrate_watchdog.go shadowlink/client/migrate_watchdog_test.go
git commit -m "fix(shadowlink): per-stream migration gate re-arms late streams (half-open A)"
```

---

## Task 3: убрать мёртвый `slot.migrationScheduled`

**Files:**
- Modify: `client/ws_pool.go` (поле `slot.migrationScheduled` ~:458, сброс ~:2143)

**Цель:** поле больше не читается (гейт переехал на stream). Убрать его и его сброс, чтобы не вводить в заблуждение. Watchdog-вызов `scheduleSlotMigration` (ws_pool.go:1809-1814) НЕ меняется.

- [ ] **Step 1: Проверить что поле больше нигде не читается**

Run: `cd shadowlink && grep -rn "migrationScheduled" client/*.go | grep -v "_test.go" | grep -v "e\.migrationScheduled\|streamEntry"`
Expected: только определение поля (`slot.migrationScheduled` :458), сброс (:2143). Если есть другие чтения `slot.migrationScheduled` — обработать их в этом шаге.

- [ ] **Step 2: Реализовать — удалить поле и сброс**

В `client/ws_pool.go` удалить поле `migrationScheduled atomic.Bool` из struct poolSlot (~:451-458, вместе с его doc-комментом) и строку сброса `slot.migrationScheduled.Store(false)` (~:2143, проверить контекст — это connectSlot/recycle; удалить только эту строку).

> Сверить точные строки grep'ом перед удалением (номера могли сдвинуться от Task 1-2).

- [ ] **Step 3: Запустить — build + весь client**

Run: `cd shadowlink && go build ./... && go vet ./client/ && go test ./client/ -count=1 2>&1 | tail -15`
Expected: build OK, тесты PASS. (Преэкзистентный флаки `TestAckJitter_ParetoTailPresent` — НЕ в client, игнорь если всплывёт в server.)

- [ ] **Step 4: Коммит**

```bash
git add shadowlink/client/ws_pool.go
git commit -m "refactor(shadowlink): drop dead per-slot migrationScheduled (half-open A)"
```

---

## Task 4: (B) `wakeUplink` helper + `defer` в downlink-goroutine

**Files:**
- Modify: `proxy/socks5/tcp.go` (helper + `defer` в `tunnelTCPStream` downlink-goroutine ~:933-936)
- Test: `proxy/socks5/tcp_test.go` (или новый файл рядом)

**Цель:** при ЛЮБОМ выходе downlink-goroutine разбудить uplink-goroutine, заблокированную в `conn.Read`. Одно `defer`, примитив `CloseRead` + гард + `Close`-фолбэк.

- [ ] **Step 1: Написать падающий тест**

В `proxy/socks5/tcp_test.go` (создать если нет; package socks5):

```go
// TestWakeUplink_CloseReadOnMemConn: wakeUplink на memConn-end закрывает read —
// заблокированный conn.Read просыпается (EOF/ErrClosedPipe).
func TestWakeUplink_CloseReadOnMemConn(t *testing.T) {
	// memConn-пара: app-end и relay-end. uplink читает relay-end.
	appEnd, relayEnd := newMemConnPair() // сверить реальный конструктор пары в memconn.go/тестах
	defer appEnd.Close()
	defer relayEnd.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := relayEnd.Read(buf) // блокируется (никто не пишет)
		readDone <- err
	}()

	time.Sleep(20 * time.Millisecond) // дать Read заблокироваться
	wakeUplink(relayEnd, false)        // должен разбудить

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Read must return an error/EOF after wakeUplink CloseRead")
		}
	case <-time.After(time.Second):
		t.Fatal("wakeUplink did not wake the blocked Read")
	}
}

// TestWakeUplink_CloseFallback: conn без CloseRead → Close-фолбэк (не паникует).
func TestWakeUplink_CloseFallback(t *testing.T) {
	c1, c2 := net.Pipe() // net.Pipe conn НЕ имеет CloseRead
	defer c2.Close()
	readDone := make(chan error, 1)
	go func() { buf := make([]byte, 16); _, err := c1.Read(buf); readDone <- err }()
	time.Sleep(20 * time.Millisecond)
	wakeUplink(c1, true) // нет CloseRead → conn.Close() фолбэк
	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("Read must error after Close fallback")
		}
	case <-time.After(time.Second):
		t.Fatal("wakeUplink Close fallback did not wake Read")
	}
}
```

> **Примечание:** `newMemConnPair` — сверить реальное имя конструктора memConn-пары (grep `func.*memConn` / как memconn_test.go строит пару). net.Pipe conn не реализует CloseRead → проверяет фолбэк.

- [ ] **Step 2: Запустить — падает**

Run: `cd shadowlink && go test ./proxy/socks5/ -run TestWakeUplink -v`
Expected: FAIL — `wakeUplink undefined`.

- [ ] **Step 3: Реализовать helper + defer**

В `proxy/socks5/tcp.go` добавить helper (рядом с relay-функциями, перед `tunnelTCPStream` или после):

```go
// wakeUplink unblocks the uplink goroutine (parked in conn.Read) when the
// downlink goroutine exits (half-open fix B, 2026-06-04). cancel() alone does
// not wake a blocking Read, and the relay conn is not closed on downlink exit,
// so without this the uplink goroutine spins reading the app's request into a
// dead stream for minutes (the "spinner" symptom). CloseRead closes only the
// read half (idempotent); a conn without CloseRead falls back to full Close
// (downlink is already gone, so closing both halves is safe).
func wakeUplink(conn net.Conn, socks5Replies bool) {
	if cr, ok := conn.(interface{ CloseRead() error }); ok {
		_ = cr.CloseRead()
		return
	}
	_ = conn.Close()
}
```

В `tunnelTCPStream` downlink-goroutine (~:933-936) добавить `defer wakeUplink` рядом с `defer cancel()`:

```go
	go func() {
		defer wg.Done()
		defer cancel()
		defer wakeUplink(conn, socks5Replies) // half-open fix B: wake uplink on ANY downlink exit
		total := 0
		...
```

> Порядок defer: `wakeUplink` выполнится ПЕРЕД `cancel` (LIFO) — оба нужны, порядок между ними не критичен (cancel рвёт ctx2 для downlink-зависимых, wakeUplink будит uplink-read). `socks5Replies` параметр оставлен для будущего гейтинга/симметрии, сейчас не влияет на выбор (CloseRead работает и для loopback TCPConn).

- [ ] **Step 4: Запустить — прошёл**

Run: `cd shadowlink && go test ./proxy/socks5/ -run TestWakeUplink -v && go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/proxy/socks5/tcp.go shadowlink/proxy/socks5/tcp_test.go
git commit -m "fix(shadowlink): wake uplink goroutine on downlink exit (half-open B)"
```

---

## Task 5: (B) интеграционные/регресс тесты

**Files:**
- Modify: `proxy/socks5/tcp_test.go` (или memconn_halfclose_test.go рядом)

**Цель:** подтвердить что (B) не ломает keep-alive half-close и покрывает full-keepalive + Bug#10 цепочку.

- [ ] **Step 1: Написать тесты**

```go
// TestWakeUplink_KeepAliveHalfCloseNotBroken (NIT): при uplink-EOF half-close
// (приложение CloseWrite) uplink уже вышел; downlink продолжает. wakeUplink
// вызванный позже (при выходе downlink) на уже-вышедшую uplink-сторону безвреден.
func TestWakeUplink_KeepAliveHalfCloseNotBroken(t *testing.T) {
	appEnd, relayEnd := newMemConnPair()
	defer appEnd.Close()
	defer relayEnd.Close()
	// app half-closes write (uplink-EOF): relayEnd.Read должен вернуть EOF сам.
	if hc, ok := appEnd.(interface{ CloseWrite() error }); ok {
		_ = hc.CloseWrite()
	}
	buf := make([]byte, 16)
	_, err := relayEnd.Read(buf)
	if err == nil {
		t.Fatal("relay Read должен вернуть EOF после app CloseWrite (half-close)")
	}
	// downlink ещё жив — wakeUplink (идемпотентно) не паникует на этом conn.
	wakeUplink(relayEnd, false)
}
```

> Полноценный e2e (full relay через tunnelTCPStream + age-drain) тяжёл для unit; основной механизм покрыт Task 4 unit + Task 6 e2e. Если в proxy/socks5 уже есть relay-driver helper (grep по tcp_test/flow_halfclose_test) — добавить full-keepalive кейс через него. Иначе — отметить покрытие Task 6.

- [ ] **Step 2: Запустить + полный proxy/socks5**

Run: `cd shadowlink && go test ./proxy/socks5/ -run TestWakeUplink -v && go test ./proxy/socks5/ -count=1 2>&1 | tail -15`
Expected: PASS, регрессов нет (memconn_halfclose_test, flow_halfclose_test зелёные).

- [ ] **Step 3: Коммит**

```bash
git add shadowlink/proxy/socks5/tcp_test.go
git commit -m "test(shadowlink): half-open B regression (keep-alive half-close intact)"
```

---

## Task 6: полный прогон + race

**Files:** —

- [ ] **Step 1: Полный прогон**

Run:
```bash
cd shadowlink && go build ./... && go vet ./client/ ./proxy/... && go test ./... 2>&1 | tail -25
```
Expected: всё PASS (преэкзистентный флаки `TestAckJitter_ParetoTailPresent` в server — НЕ связан, см. отдельную задачу; если мигает — перезапустить `-count=3`).

- [ ] **Step 2: Race на Linux/pl1 (Windows без gcc)**

Run (на Linux/CI/pl1):
```bash
cd shadowlink && go test -race -count=1 -timeout 30m ./client/ ./proxy/socks5/
```
Expected: 0 DATA RACE. Особо: новый per-stream CAS `migrationScheduled` vs `migrating` vs rebind (Task 2 interleaving); `wakeUplink` vs uplink Read.

- [ ] **Step 3: Коммит (если правки от race)** — иначе пропустить.

---

## Self-Review (выполнено при написании)

**Spec coverage:**
- (A) re-arm per-stream: Task 1 (поле) + Task 2 (гейт) + Task 3 (удалить мёртвый per-slot). ✔
- (A) MEDIUM-1 контракт возврата + re-arm тест: Task 2 Step 1. ✔
- (A) MEDIUM-2 Range-фильтр !migrating + CAS + interleaving тест: Task 2. ✔
- (B) defer wakeUplink + CloseRead+гард+фолбэк: Task 4. ✔
- (B) keep-alive half-close не сломан / full-keepalive / loopback фолбэк: Task 4 + Task 5. ✔
- race: Task 6. ✔
- Метрика переиспользует MigrateScheduled (NIT-1): Task 2 (Stats.MigrateScheduled.Add). ✔
- Cascade (HIGH-3) / взаимоблокировка (MEDIUM-4): known-limitation в спеке, кода не требуют. ✔

**Placeholder scan:** код во всех степах конкретный; `newMemConnPair`/relay-driver помечены «сверить реальное имя» (намеренно — переиспользовать существующую тест-инфраструктуру memconn/flow_halfclose). ✔

**Type consistency:** `migrationScheduled atomic.Bool` (Task1) — читается в Task2 (`e.migrationScheduled.CompareAndSwap`). `wakeUplink(conn net.Conn, socks5Replies bool)` — единая сигнатура Task4/Task5. `scheduleSlotMigration(agingIdx int, slot *poolSlot) bool` — сигнатура не меняется (Task2). ✔

## Execution Handoff

После APPROVED — **subagent-driven** (per-task subagent + two-stage review). Race на Linux/pl1 делает юзер. Коммит — пачкой с Bug#10 + 60s half-close + emergency-evict (по плану юзера).
