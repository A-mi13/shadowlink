# Bug #10 — Origin death → stream-end signal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When a stream's origin TCP socket dies (server↔destination, `broken pipe` on write or EOF on read), the server signals the client via a new `FlagStreamClose` control frame so the client tears the stream down and the app retries — instead of hanging forever.

**Architecture:** Достроить задуманный `destClosed`→stream-end контур. (1) Новый control-фрейм `core.FlagStreamClose=0x0E`. (2) Серверный централизованный хелпер `signalStreamEnd` — single-winner CAS, шлёт `FlagStreamClose` по ЖИВОМУ binding'у. Оба uplink-пути (A=startWriter, B=registry-fallback) и read-EOF зовут его. (3) **b1 (reassociate-before-publish)**: в `handleMigrateOrResume` `bound.Store(B)` публикуется ДО `CAS(stOrphaned→stActive)` — закрывает гонку RESUME↔teardown (BLOCKER-2). (4) RESUME-fallback дочитывает `destClosed`. (5) Клиент принимает `FlagStreamClose` top-level в demux ДО W5-guard. Отправка сигнала под YAML-флагом `origin_death_teardown` (default-OFF на первую канарейку, по образцу `StreamMigrationEnabled *bool`); b1-перестановка безусловна (не меняет наблюдаемое поведение без сигнала).

**Tech Stack:** Go, ShadowLink (`shadowlink/` own go.mod), AES-256-GCM chunk wire format, atomic state machine, gorilla/websocket async writer.

**Spec:** `docs/superpowers/specs/2026-06-02-bug10-origin-death-teardown-design.md` (v4, APPROVED-WITH-NITS)
**Review:** `docs/bug10-spec-review-v4-opus-2026-06-02.md`

**Критические инварианты из ревью (НЕ нарушать):**
- **NIT-1:** `bound.Store` вынести ИЗ `reassociate`; публиковать готовый `*binding` параметром ДО CAS. Один pointer, одна точка публикации B.
- **NIT-2:** переезжает РОВНО `bound.Store`. `releaseOrphanFD` (websocket.go:610), resendTail-метрика (:618), весь дренаж reassociate ОСТАЮТСЯ после CAS.
- **NIT-3:** orphaned-ветка хелпера = `destClosed.Store(true)` БЕЗ `CAS(→stClosing)`, без remove/closeReader (как relayLoop:627-629). Снос делает только single-winner (grace-timer / evict / RESUME-fallback).
- **NIT-4:** race-тест армит окно «`bound.Store(B)` сделан, `CAS(stOrphaned→stActive)` ещё НЕ сделан, state==stOrphaned».

---

## File Structure

| Файл | Ответственность | Изменение |
|---|---|---|
| `core/chunk.go` | wire-format flags + конструктор/парсер `FlagStreamClose` | Modify |
| `core/chunk_test.go` | round-trip тест FlagStreamClose | Modify |
| `server/config.go` | YAML-поле `OriginDeathTeardown *bool` + `originDeathTeardownEnabledOrDefault` | Modify |
| `server/handler.go` | `NewHandler`: резолв флага в registry (рядом с `setLimits` :292) | Modify |
| `server/relay_registry.go` | `reassociate` (вынос bound.Store + RESUME-fallback param), `signalStreamEnd`, destClosed-на-active, поле `originDeathTeardown`+сеттер | Modify |
| `server/websocket.go` | b1 в `handleMigrateOrResume`, путь B + путь A колбэк, wsStream.onWriteErr | Modify |
| `server/relay_registry_test.go` | unit: signalStreamEnd single-winner, b1-окно, регресс Bug#9 | Modify |
| `server/migrate_e2e_test.go` | e2e: origin write-death → клиент получает FlagStreamClose | Modify |
| `client/ws_pool.go` | demux приём FlagStreamClose top-level ДО W5-guard | Modify |
| `client/ws_pool_test.go` (или соседний) | client: FlagStreamClose → канал закрыт | Modify |

**Флаг:** YAML `origin_death_teardown` (`Config.OriginDeathTeardown *bool`, default-OFF, по образцу `StreamMigrationEnabled`). Резолвится в `NewHandler` → поле `relayRegistry.originDeathTeardown`. Gate на ОТПРАВКУ сигнала (Компоненты 3/4). b1-перестановка (Task 4) и destClosed-взвод (Компонент 1) НЕ под флагом — они безопасны без сигнала. НЕ env (architecturally_correct: проект держит фича-флаги протокола в YAML).

---

## Task 1: `core.FlagStreamClose=0x0E` + конструктор/парсер

**Files:**
- Modify: `core/chunk.go:13-27` (flags), после `ParseStreamAckFrame` (~:400) — конструктор/парсер
- Test: `core/chunk_test.go`

- [ ] **Step 1: Написать падающий тест**

В `core/chunk_test.go` добавить:

```go
func TestStreamCloseChunk_RoundTrip(t *testing.T) {
	const sessID, seq uint32 = 42, 7
	const streamID uint16 = 0x1234
	c := NewStreamCloseChunk(sessID, seq, streamID)
	if c.Flags != FlagStreamClose {
		t.Fatalf("flags = 0x%02x, want FlagStreamClose 0x%02x", c.Flags, FlagStreamClose)
	}
	if c.SessionID != sessID || c.SeqNum != seq {
		t.Fatalf("header mismatch: sess=%d seq=%d", c.SessionID, c.SeqNum)
	}
	got, err := ParseStreamCloseFrame(c.Payload)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != streamID {
		t.Fatalf("streamID = 0x%04x, want 0x%04x", got, streamID)
	}
}

func TestStreamCloseFrame_TooShort(t *testing.T) {
	if _, err := ParseStreamCloseFrame([]byte{0x00}); err == nil {
		t.Fatal("expected error on 1-byte payload")
	}
}

func TestFlagStreamClose_Value(t *testing.T) {
	if FlagStreamClose != 0x0E {
		t.Fatalf("FlagStreamClose = 0x%02x, want 0x0E", FlagStreamClose)
	}
	// не конфликтует с существующим старшим flag
	if FlagStreamClose == FlagStreamAck {
		t.Fatal("FlagStreamClose collides with FlagStreamAck")
	}
}
```

- [ ] **Step 2: Запустить — убедиться что падает**

Run: `cd shadowlink && go test ./core/ -run 'TestStreamClose|TestFlagStreamClose' -v`
Expected: FAIL — `undefined: NewStreamCloseChunk` / `ParseStreamCloseFrame` / `FlagStreamClose`.

- [ ] **Step 3: Реализовать**

В `core/chunk.go` в const-блоке flags (после строки `FlagStreamAck byte = 0x0D`):

```go
	FlagStreamClose  byte = 0x0E // payload = [globalStreamID(2 BE)] — origin закрылся, стрим завершён (Bug #10)
```

После `ParseStreamAckFrame` (~:400) добавить:

```go
// NewStreamCloseChunk creates a per-stream close control chunk (Bug #10): the
// origin (server↔destination TCP) for this stream died, so the stream is over.
// Payload format: [globalStreamID(2 BE)]. The client tears the stream down and
// hands EOF to the app (which then retries). NOT session-wide (unlike FlagFin).
func NewStreamCloseChunk(sessID, seq uint32, streamID uint16) *Chunk {
	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p[0:2], streamID)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagStreamClose, Payload: p}
}

// ParseStreamCloseFrame extracts the globalStreamID from a FlagStreamClose
// payload. Errors (never panics) on payload shorter than 2 bytes.
func ParseStreamCloseFrame(payload []byte) (streamID uint16, err error) {
	if len(payload) < 2 {
		return 0, fmt.Errorf("stream close frame too short: %d < 2", len(payload))
	}
	return binary.BigEndian.Uint16(payload[0:2]), nil
}
```

- [ ] **Step 4: Запустить — убедиться что прошёл**

Run: `cd shadowlink && go test ./core/ -run 'TestStreamClose|TestFlagStreamClose' -v`
Expected: PASS (3 теста).

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/core/chunk.go shadowlink/core/chunk_test.go
git commit -m "feat(shadowlink): add FlagStreamClose=0x0E control frame (Bug #10 core)"
```

---

## Task 2: YAML-флаг `origin_death_teardown` (по образцу `StreamMigrationEnabled`)

**Files:**
- Modify: `server/config.go` (поле `OriginDeathTeardown *bool` + хелпер `originDeathTeardownEnabledOrDefault`)
- Modify: `server/relay_registry.go` (поле `originDeathTeardown bool` на registry; параметр в `setLimits` ИЛИ отдельный сеттер)
- Modify: `server/handler.go:292` (передать флаг из конфига в registry в `NewHandler`)
- Test: `server/config_test.go` (или `fileconfig_test.go`) + `server/relay_registry_test.go`

> **Архитектурное решение (юзер, 2026-06-03, [architecturally_correct]):** флаг через **YAML-конфиг**, НЕ env. Проект уже держит все фича-флаги Bug #9 в YAML (`StreamMigrationEnabled *bool`, `MigrateGracePeriod`, `MaxOrphaned*` — config.go:81-106). Образец — `StreamMigrationEnabled *bool` + `streamMigrationEnabledOrDefault()` (config.go:190). Направление по умолчанию ОБРАТНОЕ Bug#9: nil → **false** (default-OFF на первую канарейку). registry НЕ держит config (`newRelayRegistry()` :260), поэтому флаг кладём ПОЛЕМ на registry в той же точке, где `setLimits` (handler.go:292 в `NewHandler`).

- [ ] **Step 1: Написать падающий тест**

В `server/config_test.go`:

```go
func TestOriginDeathTeardownEnabledOrDefault_NilOff(t *testing.T) {
	var c Config // OriginDeathTeardown == nil
	if c.originDeathTeardownEnabledOrDefault() {
		t.Fatal("nil must default OFF (first-canary safety)")
	}
}

func TestOriginDeathTeardownEnabledOrDefault_Explicit(t *testing.T) {
	on, off := true, false
	if c := (Config{OriginDeathTeardown: &on}); !c.originDeathTeardownEnabledOrDefault() {
		t.Fatal("explicit *true must enable")
	}
	if c := (Config{OriginDeathTeardown: &off}); c.originDeathTeardownEnabledOrDefault() {
		t.Fatal("explicit *false must stay off")
	}
}
```

В `server/relay_registry_test.go`:

```go
func TestRegistry_OriginDeathTeardownFlag(t *testing.T) {
	r := newRelayRegistry()
	if r.originDeathTeardown {
		t.Fatal("default zero-value must be false")
	}
	r.setOriginDeathTeardown(true)
	if !r.originDeathTeardown {
		t.Fatal("setter must enable")
	}
}
```

- [ ] **Step 2: Запустить — падает**

Run: `cd shadowlink && go test ./server/ -run 'TestOriginDeathTeardownEnabledOrDefault|TestRegistry_OriginDeathTeardownFlag' -v`
Expected: FAIL — `OriginDeathTeardown` / `originDeathTeardownEnabledOrDefault` / `setOriginDeathTeardown` не определены.

- [ ] **Step 3: Реализовать**

(3a) В `server/config.go` рядом с `StreamMigrationEnabled` (после :88) добавить поле:

```go
	// OriginDeathTeardown gates Bug #10: signal FlagStreamClose to the client when
	// a stream's origin TCP dies (broken pipe / EOF) so the app retries instead of
	// hanging. nil → default OFF (first-canary safety; opposite of Bug #9 which is
	// default-ON). An explicit *true enables it. The b1 bound.Store reorder is NOT
	// gated — it only narrows a race window and is safe unconditionally.
	OriginDeathTeardown *bool `yaml:"origin_death_teardown,omitempty"`
```

(3b) В `server/config.go` рядом с `streamMigrationEnabledOrDefault` (после :195):

```go
// originDeathTeardownEnabledOrDefault resolves Config.OriginDeathTeardown
// (nil → false, default-OFF first-canary safety; *true enables). Bug #10.
func (c Config) originDeathTeardownEnabledOrDefault() bool {
	if c.OriginDeathTeardown == nil {
		return false
	}
	return *c.OriginDeathTeardown
}
```

(3c) В `server/relay_registry.go` — поле на `relayRegistry` struct (рядом с лимитами ~:240) + сеттер:

```go
	// originDeathTeardown gates Bug #10 FlagStreamClose signalling (write-once at
	// init via setOriginDeathTeardown, read-only thereafter — same contract as the
	// setLimits int fields). Resolved from Config.originDeathTeardownEnabledOrDefault
	// in NewHandler.
	originDeathTeardown bool
```

```go
// setOriginDeathTeardown configures the Bug #10 signal gate (write-once at init).
func (r *relayRegistry) setOriginDeathTeardown(enabled bool) {
	r.originDeathTeardown = enabled
}
```

(3d) В `server/handler.go` `NewHandler`, рядом с `setLimits` (:292):

```go
	h.relayRegistry.setOriginDeathTeardown(cfg.originDeathTeardownEnabledOrDefault())
```

> Сверить имя переменной конфига в `NewHandler` (`cfg` / `config` / `h.config`) — использовать то, что в scope на :292.

- [ ] **Step 4: Запустить — прошёл**

Run: `cd shadowlink && go test ./server/ -run 'TestOriginDeathTeardownEnabledOrDefault|TestRegistry_OriginDeathTeardownFlag' -v && go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/server/config.go shadowlink/server/relay_registry.go shadowlink/server/handler.go shadowlink/server/config_test.go shadowlink/server/relay_registry_test.go
git commit -m "feat(shadowlink): origin_death_teardown YAML flag default-off (Bug #10)"
```

> **CLI-флаг (опционально, вне TDD-цикла):** если `cmd/shadowlink-server/main.go` мапит YAML-поля на CLI-флаги (как `-migrate-grace`), добавить `-origin-death-teardown` по тому же образцу. Не обязательно для канарейки (YAML-конфига на pl1 достаточно) — отметить как follow-up.

---

## Task 3: Вынести `bound.Store` из `reassociate` (NIT-1 — подготовка к b1)

**Files:**
- Modify: `server/relay_registry.go:732-763` (`reassociate`)
- Modify: `server/websocket.go:620` (вызов reassociate в handleMigrateOrResume)
- Test: `server/relay_registry_test.go`

**Цель:** `reassociate` больше НЕ делает `bound.Store` — она принимает уже-опубликованный `*binding` и только дренит. Это даёт b1 (Task 4) единственную точку публикации B. Поведение пока НЕ меняется (bound.Store просто переезжает в вызывающий код ровно перед reassociate-вызовом — окно ещё не сужено, это Task 4).

- [ ] **Step 1: Написать падающий тест на новую сигнатуру**

В `server/relay_registry_test.go`:

```go
// reassociate теперь принимает готовый *binding и НЕ сторит его сама —
// публикация binding ответственность вызывающего (NIT-1, подготовка b1).
func TestReassociate_DoesNotStoreBinding(t *testing.T) {
	e := &relayEntry{
		downBuffer:  newBoundedBuffer(1 << 20),
		unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stOrphaned)
	sess := core.NewSession(1, make([]byte, 32))
	w := core.NewWSAsyncWriter(nil) // writer без conn — Enqueue вернёт ошибку, дренаж пуст
	b := &binding{session: sess, writer: w}
	// Вызывающий публикует binding ДО reassociate:
	e.bound.Store(b)
	// reassociate получает ТОТ ЖЕ b, не создаёт новый:
	resumeSeq := e.reassociate(b, true /*migrateEnabled*/, false /*aDead*/, false /*originDeathTeardown*/)
	if got := e.bound.Load(); got != b {
		t.Fatalf("bound pointer changed: reassociate must not re-store (NIT-1)")
	}
	if resumeSeq != 0 {
		t.Fatalf("resumeSeq = %d, want 0 (empty buffer)", resumeSeq)
	}
}
```

> **Примечание:** сверить точную сигнатуру `core.NewSession` / `core.NewWSAsyncWriter` перед написанием (grep по core). Если конструктор writer'а требует non-nil conn — использовать существующий test-helper из `server/*_test.go` (например тот, что уже используют migrate-тесты для построения writer'а). Тест проверяет ТОЛЬКО что pointer не сменился — деталь конструкторов вторична.

- [ ] **Step 2: Запустить — падает**

Run: `cd shadowlink && go test ./server/ -run TestReassociate_DoesNotStoreBinding -v`
Expected: FAIL — старая сигнатура `reassociate(sess, w, migrateEnabled, aDead)` не компилируется с новым вызовом.

- [ ] **Step 3: Реализовать — изменить сигнатуру reassociate**

В `server/relay_registry.go` заменить `reassociate` (:732-763) на:

```go
// reassociate drains downlink buffered during the no-binding window onto the
// ALREADY-PUBLISHED binding `b` in seq order, and — when slot A is known-dead
// (aDead, §5.3) — resends the still-unacked tail. downSeqCounter is NEVER reset
// (NEW-3). Returns resumeDownSeq = the highest seq assigned before the binding
// switched (§3.4 MIGRATE_OK).
//
// NIT-1 (Bug #10): reassociate NO LONGER stores the binding — the caller
// publishes `e.bound.Store(b)` BEFORE calling reassociate (b1: before the
// stActive CAS). reassociate is now pure drain, so there is exactly ONE
// publication point for B. The drain is held under perEntryMu only for the
// snapshot (not the enqueue).
//
// originDeathTeardown gates the Компонент-4 RESUME-fallback (Task 7): if it is
// true AND e.destClosed is set, after the drain we send FlagStreamClose on the
// new binding (the origin died while orphaned; deliver the close on the live
// slot). Threaded as a param because reassociate is a *relayEntry method with
// no registry reference; the caller passes r.originDeathTeardown.
func (e *relayEntry) reassociate(b *binding, migrateEnabled, aDead, originDeathTeardown bool) uint64 {
	resumeDownSeq := e.downSeqCounter.Load()

	cond := e.bufCondOf()
	e.perEntryMu.Lock()
	buffered := e.downBuffer.drainAll()
	var resend []pendingDownFrame
	if aDead {
		resend = e.unackedTail.tailFrames()
	}
	cond.Broadcast()
	e.perEntryMu.Unlock()

	for _, f := range buffered {
		e.enqueueDownFrame(b, migrateEnabled, f)
	}
	for _, f := range resend {
		e.enqueueDownFrame(b, migrateEnabled, f)
	}
	return resumeDownSeq
}
```

В `server/websocket.go` в `handleMigrateOrResume` (:620) заменить:

```go
	resumeSeq := entry.reassociate(session, writer, migrateEnabled, aDead)
```

на (пока ПОСЛЕ CAS — Task 4 переставит bound.Store раньше):

```go
	b := &binding{session: session, writer: writer}
	entry.bound.Store(b)
	resumeSeq := entry.reassociate(b, migrateEnabled, aDead, h.relayRegistry.originDeathTeardown)
```

> **Проверить других вызывающих:** grep `\.reassociate(` по `shadowlink/server/` — обновить ВСЕ вызовы (тесты тоже) под новую сигнатуру `(b *binding, migrateEnabled, aDead, originDeathTeardown bool)`. В тестах, не проверяющих RESUME-fallback, передавать `false` последним аргументом.

- [ ] **Step 4: Запустить — прошёл + все server-тесты зелёные**

Run: `cd shadowlink && go test ./server/ -run 'TestReassociate|TestMigrate|TestResume' -v && go build ./...`
Expected: PASS, build OK. (Поведение не изменилось — bound.Store просто переехал в вызывающий код ровно перед reassociate.)

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/server/relay_registry.go shadowlink/server/websocket.go shadowlink/server/relay_registry_test.go
git commit -m "refactor(shadowlink): hoist bound.Store out of reassociate (Bug #10 NIT-1)"
```

---

## Task 4: b1 — `bound.Store(B)` ДО CAS (закрытие BLOCKER-2)

**Files:**
- Modify: `server/websocket.go:595-626` (`handleMigrateOrResume`)
- Test: `server/relay_registry_test.go`

**Цель:** переставить `bound.Store(B)` ПЕРЕД `CAS(stOrphaned→stActive)` для RESUME-пути. Окна «stActive + bound=мёртвый A» больше нет. Дренаж (reassociate) + releaseOrphanFD + resendTail-метрика ОСТАЮТСЯ после CAS (NIT-2).

- [ ] **Step 1: Написать падающий тест на окно b1 (NIT-4)**

```go
// b1: bound публикуется на B ДО CAS(stOrphaned→stActive). Воспроизводит окно
// «bound=B опубликован, CAS ещё НЕ сделан, state==stOrphaned» (NIT-4) и
// проверяет, что origin-death хелпер в этом окне видит state==stOrphaned (идёт
// по orphaned-ветке destClosed, НЕ сносит), а после CAS берёт bound==B.
func TestHandleResume_BoundStoredBeforeStatePublish_b1(t *testing.T) {
	h, _ := newTestHandlerWithRegistry(t) // см. существующие migrate-тесты для конструктора
	clientID := "cid-b1"
	const sid uint16 = 1

	// Orphaned entry на «мёртвом» слоте A.
	deadSess := core.NewSession(1, make([]byte, 32))
	deadW := newTestWriter(t)
	entry := &relayEntry{
		originClientID: clientID, globalStreamID: sid,
		originSessionNonce: deadSess.MigrateNonce,
		tc:                 newPipeConn(t), // half of net.Pipe или существующий fakeConn
		downBuffer:         newBoundedBuffer(1 << 20),
		unackedTail:        newBoundedBuffer(1 << 20),
	}
	entry.bound.Store(&binding{session: deadSess, writer: deadW})
	entry.state.Store(stOrphaned)
	entry.holdsFD.Store(true)
	h.relayRegistry.add(clientID, sid, entry)
	h.relayRegistry.orphanedFDInUse.Add(1)

	// Живой слот B (RESUME прилетает сюда).
	liveSess := core.NewSession(2, make([]byte, 32))
	liveW := newTestWriter(t)

	// Снимок: ДО публикации stActive bound уже должен указывать на B.
	// Эмулируем порядок b1 напрямую (как handleMigrateOrResume Task 4):
	bB := &binding{session: liveSess, writer: liveW}
	entry.bound.Store(bB) // b1: ДО CAS
	if got := entry.bound.Load(); got != bB {
		t.Fatal("b1: bound must be B before CAS")
	}
	// В этом окне state ещё stOrphaned:
	if entry.state.Load() != stOrphaned {
		t.Fatal("window invariant: state must still be stOrphaned before CAS")
	}
	// CAS публикует stActive:
	if !entry.state.CompareAndSwap(stOrphaned, stActive) {
		t.Fatal("CAS stOrphaned->stActive must win (no competitor in this test)")
	}
	// Теперь origin-death хелпер из stActive возьмёт bound==B:
	if entry.bound.Load() != bB {
		t.Fatal("after CAS, bound must be live B")
	}
}
```

> **Примечание:** имена test-helper'ов (`newTestHandlerWithRegistry`, `newTestWriter`, `newPipeConn`) — сверить с реальными в `server/migrate_handlers_test.go` / `migrate_e2e_test.go` и использовать существующие. Если их нет — построить минимально из `net.Pipe()` и существующего конструктора writer'а. Суть теста: проверить ИНВАРИАНТ ПОРЯДКА b1, а не конкретные имена.

- [ ] **Step 2: Запустить — падает (или компилируется но проверяет старый порядок)**

Run: `cd shadowlink && go test ./server/ -run TestHandleResume_BoundStoredBeforeStatePublish_b1 -v`
Expected: до Task-4-правки в `handleMigrateOrResume` порядок другой — тест на сам handler (см. e2e Task 8) поймает; этот unit фиксирует инвариант. Если зелёный сразу — это OK, он guard-инвариант; реальную перестановку проверит e2e.

- [ ] **Step 3: Реализовать b1 в handleMigrateOrResume**

В `server/websocket.go` заменить блок RESUME-CAS + reassociate (:595-626). Текущий порядок:
```
aDead := flag == core.FlagResume
if flag == core.FlagResume {
	if !entry.state.CompareAndSwap(stOrphaned, stActive) { ...fail... }
	h.relayRegistry.releaseOrphanFD(entry)
}
if aDead { h.metrics.MigrateTailResent.Add(...) }
b := &binding{session: session, writer: writer}  // из Task 3
entry.bound.Store(b)
resumeSeq := entry.reassociate(b, migrateEnabled, aDead)
```

Новый порядок (b1 — `bound.Store(B)` ДО CAS; releaseOrphanFD/метрика/reassociate ПОСЛЕ — NIT-2):

```go
	aDead := flag == core.FlagResume

	// b1 (Bug #10 BLOCKER-2): publish the binding onto the NEW live slot B
	// BEFORE flipping state to stActive. This eliminates the window where
	// state==stActive but bound still points at the dead slot A — in which an
	// origin-death teardown could win CAS(stActive→stClosing) and signal/close
	// the relay the RESUME is about to revive. After this Store, any origin-death
	// winner from stActive reads bound==B (live). NIT-2: ONLY bound.Store moves
	// up here — releaseOrphanFD / tail-resend metric / reassociate drain all stay
	// AFTER the CAS (they are correct only once the RESUME has actually won).
	b := &binding{session: session, writer: writer}
	entry.bound.Store(b)

	if flag == core.FlagResume {
		// Single-winner vs grace timer / evict. If CAS fails the entry is gone
		// (closing/closed) — RESUME is too late. (bound is already B but the entry
		// is being torn down by the single-winner; harmless — teardown closes the
		// whole entry regardless of binding.)
		if !entry.state.CompareAndSwap(stOrphaned, stActive) {
			h.metrics.MigrateFail.Add(1)
			h.metrics.MigrateFailGraceExpired.Add(1)
			h.enqueueMigrateFail(session, writer, flag, sid, core.MigrateReasonGraceExpired)
			return
		}
		// FD budget released only now that RESUME genuinely won the entry.
		h.relayRegistry.releaseOrphanFD(entry)
	}

	if aDead {
		h.metrics.MigrateTailResent.Add(uint64(len(entry.resendTail())))
	}
	resumeSeq := entry.reassociate(b, migrateEnabled, aDead, h.relayRegistry.originDeathTeardown)
	if flag == core.FlagResume {
		h.metrics.ResumeOK.Add(1)
	} else {
		h.metrics.MigrateOK.Add(1)
	}
	h.enqueueMigrateOK(session, writer, flag, sid, resumeSeq)
```

> **Важно (MIGRATE-путь):** при `flag==FlagMigrate` (не Resume) entry уже stActive (слот A жив) — CAS не делается, `bound.Store(b)` просто перепривязывает на новый слот, что и было. b1 двигает Store на ~25 строк раньше внутри той же горутины без новых сигналов — поведение MIGRATE не меняется.

- [ ] **Step 4: Запустить — прошёл + регресс Bug#9 зелёный**

Run: `cd shadowlink && go test ./server/ -run 'TestHandleResume|TestMigrate|TestResume|TestReassociate' -v && go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/server/websocket.go shadowlink/server/relay_registry_test.go
git commit -m "fix(shadowlink): b1 reassociate-before-publish closes Bug #10 BLOCKER-2 race"
```

---

## Task 5: `signalStreamEnd` хелпер + destClosed на read-EOF active

**Files:**
- Modify: `server/relay_registry.go` (новый метод `signalStreamEnd`, снять `==stOrphaned` на read-EOF :627)
- Test: `server/relay_registry_test.go`

**Семантика (спека §65-105, NIT-3):**
- CAS `stActive→stClosing`: ВЫИГРАЛ → snapshot `b:=bound.Load()` (nil-guard), если `b.writer` пригоден — шлёт `FlagStreamClose`, затем `remove`+`closeReader`+`releaseOrphanFD`+`tc.Close`+broadcast.
- state НЕ stActive (orphaned/closing): НЕ CAS, НЕ снос — только `destClosed.Store(true)` (NIT-3). Подберёт RESUME-fallback (Task 7) или grace-timer.
- gate на `enabled bool` (флаг Task 2) + `migrateEnabled` assert (HIGH-C).

- [ ] **Step 1: Написать падающие тесты**

```go
func TestSignalStreamEnd_ActiveWinnerSendsAndTearsDown(t *testing.T) {
	reg := newRelayRegistry()
	reg.setLimits(10, 100, 100)
	reg.setOriginDeathTeardown(true) // включить отправку сигнала для теста
	sess := core.NewSession(1, make([]byte, 32))
	w := newTestWriter(t)
	tc := newPipeConn(t)
	e := &relayEntry{
		originClientID: "c", globalStreamID: 5, tc: tc,
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stActive)
	e.bound.Store(&binding{session: sess, writer: w})
	reg.add("c", 5, e)

	reg.signalStreamEnd(e, true /*migrateEnabled*/, "pathB")

	if e.state.Load() != stClosing {
		t.Fatalf("state = %d, want stClosing", e.state.Load())
	}
	if _, ok := reg.find("c", 5); ok {
		t.Fatal("entry must be removed after active teardown")
	}
	// FlagStreamClose должен быть отправлен — проверить через test-writer capture
	// (newTestWriter должен уметь вернуть enqueued frames; см. существующий helper).
}

func TestSignalStreamEnd_OrphanedOnlySetsDestClosed_NIT3(t *testing.T) {
	reg := newRelayRegistry()
	reg.setLimits(10, 100, 100)
	e := &relayEntry{
		originClientID: "c", globalStreamID: 6,
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stOrphaned)
	reg.add("c", 6, e)

	reg.signalStreamEnd(e, true, "read")

	if e.state.Load() != stOrphaned {
		t.Fatalf("orphaned entry must STAY stOrphaned (NIT-3), got %d", e.state.Load())
	}
	if !e.destClosed.Load() {
		t.Fatal("destClosed must be set on orphaned path")
	}
	if _, ok := reg.find("c", 6); !ok {
		t.Fatal("orphaned entry must NOT be removed (RESUME/grace will)")
	}
}

func TestSignalStreamEnd_SingleWinner(t *testing.T) {
	reg := newRelayRegistry()
	reg.setLimits(10, 100, 100)
	sess := core.NewSession(1, make([]byte, 32))
	e := &relayEntry{
		originClientID: "c", globalStreamID: 7, tc: newPipeConn(t),
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stActive)
	e.bound.Store(&binding{session: sess, writer: newTestWriter(t)})
	reg.add("c", 7, e)

	reg.signalStreamEnd(e, true, "A") // winner
	st := e.state.Load()
	reg.signalStreamEnd(e, true, "B") // loser — no-op
	if e.state.Load() != st {
		t.Fatal("second signalStreamEnd must be a no-op (single-winner)")
	}
}
```

- [ ] **Step 2: Запустить — падает**

Run: `cd shadowlink && go test ./server/ -run TestSignalStreamEnd -v`
Expected: FAIL — `undefined: (*relayRegistry).signalStreamEnd`.

- [ ] **Step 3: Реализовать**

В `server/relay_registry.go` добавить (после `launchGraceTimer`):

```go
// signalStreamEnd is the centralized Bug #10 origin-death teardown. Called from
// BOTH uplink write-error paths (A=startWriter callback, B=registry-fallback)
// and the relayLoop read-EOF path when an origin TCP died. Single-winner via
// CAS(stActive→stClosing):
//
//   - WON (was stActive, live WS slot): snapshot bound ONCE, send FlagStreamClose
//     on that live binding (session+writer from one snapshot — MEDIUM-4), then
//     permanent teardown (remove + closeReader + releaseOrphanFD + tc.Close +
//     broadcast). The client tears the stream down and retries.
//   - NOT stActive (orphaned/closing): do NOT CAS, do NOT remove — only
//     destClosed.Store(true) (NIT-3, mirrors relayLoop:627). RESUME-fallback
//     (reassociate) or the grace timer will deliver the close on a live slot and
//     tear down. This covers "both TCP died at once" (WS slot also gone).
//
// r.originDeathTeardown gates SENDING (YAML origin_death_teardown, default-off
// first canary). `migrateEnabled` is a defense-in-depth assert (HIGH-C): the helper is
// only reachable under migration paths; on a legacy session it logs and returns
// without sending (a raw STREAM_CLOSE on a non-seq stream would corrupt the app
// byte stream).
func (r *relayRegistry) signalStreamEnd(e *relayEntry, migrateEnabled bool, pathTag string) {
	if !migrateEnabled {
		slog.Warn("bug10 helper reached on non-migration session", "stream", e.globalStreamID, "path", pathTag)
		return
	}

	// Active path: single-winner teardown + immediate signal on the live slot.
	if e.state.CompareAndSwap(stActive, stClosing) {
		b := e.bound.Load()
		if r.originDeathTeardown && b != nil && b.session != nil && b.writer != nil {
			chunk := core.NewStreamCloseChunk(b.session.ID, b.session.NextSeqNum(), e.globalStreamID)
			if enc, err := b.session.EncryptChunk(chunk); err == nil {
				_ = b.writer.Enqueue(websocketBinaryMessage, enc)
			}
			core.PutBuffer(chunk.Payload)
		}
		r.remove(e.originClientID, e.globalStreamID)
		e.closeReader()
		r.releaseOrphanFD(e)
		if e.tc != nil {
			e.tc.Close()
		}
		cond := e.bufCondOf()
		e.perEntryMu.Lock()
		cond.Broadcast()
		e.perEntryMu.Unlock()
		return
	}

	// Orphaned/closing path: only record destClosed (NIT-3). RESUME-fallback or
	// grace timer owns the teardown — do NOT remove/closeReader here, or we'd
	// snatch the entry from a RESUME that is about to revive it on a live slot.
	if e.state.Load() == stOrphaned {
		e.destClosed.Store(true)
	}
}
```

В `relayLoop` read-EOF (relay_registry.go:627-629) снять условие `==stOrphaned` — взводить destClosed и на active (Компонент 1). Заменить:
```go
				if e.state.Load() == stOrphaned {
					e.destClosed.Store(true)
				}
```
на:
```go
				// Bug #10: origin TCP read closed/errored. Centralized teardown
				// signals the client (if active+live) or records destClosed (if
				// orphaned) so the stream never hangs. r is not in scope here —
				// the registry reference is passed via closeCh owner; see Task 6
				// note. For read-EOF we set destClosed unconditionally and let the
				// caller's teardown / RESUME-fallback deliver the signal.
				e.destClosed.Store(true)
```

> **Scope note:** `relayLoop` — метод `*relayEntry`, не держит `*relayRegistry`. Для read-EOF мы лишь взводим `destClosed` (как раньше, но теперь и на active). Активный сигнал на read-EOF доставит либо session-teardown (entry уже active в registry — orphan→grace), либо RESUME-fallback. Прямой вызов `signalStreamEnd` с read-пути НЕ требуется (uplink-пути A/B — основные триггеры Bug #10; read-EOF — вторичный, покрыт destClosed+RESUME-fallback). Это согласуется со спекой §56 (read-EOF: снять `==stOrphaned`).

- [ ] **Step 4: Запустить — прошёл**

Run: `cd shadowlink && go test ./server/ -run TestSignalStreamEnd -v && go build ./...`
Expected: PASS.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/server/relay_registry.go shadowlink/server/relay_registry_test.go
git commit -m "feat(shadowlink): signalStreamEnd helper + destClosed on active read-EOF (Bug #10)"
```

---

## Task 6: Путь B (registry-fallback) зовёт signalStreamEnd

**Files:**
- Modify: `server/websocket.go:855-860` (uplink registry-fallback write error)
- Test: `server/relay_registry_test.go` (или migrate_handlers_test.go)

- [ ] **Step 1: Написать падающий тест**

```go
// Путь B: uplink в мёртвый origin → werr != nil → signalStreamEnd, НЕ только лог.
// Проверяем что после write-error на live entry стрим уходит в stClosing.
func TestUplinkPathB_OriginWriteError_SignalsStreamEnd(t *testing.T) {
	// Построить relayEntry с tc = половина net.Pipe, закрыть peer → Write вернёт err.
	// Прогнать через ветку path B (или вызвать signalStreamEnd напрямую как делает
	// path B) и проверить state==stClosing + entry removed.
	// Деталь: интеграционно проще проверить в e2e (Task 8); этот тест — unit на
	// то, что path B при werr зовёт signalStreamEnd(entry, migrateEnabled, "B").
}
```

> Если полноценный driver для reader-loop тяжёл — отметить тест как покрытый e2e (Task 8) и проверить здесь ТОЛЬКО что код path B вызывает `signalStreamEnd` (можно через рефактор-вынос мелкой функции или прямую проверку в e2e). НЕ оставлять path B как «только лог».

- [ ] **Step 2: Запустить — падает / отметить покрытие e2e**

Run: `cd shadowlink && go test ./server/ -run TestUplinkPathB -v`

- [ ] **Step 3: Реализовать**

В `server/websocket.go:855-860` заменить:
```go
					if entry, ok := h.relayRegistry.find(migrateClientID, streamID); ok && entry.tc != nil {
						if _, werr := entry.tc.Write(payload); werr != nil {
							slog.Warn("WS uplink registry-fallback write failed",
								"stream", streamID, "err", werr)
						}
					}
```
на:
```go
					if entry, ok := h.relayRegistry.find(migrateClientID, streamID); ok && entry.tc != nil {
						if _, werr := entry.tc.Write(payload); werr != nil {
							// Bug #10: origin TCP (entry.tc) died (broken pipe). Do NOT
							// just log-and-continue — that left the client uploading into
							// a dead origin forever (the hang). Centralized teardown
							// signals FlagStreamClose on the live WS slot (or records
							// destClosed if orphaned) so the client retries.
							slog.Warn("WS uplink registry-fallback write failed",
								"stream", streamID, "err", werr, "reason", "origin_write_broken_pipe")
							h.relayRegistry.signalStreamEnd(entry, migrateEnabled, "B")
						}
					}
```

- [ ] **Step 4: Запустить — прошёл**

Run: `cd shadowlink && go test ./server/ -v && go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/server/websocket.go shadowlink/server/relay_registry_test.go
git commit -m "fix(shadowlink): uplink path B signals stream-end on origin death (Bug #10)"
```

---

## Task 7: Путь A (startWriter колбэк) + RESUME-fallback дочитывает destClosed

**Files:**
- Modify: `server/websocket.go:285-295` (wsStream — поле `onWriteErr`), `:328-360` (startWriter), `:1032-1055` (CONNECT migration — выставить колбэк)
- Modify: `server/relay_registry.go` (`reassociate` — после дренажа, если destClosed → FlagStreamClose на B; Компонент 4)
- Test: `server/relay_registry_test.go`

- [ ] **Step 1: Написать падающий тест на RESUME-fallback (Компонент 4)**

```go
// Компонент 4: orphaned entry с destClosed=true → reassociate после дренажа
// шлёт FlagStreamClose на новый binding B. Покрывает "оба TCP умерли разом".
func TestReassociate_DestClosed_SendsStreamClose(t *testing.T) {
	e := &relayEntry{
		originClientID: "c", globalStreamID: 9,
		downBuffer: newBoundedBuffer(1 << 20), unackedTail: newBoundedBuffer(1 << 20),
	}
	e.state.Store(stOrphaned)
	e.destClosed.Store(true)
	sess := core.NewSession(2, make([]byte, 32))
	w := newTestWriter(t)
	b := &binding{session: sess, writer: w}
	e.bound.Store(b)

	_ = e.reassociate(b, true /*migrateEnabled*/, true /*aDead*/, true /*originDeathTeardown*/)

	// w должен получить ровно один FlagStreamClose-фрейм (проверить через capture).
	frames := w.captured() // helper из newTestWriter
	if !hasStreamCloseFrame(t, sess, frames, 9) {
		t.Fatal("reassociate with destClosed must enqueue FlagStreamClose on B")
	}
}
```

> `w.captured()` / `hasStreamCloseFrame` — построить минимальный test-writer, складывающий enqueued байты, и хелпер, расшифровывающий их под sess и матчащий Flags==FlagStreamClose + streamID. Если в server-тестах уже есть capture-writer (migrate-тесты его используют для проверки MIGRATE_OK) — переиспользовать.

- [ ] **Step 2: Запустить — падает**

Run: `cd shadowlink && go test ./server/ -run TestReassociate_DestClosed -v`
Expected: FAIL — reassociate пока не шлёт stream-close.

- [ ] **Step 3: Реализовать**

(3a) RESUME-fallback в `reassociate` (relay_registry.go) — в конце метода, после двух циклов enqueue, ПЕРЕД `return resumeDownSeq`:

```go
	// Bug #10 Компонент 4 (RESUME-fallback): if the origin died while this relay
	// was orphaned (destClosed), the immediate FlagStreamClose (signalStreamEnd)
	// either was never sent (read-EOF orphaned path) or went to a dead writer
	// ("both TCP died at once"). Now that we have a LIVE binding B again, deliver
	// the stream-close on it so the client tears down and retries.
	if originDeathTeardown && e.destClosed.Load() {
		chunk := core.NewStreamCloseChunk(b.session.ID, b.session.NextSeqNum(), e.globalStreamID)
		if enc, err := b.session.EncryptChunk(chunk); err == nil {
			_ = b.writer.Enqueue(websocketBinaryMessage, enc)
		}
		core.PutBuffer(chunk.Payload)
	}
```

(3b) wsStream колбэк (websocket.go). Добавить поле в struct (:285-295):
```go
	// onWriteErr (Bug #10): for a migration relay, startWriter calls this on an
	// origin write error INSTEAD of bare s.Close() — it routes the failure to
	// signalStreamEnd (which closes the egress + signals the client). nil for
	// non-migration streams (they keep the legacy s.Close() teardown).
	onWriteErr func(err error)
```

В `startWriter` (:340-343) заменить:
```go
				if err != nil {
					s.Close()
					return
				}
```
на:
```go
				if err != nil {
					// Bug #10: for a migration relay, route the origin write error to
					// centralized teardown (signals FlagStreamClose on the live slot +
					// closes egress). Otherwise legacy close. The callback owns egress
					// closure, so we do NOT call s.Close() in the migration case.
					if s.onWriteErr != nil {
						s.onWriteErr(err)
					} else {
						s.Close()
					}
					return
				}
```

В CONNECT migration branch (websocket.go ~:1054, сразу после `h.relayRegistry.add(clientID, sid, entry)`):
```go
						// Bug #10 path A: wire the stream's writer-error to centralized
						// teardown. startWriter calls this on s.targetConn (==entry.tc)
						// write error instead of bare s.Close(), so the client gets a
						// FlagStreamClose and the egress is closed via signalStreamEnd.
						s.mu.Lock()
						s.onWriteErr = func(error) {
							h.relayRegistry.signalStreamEnd(entry, true /*migrateEnabled*/, "A")
						}
						s.mu.Unlock()
```

> **Проверить гонку:** `onWriteErr` ставится после `Activate` (которая стартует writer goroutine на :324). Writer goroutine читает `s.onWriteErr` только в ветке ошибки. Чтобы избежать data-race между установкой колбэка и чтением в горутине — ставить под `s.mu` (как выше) И в startWriter читать под `s.mu` ИЛИ сделать `onWriteErr` атомиком. **Решение для плана:** прочитать `onWriteErr` в startWriter под `s.mu.Lock()` непосредственно перед вызовом. Обновить Step 3 startWriter-правку: снять копию `cb := s.onWriteErr` под mu в начале error-ветки. (Альтернатива — `atomic.Pointer[func]`; mu проще и согласуется с остальным wsStream.) Гонку обязан поймать `-race` в Task 9.

- [ ] **Step 4: Запустить — прошёл + race**

Run: `cd shadowlink && go test ./server/ -run 'TestReassociate_DestClosed|TestSignalStreamEnd' -v && go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/server/websocket.go shadowlink/server/relay_registry.go shadowlink/server/relay_registry_test.go
git commit -m "fix(shadowlink): path A callback + RESUME-fallback destClosed (Bug #10)"
```

---

## Task 8: Клиент принимает FlagStreamClose (top-level ДО W5-guard)

**Files:**
- Modify: `client/ws_pool.go:3233` (после migrate-reply branch, ПЕРЕД `len<2` :3235)
- Test: `client/ws_pool_test.go` (или соседний client-тест)

- [ ] **Step 1: Написать падающий тест**

```go
// Клиент: FlagStreamClose для streamID → streamMap.Delete + close(streamChans).
// Reader реассемблера видит закрытый канал → EOF. Принимается с любого слота
// (top-level ДО W5-guard).
func TestDemux_FlagStreamClose_ClosesStream(t *testing.T) {
	// Построить client+pool с одним зарегистрированным стримом (streamMap + streamChans).
	// Подсунуть в demux зашифрованный FlagStreamClose-чанк для streamID.
	// Проверить: streamChans[streamID] закрыт, streamMap не содержит streamID.
	// Сверить конструкторы с существующими client-тестами (RouteToStream tests).
}
```

> Сверить, как существующие client-тесты строят `*client`/`*wsPool` с stream registry и прогоняют через demux. Если прямой вызов demux тяжёл — проверить хотя бы хелпер закрытия (вынести `closeStreamByID(streamID)` метод и протестировать его + проверить, что demux его зовёт на FlagStreamClose).

- [ ] **Step 2: Запустить — падает**

Run: `cd shadowlink && go test ./client/ -run TestDemux_FlagStreamClose -v`
Expected: FAIL — demux не распознаёт FlagStreamClose.

- [ ] **Step 3: Реализовать**

В `client/ws_pool.go` сразу ПОСЛЕ migrate-reply branch (:3233), ПЕРЕД `if len(chunk.Payload) < 2` (:3235):

```go
		// Bug #10: FlagStreamClose is a top-level control frame (origin of this
		// stream died on the server). Handle it BEFORE the W5 stale-frame guard
		// (:3252) so the close is honored even if the stream just migrated to a
		// different slotIdx (Компонент 4 RESUME-fallback delivers it on slot B).
		// Tear the stream down → reassembler sees a closed chan → EOF to the app
		// → SOCKS5/memConn reader closes appConn → app (Claude Code) retries.
		if chunk.Flags == core.FlagStreamClose {
			if sid, perr := core.ParseStreamCloseFrame(chunk.Payload); perr == nil {
				p.streamMap.Delete(sid)
				cl.streamMu.Lock()
				if ch, ok := cl.streamChans[sid]; ok {
					close(ch)
					delete(cl.streamChans, sid)
				}
				cl.streamMu.Unlock()
			}
			continue
		}
```

> Сверить точные имена `p.streamMap`, `cl.streamMu`, `cl.streamChans` со scope demux (они уже используются в slot-death `closeStream` :3549-3556 — те же поля). Delete-before-close инвариант соблюдён (как в closeStream).

- [ ] **Step 4: Запустить — прошёл**

Run: `cd shadowlink && go test ./client/ -run TestDemux_FlagStreamClose -v && go build ./...`
Expected: PASS, build OK.

- [ ] **Step 5: Коммит**

```bash
git add shadowlink/client/ws_pool.go shadowlink/client/ws_pool_test.go
git commit -m "feat(shadowlink): client demux accepts FlagStreamClose (Bug #10 client)"
```

---

## Task 9: e2e + race — origin write-death воспроизводит Bug #10

**Files:**
- Modify: `server/migrate_e2e_test.go`
- Test: тот же

- [ ] **Step 1: Написать e2e-тест (прямое воспроизведение Bug #10)**

```go
// Прямое воспроизведение Bug #10: стрим active на migration-сессии → origin
// (entry.tc) закрыт → uplink write → broken pipe → signalStreamEnd → клиент
// получает FlagStreamClose по живому WS-слоту. С флагом ON.
func TestE2E_OriginWriteDeath_SignalsClient_Bug10(t *testing.T) {
	// Включить флаг через конфиг (YAML-поле): on := true; ha.h.config.OriginDeathTeardown = &on
	// ИЛИ ha.h.relayRegistry.setOriginDeathTeardown(true) после сборки handler'а.
	// 1. Поднять migration-сессию + relayEntry (см. существующие e2e helpers).
	// 2. entry.tc = половина net.Pipe; закрыть peer-конец.
	// 3. Прогнать uplink FlagData через path B (reader-loop) ИЛИ вызвать
	//    signalStreamEnd(entry, true, "B") как делает path B при werr.
	// 4. Расшифровать то, что ушло на binding.writer → ожидать FlagStreamClose
	//    для globalStreamID.
	// 5. Проверить: entry removed, state==stClosing, tc closed.
}

// Флаг OFF — сигнал НЕ шлётся (но teardown идёт, чтобы не висел egress).
func TestE2E_OriginWriteDeath_FlagOff_NoSignal(t *testing.T) {
	// Флаг НЕ включаем (default-off): ha.h.relayRegistry.originDeathTeardown == false.
	// Тот же сетап; ожидать: НИ одного FlagStreamClose на writer; state==stClosing
	// (teardown active-ветки всё равно сносит entry — egress не висит).
}
```

> Сверить с существующими e2e-helper'ами в `migrate_e2e_test.go` (они уже строят полный handler+session+relay). Переиспользовать их сетап.

- [ ] **Step 2: Запустить — падает (до интеграции) / зелёный (после Tasks 5-8)**

Run: `cd shadowlink && go test ./server/ -run TestE2E_OriginWriteDeath -v`
Expected: PASS после Tasks 5-8.

- [ ] **Step 3: Полный прогон + race**

Run:
```bash
cd shadowlink && go test ./... && go vet ./...
```
На Linux/CI (или Windows+gcc):
```bash
cd shadowlink && go test -race -count=3 ./server/ ./client/ ./core/
```
Expected: всё PASS, 0 гонок. **Если race найдёт гонку на `onWriteErr` (Task 7) — починить (mu или atomic) и перезапустить.**

- [ ] **Step 4: Коммит**

```bash
git add shadowlink/server/migrate_e2e_test.go
git commit -m "test(shadowlink): e2e origin write-death reproduces+fixes Bug #10"
```

---

## Self-Review (выполнено при написании плана)

**Spec coverage:**
- Компонент 1 (destClosed на все origin-смерти): Task 5 (read-EOF active) + Task 6 (path B) + Task 7 (path A). ✔
- Компонент 2 (FlagStreamClose=0x0E): Task 1. ✔
- Компонент 3 (signalStreamEnd single-winner + b1): Task 4 (b1) + Task 5 (хелпер). ✔
- Компонент 4 (RESUME-fallback destClosed): Task 7 (3a). ✔
- Компонент 5 (клиент top-level demux): Task 8. ✔
- YAML-флаг `origin_death_teardown` default-off: Task 2 (поле+хелпер+registry-сеттер), gate в Task 5/7 (`r.originDeathTeardown` / param). ✔
- NIT-1 (вынос bound.Store): Task 3. NIT-2 (только bound.Store переезжает): Task 4. NIT-3 (orphaned=destClosed без CAS): Task 5. NIT-4 (race-тест окна): Task 4 Step 1. ✔
- Тесты: core round-trip (T1), signalStreamEnd single-winner (T5), b1-окно (T4), регресс Bug#9 (T3/T4 Step 4), e2e (T9), client (T8). ✔

**Placeholder scan:** код во всех code-степах конкретный; test-helper имена помечены «сверить с существующими» (намеренно — переиспользовать инфраструктуру migrate-тестов, а не плодить). ✔

**Type consistency:** `signalStreamEnd(e *relayEntry, migrateEnabled bool, pathTag string)` — единая сигнатура в T5/T6/T7 (читает `r.originDeathTeardown` поле). `reassociate(b *binding, migrateEnabled, aDead, originDeathTeardown bool)` — единая в T3/T4/T7 (4 параметра, последний — gate для RESUME-fallback). `NewStreamCloseChunk(sessID, seq uint32, streamID uint16)` / `ParseStreamCloseFrame([]byte)(uint16,error)` — единые T1/T5/T7/T8. `Config.OriginDeathTeardown *bool` + `originDeathTeardownEnabledOrDefault()` + `relayRegistry.setOriginDeathTeardown(bool)` — единые T2, читаются T5/T7. ✔

## Execution Handoff

После APPROVED — **subagent-driven** (per-task subagent + two-stage review, как Bug#8/#9). Staged deploy pl1 (сервер первым) делает юзер сам ([pl1 manual deploy]). Коммит Bug#10 — вместе с готовым 60s half-close + emergency-evict (пачкой, по плану юзера).
