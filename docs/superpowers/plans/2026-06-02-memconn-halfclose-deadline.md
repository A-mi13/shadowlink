# memConn half-close read-deadline ignore — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Не давать чужому 60-секундному half-close таймауту tun2socks рвать живой long-poll/SSE downlink — memConn полностью игнорирует read-deadline на downlink-стороне после того, как его uplink был полу-закрыт (`CloseWrite`).

**Architecture:** На app-end memConn вводится sticky-флаг `downlinkDeadlineImmune`. Он взводится в `CloseWrite()` (момент half-close от tun2socks). Пока он взведён и full close не наступил, downlink read-deadline трактуется как не-наступающий: `CloseWrite()` снимает уже взведённый дедлайн, а последующий `SetReadDeadline()` на app-end становится no-op (закрывает гонку порядка `CloseWrite()`→`SetReadDeadline()` внутри tun2socks `unidirectionalStream`, tcp.go:68→72). Full close (`Close()`) и закрытие WS-стрима рвут стрим по-прежнему — на них immune не влияет.

**Tech Stack:** Go, stdlib `net`/`sync`/`time`. Файлы: `shadowlink/proxy/socks5/memconn.go`, `shadowlink/proxy/socks5/memconn_halfclose_test.go`. Рабочая директория для всех команд: `D:\NIXAVPN\shadowlink`. ЗАПРЕТ на git-операции (правило юзера) — шаги «Commit» НЕ выполнять; вместо коммита просто переходить к следующей задаче. Юзер коммитит сам пачкой в конце.

**Ключевые факты о memConn (из memconn.go, чтобы не перечитывать):**
- `newMemPipe()` (memconn.go:194-202): `a` = app-end (`isAppEnd=true`, `wr=d1` uplink, `rd=d2` downlink), `b` = relay-end (`isAppEnd=false`, `wr=d2`, `rd=d1`). `d1`: app пишет → relay читает. `d2`: relay пишет → app читает.
- `memConn.CloseWrite()` (memconn.go:229-232): `c.wr.close()`. На app-end закрывает `d1` (uplink).
- `memConn.SetReadDeadline(t)` (memconn.go:265): `c.rd.setReadDeadline(t)`. На app-end ставит дедлайн на `d2` (downlink).
- `memConn.Close()` (memconn.go:216-225): `wr.close()` + `rd.close()` + (app-end) `close(peerFullClose)`. Это full close.
- `memBuffer.read` (memconn.go:91-110): таймаутит по `b.timedOut(b.rdeadline)`.
- `memBuffer.setReadDeadline` (memconn.go:132-138): пишет `b.rdeadline = t` под `b.mu`.
- `memConn.writeClosed()` (memconn.go:255): `c.wr.isClosed()`.

**tun2socks порядок (vendored tcp.go:64-72) — почему нужны ОБА шага фикса:**
```
68: dst.CloseWrite()                      // appConn.CloseWrite() → наш immune-флаг + снять дедлайн
72: dst.SetReadDeadline(now + 60s)        // ВЫПОЛНЯЕТСЯ СРАЗУ ПОСЛЕ → должен стать no-op
```
Строки 68 и 72 последовательны в одной горутине. Снять дедлайн только в `CloseWrite()` недостаточно — строка 72 поставит его обратно. Поэтому `SetReadDeadline` на app-end в immune-состоянии ОБЯЗАН быть no-op.

---

## File Structure

- **Modify** `shadowlink/proxy/socks5/memconn.go`: добавить sticky immune-флаг на app-end, правки `CloseWrite()` и `SetReadDeadline()`. Один сосредоточенный файл, ответственность не меняется.
- **Modify** `shadowlink/proxy/socks5/memconn_halfclose_test.go`: 6 новых тестов (см. ниже). Существующие тесты в файле не трогать — они должны остаться зелёными.

---

## Task 1: Тест на корневой симптом (Red) — half-close нейтрализует уже взведённый дедлайн

**Files:**
- Test: `shadowlink/proxy/socks5/memconn_halfclose_test.go`

- [ ] **Step 1: Прочитать существующий тест-файл целиком**

Run: открыть `proxy/socks5/memconn_halfclose_test.go` через Read. Понять стиль (как создаётся пара, имена хелперов), чтобы новые тесты были консистентны. НЕ менять существующие тесты.

- [ ] **Step 2: Написать падающий тест**

Добавить в `memconn_halfclose_test.go`:

```go
// Bug 2026-06-02: после half-close (CloseWrite от tun2socks) read-deadline на
// downlink-стороне app-end ДОЛЖЕН игнорироваться — long-poll downlink молчит
// легитимно, пока модель «думает». Иначе tun2socks 60s tcpWaitTimeout рвёт стрим.
func TestMemConn_HalfClose_IgnoresPriorReadDeadline(t *testing.T) {
	app, _ := newMemPipe() // app-end отдаётся tun2socks; relay-end не нужен здесь

	// Эмулируем tun2socks unidirectionalStream после upload-EOF:
	//   68: appConn.CloseWrite()   (uplink полу-закрыт)
	// Дедлайн взведён ДО CloseWrite (порядок взведения здесь не важен — проверяем,
	// что CloseWrite его нейтрализует).
	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_ = app.CloseWrite()

	// downlink молчит дольше дедлайна.
	done := make(chan error, 1)
	go func() {
		b := make([]byte, 16)
		_, err := app.Read(b) // должен БЛОКИРОВАТЬСЯ, не таймаутить
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Read вернулся раньше времени (immune не сработал): err=%v", err)
	case <-time.After(200 * time.Millisecond):
		// Ожидаемо: Read всё ещё блокируется через 200ms (дедлайн был 50ms).
	}
}
```

- [ ] **Step 3: Запустить тест — убедиться, что падает**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/socks5/ -run TestMemConn_HalfClose_IgnoresPriorReadDeadline -v`
Expected: FAIL — `Read вернулся раньше времени (immune не сработал): err=i/o timeout` (текущий код таймаутит на 50ms-дедлайне).

- [ ] **Step 4: Commit** — ПРОПУСТИТЬ (запрет на git). Перейти к Task 2.

---

## Task 2: Реализация immune-флага + правки CloseWrite/SetReadDeadline (Green)

**Files:**
- Modify: `shadowlink/proxy/socks5/memconn.go`

- [ ] **Step 1: Добавить sticky immune-поле на memConn**

В объявление структуры `memConn` (memconn.go:181-189) добавить поле и atomic-импорт. Открыть файл, в блок `import` (memconn.go:3-8) добавить `"sync/atomic"`. В структуру `memConn` добавить поле после `fullCloseOnce`:

```go
	// downlinkDeadlineImmune is set on the APP end when tun2socks half-closes the
	// uplink (CloseWrite). While set (and full Close has not happened), the app's
	// downlink Read ignores any read-deadline: a long-poll / SSE response that goes
	// quiet for >tun2socks tcpWaitTimeout (60s) is legitimate and must NOT be torn
	// down. tun2socks calls CloseWrite() THEN SetReadDeadline(now+60s) in sequence
	// (vendored tunnel/tcp.go:68→72), so both CloseWrite (clears the live deadline)
	// and SetReadDeadline (becomes a no-op) must honor this flag. Full Close still
	// tears down via rd.close()/peerFullClose — immune does not affect that.
	downlinkDeadlineImmune atomic.Bool
```

- [ ] **Step 2: Править CloseWrite — взвести immune и снять активный downlink-дедлайн (app-end)**

Заменить `memConn.CloseWrite()` (memconn.go:229-232):

```go
// CloseWrite half-closes the write direction: the peer's Read drains buffered
// data then returns io.EOF. Our Read side stays open. [tun2socks half-close]
//
// On the APP end this is the tun2socks half-close signal (uplink done). We mark
// the downlink deadline-immune and clear any already-armed read-deadline so a
// quiet long-poll downlink is not torn down by the 60s tcpWaitTimeout that
// tun2socks arms on the very next line (vendored tunnel/tcp.go:72).
func (c *memConn) CloseWrite() error {
	c.wr.close()
	if c.isAppEnd {
		c.downlinkDeadlineImmune.Store(true)
		c.rd.setReadDeadline(time.Time{}) // clear any deadline armed before CloseWrite
	}
	return nil
}
```

- [ ] **Step 3: Править SetReadDeadline — no-op на app-end в immune-состоянии**

Заменить `memConn.SetReadDeadline()` (memconn.go:265):

```go
func (c *memConn) SetReadDeadline(t time.Time) error {
	// After a half-close on the app end, ignore read-deadlines on the downlink:
	// tun2socks arms a 60s deadline right after CloseWrite, which would otherwise
	// kill a legitimately-quiet long-poll/SSE response.
	if c.isAppEnd && c.downlinkDeadlineImmune.Load() {
		return nil
	}
	c.rd.setReadDeadline(t)
	return nil
}
```

- [ ] **Step 4: Проверить SetDeadline (combined) — он тоже не должен армить downlink-дедлайн в immune**

`memConn.SetDeadline()` (memconn.go:260-264) вызывает `c.rd.setReadDeadline(t)` напрямую, минуя наш guard. tun2socks использует `SetReadDeadline`, не `SetDeadline`, на half-close пути — но для корректности заменить `SetDeadline`, чтобы read-часть шла через тот же guard:

```go
func (c *memConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)            // honors immune guard
	c.wr.setWriteDeadline(t)
	return nil
}
```

- [ ] **Step 5: Запустить тест Task 1 — убедиться, что проходит**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/socks5/ -run TestMemConn_HalfClose_IgnoresPriorReadDeadline -v`
Expected: PASS (Read блокируется 200ms, тест завершается по таймеру ожидания).

- [ ] **Step 6: Commit** — ПРОПУСТИТЬ (запрет на git). Перейти к Task 3.

---

## Task 3: Тест на гонку порядка — SetReadDeadline ПОСЛЕ CloseWrite тоже no-op

**Files:**
- Test: `shadowlink/proxy/socks5/memconn_halfclose_test.go`

- [ ] **Step 1: Написать тест, воспроизводящий точный порядок tun2socks (68→72)**

```go
// Точный порядок tun2socks unidirectionalStream: CloseWrite() (tcp.go:68) ТОГДА
// SetReadDeadline(now+60s) (tcp.go:72). Дедлайн, поставленный ПОСЛЕ CloseWrite,
// должен быть проигнорирован (иначе строка 72 возвращает 60s-таймер обратно).
func TestMemConn_HalfClose_IgnoresLaterReadDeadline(t *testing.T) {
	app, _ := newMemPipe()

	_ = app.CloseWrite()                                    // tcp.go:68
	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) // tcp.go:72 — должен быть no-op

	done := make(chan error, 1)
	go func() {
		b := make([]byte, 16)
		_, err := app.Read(b)
		done <- err
	}()

	select {
	case err := <-done:
		t.Fatalf("Read вернулся раньше времени (later-deadline no-op не сработал): err=%v", err)
	case <-time.After(200 * time.Millisecond):
		// Ожидаемо: дедлайн проигнорирован, Read блокируется.
	}
}
```

- [ ] **Step 2: Запустить — убедиться, что проходит (фикс из Task 2 уже покрывает)**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/socks5/ -run TestMemConn_HalfClose_IgnoresLaterReadDeadline -v`
Expected: PASS.

- [ ] **Step 3: Commit** — ПРОПУСТИТЬ. Перейти к Task 4.

---

## Task 4: Регресс-тест — full Close ПОСЛЕ half-close всё ещё рвёт downlink

**Files:**
- Test: `shadowlink/proxy/socks5/memconn_halfclose_test.go`

- [ ] **Step 1: Написать тест**

```go
// immune НЕ должен мешать настоящему full close: после CloseWrite()+Close()
// app.Read обязан немедленно вернуть EOF (real FIN от приложения).
func TestMemConn_HalfClose_FullCloseStillTearsDown(t *testing.T) {
	app, _ := newMemPipe()

	_ = app.CloseWrite()
	_ = app.SetReadDeadline(time.Now().Add(time.Hour)) // no-op в immune
	_ = app.Close()                                     // full close → rd.close()

	done := make(chan error, 1)
	go func() {
		b := make([]byte, 16)
		_, err := app.Read(b)
		done <- err
	}()

	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("ожидался io.EOF после full Close, получено: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read завис после full Close — immune ошибочно блокирует teardown")
	}
}
```

- [ ] **Step 2: Запустить**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/socks5/ -run TestMemConn_HalfClose_FullCloseStillTearsDown -v`
Expected: PASS (full close рвёт через `c.rd.close()`, минуя deadline-логику).

- [ ] **Step 3: Commit** — ПРОПУСТИТЬ. Перейти к Task 5.

---

## Task 5: Регресс-тест — без half-close read-deadline работает как раньше

**Files:**
- Test: `shadowlink/proxy/socks5/memconn_halfclose_test.go`

- [ ] **Step 1: Написать тест**

```go
// Без CloseWrite (соединение не полу-закрыто) read-deadline должен работать
// штатно — мы не сломали обычный таймаут для не-half-closed соединений.
func TestMemConn_NoHalfClose_ReadDeadlineStillFires(t *testing.T) {
	app, _ := newMemPipe()

	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	b := make([]byte, 16)
	start := time.Now()
	_, err := app.Read(b)
	elapsed := time.Since(start)

	netErr, ok := err.(interface{ Timeout() bool })
	if !ok || !netErr.Timeout() {
		t.Fatalf("ожидался timeout error, получено: %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("дедлайн не сработал вовремя: elapsed=%v", elapsed)
	}
}
```

- [ ] **Step 2: Запустить**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/socks5/ -run TestMemConn_NoHalfClose_ReadDeadlineStillFires -v`
Expected: PASS (timeout срабатывает ~50ms).

- [ ] **Step 3: Commit** — ПРОПУСТИТЬ. Перейти к Task 6.

---

## Task 6: Регресс-тест — relay-end не затронут + downlink-данные доставляются после half-close

**Files:**
- Test: `shadowlink/proxy/socks5/memconn_halfclose_test.go`

- [ ] **Step 1: Написать тест relay-end (дедлайн работает на не-app-end)**

```go
// relay-end (isAppEnd==false) НЕ участвует в immune-логике: его read-deadline
// работает штатно. tun2socks армит дедлайны только на app-end, но фиксируем
// контракт явно.
func TestMemConn_RelayEnd_ReadDeadlineUnaffected(t *testing.T) {
	app, relay := newMemPipe()
	_ = app.CloseWrite() // immune на app-end; relay-end не должен затрагиваться

	_ = relay.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	b := make([]byte, 16)
	_, err := relay.Read(b)

	netErr, ok := err.(interface{ Timeout() bool })
	if !ok || !netErr.Timeout() {
		t.Fatalf("relay-end read-deadline должен срабатывать, получено: %v", err)
	}
}
```

- [ ] **Step 2: Написать тест доставки данных после half-close**

```go
// immune блокирует только TIMEOUT, не доставку: после CloseWrite relay пишет
// downlink-данные, app.Read обязан их получить (long-poll ответ доходит).
func TestMemConn_HalfClose_DownlinkDataStillDelivered(t *testing.T) {
	app, relay := newMemPipe()
	_ = app.CloseWrite()
	_ = app.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) // no-op

	want := []byte("hello-from-server")
	go func() {
		time.Sleep(150 * time.Millisecond) // дольше «дедлайна» — данные приходят после
		_, _ = relay.Write(want)
	}()

	b := make([]byte, len(want))
	got, err := app.Read(b)
	if err != nil {
		t.Fatalf("Read вернул ошибку вместо данных: %v", err)
	}
	if string(b[:got]) != string(want) {
		t.Fatalf("downlink данные искажены: got=%q want=%q", b[:got], want)
	}
}
```

- [ ] **Step 3: Запустить оба теста**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/socks5/ -run 'TestMemConn_RelayEnd_ReadDeadlineUnaffected|TestMemConn_HalfClose_DownlinkDataStillDelivered' -v`
Expected: PASS оба.

- [ ] **Step 4: Commit** — ПРОПУСТИТЬ. Перейти к Task 7.

---

## Task 7: Полная верификация пакета + build/vet

**Files:** нет (проверка)

- [ ] **Step 1: Весь пакет socks5 (новые + существующие half-close тесты зелёные)**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/socks5/ -v`
Expected: PASS, в т.ч. ранее существовавшие `memconn_test.go` / `memconn_halfclose_test.go` тесты (immune не должен их сломать — у них нет CloseWrite на app-end перед deadline, либо они на relay-end).

- [ ] **Step 2: Build всего модуля**

Run: `cd /d/NIXAVPN/shadowlink && go build ./...`
Expected: без ошибок (новый импорт `sync/atomic` подхвачен).

- [ ] **Step 3: Vet**

Run: `cd /d/NIXAVPN/shadowlink && go vet ./proxy/socks5/`
Expected: чисто.

- [ ] **Step 4: Весь client/socks5 smoke (не сломали смежное)**

Run: `cd /d/NIXAVPN/shadowlink && go test ./proxy/... ./client/ 2>&1 | tail -30`
Expected: PASS (или только преэкзистентные Windows-без-gcc пропуски race-тестов — НЕ новые падения).

- [ ] **Step 5: Commit** — ПРОПУСТИТЬ. Сообщить юзеру итог.

---

## Остаётся юзеру (вне плана — выполняет сам)

1. **race-тест на Linux/CI:** `go test -race -count=3 ./proxy/socks5/` (atomic.Bool под конкурентным CloseWrite/SetReadDeadline/Read — Windows-dev без gcc race не гоняет).
2. **Пересборка клиентского бинаря** (тот, что в `bin/connect-vpn-DEBUG.bat` → `nixavpn-client-graceful-drain.exe`).
3. **Коммит пачкой** (по правилу — git делает юзер).
4. **Полевой ретест:** Claude Code через ShadowLink — длинный ответ модели (>60 с «раздумий» / большой агентский стрим) НЕ обрывается; обычные сайты + закачка >2MiB не регрессировали.
5. Сервер pl1 **НЕ трогаем** — фикс чисто клиентский, протокол не меняется.

## Self-Review (выполнено при написании)

- **Spec coverage:** оба шага фикса (CloseWrite clear + SetReadDeadline no-op) из спеки → Task 2 steps 2-3. Гонка порядка 68→72 → Task 3. Безопасность full-close → Task 4. Все 6 тестов спеки → Tasks 1,3,4,5,6. ✅
- **Placeholder scan:** нет TBD/«handle edge cases» — весь код приведён. ✅
- **Type consistency:** `downlinkDeadlineImmune atomic.Bool`, `.Store(true)`/`.Load()`, `c.isAppEnd`, `c.rd.setReadDeadline(time.Time{})`, `newMemPipe()` возвращает `(app, relay)` — имена сверены с memconn.go. ✅
- **Git:** все шаги «Commit» помечены ПРОПУСТИТЬ (правило юзера). ✅
