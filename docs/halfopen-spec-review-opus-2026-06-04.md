# Pre-implementation opus review — Half-open drain stream leak fix

**Spec:** `docs/superpowers/specs/2026-06-04-halfopen-drain-stream-leak-design.md`
**Date:** 2026-06-04
**Reviewer:** opus (senior Go), построчная сверка с кодом
**Verdict:** **NEEDS-REVISION**

Счётчики: **2 BLOCKER · 3 HIGH · 4 MEDIUM · 5 NIT**

---

## Сводка вердикта

Диагноз бага корректен и подтверждён кодом с обеих сторон: (A) age-drain natural-finish шлёт RESUME *после* `transport.Close()`, который сервер видит как `not_found`/`grace_expired`; (B) uplink-goroutine блокируется в `conn.Read(buf)` (tcp.go:859) и `cancel()` её не будит — реальная дыра, подтверждена в обоих путях (migration и legacy) и в memConn (нет закрытия `conn` при выходе downlink).

Компонент (B) — почти готов: memConn умеет всё нужное (SetReadDeadline/CloseRead/Close), точка вставки определена верно. Но есть конкретные ошибки в спеке (BLOCKER-2, HIGH-1, HIGH-2).

Компонент (A) — концептуально верен, НО спека **упускает уже существующую превентивную миграцию** (`scheduleSlotMigration` на ~60s, ws_pool.go:1813), которая по таймингу срабатывает ЗА ~60s ДО age-drain (~120s). Это меняет всю постановку (A): предлагаемая в спеке вставка в `startDrain` — частично дублирующая, и реальный корень FAIL'ов другой, чем описано (BLOCKER-1). Без переосмысления (A) рискует не дать ожидаемого эффекта и добавить лишнюю миграцию-нагрузку.

---

## BLOCKER

### BLOCKER-1 — (A) игнорирует уже существующую превентивную миграцию scheduleSlotMigration; постановка корня (A) неполна
Спека §15/§24 утверждает: «Превентивная миграция (`migrateVictimStreams`) есть ТОЛЬКО в emergency-evict пути; в обычном `startDrain(reason=age)` её нет». Это **неверно по факту кода**.

Трассировка `ws_pool.go:1799-1831` (watchdog sweep, тот же цикл что зовёт `startDrain(...,"age")`):
```
1809  if migThresh := slot.migrationThresholdNs.Load(); migThresh > 0 &&
1810      nowNs-started >= migThresh &&
1811      p.MigrateCapable() &&
1812      slot.streams.Load() > 0 {
1813      p.scheduleSlotMigration(idx, slot)   // <-- превентивная миграция УЖЕ ЕСТЬ
1814  }
      ...
1818  if nowNs-started < effectiveMaxAge { continue }
1821  if p.gracefulDrain { p.startDrain(p.client, idx, "age") }
```
Дефолты (подтверждены): `migrationThresholdDefault=60s` (migrate_watchdog.go:37, jitter U(0.7,1.0) → ~42-60s), `maxSlotAge=2min` (engine_shadowlink.go:386, + per-slot stagger 15s×idx). То есть **каждый активный стрим уже планируется к MIGRATE на ~60s — за ~60-90s ДО того как слот дойдёт до age-drain**. `scheduleSlotMigration` → per-stream AfterFunc → `migrateStream` (preemptive MIGRATE по живому слоту, ровно тот примитив что спека хочет «добавить»).

Из этого следуют два вывода, которые спека не учитывает:
1. **Стримы, которые спека хочет «превентивно мигрировать в startDrain», в норме УЖЕ мигрированы** (или мигрируют) к моменту age-drain. Значит реальные жертвы FAIL'ов (`not_found=207`, `grace_expired=123`) — это стримы, для которых preemptive MIGRATE на 60s **провалился или не отработал**: `migrateStream` упал (`res.kind != OK` → стрим остался на aging-слоте, migrate_watchdog.go:265-267), либо стрим аппнулся ПОСЛЕ scheduling-CAS (migrationScheduled уже true, новый стрим не планируется — см. MEDIUM-2), либо `MigrateCapable()` просел по гистерезису. Спека должна объяснить ПОЧЕМУ 60s-миграция не спасла эти стримы — иначе вставка такого же `migrateStream` в `startDrain` (на 120s) спасёт ровно столько же (т.е. ничего нового), кроме тех, что аппнулись в окне 60→120s.
2. **Эффект (A) переоценён**: спека ожидает «`not_found`/`grace_expired` РЕЗКО падают». Но если 60s-миграция уже покрывает большинство, прирост от дубля в startDrain — только стримы возрастом 60-120s, появившиеся после scheduling-CAS. Это надо измерить/обосновать ДО реализации, иначе (A) — лишний код с нагрузкой на сервер при каждом age-drain без пропорционального выигрыша.

**Требование:** переписать корень (A) с учётом scheduleSlotMigration. Либо (предпочтительно) **закрыть дыру в существующем пути** (re-arm scheduling для поздно-появившихся стримов / повтор миграции для упавших — MEDIUM-2), либо чётко обосновать, что вставка в startDrain покрывает измеримый непокрытый класс. Текущая постановка «миграции в drain вообще нет» — фактически ложная и ведёт проект не туда.

### BLOCKER-2 — (B) точка вставки описана неверно: cancel() уже есть, проблема в conn, а спека предлагает «добавить пробуждение в downlink-ветке»
Спека §29/§65: «при выходе downlink-goroutine `defer cancel()` (tcp.go:935) отменяет ctx2 … разбудить uplink в migration downlink-ветке (~:1041-1043) и в legacy (~:1050)».

Трассировка показывает, что `cancel()` вызывается из **downlink-goroutine** через `defer cancel()` (tcp.go:935), а uplink сидит в `conn.Read` (tcp.go:859). Пробуждать надо `conn`, не ctx. Но спека предлагает вставить пробуждение «в downlink-ветке … перед/вместе с `downlink done` логом (~:1041)». Это **только migration-путь, и только успешный `return` из downlinkReassemblyLoop**. Однако downlink-goroutine может выйти многими путями, и часть из них — НЕ в указанных строках:
- migration: `downlinkReassemblyLoop` возвращается (tcp.go:1040) — ✅ покрыто if поставить ПОСЛЕ него;
- legacy: `return` из `<-incomingCh ok==false` (tcp.go:1052), `CONNECT_FAIL` (:1073), `<-peerFullClose` (:1125), `<-ctx2.Done()` (:1129), write-error drain `return` (:1108). Это **5 разных return-точек** в legacy, не одна на :1050.

Правильная архитектура — **не точечная вставка перед каждым логом**, а централизованное пробуждение через `defer` в самой downlink-goroutine (рядом с `defer cancel()` на tcp.go:935), покрывающее ВСЕ пути выхода обоих веток одним местом:
```go
go func() {
    defer wg.Done()
    defer cancel()
    defer wakeUplink(conn, socks5Replies)   // <-- одно место, все выходы
    ...
}()
```
Спека в текущем виде (вставка «в migration-ветке … и в legacy симметрично») оставит непокрытыми минимум gap-timeout (:577 внутри loop → migration `return` :1043 покрыт, ОК) и часть legacy return'ов, если автор поймёт «~:1050» буквально. Требование: переформулировать (B) как `defer`-пробуждение в downlink-goroutine, а не как N точечных вставок.

---

## HIGH

### HIGH-1 — (B) выбор примитива: SetReadDeadline(now) НЕ разбудит uplink на app-half-closed memConn из-за downlinkDeadlineImmune
Спека §61 предлагает (B1) `conn.SetReadDeadline(time.Now())` как вариант. Но `conn` здесь — это relay-end `ourConn` (`isAppEnd=false`), а uplink читает `ourConn.Read` = `c.rd.read` (d1). `SetReadDeadline` на relay-end идёт в `c.rd.setReadDeadline` — НЕ под immune-гард (immune только для `isAppEnd`, memconn.go:289). Значит на relay-end SetReadDeadline сработает… НО: семантически uplink Read d1 — это чтение того, что пишет приложение (`appConn.Write`→d1). Если приложение в keep-alive half-close уже сделало `appConn.CloseWrite()` → d1.closed=true → uplink Read уже вернул EOF и goroutine ушла (tcp.go:882-888 half-close path). То есть в half-close сценарии uplink УЖЕ не висит. Висит он когда приложение НЕ закрыло uplink (full keep-alive, обе стороны открыты) и downlink умер от (A). Тогда `SetReadDeadline(now)` на `ourConn.rd` сработает (immune не на relay-end) — uplink выйдет по timeoutError.

**Но** `CloseRead()`/`Close()` чище и не оставляет «мёртвый» deadline на recycled conn. Спека должна **выбрать (B2) `ourConn.CloseRead()`** (закрывает d1 → uplink Read EOF, идемпотентно, без deadline-мусора), а не оставлять выбор «решить в плане». Для loopback (real socket, socks5Replies=true) `CloseRead()` тоже валиден (TCPConn.CloseRead). Требование: зафиксировать примитив = CloseRead (с фолбэком на Close если conn не реализует CloseRead интерфейс), убрать SetReadDeadline-вариант как уступающий.

### HIGH-2 — (B) на loopback-пути conn может НЕ иметь CloseRead, нужен гард по интерфейсу
Спека §69 говорит «проверить что способ работает или гейтить на in-process путь». Это надо не «проверить», а спроектировать: на loopback `conn` — `net.Conn` от `net.Listener.Accept()`, конкретный тип `*net.TCPConn` (есть `CloseRead`), НО формально тип не гарантирован (может быть обёрнут). memConn реализует `CloseRead`/`Close`. Правильно:
```go
func wakeUplink(conn net.Conn, socks5Replies bool) {
    if cr, ok := conn.(interface{ CloseRead() error }); ok {
        cr.CloseRead()
        return
    }
    conn.Close() // фолбэк — грубее, но downlink уже мёртв
}
```
Без гарда падение на типе, не реализующем CloseRead, либо тихий no-op. Спека должна это зафиксировать как обязательный интерфейс-гард, а не «проверить».

### HIGH-3 — (A) target = selectYoungTargetSlot может вернуть newIdx (replacement-слот), который ещё поднимается → миграция на не-ready слот
Спека §48 утверждает: target = `selectYoungTargetSlot`, «НЕ newIdx т.к. он ещё поднимается». Но `selectYoungTargetSlot` (migrate_watchdog.go:129-153) фильтрует по `slot.getState() != slotReady` → пропускает не-ready. `newIdx` в момент вставки (после Gate 7) — это claimed-cell, который `connectReserveSlot` поднимает асинхронно (ws_pool_drain.go:594 `go p.connectReserveSlot`). Его состояние в этот момент — НЕ slotReady (он ещё placeholder/connecting). Значит `selectYoungTargetSlot` его и так НЕ выберет — утверждение спеки про «НЕ newIdx» избыточно, но не вредно. РЕАЛЬНАЯ проблема: **selectYoungTargetSlot выбирает youngest READY слот по startedAtNs DESC** (migrate_watchdog.go:144 `started > bestStart`). При age-drain слот стареет последним; youngest ready слот — это, как правило, недавно реконнекченный сосед. Но если ВСЕ соседи тоже near-age (cascade age-cut, типичная ситуация в РФ — memory: «cascade of mature-slot cuts»), youngest ready может сам быть на грани age-drain → стрим мигрирует на слот, который через секунды сам пойдёт в drain → повторная миграция/FAIL. Спека не рассматривает cascade-случай для (A)-таргета. Требование: явно описать поведение при отсутствии «молодого» таргета (нет — fallback на natural-finish, OK; есть, но сам near-age — принять как деградацию, задокументировать).

---

## MEDIUM

### MEDIUM-1 — (A) гонка migrateVictimStreams (в startDrain) vs scheduleSlotMigration AfterFunc vs drainWatchdog
Если (A) реализуется как вызов `migrateVictimStreams(target)` в startDrain, он будет конкурировать с уже-запланированными (на 60s) AfterFunc-таймерами `migrateStream` для тех же стримов. Защита есть: `e.migrating.CompareAndSwap(false,true)` single-winner (migrate_watchdog.go:243) + `migrateVictimStreams` считает по departure-факту, не по migrateStream-исходу (ws_pool_drain.go:380-385). Это корректно обработает гонку. НО спека должна это явно зафиксировать как инвариант теста (одновременный preemptive-timer + drain-migrate одного streamID → ровно один MIGRATE, счётчик не двоится). Сейчас спека §50 упоминает single-winner вскользь.

### MEDIUM-2 — (A) непокрытый класс: стримы, аппнувшиеся ПОСЛЕ scheduleSlotMigration CAS, никогда не планируются превентивно
`scheduleSlotMigration` CAS'ит `migrationScheduled false→true` один раз за жизнь слота (migrate_watchdog.go:176). Range берёт snapshot стримов В МОМЕНТ вызова (на ~60s). Стрим, появившийся на слоте ПОСЛЕ 60s (новый CONNECT на тот же aging-слот), в этот snapshot не попадёт и НИКОГДА не получит preemptive AfterFunc (флаг уже true). Вот реальный непокрытый класс жертв age-drain FAIL. Вставка `migrateVictimStreams` в startDrain (на 120s) ИМЕННО его и покрывает — **это и есть настоящая ценность (A)**, но спека её не идентифицирует (см. BLOCKER-1). Требование: либо так и сформулировать ценность (A), либо альтернатива — re-arm scheduling в существующем пути.

### MEDIUM-3 — (B) взаимодействие с peerFullClose: после CloseRead на ourConn нужно ли что-то app-end?
После `ourConn.CloseRead()` (закрыли d1) приложение, продолжающее `appConn.Write` (→d1), получит `io.ErrClosedPipe` (memconn.go:74-76). Это корректный сигнал «соединение умерло» для tun2socks → он сделает `appConn.Close()`. Но `appConn.Close()` фактически уже не нужен downlink'у (мёртв). Проверить: не зависнет ли tun2socks на стороне приложения, если оно ждёт downlink-ответа, а uplink-write начал ошибаться? Ожидаемо tun2socks закроет flow и приложение получит RST/EOF → retry. Спека §76 это и обещает («приложение получает обрыв → retry»). Нужен e2e-тест именно этого: full-keepalive стрим, downlink убит, app видит обрыв обеих сторон, не виснет.

### MEDIUM-4 — связь (A)+(B): сценарий где оба не срабатывают (вопрос 3 из задания)
(B) — страховка при ЛЮБОМ закрытии downlink. Дыра: downlink-goroutine выходит ТОЛЬКО через свои select-ветки/return. Если downlink-goroutine сама зависнет (например, `conn.Write(d)` в downlinkReassemblyLoop:547 заблокируется навсегда — d2 buffer full, app не читает), то downlink не выйдет → defer-wake (B) не выполнится → uplink висит. На memConn `conn.Write`→d2.write блокируется при полном буфере, пока app не прочитает или d2 не закроется. Если app завис (ждёт, не читает) и downlink пытается писать — оба висят. Это узкий, но реальный сценарий взаимной блокировки, который ни (A) ни (B) не закрывают. Митигатор: gap-timeout (:572) и reassembly overflow (:541) дают downlink-goroutine пути выхода даже без прогресса записи — НО только если есть необработанные frame'ы; на полностью тихом канале (нет входящих) downlink сидит в select без таймера. Требование: задокументировать этот остаточный сценарий и подтвердить, что keepalive/idle-механизмы его покрывают (либо принять как known-limitation).

---

## NIT

- **NIT-1** §90: новый счётчик `shadowlink_drain_preemptive_migrated_total` дублирует семантику `EmergencyEvictMigratedTotal`/`MigrateScheduled`. Если (A) переиспользует `migrateVictimStreams`, рассмотреть переиспользование счётчика или чёткое разделение трёх (scheduled/emergency/drain-preemptive).
- **NIT-2** §83: тест (B) «по образцу memconn_halfclose_test.go» — хорошо, но добавить кейс full-keepalive (НЕ half-close): обе стороны открыты, downlink закрыт извне, uplink в Read → wake.
- **NIT-3** §46 точка «~:594» — фактически строка `go p.drainWatchdog(...)` на ws_pool_drain.go:595, вставка ПЕРЕД ней (после `committed=true` :579). Уточнить, что слот в этот момент `slotDraining`, а target-резолв через selectYoungTargetSlot его не выберет (он не slotReady) — самотаргет невозможен.
- **NIT-4** §77 про Bug #10: (B) и Bug#10 не конфликтуют — Bug#10 шлёт FlagStreamClose на downlink при смерти origin (server-side), (B) будит uplink на client-side при закрытии downlink. Ортогональны. Но добавить регресс-тест: origin умер → Bug#10 закрыл downlink demux → (B) разбудил uplink → relay чисто завершился (оба механизма в цепочке).
- **NIT-5** §96 «Сервер НЕ меняется» — верно, подтверждено: FAIL на поздний RESUME — корректное серверное поведение. Оставить как есть.

---

## Ответы на вопросы задания

1. **(A) точка вставки / переиспользование / гонка / регресс:** точка (после Gate7, перед drainWatchdog) технически валидна (слот slotDraining, жив); `migrateVictimStreams` переиспользуем; гонка с preemptive-таймерами защищена single-winner CAS. НО постановка корня неверна (BLOCKER-1): превентивная миграция уже есть на 60s. Target через selectYoungTargetSlot корректен (newIdx и так не slotReady), но cascade-случай не покрыт (HIGH-3). Регресс Bug#8/#9: migrateStream — стабилизированный примитив, расширение зоны применения; race на Linux обязателен (спека требует — ОК).
2. **(B) пробуждение:** memConn поддерживает все три (SetReadDeadline/CloseRead/Close). Рабочий и чистый — **CloseRead** (HIGH-1). Keep-alive half-close НЕ ломается (immune-флаг только app-end; relay-end CloseRead закрывает d1, а в half-close uplink уже вышел). Loopback (real socket) — нужен интерфейс-гард (HIGH-2). Точка — `defer` в downlink-goroutine, НЕ точечно (BLOCKER-2).
3. **(A)+(B) достаточность:** (B) страхует (A). Остаточный сценарий взаимной блокировки downlink-write + app-not-reading (MEDIUM-4) — узкий, надо задокументировать/подтвердить покрытие idle-механизмами.
4. **Bug#10:** не конфликтует, дополняет (NIT-4).
5. **Полнота путей закрытия downlink (A):** (A) НЕ покрывает все — стримы без молодого таргета, при migration-off, аппнувшиеся после scheduling-CAS (MEDIUM-2). Для них спасает только (B). Это приемлемо ЕСЛИ (B) реализован централизованно (BLOCKER-2).
6. **Новые гонки/дыры:** MEDIUM-1 (двойная миграция — защищено), MEDIUM-4 (взаимная блокировка — остаточная). Метрики — NIT-1. Тест-покрытие в спеке адекватно по структуре, но не хватает: full-keepalive wake (NIT-2), Bug#10+B цепочка (NIT-4), двойная миграция инвариант (MEDIUM-1).

---

## Что нужно для перехода в APPROVED
1. Переписать корень (A) с учётом существующей `scheduleSlotMigration` (60s); явно идентифицировать непокрытый класс (стримы после scheduling-CAS / упавшие миграции) как реальную ценность (A) — или закрыть дыру в существующем пути вместо дубля в startDrain (BLOCKER-1).
2. Переформулировать (B) как `defer wakeUplink(conn, socks5Replies)` в downlink-goroutine рядом с `defer cancel()`, покрывающий все выходы обоих веток (BLOCKER-2).
3. Зафиксировать примитив (B) = `CloseRead` с интерфейс-гардом и Close-фолбэком (HIGH-1, HIGH-2).
4. Описать cascade-таргет деградацию (A) (HIGH-3) и остаточную взаимную блокировку (MEDIUM-4).
