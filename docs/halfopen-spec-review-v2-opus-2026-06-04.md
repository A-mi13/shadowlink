# Pre-implementation opus review v2 — Half-open drain stream leak fix

**Spec:** `docs/superpowers/specs/2026-06-04-halfopen-drain-stream-leak-design.md` (v2)
**Prior review:** `docs/halfopen-spec-review-opus-2026-06-04.md` (v1 → NEEDS-REVISION, 2 BLOCKER / 3 HIGH)
**Date:** 2026-06-04
**Reviewer:** opus (senior Go), построчная сверка с кодом (НЕ верю спеке)
**Verdict:** **APPROVED-WITH-NITS**

Счётчики: **0 BLOCKER · 0 HIGH · 2 MEDIUM · 5 NIT**

---

## Сводка вердикта

v2 закрывает **все** замечания v1 — корректно и по сути, а не косметически:

- **BLOCKER-1 (закрыт):** v2 переформулировал корень (A). Постановка «миграции в drain нет» (ложная) заменена на точную: `scheduleSlotMigration` существует, но per-slot CAS-гейт `slot.migrationScheduled` делает ОДНОКРАТНЫЙ snapshot стримов на ~60s; стрим, привязавшийся к aging-слоту ПОСЛЕ первого вызова, никогда не получает preemptive AfterFunc. Это **в точности** непокрытый класс, который я идентифицировал в v1 MEDIUM-2. Фикс — re-arm per-stream — лечит именно его, а не дублирует. Подтверждено кодом (migrate_watchdog.go:176, ws_pool.go:1809-1814).
- **BLOCKER-2 (закрыт):** v2 = `defer wakeUplink(conn, socks5Replies)` в downlink-goroutine рядом с `defer cancel()`. Одно место покрывает все 6 return-путей. Точечные вставки отвергнуты.
- **HIGH-1 (закрыт):** примитив зафиксирован = `CloseRead` (не SetReadDeadline). Обоснование корректно.
- **HIGH-2 (закрыт):** интерфейс-гард `interface{ CloseRead() error }` + Close-фолбэк — дословно как требовалось.
- **HIGH-3 (закрыт):** cascade-таргет задокументирован как принятая деградация + re-arm покрывает повторную миграцию.
- **MEDIUM-4 (закрыт):** остаточная взаимоблокировка (downlink в conn.Write d2-full + app не читает) задокументирована как known-limitation с разбором митигаторов.

Диагноз бага подтверждён кодом с трёх сторон (как и в v1). Оба компонента реализуемы по описанию. Остаются 2 MEDIUM (оба — требования к плану/тесту, не пороки дизайна) и 5 NIT. **Ни одного BLOCKER/HIGH — спека готова к переходу в план.**

---

## Построчная верификация закрытия v1-замечаний

### BLOCKER-1 → закрыт. Корень (A) переформулирован верно

Сверка с кодом `scheduleSlotMigration` (migrate_watchdog.go:169-213):
```
176  if !slot.migrationScheduled.CompareAndSwap(false, true) {   // per-slot gate, один раз за жизнь слота
177      return false
178  }
182  p.streamMap.Range(func(...) {                                // snapshot В ЭТОТ МОМЕНТ (~60s)
...      e.slotIdx != agingIdx → skip; иначе AfterFunc(migrateStream)
203  if scheduled == 0 { slot.migrationScheduled.Store(false); ... } // re-arm ТОЛЬКО если 0 стримов
```
Watchdog sweep (ws_pool.go:1809-1814) зовёт это каждые 5s пока `slot.streams.Load() > 0` и слот выше threshold. Но из-за per-slot CAS второй+ вызовы short-circuit'ят на :176. → **стрим, появившийся после первого scheduled>0, не попадает в Range повторно и навсегда без AfterFunc.** Спека v2 §15-28 описывает это ТОЧНО. Доказательная база (`migrate_fail{not_found}=207, grace_expired=123`) согласуется: это поздние стримы, дожившие до age-drain → RESUME-on-death после Close. Постановка корня (A) теперь корректна.

### BLOCKER-2 → закрыт. defer-架 в downlink-goroutine

Сверка downlink-goroutine (tcp.go:932-1135):
```
933  go func() {
934      defer wg.Done()
935      defer cancel()
         // v2 предлагает: defer wakeUplink(conn, socks5Replies)
```
Подтверждены ВСЕ выходы downlink-goroutine, каждый из которых исполнит defer:
- migration-ветка: `return` :1043 (после downlinkReassemblyLoop) — единственный return migration-пути ✅
- legacy: ch-closed :1052 ✅; CONNECT_FAIL :1073 ✅; write-error drain :1108 ✅; peerFullClose :1125 ✅; ctx2.Done :1129 ✅
defer покрывает все 6. Спека §62 перечисляет их верно. **Архитектурно корректно** — централизованная точка вместо N локальных патчей (соответствует [feedback_architecturally_correct]).

### HIGH-1 → закрыт. CloseRead — корректный примитив, проверено по memconn.go

`conn` в relay — relay-end `ourConn` (b из newMemPipe, isAppEnd=false): `rd=d1, wr=d2` (memconn.go:211). Uplink читает `conn.Read` = `c.rd.read` = d1 (tcp.go:859). `CloseRead()` (memconn.go:256-259) делает `c.rd.close()` → d1.closed=true → блокированный uplink `conn.Read` просыпается и возвращает `io.EOF` (memconn.go:102-104). **Подтверждено: CloseRead на relay-end будит uplink.** Идемпотентно (memBuffer.close под `if !b.closed`, memconn.go:114-121). SetReadDeadline-вариант справедливо отвергнут (оставлял бы deadline-мусор; к тому же на relay-end он бы сработал, но грязнее).

### HIGH-2 → закрыт. Интерфейс-гард + фолбэк

Спека §77-85:
```go
func wakeUplink(conn net.Conn, socks5Replies bool) {
    if cr, ok := conn.(interface{ CloseRead() error }); ok { _ = cr.CloseRead(); return }
    _ = conn.Close()
}
```
memConn реализует `CloseRead` (memconn.go:256) → основной путь. Loopback `*net.TCPConn` тоже реализует CloseRead → тоже основной путь (корректно). Обёртки без CloseRead → Close-фолбэк. Гард обязателен и зафиксирован. Корректно.

### HIGH-3 → закрыт. Cascade-таргет

`selectYoungTargetSlot` (migrate_watchdog.go:129-153) фильтрует `getState() != slotReady` → newIdx (поднимающийся replacement) не выбирается. При cascade (все соседи near-age) youngest ready может сам скоро уйти в drain → повторная миграция. v2 §56 принимает как деградацию, и **re-arm per-stream её действительно покрывает**: после rebind на новый слот свежий entry имеет `migrationScheduled=false` (rebindStreamToSlot Store newStreamEntry, migrate_watchdog.go:355) → на новом слоте стрим снова кандидат когда тот состарится. Логически замкнуто.

### MEDIUM-4 → закрыт. Остаточная взаимоблокировка

v2 §96: если downlink-goroutine виснет в `conn.Write(d)` (tcp.go:1093, d2-буфер полон, app не читает) — defer-wake не исполнится. Верно по коду: `conn.Write` = `c.wr.write` = d2.write блокируется при `len(buf) >= max` пока reader не освободит или buf не закроется (memconn.go:69-73). Принято как known-limitation с разбором: на тихом канале conn.Write не вызывается (нечего писать); gap-timeout (tcp.go) и reassembly-overflow дают пути выхода при наличии фреймов. Адекватно.

---

## MEDIUM (требования к плану/тестам, НЕ пороки дизайна — не блокируют APPROVED)

### MEDIUM-1 — (A) контракт возврата `scheduleSlotMigration` меняется; существующий тест TestScheduleSlotMigration_Idempotent сломается по СМЫСЛУ, не только по строке

`TestScheduleSlotMigration_Idempotent` (migrate_watchdog_test.go:187-233) пинит per-slot семантику:
```
217  if !p.scheduleSlotMigration(0, p.slots[0]) { t.Fatal("first ... scheduled=true") }
221  if p.scheduleSlotMigration(0, p.slots[0])  { t.Fatal("second ... idempotent (scheduled=false)") }
230  if calls[10] != 1 || calls[11] != 1 { ... "exactly once" }
```
После переноса гейта per-slot→per-stream второй вызов с теми же УЖЕ-запланированными стримами должен вернуть `false` (scheduled count=0, все стримы уже flag=true) — то есть инвариант «exactly once» сохраняется, но **возвращаемое значение `false` теперь означает «0 НОВЫХ стримов запланировано», а не «слот уже обработан»**. Контракт функции меняется семантически. Спека §58/§100 это упоминает («обновить пинящие per-slot флаг»), но НЕ фиксирует новый контракт возврата явно. **Требование к плану:** документировать новый возвратный контракт (true ⇔ запланирован ≥1 НОВЫЙ стрим на этом проходе) и переписать тест на проверку «поздний стрим, привязавшийся после первого прохода, получает AfterFunc на втором проходе; уже-запланированный — нет». Это и есть позитивный тест ценности (A) из §100 — свести их в один. Не дизайн-порок, но без явного контракта реализатор может вернуть `true` каждый тик (косметика метрики) или сломать idempotent-инвариант.

### MEDIUM-2 — (A) гонка нового per-stream CAS `migrationScheduled` vs `migrating` vs rebind — нужен явный инвариант теста

Три CAS-флага теперь живут на entry: `migrationScheduled` (новый, гейт планирования) и `migrating` (существующий, гейт исполнения move). Последовательность на поздний стрим:
1. watchdog tick: CAS `e.migrationScheduled` false→true, арм `AfterFunc(migrateStream)`.
2. AfterFunc firing: `migrateStream` Load entry по streamID (migrate_watchdog.go:228 — re-Load, НЕ использует stale e), CAS `e.migrating` false→true.
3. rebind на OK: `streamMap.Store(newStreamEntry(targetIdx))` — свежий entry, оба флага zero.

Гонки, которые надо подтвердить тестом/race-проходом:
- **(a) AfterFunc fires ПОСЛЕ rebind:** старый entry уже не в map; `migrateStream` Load по streamID получит НОВЫЙ entry (на target). Если target ещё не состарился, его `migrationScheduled=false` — но AfterFunc был арм-нут для СТАРОГО прохода. `migrateStream` не читает `migrationScheduled` вообще (только `migrating`), так что лишний вызов на новом entry просто пере-мигрирует стрим раньше времени? **Нет** — `migrateStream` сам решает по `selectYoungTargetSlot`; если target свежий, youngest может оказаться сам target (srcIdx==targetIdx → rebind no-op, migrate_watchdog.go:325) либо другой — но move произойдёт раньше threshold. Это безвредно (миграция всегда валидна), но это «лишняя» преждевременная миграция от устаревшего таймера. Узко и редко (AfterFunc offset ≤ spread 8s, окно rebind мало). **Требование к плану:** тест «AfterFunc арм-нутый до rebind, fired после — не вызывает двойную миграцию / отрицательный счётчик» (single-winner `migrating` CAS + srcIdx==targetIdx guard уже защищают — подтвердить, не добавлять код).
- **(b) Конкурентный watchdog tick во время migrating:** стрим `migrating=true`, ещё не rebind. Спека §50 говорит «migrating-стрим пропускается». Но **в коде Range у scheduleSlotMigration сейчас НЕ проверяет `e.migrating`** (migrate_watchdog.go:182-201) — только slotIdx. v2-реализация ДОЛЖНА добавить `if e.migrating.Load() { skip }` И `if !e.migrationScheduled.CompareAndSwap(false,true) { skip }` в Range. Если реализатор забудет migrating-check, mid-move стрим (migrating=true, migrationScheduled ещё false на старом entry) получит ВТОРОЙ AfterFunc — но он короткозамкнётся на `migrating` CAS в migrateStream (loser стоит down, migrate_watchdog.go:243). Двойного move нет, но лишний таймер арм-нётся. **Требование к плану:** Range-фильтр = `slotIdx==aging && !migrating && CAS(migrationScheduled)`; тест на оба гейта.

Оба сценария защищены существующим single-winner `migrating` CAS — это НЕ новые дыры, а инварианты, которые план обязан зафиксировать тестом (как и MEDIUM-1 в v1-ревью для драйв-миграции). Дизайн (A) корректен.

---

## NIT

- **NIT-1 (закрыт в v2):** метрика — переиспользован `MigrateScheduled` (§112), новый счётчик не плодится. Подтверждено: `Stats.MigrateScheduled.Add(scheduled)` уже в scheduleSlotMigration (migrate_watchdog.go:211); после фикса он естественно растёт за счёт поздних стримов. Хорошо. (Замечание: при re-arm каждые 5s счётчик инкрементируется на число НОВЫХ стримов за проход — семантика «scheduled events», не «slots» — отразить в дашборде.)
- **NIT-2:** defer-ordering. `defer wg.Done()` (:934) → `defer cancel()` (:935) → `defer wakeUplink` (новый, последний). Go исполняет defers LIFO: wakeUplink ПЕРВЫМ, затем cancel, затем wg.Done. Это корректно (будим uplink → uplink return → его `wg.Done`; downlink `wg.Done` последним; `wg.Wait` на :1134 дождётся обоих). Зафиксировать порядок в плане: wakeUplink ДОЛЖЕН идти ПОСЛЕ `defer cancel()` в исходнике (чтобы исполниться ПЕРВЫМ) — иначе разницы по корректности нет, но логичнее будить до отмены ctx.
- **NIT-3:** full-keepalive тест (§103) — обязателен и отличается от half-close: обе стороны открыты, downlink убит извне, uplink в Read d1 → CloseRead → EOF. По образцу memconn_halfclose_test.go. Спека это уже требует — оставить.
- **NIT-4:** Bug#10 цепочка (§95/§106) — ортогонально, регресс-тест предусмотрен. Подтверждено: Bug#10 FlagStreamClose закрывает downlink demux (server→client), wakeUplink будит uplink (client). Не конфликтуют.
- **NIT-5:** §52 «удалить или занопить slot.migrationScheduled» — рекомендую УДАЛИТЬ поле (ws_pool.go:458) и его сброс (:2143) после переноса гейта, иначе мёртвый код вводит в заблуждение (две одноимённые сущности — slot-level и stream-level). Решить в плане; чище удалить, как и пишет спека.

---

## Ответы на вопросы задания

1. **(A) re-arm per-stream корректен?** Да. Перенос гейта per-slot→per-stream сохраняет идемпотентность (per-stream CAS = ровно один AfterFunc на стрим за жизнь на слоте). Сброс при rebind корректен: rebindStreamToSlot Store'ит свежий newStreamEntry (zero-value `migrationScheduled`, migrate_watchdog.go:355) → на новом слоте стрим снова кандидат. Гонка CAS vs migrating vs rebind — защищена существующим single-winner `migrating` CAS + srcIdx==targetIdx guard; зафиксировать инвариантами в тестах (MEDIUM-1, MEDIUM-2). Migrate-watchdog тесты: TestScheduleSlotMigration_Idempotent сломается ПО СМЫСЛУ (возвратный контракт), переписать (MEDIUM-1); samplers-тесты (migrate_antidpi) не затронуты.
2. **(A) полнота.** Теперь покрыты И ранние (первый snapshot) И поздние (re-arm на след. тике ≤5s) стримы aging-слота. Непокрытые классы: (i) стрим без живого target (selectYoungTargetSlot=false) — fallback на (B); (ii) MigrateCapable просел по гистерезису — fallback на (B); (iii) origin реально умер — Bug#10 + (B). Все остаточные классы ловит (B). Приемлемо.
3. **(B) defer wakeUplink покрывает ВСЕ выходы?** Да — 6 return-путей downlink-goroutine, все под defer. CloseRead на memConn relay-end реально будит uplink Read d1 (verified memconn.go:256→102). Гард+фолбэк корректны. Half-close keep-alive не ломается: immune-флаг только app-end (memconn.go:289), relay-end CloseRead не затронут; в half-close uplink уже вышел (tcp.go:882-888) до downlink-выхода → wakeUplink на ушедшую goroutine безвреден (CloseRead идемпотентен). Loopback покрыт фолбэком.
4. **Регресс Bug#8/#9/#10.** Re-arm — расширение зоны применения стабилизированного `migrateStream`/`rebindStreamToSlot` (Bug#9 примитивы), не их изменение. wakeUplink ортогонален Bug#10 (дополняет). Bug#8 flow-control не затронут (B трогает только закрытие read-стороны при выходе downlink). Race на Linux обязателен — спека требует (§108).
5. **Новые гонки / тесты / метрика.** Новых дыр нет; два инварианта зафиксировать тестом (MEDIUM-1/2). Тест-покрытие в §98-108 адекватно по структуре; добавить явный тест возвратного контракта (A) и Range-фильтр-гейтов. Метрика MigrateScheduled переиспользована корректно (NIT-1).
6. **Cascade (HIGH-3) и взаимоблокировка (MEDIUM-4).** Обе приняты как деградация/known-limitation адекватно и с разбором кода. HIGH-3 дополнительно закрывается re-arm (повторная миграция). MEDIUM-4 — узкий сценарий, митигаторы названы.

---

## Что нужно для APPROVED (clean)

Ни одного блокирующего пункта. Перед/во время плана закрыть 2 MEDIUM как требования к тестам:
1. Зафиксировать новый возвратный контракт `scheduleSlotMigration` (true ⇔ ≥1 новый стрим) и переписать TestScheduleSlotMigration_Idempotent → тест ценности re-arm (MEDIUM-1).
2. Реализовать Range-фильтр `slotIdx==aging && !e.migrating.Load() && e.migrationScheduled.CAS(false,true)`; тест на двойной гейт + AfterFunc-после-rebind инвариант (MEDIUM-2).
3. (NIT-5) удалить мёртвый `slot.migrationScheduled`.
4. (NIT-2) порядок defer: wakeUplink после `defer cancel()`.

Все — план-уровень, не дизайн. **Спека APPROVED-WITH-NITS, готова в план.**
