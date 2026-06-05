# Финальное code-review реализации фикса half-open (2026-06-04)

**Скоуп:** целостное ревью фичи half-open (компоненты A + B), а не отдельных задач.
**Module:** github.com/nixavpn/shadowlink. Working dir D:\NIXAVPN. Изменения в рабочем дереве (не закоммичены — норма).
**Спека:** docs/superpowers/specs/2026-06-04-halfopen-drain-stream-leak-design.md (v2 APPROVED).
**Спека-ревью:** docs/halfopen-spec-review-v2-opus-2026-06-04.md (0 BLOCKER / 0 HIGH / 2 MEDIUM / 5 NIT).

## ВЕРДИКТ: APPROVED

Счётчики: **0 BLOCKER · 0 HIGH · 2 MEDIUM · 4 NIT**

Реализация дословно соответствует v2-спеке. Build/vet/test зелёные. Оба корня
закрыты согласованно. Найденные MEDIUM — это остаточные нюансы покрытия/контракта,
не пороки; их можно закрыть отдельным микро-PR или принять как known.

---

## go test (фактический запуск)

```
cd shadowlink && go build ./...                          → OK (без вывода)
go vet ./client/ ./proxy/...                             → OK (без вывода)
go test ./client/ ./proxy/socks5/ ./core/ -count=1:
  ok   github.com/nixavpn/shadowlink/client       50.874s
  ok   github.com/nixavpn/shadowlink/proxy/socks5  5.949s
  ok   github.com/nixavpn/shadowlink/core          8.977s
```

Прицельно (verbose):
- TestScheduleSlotMigration_ReArmsLateStreams — PASS
- TestScheduleSlotMigration_SkipsMigratingStream — PASS
- TestStreamEntry_MigrationScheduledDefaultsFalse — PASS
- TestWakeUplink_CloseReadOnMemConn / _AfterHalfCloseIsHarmless / _DoesNotPanicOnClosedConn / _CloseFallback — PASS
- TestMemConn_HalfClose_* (6 шт, immune-фикс 60s) — PASS

---

## 1. Интеграция (A)+(B): согласованность

**Вывод: согласованы, не конфликтуют, страхуют друг друга.**

- (A) `scheduleSlotMigration` (client/migrate_watchdog.go:171-212) уменьшает ЧИСЛО
  событий рваного downlink: стримы стареющего слота превентивно мигрируют на молодой
  слот ДО того, как middlebox заморозит TCP, поэтому downlink-goroutine реже видит
  обрыв вообще.
- (B) `wakeUplink` (proxy/socks5/tcp.go:601-606, defer на :952) — backstop: при ЛЮБОМ
  закрытии downlink-goroutine (миграция провалилась, slot умер, ctx отменён, peer full
  close, ch closed) parked-в-conn.Read uplink-goroutine будится через CloseRead и не
  висит навечно в мёртвом стриме.
- Сценарий «оба не сработают» отсутствует: (B) — финальный defer, покрывающий все 6
  return-путей downlink-goroutine (миграционный путь :1060 и legacy :1069/:1090/:1142/
  :1146). Даже если (A) не успел/не нашёл target — слот умрёт, downlink-goroutine
  выйдет, (B) разбудит uplink. (A) и (B) работают на РАЗНЫХ уровнях (планирование
  миграции vs пробуждение goroutine), пересечения состояния нет.
- Конфликт исключён: (A) трогает streamMap/poolSlot.streams; (B) трогает только
  memConn.rd (read-half relay-end). Разные объекты, разные локи.

---

## 2. (A) Полнота и корректность

**Покрытие ранних + поздних стримов: ДА.** Гейт переведён per-slot→per-stream. Watchdog
(`rotationWatchdogSweep`, ws_pool.go:~1796) тикает каждые 5s, пока слот выше порога; на
каждом тике `Range` фильтрует `e.slotIdx == agingIdx`, пропускает `migrating` и
`migrationScheduled==true`, остальным CAS'ит флаг и арм-ит ОДИН AfterFunc. Поздний стрим,
привязавшийся ПОСЛЕ первого прохода, ловится на следующем тике. Подтверждено тестом
`TestScheduleSlotMigration_ReArmsLateStreams`.

**Идемпотентность (нет дублей AfterFunc каждые 5s): ДА.** `e.migrationScheduled.CAS(false,true)`
(migrate_watchdog.go:188) — single-winner на жизнь стрима на слоте. Второй проход с тем же
стримом → CAS проигрывает → таймер не арм-ится. Старый per-slot `slot.migrationScheduled`
полностью удалён (см. п.2-orphans).

**Фильтр !migrating ПЕРЕД CAS migrationScheduled: ДА** (строки 184 → 188). Порядок верный:
стрим, который УЖЕ в процессе move (его двигает второй таймер или slot-death RESUME-путь),
не помечается migrationScheduled зря и не получает второй таймер.

**Сброс при rebind (свежий entry zero-value): ДА.** `migrateStream` на успехе зовёт
`rebindStreamToSlot` → `streamMap.Store(streamID, newStreamEntry(targetIdx))`
(migrate_watchdog.go:354). `newStreamEntry` даёт `migrationScheduled=false` (zero value,
подтверждено `TestStreamEntry_MigrationScheduledDefaultsFalse`). На новом слоте стрим снова
кандидат, когда тот состарится — замкнуто корректно.

**Мёртвый slot.migrationScheduled удалён полностью: ДА.** grep по non-test коду:
поле удалено из struct poolSlot (ws_pool.go), удалён `slot.migrationScheduled.Store(false)`
в connectSlot (:2132 — заменён комментарием), удалён CAS+release в scheduleSlotMigration.
Осиротевших чтений нет — остались только `e.migrationScheduled` (per-stream) и комментарии.

---

## 3. (B) Корректность

**defer покрывает все выходы downlink-goroutine: ДА.** `defer wakeUplink(conn, socks5Replies)`
(tcp.go:952) поставлен сразу после `defer cancel()` / `defer wg.Done()`. Defer-стек LIFO:
wakeUplink → cancel → wg.Done. Все return-пути downlink-goroutine (миграционный
downlinkReassemblyLoop-выход и legacy for-select) проходят через defer.

**CloseRead идемпотентен: ДА.** memConn.CloseRead → `c.rd.close()`, а memBuffer.close под
`if !b.closed` (memconn.go). Двойной вызов безвреден — подтверждено
`TestWakeUplink_AfterHalfCloseIsHarmless` (двойной вызов) и `_DoesNotPanicOnClosedConn`.

**Гонка с uplink Read безопасна: ДА.** `conn` в relay = relay-end ourConn (isAppEnd=false):
`rd=d1, wr=d2`. Uplink читает `conn.Read` = d1. `CloseRead()` закрывает d1 → блокированный
uplink Read просыпается с io.EOF и штатно выходит. Uplink ПИШЕТ в WS (StreamWrite), НЕ в
conn — поэтому CloseRead не может повредить uplink-данные на лету. Подтверждено
`TestWakeUplink_CloseReadOnMemConn`.

**Half-close keep-alive НЕ сломан: ДА (ключевой инвариант).** Сценарий keep-alive: app
делает CloseWrite (uplink видит EOF на conn.Read и выходит САМ, БЕЗ cancel, tcp.go:898-904);
downlink продолжает обслуживать ответ. Когда downlink наконец выходит (real FIN через
peerFullClose / ctx2), его defer wakeUplink зовёт CloseRead на ourConn — но uplink-goroutine
УЖЕ вышел, так что CloseRead безвреден. Подтверждено `TestWakeUplink_AfterHalfCloseIsHarmless`
(downlink Write ДО wakeUplink проходит; wakeUplink после — no-op) и интеграционным
`TestMemConn_HalfCloseKeepsDownlinkAlive`. wakeUplink НЕ трогает wr (d2 — downlink
направление), только rd, поэтому downlink-доставка не затрагивается.

---

## 4. Регресс Bug#8 / Bug#9 / Bug#10

- **Bug#8 (flow control):** не задет. wakeUplink трогает только read-half relay-end;
  кредитный путь (OnStreamConsumed / onData) — на downlink (wr-направление). Тест
  `TestHalfClose_DownlinkCreditPathSurvives` зелёный. Per-stream channel cap / RouteToStreamSeq
  не менялись.
- **Bug#9 (миграция) — сердце фикса (A):** НЕ сломан, УЛУЧШЕН. Изменён ТОЛЬКО гейт
  ПЛАНИРОВАНИЯ (per-slot→per-stream). Исполнение move (`migrateStream`), single-winner
  `migrating` CAS, uplink-барьер §5.3, rebind/counter-transfer — без изменений в логике.
  Тесты TestMigrateStream_TransfersSlotCounter / _TransferCounter_EdgeCases зелёные.
- **Bug#10 (origin-death):** wakeUplink ДОПОЛНЯЕТ, не конфликтует. Bug#10 FlagStreamClose
  (ws_pool.go:3226 + handleStreamClose:3524) закрывает streamChans/streamFramesChans →
  downlink-goroutine видит EOF/closed-ch → выходит → его defer wakeUplink будит uplink.
  Это ровно тот путь, ради которого Bug#10-фрейм существует (комментарий :3231-3233 «closes
  its chan → SOCKS5/memConn reader gets EOF → app retries»). wakeUplink замыкает вторую
  половину (uplink) того же teardown. Согласованно.

  Замечание (см. NIT-1): рабочее дерево содержит ПОЛНЫЙ набор Bug#10 (FlagStreamClose,
  handleStreamClose, isAgeCut-ревизия) + counter-leak F1-фикс в rebindStreamToSlot +
  memconn immune (60s-фикс) — это бандл из НЕСКОЛЬКИХ фич, не только half-open. Для half-open
  ревью существенно лишь, что они не конфликтуют — подтверждено.

---

## 5. Гонки (логически)

- **per-stream CAS migrationScheduled vs migrating vs rebind:** все три флага на *streamEntry
  (atomic.Bool). Порядок в scheduleSlotMigration: read migrating → CAS migrationScheduled.
  migrateStream: CAS migrating (single-winner). Двойной таймер на один стрим невозможен
  (migrationScheduled CAS). Таймер, арм-нутый ДО rebind и сработавший ПОСЛЕ: migrateStream
  делает Load по streamID → получает НОВЫЙ entry (migrating=false, на target); защищён
  `srcIdx==targetIdx`-guard (no-op) и single-winner migrating CAS. Лишняя преждевременная
  миграция теоретически возможна, но всегда валидна и без двойного счётчика — покрыто
  `TestMigrateStream_TransferCounter_EdgeCases`.
- **wakeUplink (CloseRead) vs uplink Read:** оба на d1; close() и read() синхронизированы
  внутри memBuffer (мьютекс/cond). CloseRead будит Read, Read возвращает EOF. Безопасно.
- pl1 race-прогон: 0 DATA RACE (по заданию) — логически подтверждаю.

---

## 6. Метрика и тест-покрытие

- **Метрика:** `Stats.MigrateScheduled.Add(scheduled)` переиспользована корректно — теперь
  считает «новые стримы, запланированные на этом проходе» (а не «слоты»). Это семантически
  валидно (счётчик per-stream намерений миграции). Семантика инкремента стала точнее.
- **Покрытие достаточно для APPROVED:** (A) — re-arm late, skip migrating, default-false,
  counter edge-cases. (B) — CloseRead-wake, after-half-close-harmless, no-panic-on-closed,
  Close-fallback. immune (60s) — 6 тестов.
- **Что НЕ покрыто (NIT, не блокирует):**
  - Нет ИНТЕГРАЦИОННОГО теста полного tunnelTCPStream, где downlink-exit реально будит
    parked uplink через defer (юнит-тесты wakeUplink проверяют примитив изолированно, но
    не «defer фактически вызывается в goroutine»). defer тривиален и проверен глазами.
  - Нет теста «AfterFunc арм-нут до rebind, fired после» как отдельного кейса (косвенно
    покрыт edge-cases).

---

## MEDIUM (закрыть микро-PR'ом или принять как known)

### MEDIUM-1 — нет интеграционного теста defer wakeUplink внутри tunnelTCPStream
wakeUplink проверен как примитив (4 теста) и факт `defer` стоит в нужном месте (tcp.go:952),
но нет теста, гоняющего обе goroutine, где реальный выход downlink-goroutine будит реально
запаркованный uplink. Риск низкий (defer однострочный, путь прямой), но именно этот контур —
суть бага. Рекомендация: добавить тест с двумя goroutine на newMemPipe, повторяющий
структуру tunnelTCPStream (downlink выходит → uplink, висящий в Read, разблокируется).

### MEDIUM-2 — поведенческое изменение loopback-пути (socks5Replies=true) не зафиксировано тестом
В loopback-режиме при раннем выходе downlink (например server закрыл, ch closed на tcp.go:1066)
defer wakeUplink CloseRead'ит реальный *net.TCPConn → uplink Read немедленно ошибается и
выходит, НЕ дожидаясь своей 15s idle-grace (idle_grace.go). Это КОРРЕКТНОЕ и желательное
ускорение teardown (downlink уже мёртв — продолжать читать uplink бессмысленно), но это
наблюдаемое изменение поведения loopback-пути, для которого нет регресс-теста. Рекомендация:
тест «downlink-exit в loopback не теряет уже-записанные uplink-байты и корректно завершает
стрим без 15s ожидания».

---

## NIT (косметика)

- **NIT-1:** Рабочее дерево бандлит несколько фич (half-open A+B, Bug#10 FlagStreamClose,
  counter-leak F1 в rebindStreamToSlot, memconn immune 60s). Для атрибуции/отката стоит
  коммитить отдельными логическими коммитами (по памяти проекта — пачкой, так что это
  замечание к структуре коммита, не к коду).
- **NIT-2:** scheduleSlotMigration CAS migrationScheduled выполняется ДО
  `key.(uint16)`-ассерта (migrate_watchdog.go:188 vs :191-194). Если ассерт упадёт (на
  практике невозможно — ключи всегда uint16), флаг останется true, а таймер не арм-нется →
  стрим никогда не мигрирует. Чисто теоретический сценарий; для строгости можно вынести
  type-assert до CAS. Не дефект.
- **NIT-3:** Параметр `socks5Replies` в `wakeUplink` сейчас не влияет на логику (CloseRead
  пробуется всегда). Комментарий честно говорит «kept for symmetry/future gating». ОК, но
  если gating не появится — параметр стоит убрать, чтобы не вводить читателя в заблуждение
  (сигнатура намекает на ветвление, которого нет).
- **NIT-4:** Док-строка scheduleSlotMigration дважды повторяет «Returns true if >=1 NEW
  stream was scheduled on THIS pass» (строки 158 и 164-165) — дубль, можно ужать.

---

## Итог

Фикс корректен, минимален, архитектурно верен (централизованный per-stream гейт покрывает
все code paths появления стримов на стареющем слоте; defer wakeUplink — единая точка для всех
выходов downlink). (A)+(B) согласованы, регрессов Bug#8/#9/#10 нет. Build/vet/test зелёные.
**APPROVED.** Перед мержем желательно (не блокер) добавить 2 теста из MEDIUM-1/2.
