# Bug #8 — byte_budget drain рвёт активную закачку: причинная трасса

Дата: 2026-05-30
Метод: code-trace по горячим путям (без нового diag-run). Опорный полевой лог:

```
14:57:04.721 drain started slot=8 reason=byte_budget active_streams=1
14:57:04.721 downlink cancelled stream=85 bytes=71819544 (71MB) elapsed=2.448s + appConn.Close(full) ageMs=2448
14:57:15.145 drain started slot=9 reason=byte_budget active_streams=2
14:57:15.150 downlink write error stream=86 closed pipe downlinkBytes=95921178 (96MB) streamAgeMs=4094 fullClose=true ctxErr=nil
14:57:25.437 drain started slot=8 reason=byte_budget active_streams=4
14:57:25.440 closed pipe stream=88 downlinkBytes=225052822 (225MB) streamAgeMs=7189 fullClose=true
```

## TL;DR — корень

`byte_budget` на graceful-пути зовёт `startDrain` **БЕЗУСЛОВНО и СИНХРОННО внутри reader-горутины слота**
(`slotReaderWithClient`, ws_pool.go:2710), НЕ через `maybeRotateSlot` (который умеет defer'ить при активных
стримах). `startDrain` под капотом берёт пул-широкий `reserveMu` в `claimFreeSlot`, а при насыщенном пуле
(нет free cell) **синхронно** прогоняет `tryForceEvictIdleSlot` / `tryEmergencyEvictMinStreamsSlot` →
`handleSlotDeath` (тоже берёт `reserveMu`, перебирает `streamMap`, шлёт session-FIN, `transport.Close`).

Пока reader-горутина слота 8 стоит внутри `startDrain`, она **НЕ вызывает `ReadMessage` и НЕ делает
`RouteToStream`** для своего же активного 71-225MB downlink-стрима. На 141 МБ/с это мгновенный stall
канала. tun2socks (gVisor) видит, что downlink-копия в локальное приложение перестала продвигаться
именно в момент когда uplink уже half-closed, и рвёт flow → `appConn.Close(full)` → `fullClose=true`.
Корреляция "в ту же мс" = это один и тот же стек reader-горутины: drain-лог и срыв downlink идут
последовательно в одной горутине без переключения.

**Корень-строка: ws_pool.go:2710** — `p.startDrain(cl, idx, "byte_budget")` вызван синхронно из reader'а
слота, который сам обслуживает downlink активного стрима. Reader блокирует собственный downlink ради
оркестрации дренажа.

## Почему именно byte_budget, а не age

| | byte_budget | age (rotationWatchdog) |
|---|---|---|
| Кто зовёт startDrain | **reader-горутина слота** (slotReaderWithClient) | отдельная pool-горутина rotationWatchdog |
| Влияние на downlink слота | reader стоит в startDrain → downlink этого слота не читается | reader продолжает читать параллельно |
| Проверка активных стримов | НЕТ (безусловный вызов) | тоже идёт через startDrain, но reader не страдает |

Это и есть архитектурная асимметрия. `age`-дренаж вызывает тот же `startDrain`, но из ПОСТОРОННЕЙ горутины,
поэтому reader слота продолжает качать downlink. `byte_budget` вызывает `startDrain` ИЗ reader'а слота —
и downlink этого слота замирает на всё время оркестрации (взятие reserveMu + возможный синхронный
handleSlotDeath с обходом streamMap и Close транспорта). На горячей закачке этого окна достаточно, чтобы
tun2socks порвал flow.

## Детальная трасса

### 1. Точка входа (ws_pool.go:2684-2718) — reader-горутина слота

```
budget := slot.byteBudget.Load()
if budget > 0 {
    total := slot.downBytes.Add(int64(len(data)))
    if total >= budget && byteBudgetRotationAllowed(time.Since(slotStart), p.byteBudgetMinInterval) {
        if p.gracefulDrain {
            p.startDrain(cl, idx, "byte_budget")   // ← СИНХРОННО, в reader-горутине
            slot.downBytes.Store(0)
            continue                                // downlink возобновится ТОЛЬКО после возврата startDrain
        }
        ...
    }
}
```

На 141 МБ/с один WS-фрейм приносит десятки КБ; `downBytes` слота-носителя закачки перешагивает budget
за доли секунды (Bug #4 floor 10s лишь задерживает первый дренаж, дальше дренаж на каждом
`byteBudgetMinInterval`). `active_streams` в логе растёт 1→2→4, slot 8 дренится дважды (04.721 и 25.437) —
пул насыщается reconnect-плодом + drain/reserve overlap (это уже зафиксировано в Bug#8 диагностике 29 мая).

### 2. startDrain (ws_pool_drain.go:358-494) — что блокирует reader

- Gate 7 `claimFreeSlot()` (ws_pool_drain.go:163) — `p.reserveMu.Lock()` + полный проход среза.
  `reserveMu` контендится с `reconnectLoop` (ws_pool.go:1801), `connectReserveSlot` cleanup
  (ws_pool_drain.go:524) и `handleSlotDeath` (ws_pool.go:3027). При активной канители reconnect'ов
  (раздутый пул) это окно — не нулевое.
- Если `claimFreeSlot` вернул -1 (срез полон — типично для насыщенного пула в логе): reader
  **синхронно** выполняет `tryForceEvictIdleSlot` (ws_pool_drain.go:217, ещё один проход среза) и при
  over-aged — `tryEmergencyEvictMinStreamsSlot` → `handleSlotDeath(deathCauseDrainTeardown)`
  (ws_pool.go:2954). `handleSlotDeath` снова берёт `reserveMu`, `streamMap.Range` со взятием
  `cl.streamMu` на каждый стрим, `sendSlotSessionFIN`, `slot.transport.Close()`. Всё это — в reader-горутине
  слота 8, пока его downlink стоит.

`go connectReserveSlot` и `go drainWatchdog` уходят в отдельные горутины (это ок), но ДО них reader уже
потратил время на claimFreeSlot/eviction синхронно.

### 3. Почему срыв = appConn.Close(full), а не наша отмена

- Parent-ctx relay'я (inprocess.go:76 `relayCtx := d.engineCtx`) — долгоживущий engine-ctx; дренаж его
  НЕ отменяет. Поэтому `ctxErr=nil` у stream 86/88, а `downlink cancelled` у stream 85 пришёл из самого
  relay'я (uplink full-close ветка tcp.go:681), не от дренажа.
- Управляющие (WINDOW_UPDATE) и uplink-фреймы на `slotDraining` принимаются
  (ws_pool.go:2408/2439 — `st == slotReady || st == slotDraining`), так что сам факт `slotDraining`
  поток НЕ режет. Режет именно **пауза чтения downlink** этого слота, пока reader сидит в startDrain.
- В in-process пути idle-grace нет (tcp.go:679-685: half-close → return без cancel). Поэтому стрим жив,
  пока tun2socks держит flow. Но downlink-stall на 141 МБ/с заставляет gVisor-копию в приложение
  упереться: uplink уже half-closed (`uplink done fullClose=false`), приложение ждёт тело ответа,
  а оно перестало течь → tun2socks теряет терпение и делает `appConn.Close()` (full) →
  d2 closed + peerFullClose → наш in-flight `conn.Write` (tcp.go:778) ловит `io.ErrClosedPipe`
  "closed pipe" с `fullClose=true` (stream 86/88), либо downlink уже выбрал ctx2.Done после
  uplink-cancel (stream 85).

### 4. Вторичный дефект (усугубляет, не корень)

`slot.downBytes.Store(0)` (ws_pool.go:2711) обнуляет счётчик ПОСЛЕ старта дренажа. drainWatchdog потом
читает `oldSlot.downBytes.Load()` (ws_pool_drain.go:668) для bytes-backstop решения Bug#6 и видит ~0 —
sticky bytes-backstop искажён. На срыв напрямую не влияет, но ломает Bug#6-логику "доиграть до 256MiB".

## Что это исключает

- НЕ teardown watchdog'а: drainPollInterval=500ms, hard-cap=90s; срыв на 3-5мс — watchdog не успел.
- НЕ отмена нашего ctx2: engine-ctx жив; `ctxErr=nil`.
- НЕ отказ записи на draining-слот: WriteControl/WriteMessageForStream принимают slotDraining.
- НЕ RouteToStream-overflow сам по себе (тот дропает молча, не закрывает appConn) — здесь корень в
  паузе чтения, а не переполнении канала.

## Применяется ли sticky (Bug#6) к byte_budget

НЕТ по существу. Bug#6 sticky живёт в `drainWatchdog` (решает «доиграть vs порвать» на тике/deadline).
Но к моменту, когда watchdog получает управление, reader уже простоял downlink в `startDrain` и tun2socks
уже порвал flow. `maybeRotateSlot` (который умеет defer'ить byte_budget при активных стримах,
ws_pool.go:2809-2848) на graceful-пути **не вызывается вообще** — graceful ветка идёт мимо него прямо в
`startDrain`. То есть защита «не рвать активную закачку» (grace 30s) существует только для legacy
hard-rotation пути и для НЕ-graceful, а graceful byte_budget её обходит.

## Фикс-направление (оценка)

Лучший по архитектуре (централизованно, покрывает все code paths):
**byte_budget на graceful-пути НЕ должен оркестрировать дренаж синхронно в reader-горутине слота.** Варианты
по возрастанию корректности:

1. **Не дренить слот с недавно-писавшим активным downlink-стримом** — добавить перед `startDrain` проверку
   как в `maybeRotateSlot` (defer до idle / до grace-окна). По сути — провести graceful byte_budget через
   `maybeRotateSlot`-подобный gate (или прямо через него), а не мимо. Это убирает срыв активной закачки и
   сохраняет анти-DPI цель (дренаж произойдёт когда стрим доиграет / по age-watchdog как upper bound).
2. **Вынести `startDrain` из reader-горутины** — reader лишь ставит флаг/шлёт в канал «нужен дренаж slot N»,
   а отдельная горутина (как rotationWatchdog для age) выполняет claimFreeSlot/eviction. Тогда downlink
   слота не простаивает. Устраняет именно механизм срыва.
3. Комбинация 1+2: пометить sticky сразу при byte_budget-триггере и отдать оркестрацию воркеру.

Рекомендация: **Вариант 1 как минимум** (провести byte_budget через тот же active-stream gate, что и age),
плюс по возможности Вариант 2 (асинхронная оркестрация), плюс убрать преждевременный `downBytes.Store(0)`
до решения watchdog'а.

## Уверенность / нужен ли ещё diag

Механизм (reader блокирует свой downlink в синхронном startDrain → tun2socks RST) выведен из кода + лога
с высокой уверенностью: корреляция «в ту же мс / +3-5мс» объясняется одной reader-горутиной, а не
случайным app-abort'ом (3/3 корреляция в поле + `fullClose=true` + uplink-half-close-then-full паттерн).
Что НЕ доказано из лога железно — длительность простоя startDrain в этом конкретном прогоне (зависело ли
от eviction-ветки или хватило claimFreeSlot+reserveMu contention). Решающий diag, если нужен: залогировать
в reader-горутине `dur := time.Since(t0)` вокруг `p.startDrain(...)` на byte_budget-пути и сравнить с
`streamAgeMs`-окном до срыва. Если `dur` стабильно сопоставим с gap до `appConn.Close` — Вариант 2
обязателен; если `dur` мал — достаточно Варианта 1. Но фикс Варианта 1 безопасен и оправдан независимо от
этого diag (приоритет «не рвать активную закачку» > «слот не прокачал >N байт прямо сейчас»).
