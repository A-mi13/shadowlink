# Bug #9 — Тихий долго-живущий стрим умирает со слотом и не мигрирует (НАХОДКА)

Дата: 2026-05-31. Симптом от юзера: «на долгих ожиданиях обрывы и НЕ восстанавливается больше».
Воспроизведено вживую: общение с Claude через туннель (агент думает 5+ мин молча) → стрим рвётся,
не реконнектится. Закачки (Bug#8) при этом РАБОТАЮТ — это ДРУГОЙ корень.

## Факты из лога nixavpn-DEBUG-20260531-105253.log (окно 11:24-11:26, живая сессия)

Массовый `WS pool slot reader error ... close 1006 (abnormal closure): unexpected EOF` на ЗРЕЛЫХ слотах:
```
slot=12 close 1006 anomaly=close_other slot_age_ms=82890  last_write_age_ms=11750  mode=direct
slot=4  close 1006 anomaly=close_other slot_age_ms=157066 last_write_age_ms=672    mode=direct
slot=3  close 1006 anomaly=close_other slot_age_ms=258994 last_write_age_ms=9776   mode=direct
slot=11 close 1006 anomaly=close_other slot_age_ms=157794 last_write_age_ms=11830  mode=direct
slot=10 close 1006 anomaly=close_other slot_age_ms=134179 last_write_age_ms=15001  mode=direct
slot=2  close 1006 anomaly=close_other slot_age_ms=474843 last_write_age_ms=3723   mode=direct
```

КЛЮЧ: `last_write_age_ms=10000-15000` — слот МОЛЧАЛ 10-15 секунд перед тем как middlebox его прибил.
Это ТИХИЕ слоты (юзер ждёт ответ агента, ничего не передаётся).

Реконнект с долгим backoff:
```
WS pool reconnecting slot=3  backoff=7.636s attempt=0
WS pool reconnecting slot=2  backoff=9.573s attempt=0
WS pool reconnecting slot=11 backoff=7.862s
```

Просадка пула в момент шторма close 1006:
```
11:24:56 alive=11 dead=3 ... rate_limited_recent=3 active_streams=25
```

Счётчики за сессию (~33 мин): **404** `closed pipe|downlink write error|decrypt` (МНОГО — разобрать что из них реальные
обрывы тихих стримов vs app-close), **7** `no ready slot|no free|exhausted` (стрим искал куда переехать и НЕ нашёл).

Долгие стримы что ВЫЖИЛИ: stream 30 elapsed=31m35s (uplink done EOF), stream 142 = 25m (но были с трафиком —
uploads=8, bytes растут). Контраст: выживают стримы С активностью, режутся ТИХИЕ.

## Гипотеза корня (НЕ доказана до конца — нужно исследование кода)

Тихий долго-живущий стрим убивается вместе со слотом:
1. Слот молчит 10-15с (тихий стрим: юзер ждёт, нет байт ни вверх ни вниз).
2. TSPU/middlebox режет тихий долгий direct-TCP к голому origin (104.222.177.67) → close 1006.
   (`mode=direct` — это direct, не через CF; CF в РФ блокируется, direct намеренный.)
3. Слот → reconnect с backoff 5-9с.
4. Пул проседает (alive=11 dead=3), стримы с мёртвого слота ищут живой → `no ready slot` (все мертвы/в backoff).
5. Стрим НЕ мигрирует (некуда) → умирает → агент/сессия обрывается, не восстанавливается.

## Направления для исследования (проверить по коду, НЕ патчить вслепую — урок Bug#8)

1. **Keepalive на слоте**: почему слот молчит 10-15с? Есть ли per-slot keepalive ticker, какой интервал,
   почему он не держит тихий слот «живым» для middlebox? `last_write_age_ms=15001` = keepalive НЕ сработал
   или интервал > времени реза middlebox. NB: NEW-1 jittered keepalive 20s±30% (CLAUDE.md) — 20с МОЖЕТ БЫТЬ
   СЛИШКОМ РЕДКО если middlebox режет на ~10-15с молчания. Это сильный кандидат в корень.
2. **Stream migration**: мигрирует ли активный-но-тихий стрим на другой слот при смерти его слота?
   Или стрим жёстко привязан к слоту и умирает с ним? Где в ws_pool.go обрабатывается handleSlotDeath
   относительно стримов слота.
3. **Backoff 5-9с**: не слишком ли долго? На это время стримы повисают без слота.
4. **Bug#6 sticky vs тихий стрим**: sticky-drain даёт АКТИВНЫМ доиграть, но ТИХИЙ стрим (0 байт) drain-логика
   считает idle → снимает досрочно. Тихий долгий стрим = слепое пятно sticky-логики.
5. **404 closed pipe**: разобрать сколько из них — реальные обрывы тихих стримов vs штатные app-close.
6. close 1006 mode=direct — middlebox режет именно тихий direct. Keepalive чаще = маскировка под живой
   браузер (реальный idle keep-alive WS шлёт ping). Но НЕ ломать анти-DPI (jitter, не fixed period).

## Что Bug#9 НЕ является
- НЕ Bug#8 (потеря байт на закачке — починено, закачки работают).
- НЕ idle-timeout агентского API (тот завершил бы агента чисто; здесь — обрыв стрима В туннеле,
  «не восстанавливается»). Доказано: юзер выключил протокол → агенты перестали рваться.

Resume: "Bug #9 тихий стрим" / "close 1006 на молчании" / "стрим не мигрирует".
