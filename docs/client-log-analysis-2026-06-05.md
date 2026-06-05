# Разбор клиентского DEBUG-лога 2026-06-05 10:05–10:11 (обрыв Claude Code auto-update)

**Бинарь:** `nixavpn-client-graceful-drain.exe` (04.06 15:58) — **содержит half-open фикс A+B**
(подтверждено: пересборка из текущих исходников 05.06 10:15 дала байт-в-байт идентичный файл;
исходники содержат `wakeUplink` defer в tcp.go:952 и per-stream `migrationScheduled` в
stream_entry.go:54 / migrate_watchdog.go:194).

**Режим:** ShadowLink full-direct к origin `104.222.177.67:443`, sni=datacanvases.com, viaCF=false,
max_conns=8, GRACEFUL_DRAIN=1, DRAIN_HARD_CAP=90s, FLOW_WINDOW=4 MiB.

## Факт 1 — туннель тянет большие файлы (НЕ вопрос пропускной способности)
Дошедшие целиком (downlink done (migration), байты целы):
- stream=593 bytes=99 602 041 (99 МБ)
- stream=583 bytes=131 132 469 (131 МБ)
- stream=438 bytes=77 192 952 (77 МБ)
- stream=455 bytes=63 507 047 (63 МБ)
- stream=452 bytes=61 669 626 (61 МБ)
- stream=441 bytes=52 173 869 (52 МБ)
- stream=301 bytes=11 987 469 (12 МБ), stream=86 bytes=3 324 976
Пик downlink_kb=324835 / 5с ≈ 520 Мбит/с. decrypt_fails=0 ВСЮ сессию.

## Факт 2 — `bytes=0 chunks=0` обрывы = чистка пустых control-стримов, НЕ потеря данных
Пачка в окне 10:08:48–10:09:25: stream=486/481/473/469/484/479/474/485/531/526/533/555 и др.
Все — короткие CONNECT-стримы без переданных данных; закрыты при teardown слота (drain/age-cut).
bytes=0 потому что данных по ним не шло. Не симптом.

## Факт 3 — КОРЕНЬ: 30s downlink-stall перед age-cut на «горячих» слотах
```
10:09:11 slot=5  i/o timeout cause=age_cut down_bytes=142 150 067 last_write_age_ms=33725
10:08:40 slot=3  close 1006   cause=age_cut down_bytes=332 116 809 last_write_age_ms=30360
10:10:27 slot=6  i/o timeout cause=age_cut down_bytes=501 603     last_write_age_ms=29995
10:08:42 "ws async writer exit" err="write tcp ...->104.222.177.67:443: i/o timeout" writeTimeout=0s
```
`last_write_age_ms` ~30 000 на слоте, который ТОЛЬКО ЧТО прокачал 142–332 МБ → слот 30 секунд
не получал ни байта downlink, потом сработал age-cut/io_timeout.

Серверный код (handler.go:1153-1196): `streamWriteTimeout = 60s`, `SetWriteDeadline` на каждую
downlink-запись; при срабатывании — `download stream write error err="i/o timeout"` и конец цикла.

**Для долгого single-stream GET (Claude update = один большой файл) этот 30-секундный провал
downlink = обрыв TCP в середине файла → апдейтер ретраит → снова на stale-слот → Auto-update failed.**
Stream migration спасает байты для стримов, которые УСПЕЛИ; стрим, который сам длиннее жизни слота
И попал в stall-окно — рвётся.

## Факт 4 — MEDIUM-4 (зависание downlink в conn.Write) в этой сессии НЕ основной механизм
Систематических стримов «uplink done есть, downlink done нет минутами» не найдено — почти все
стримы имеют парный downlink done (migration). Остаточная дыра MEDIUM-4 (tcp.go:547 conn.Write без
таймаута при полном d2-буфере) теоретически возможна, но в логе массово не проявилась.

## Нерешённая развилка (нужен серверный лог pl1)
30s-stall — это:
- **(1) сервер сам залип** (per-conn timeout/лимит/stall на стороне pl1), ИЛИ
- **(2) middlebox/TSPU режет долгий direct-TCP** к голому origin IP 104.222.177.67.

Клиентский лог их НЕ различает. Различение возможно только серверным логом:
- `download stream write error err="i/o timeout"` при непустом outgoingLen ⇒ гипотеза 1
- `download stream ended (client disconnect)` / `connection reset` / `broken pipe` ⇒ гипотеза 2

Доступ сейчас: SSH к pl1 — нужен пароль (BatchMode → Permission denied); mgmt :9443 — timeout
(закрыт снаружи); origin :443 — жив (200 за 0.22с). Сохранённого серверного лога за окно в репо нет.

## Статус half-open фикса
A (per-stream re-arm миграции) + B (defer wakeUplink) — реализованы, ревью APPROVED, в бинаре.
Они УМЕНЬШАЮТ обрывы (мигрируют поздние стримы, будят uplink), но НЕ закрывают сценарий
«сам стрим длиннее жизни слота + stall-окно» — это остаточный класс, для него нужен отдельный фикс.

## РАЗВИЛКА РЕШЕНА (серверный лог pl1, 2026-06-05 07:05-07:12 UTC = 10:05-10:12 МСК)

**Сервер pl1 ЗДОРОВ — гипотеза 1 (сервер залип) ОТВЕРГНУТА:**
- Бинарь `/opt/shadowlink/shadowlink-server` собран 2026-06-04 07:59 UTC, аптайм 17ч, активен НЕПРЕРЫВНО
  (таймстемпы плотные, без 30с-дыр в собственной активности — обрабатывал другие стримы в те же секунды).
- Дилит цели за 1-45ms, `WS CONNECT_OK ... migrate=true` на каждом стриме (506 раз). decrypt_fails=0.
- Распределение причин закрытия слотов за окно: io_timeout=18, peer_eof=17, local_close=3.
- io_timeout reader exit = сервер 60с не получал uplink от клиента по конкретному слоту, в ТЕ ЖЕ секунды
  принимая CONNECT на других (127.0.0.1:10443 = nginx↔backend loopback).
- **0 RESUME / 0 migrate_fail на сервере** — миграция чисто КЛИЕНТСКАЯ (стрим переехал на свежий WS,
  сервер старый слот просто потерял по io_timeout). half-open фикс A работает штатно.

**ВЕРДИКТ = ГИПОТЕЗА 2: middlebox/TSPU замораживает зрелые direct-TCP к голому IP 104.222.177.67 по ВОЗРАСТУ.**
Симметричный i/o timeout на КОНКРЕТНЫХ зрелых TCP при живом сервере и живых соседних соединениях.

## ИЗМЕРЕННОЕ ОКНО ЗАМОРОЗКИ (клиентский slot_age_ms при stall)
```
slot=0  slot_age_ms=141151 last_write_age_ms=12203  ← заморозка
slot=3  slot_age_ms=157662 last_write_age_ms=30360  ← заморозка 30с
slot=5  slot_age_ms=189124 last_write_age_ms=33725  ← заморозка 33с
slot=6  slot_age_ms=264730 last_write_age_ms=29995  ← заморозка 30с
slot=11 slot_age_ms=132756 last_write_age_ms=15436  ← заморозка 15с
slot=7  slot_age_ms=101756 last_write_age_ms=11     (норма, писал только что)
slot=10 slot_age_ms=89234  last_write_age_ms=2382   (норма)
```
**Заморозка начинается в возрасте TCP ~130-190с.**

## ПОЧЕМУ KEEPALIVE НЕ СПАСАЕТ (уточнение подхода)
`keepaliveDefaultBase = 5s` (ws_pool.go:543) — клиент УЖЕ шлёт WS keepalive каждые ~5с (window [2.5s,10s]).
Заморозка случается НЕСМОТРЯ на 5с PING ⇒ **TSPU режет по ВОЗРАСТУ TCP, не по idle**. Keepalive-половина
комбо-фикса бессмысленна — она уже есть и не помогает. Реальный рычаг — ТОЛЬКО age-cut раньше окна.

## ТЕКУЩИЕ ПОРОГИ vs ОКНО ЗАМОРОЗКИ (корень в цифрах)
| Параметр | Значение | Файл |
|----------|----------|------|
| migrationThresholdBase | 60s (env→45s), фактич. ×U(0.7,1.0)=42-60s | migrate_watchdog.go:52 |
| MaxSlotAge | **120s** + stagger idx×15s → 120-225s | engine_shadowlink.go:386 |
| slotRotationStaggerStep | 15s | ws_pool.go:473 |
| DrainHardCap | 90s | engine_shadowlink.go:433 |
| ageCutMinAgeMs (классификатор) | 60s | ws_pool.go:1032 |
| keepalive | 5s | ws_pool.go:543 |

**Корень:** maxSlotAge=120s + stagger до +105s → старшие слоты (idx 4-7) доживают до 160-225с, прямо
в зоне заморозки 130-190с. Долгий single-stream GET (Claude update), осевший на таком слоте, ловит
30с-провал downlink = обрыв TCP в середине файла → апдейтер ретраит → Auto-update failed.

**Фикс:** опустить MaxSlotAge + сократить stagger так, чтобы ВЕСЬ разброс ротации (slot 0..7) укладывался
НИЖЕ 130с (начало окна заморозки). Превентивную миграцию (42-60s) оставить. Keepalive не трогать.
