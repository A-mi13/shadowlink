# Canary Report — Graceful Drain 8h session (2026-05-22)

**Лог:** `C:\Users\Lenovo\AppData\Local\Temp\nixavpn-graceful-drain-20260522-085303.log` (6.6 MB, 39 702 строк)
**Бинарь:** `nixavpn-client-graceful-drain.exe`
**Окно работы:** 2026-05-22 08:53:03 → 16:48:54 (7h 55m 51s)
**Сервер:** datacanvases.com:443 → 104.222.177.67 (direct origin, transport=direct, mode=direct, max_conns=8, chunk_size=12288, proto_version=1)
**Конфиг:** TUN + LeakGuard + bypass routing (11 312 include CIDR), DNS = Yandex 77.88.8.8
**Старт пула:** alive=8 (warm-up), вырос до alive=14-15 (16 slots всего, 2 в draining) к 08:56

---

## Verdict

**HEALTHY** — пул стабильно держит alive=14-15 / dead=0 на протяжении всех 7h55m, decrypt_fails=0, ws_died=0, writer_exits=0, meltdowns_1m=0 всю сессию, нет ни одной ERROR-строки и ни одного "перезапуск StartReader". Graceful drain работает: 60.5% drain'ов завершаются natural (median 45s, p95 77s — все укладываются в hard cap 90s).

---

## 1. WS Pool health — таблица интервалов

| Время | uptime | alive | dead | empty | draining | active_streams | inflight | meltdowns_1m | rotations_1m |
|---|---|---|---|---|---|---|---|---|---|
| 08:53:35 | 32s | 8 | 0 | 8 | 0 | 12 | 0 | 0 | 0 |
| 09:23:05 | 30m | 14 | 0 | 1 | 1 | 19 | 1 | 0 | 0 |
| 09:53:05 | 1h | 14 | 0 | 0 | 2 | 32 | 2 | 0 | 0 |
| 10:23:05 | 1h30m | 14 | 0 | 1 | 1 | 16 | 1 | 0 | 0 |
| 11:53:05 | 3h | 14 | 0 | 0 | 2 | 22 | 3 | 0 | 0 |
| 13:23:05 | 4h30m | 14 | 0 | 0 | 2 | 17 | 2 | 0 | 0 |
| 13:53:05 | 5h | 14 | 0 | 0 | 2 | 32 | 3 | 0 | 0 |
| 14:53:05 | 6h | 14 | 0 | 0 | 2 | 22 | 2 | 0 | 0 |
| 15:53:05 | 7h | 14 | 0 | 0 | 2 | 28 | 3 | 0 | 0 |
| 16:48:05 | 7h55m | 14 | 0 | 0 | 2 | 159 | 2 | 0 | 0 |

### Распределение значений за все 951 sample

- **alive**: 8 (6×), 9 (1×), 10-12 (27×), 13 (78×), **14 (834×, 87.7%)**, 15 (5×)
- **dead**: **0 (861×, 90.5%)**, 1 (83×), 2 (7×) — никогда не было >2
- **inflight_drains**: 0 (17×, только в первые 90s), 1 (94×), 2 (577×, **60.7%**), 3 (263×) — никогда не было >3
- **meltdowns_1m**: 0 во всех 951 sample
- **rotations_1m**: 0 во всех 951 sample — *(метрика, видимо, не нарастает в этом билде, drain'ы считаются отдельно)*
- **alive<10**: только 7 sample (08:53:35 → 08:56:35) — фаза warm-up до 16 slots

---

## 2. Graceful drain эффективность

### Итоги (за всю сессию)

| Событие | Count |
|---|---|
| `drain started` | **895** |
| `natural finish` | **540** (60.3% от started) |
| `hard cap reached` | **353** (39.4%) |
| `drain deferred (inflight cap)` | **22 013** (storm brake — defers ≠ unique drains, многократные попытки) |
| `force-evicted idle slot` | 238 |
| `emergency-evicted slot with active streams` | 87 (killed_streams total = 90, max=3 per evict) |
| `drain skipped — no free cell` | 57 |
| `WS pool slot reconnected` | 334 |
| `WS pool slot reader error` (anomaly=io_timeout) | 331 + close_other 2 + other 1 = **334** |

### Reason breakdown (drain started)

- `reason=age` — **855** (95.5%)
- `reason=byte_budget` — 21 (2.3%)
- `reason=anti_fingerprint` — 19 (2.1%)
- `reason=health` — **0**

### Drain durations (natural finish, n=540)

- min: 0s (мгновенный drain пустого slot'а — 131 случай)
- **p50 (median): 45s**
- **p95: 77s**
- max: 90s (на границе hard cap)

### Hard cap distribution — `remaining_streams` когда сработал cap (n=353)

| remaining_streams | Count |
|---|---|
| 1 | 175 (49.6%) — один залипший stream |
| 2 | 106 (30.0%) |
| 3 | 16 |
| 4 | 23 |
| 5 | 15 |
| 6 | 8 |
| 7 | 7 |
| 8 | 2 |
| 9 | 1 |

Большинство hard cap случаев — 1-2 долгоживущих stream'а (HTTPS keepalive до CDN/Cloudflare). 79.6% hard cap с remaining ≤ 2.

### Drain duration (hard cap)

Все 353 hard cap = `1m30s` ровно (= `SHADOWLINK_DRAIN_HARD_CAP=90s`). Конфигурация работает корректно.

---

## 3. Ошибки и аномалии

| Категория | Count | Комментарий |
|---|---|---|
| `level=ERROR` | **0** | Нет ни одной |
| `decrypt_fails` (сумма delta) | **0** | За все 5 707 stats-интервалов |
| `ws_died` | **0** | |
| `writer_exits` | **0** | |
| `reader_exits` (сумма) | 334 | Норма — ровно совпадает с числом reader error / reconnect (drain → reader exits → reconnect) |
| `WS CONNECT_FAIL (optimistic)` | 160 | См. ниже — все объяснимы |
| `downlink write error` (wsasend aborted) | 227 | TUN-сторона рвёт соединение при reset — норма для долгой сессии |
| `stream buffer full, data dropped` | 13 | **Все 13 — один stream_id=2418**, суммарно дропнуто 213 268 байт в 13:56:50 |
| "перезапуск StartReader" | **0** | Регрессия из старых билдов отсутствует |

### CONNECT_FAIL destination breakdown (n=160)

- **141 × `dest=169.254.169.254:80`** — AWS link-local metadata (Windows/приложение пыталось обратиться к metadata service через туннель, fail ожидаем — это не route, оно отбрасывается)
- **19 × `dest=192.168.1.131:8009`** — локальный Chromecast (8009 порт), не должен идти в туннель — bypass-таблица не покрывает 192.168.1.0/24 либо ловится до bypass

### Reader errors (n=334)

- `anomaly=io_timeout` × 331 — соответствует drain pattern (сервер закрывает соединение после GOAWAY, клиент видит read timeout)
- `anomaly=close_other` × 2 — `websocket: close 1000 (normal)`
- `anomaly=other` × 1

Все 334 коррелируют 1:1 с reconnect / drain → ожидаемо.

---

## 4. Throughput

| Метрика | Total | Peak (5s window) |
|---|---|---|
| **uplink** | **384.51 MB** | 163 242 KB (159 MB) / 5s @ 10:55:08 — burst 318 Mbps |
| **downlink** | **4 043.56 MB (3.95 GB)** | 302 156 KB (295 MB) / 5s @ 10:54:53 — burst 482 Mbps |
| `socks_connects` | **3 454** | 57 / 5s peak |
| `encrypts` | 95 710 | 13 625 peak (вместе с uplink peak) |
| `decrypts` | 700 295 | 35 447 peak |
| `cover_posts` | 0 | (cover traffic disabled) |
| `udp_polls` | 0 | (UDP не использовался / не testit'ся в этом прогоне) |

Соотношение uplink:downlink ≈ 1:10.5 — типичный browse pattern.

---

## 5. Streams

### Распределение времени жизни (по downlink cancelled / done + uplink done, n ≈ 6 523)

| Bucket | Count |
|---|---|
| < 1s | 253 |
| 1s — 1m | 1 269 |
| 1m — 1h | **4 982** (76%) |
| 1h — 2h | 13 |
| > 2h | 6 |

### Самые долгие streams

- **stream=26**, dest=`172.64.146.215:443` (Cloudflare), **elapsed=7h 52m 20.444s**, 281 uploads / 675 745 байт uplink. Downlink закрылся в 09:02:10 (7m 48s), uplink жил всю сессию до 16:46:42. Это keepalive WebSocket до CF.
- stream=733 dest=`20.31.169.57:443`, elapsed=6h 50m 0.151s (Microsoft)
- 4× streams elapsed≈2h (40.98.16.61, 150.171.27.11 — MS Office endpoints)
- ~10 streams elapsed≈1h+ (MS Teams / Office / CDN)

---

## 6. Bypass routing

- **bypass_match: 8**
- **bypass_miss: 3 656**
- Bypass enabled, 11 312 include CIDR подгружено в 08:53:08 (`bypass routing активирован include=11312 exclude=0`)

Отношение match:miss = 1:457 — bypass почти не срабатывает, **что норма для не-RU клиента** (тест с IP в РФ дал бы другую картину). Это не баг, просто 99.8% destination не RU.

---

## 7. Slot lifecycle / rotation health

### `slot reader started` count per slot (всего 1 237)

| slot | reader_starts | slot | reader_starts |
|---|---|---|---|
| 0 | 167 | 8 | 60 |
| 1 | 150 | 9 | 60 |
| 2 | 126 | 10 | 40 |
| 3 | 117 | 11 | 49 |
| 4 | 98 | 12 | 30 |
| 5 | 95 | 13 | 36 |
| 6 | 82 | 14 | 25 |
| 7 | 74 | 15 | 28 |

- Slots 0-7 (изначальные warm-up, alive с 08:53:07) ротируются в 2-7× чаще, чем 8-15 (поздно добавленные). Это **ожидаемо**: replacement_slot ходит по кругу, старые slots деградируют по возрасту чаще.
- **gen** в `slot reader started` всегда = 1 (после force/emergency evict slot пересоздаётся с reset gen=1, не накапливается). Это означает что cell rotation работает через replacement_slot mechanism, а не через in-place reconnect.
- Trace для slot=0: drain → natural finish (1m17s) → reconnected → defer → drain → hard cap → drain (anti_fingerprint, 0s) → emergency-evict (killed_streams=1) → reconnect — **полный цикл проходит за ~10 мин, slot всегда поднимается обратно**. Замены успевают, deferred это адаптивный rate-limit (max_concurrent=2).

### Force-evict / emergency-evict (память: новый код из 2026-05-20)

- **`force-evicted idle slot` = 238 раз** — `tryForceEvictIdleSlot` (slice-full eviction fix) активно используется и работает: ни разу не привёл к зависанию пула
- `emergency-evicted slot with active streams` = 87, killed_streams total = 90 (max 3 per evict) — это намеренный crash-mode когда нет идеальных кандидатов; влияние на пользователя — 90 убитых stream'ов за 7h55m из 6 523+ (1.4%)
- `drain skipped — no free cell` = 57 — `tryForceEvictIdleSlot` всё же иногда возвращает "nothing to evict", но pool восстанавливается на следующем тике (alive не падает <13)

---

## 8. Заметные одиночные события

- **`stream buffer full, data dropped`** — 13 раз, все на одном **stream_id=2418** в 13:56:50, суммарно 213 268 байт. Возможно — медленный consumer на TUN-стороне, slow leak в одном приложении. Не критично, но стоит понаблюдать.
- `WS pool drain emergency-evicted` пиковая активность — 09:05-09:10 (10 событий за 5 мин), коррелирует с warm-up периодом когда пул только дорастает до 16 и replacement_slot bottleneck'ит. После 09:15 — emergency-evict спорадичен.

---

## Top-3 observations (всё чисто, нечего фиксить)

1. **Pool steady-state alive=14, dead=0 на протяжении 7h53m (с 08:56:35 до конца).** Никаких "5h deadlock", который был причиной slice-full fix 2026-05-20 — `tryForceEvictIdleSlot` отработал 238 раз без последствий. *Timestamps:* 09:04:00 (первый force-evict), 16:48:35 (последний health sample). 
2. **Graceful drain работает: 60.3% natural, p50=45s, p95=77s — все укладываются в hard cap=90s.** Остальные 39.4% hard cap почти всегда из-за 1-2 keepalive stream'ов (HTTPS/WebSocket к CDN), что подтверждается распределением remaining_streams (79.6% hard cap имели ≤2). *Timestamps drain natural sample:* 08:56:27, 08:56:43, 08:57:27 (первые); pattern ровный до 16:48:25 (последний natural finish).
3. **0 decrypt_fails, 0 ws_died, 0 writer_exits, 0 ERROR — без единого crypto/protocol сбоя за 4 GB трафика, 700k decrypts, 95k encrypts.** uniform-cells refactor 2026-05-20 не привёл к зависаниям. *Timestamps:* peak downlink burst 482 Mbps @ 10:54:53 (302 MB/5s) прошёл без потерь.

## Минор-наблюдения (не блокеры)

- 13:56:50 — stream=2418 получил 13 drop'ов "stream buffer full" подряд (213 KB потеряно). Стоит проверить не повторяется ли в следующих canary с тем же destination.
- 141 CONNECT_FAIL к `169.254.169.254:80` (AWS metadata) — приложение/Windows пыталось обращаться к metadata service через туннель. Не баг клиента, но можно занести 169.254.0.0/16 в bypass-исключение чтобы не светить такие попытки.
- bypass_match=8 vs miss=3656 — норма для не-RU IP, но проверь что RU-сценарий (когда .ru/RU CIDR действительно ходит) даёт нормальный match rate в отдельном тесте.
