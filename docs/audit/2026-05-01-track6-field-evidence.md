# Track 6 — Field evidence (2026-05-01 ~10:44 MSK)

**Источник:** клиентский лог nixavpn-client.exe на Windows под throttle хостера (datacanvases.com / 172.67.133.218 — Cloudflare orange-cloud).

**Контекст:** field-test после shipping'а Tier S R.1 + R.3a (`bin/` от 09:49). Цель — проверить что cascade под throttle (`data-plane-drift-2026-04-30.md`) закрыт. **Не закрыт полностью** — ниже список новых findings, которые надо включить в consolidated report.

---

## F1 — `Critical` overflow в slotBackoffDuration при больших attempt

**Доказательство:**
```
WS pool reconnecting slot=3 backoff=-2562047h47m16.854775808s attempt=37
```

`-2562047h47m16.854775808s` ≈ `time.Duration(math.MinInt64)`. Это integer overflow при exponential backoff: 5s × 2^37 → выходит за `int64` после ~63 итераций умножения, но судя по escape — гораздо раньше из-за float64 → time.Duration кастинга.

**Эффект:** negative duration → `time.Sleep(negative)` возвращается мгновенно → reconnect-storm БЕЗ backoff. Симптомы видны в той же серии:
```
attempt=24 slot=3 backoff=1m0s
attempt=37 slot=3 backoff=-2562047h...  ← overflow
attempt=37 (после reconnect) slot=3 backoff=1m0s ← снова cap, но уже после storm
```

Между `attempt=24` и `attempt=37` slot успел сделать 13 неудачных попыток за <30 секунд — это и есть storm.

**Где искать:** `shadowlink/client/wspool/` (или там где живёт `slotBackoffDuration`). `cap=60s` post-jitter не спасает — overflow happens ДО clamp'а.

**Fix предложение:** clamp attempt до `attempt = min(attempt, 6)` ДО expo: `5s × 2^min(attempt, 6) = max 320s` → потом cap 60s. Или явный guard `if exp > 60 { return 60 }`.

---

## F2 — `Critical` Server возвращает decoy HTML на WS upgrade при rate-limit

**Доказательство:**
```
WS pool slot reconnect failed slot=4 err="slot 4: handshake: server returned HTML instead of JSON
(first 200 bytes): <!DOCTYPE html>\r\n<html lang=\"en\">\r\n  <head>\r\n    <meta charset=\"UTF-8\" />
\r\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\" />\r\n\r\n
<!-- SEO — Go заменяет плей"
```

HTML — наша live decoy template. Server обслуживает её на пути `/ws` когда срабатывает `per-clientID handshake rate limit` (Tier S R.4 spec).

**Проблема 1:** rate-limit hit очень рано. Slot=2 attempt=9, slot=4 attempt=2, slot=0 attempt=3 — после нескольких неудачных попыток сервер уже считает clientID злостным.

**Проблема 2:** decoy HTML вместо явного `429 Too Many Requests` или close с кодом — клиент не может различить "rate-limited" vs "decoy" vs "down" → одинаковый exponential backoff для всех трёх кейсов. Под throttle хостера TLS ломается → клиент попадает в rate-limit → backoff 60s → snowball.

**Fix направление:** добавить sentinel-сигнал rate-limit'а ВНУТРИ decoy (специальный header / tag) или на отдельной WS close-code чтобы клиент мог отличить и применить более длинный, фиксированный cool-down (например, 120-300s) вместо exponential, который и так уплыл.

---

## F3 — `High` Zombie streams не очищаются при slot reconnect

**Доказательство:**
```
uplink done dest=91.105.192.100:443 stream=12 bytes=462 uploads=2 elapsed=50m19.795s
uplink done dest=91.105.192.100:443 stream=10 bytes=326 uploads=2 elapsed=50m19.811s
uplink done dest=149.154.167.51:443 stream=25 bytes=410 uploads=2 elapsed=50m19.438s
```

Стримы 10, 12, 13, 16, 24, 25 жили **50 минут 19 секунд** с 2 uploads каждый (≈один upload на 25 минут). Это либо:
- Telegram-style long-poll keepalive (правдоподобно для `91.105.192.100` — Telegram MTProto)
- ИЛИ zombie streams которые копили pending writes пока pool лежал

В обоих случаях: `BroadcastStreamClose` (T1.7) НЕ закрывает их когда все слоты падают — стримы продолжают `stream assigned` копиться (`pending=70`).

**Где смотреть:** `shadowlink/core/broadcast.go` (T1.7 errgroup) и логика "когда нет ready slots". Сейчас pool возвращает `err="ws pool: no ready slots"` на `uplink write` — но read-side стрима не закрывается → goroutine висит.

---

## F4 — `High` Pool starvation cascade: 70+ pending streams pile up до восстановления slot'а

**Доказательство:** в окне 10:44:32–10:44:36 (4 секунды) на slot=0 (единственный временно живой):
```
pending=52 → 54 → 55 → ... → 70 streams=1-3
```

И большинство — `connection refused` от exit'а (Telegram IPs `149.154.167.41/51` — RU-blocked в РФ, exit отдаёт refused). Это не наша проблема — клиент просит refused dest. Но pool аккумулирует ИХ всех в pending заодно.

**Эффект:** живой slot захлёбывается; остальные 7 slots пытаются reconnect → попадают в decoy/rate-limit → не помогают.

**Fix направление:**
1. Per-stream pre-flight: если pool degraded (<2 ready slots), fail-fast NEW SOCKS5 connect вместо assign-and-queue.
2. Bound pending size per slot (сейчас слот=0 принял 70 pending — это явно >> capacity).
3. Sticky assignment: если single slot сейчас survivor, не размазывать новые streams по нему.

---

## F5 — `Medium` "Все reader'ы вышли" loop повторяется

**Доказательство:**
```
10:44:14 WS Pool: все reader'ы вышли, перезапуск StartReader backoff=8s
10:44:30 WS Pool: все reader'ы вышли, перезапуск StartReader backoff=16s
```

Через 16 секунд backoff удвоился. Если cascade продолжается, дойдёт до cap'а и reader-restart станет редким — это значит **fallback poll mode** активирован (см. `Download stream завершился, poll fallback активен`), но poll mode неясно как себя ведёт под throttle. Нужно проверить полный код-путь.

**Где смотреть:** `shadowlink/client/transport/` где живёт `StartReader` + poll-fallback.

---

## F6 — `Medium` UDP ASSOCIATE без активных слотов

```
10:44:25.651 SOCKS5 UDP ASSOCIATE (WS) udp_addr=127.0.0.1:65384
```

UDP ASSOCIATE поднимается даже когда pool degraded (только slot=3 живой и тот секунду назад reconnected). UDP packets потом улетают в blackhole (`udp_polls=0` в stats). Не critical, но: SOCKS5 UDP ASSOCIATE должен проверять readiness pool'а и failing fast если нет слотов.

---

## Связь с предыдущими findings

| Field finding | Связан с |
|---|---|
| F1 overflow | `phase-1-debt-closure-done.md` Tier S R.1 — этот fix НЕ покрыл overflow при больших attempt |
| F2 decoy на WS rate-limit | Tier S R.4 spec в `2026-04-30-current-state-and-improvements.md` — пометить implementation-needed |
| F3 zombie streams | T1.7 BroadcastStreamClose в `phase-2-tls-modernity-done.md` — вероятно не вызывается на cascade close |
| F4 pool starvation | Tier S целиком — backpressure отсутствует |
| F5 reader loop | Tier A throughput backlog |

## Приоритезация для consolidation

- **P0** (блокер для prod throttle): F1 overflow, F2 decoy-as-ratelimit ambiguity
- **P1** (критично для UX): F3 zombie cleanup, F4 starvation backpressure
- **P2**: F5 reader loop visibility, F6 UDP guard

## Repro

Лог снят на:
- Клиент: `bin/nixavpn-client.exe` (build 2026-05-01 09:49)
- Сервер: datacanvases.com (104.222.177.67), CF orange-cloud, под VPS throttle (превышен трафик-лимит у hostера)
- Время: 2026-05-01 10:44:11–10:44:36 MSK (25-секундное окно cascade'а)
