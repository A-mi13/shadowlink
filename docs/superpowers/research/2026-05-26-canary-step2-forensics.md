# Канарейка 2026-05-26 Step 2 — forensics & research findings

**Log:** `nixavpn-graceful-drain-20260526-095616.log` (4h42m, 09:56–14:38).
**Binary:** `bin/nixavpn-client-graceful-drain.exe` md5=d0cb4ed8... (Step 2).

## Headline

Step 2 (per-stream idle decision) **не дал прироста natural_ratio** — 55.8% vs 56% baseline Step 1.
Прогноз spec'и был 77.6%. Дельта = +0.2pp (в пределах stochastic noise).

**Step 2 функционально работает корректно** — `allStreamsIdle` правильно классифицирует. Refactor оставил код чище (убрал `slot.lastActivityNs`), починил R2-H2 ReleaseStream race. Регрессий нет.

## Почему гипотеза H1 не сработала

Step 1 показал что 64.9% hard caps имеют `idle≥1 + active≥1` — мы предположили что "active=1" это короткий trickle heartbeat. **Реальность по сегодняшним diag**:

В 231 H1 hard cap events:
- 100% случаев `diag_min_stream_age_ms < 30000` (самый молодой stream <30s — реально активен)
- 40% — самый молодой <5s
- 85% — самый молодой <15s

В bucket=2 H1 (102 кейсa): один stream живёт >60s в 90% случаев (long-lived idle), но второй stream **пишет данные <30s интервалами**. Это не heartbeat-ping (15-25s spacing) — это реальный data stream.

**Step 2 корректно НЕ teardown'ит такой slot** (один из streams реально активен). Иначе был бы data loss.

## Ключевая архитектурная находка

**Hard cap НЕ убивает streams.** Анализ 3275 unique stream IDs за сессию:
- **3275/3275 (100%) получили clean `uplink done`/`downlink done`**
- Sum `remaining_streams` в 348 hard caps = 830 — но все эти streams позже завершились штатно
- В коде (`ws_pool.go:2748`): `deathCauseDrainTeardown` освобождает cell, **streams продолжают читать/писать**

Hard cap = только slot teardown, не stream kill. Streams перенаправляются через replacement slot (uniform-cells pool, Phase 3 ws_pool refactor 2026-05-20).

## User-visible симптомы (что реально болит)

Из всего лога (4h42m, 3275 streams):

| Сигнал | Count | Severity |
|---|---|---|
| ERROR events | 0 | — |
| decrypt_fails | 0/473245 decrypts | — |
| stream buffer overflow | 1 (на user disconnect в конце сессии) | low |
| stream buffer full data dropped | 0 | — |
| reader_exits | 1 (по 1006 abnormal closure через 162s) | low |
| writer_exits | 0 | — |
| downlink write error (client SOCKS RST) | 97 | информативно |
| meltdowns_1m | 0 (max за всю сессию) | — |
| force_evict (slice-full) | 0 | — |

**Hard cap → downlink write error correlation (окно +30s):**  
35/348 = **10.1%** hard caps сопровождаются client-side RST. 89.9% hard caps "тихие".

97 downlink write errors не значит "наш баг" — это нормальное поведение когда:
- Браузер закрыл tab (SOCKS RST в нашу сторону)
- Background app завершил HTTPS keepalive
- Mobile screen lock

Это видно по top-destinations RST: `74.125.153.230 (Google)` 42 случая, `185.40.196.218:8080`, `109.233.89.131:8080` — это патерн HTTP-poll'ов фоновых приложений Windows.

## Что такое 44% hard cap реально

Это:
1. Slot достиг age budget (90s drain hard cap)
2. На нём есть >=1 real-active stream который **продолжал писать данные** в течение последних 30s
3. Дальше slot закрывается, capacity transferred to replacement, streams продолжают жить через replacement

**Не data loss. Не connection break. Не bug.** Это "slot rotation completed while data was flowing" event.

## Stream lifetime distribution

```
uplink done:   n=2797  p50=220s  p90=430s  p95=672s  p99=1744s  max=3051s (51m)
downlink done: n=1685  p50=181s  p90=288s  p95=314s  p99=367s   max=429s
```

69.4% uplinks и 89.0% downlinks живут >90s — то есть **большинство streams длиннее чем drain hard cap budget**. Это объясняет почему hard cap происходит часто — streams **по природе** долгоживущие.

## Что говорит destination pattern

TOP destinations long-lived streams (>90s):
- `142.251.1.94`, `74.125.205.94`, `209.85.233.95` — Google services (YouTube, Drive, Maps)
- `172.64.146.215`, `104.18.41.41` — Cloudflare assets
- `34.36.73.246` — Google Cloud
- `149.154.167.51` — Telegram MTProto

Это **легитимные long-lived HTTPS connections** (video streaming, push notifications, file transfer, Telegram persistent connection). Все они реально пишут данные в туннель — `allStreamsIdle` правильно их видит как active.

## Pool health (4h42m)

- alive=8-9 (target=8, +1 replacement during drain — норма)
- 0 meltdowns
- 0 force-evict (Phase 3 ws_pool refactor больше не нужен)
- 0 deferred drain в финале (deferred_drains_1m max=45 в пике, но это рабочая нагрузка)
- inflight_cap_deferred_total grew к 342 за сессию (это **исторический counter**, не сейчас) — норма для 4h42m работы

**Pool полностью здоров.**

## Итог research

**Step 2 не дал прироста потому что H1 hypothesis была неверна:** 44% hard cap'ов — это не heartbeat-trickle, а реальные active data streams. Они правильно держат slot. Step 2 правильно их не trips.

**Hard cap не является user-visible проблемой:**
- Streams выживают через teardown (100% clean done event)
- 10.1% корреляция с RST = в основном legitimate user-end disconnects
- 0 data loss, 0 decrypt fails, 0 ERROR

**Открытый вопрос: что мы тогда оптимизируем?** Без ответа на это — любое следующее изменение будет цеплять metric ради metric.

## Возможные направления (для дальнейшего brainstorming)

1. **Принять текущее состояние как baseline.** Hard cap = "slot rotation while data flows" — это работает. Закрыть direction H1, открыть anti-DPI / новые протоколы.

2. **Anti-DPI fingerprint risk.** Slot тuр'ится ровно на 90s drain hard cap → timing pattern может быть видим в TCP timing. Решение: jittered hard cap budget (75-120s log-normal), вынести exact-90s point-mass.

3. **Resource efficiency.** Hard cap = force teardown TCP connection + slot replacement = TLS handshake cost. При 348 hard caps за 4h42m = ~75/hour = ~1 TLS handshake/min. Можно ли это снизить? Например, увеличить slot age budget с текущего до 3-5 min для long-lived streams.

4. **HTTP/2 GOAWAY semantics deeper.** Сейчас replacement slot принимает новые streams, а existing streams продолжают через старый slot до его hard cap. Можно ли **на лету** мигрировать stream с draining slot на replacement (stream ID rewriting) чтобы вообще не было hard cap? Большая работа, но решает корневую причину.

5. **Stream cancellation сигнал от сервера.** Server знает когда reply finished (HTTP response complete). Может в коротком keepalive frame передавать клиенту "stream X — server-side done, cleanup OK". Сейчас stream держится до timeout/client close.
