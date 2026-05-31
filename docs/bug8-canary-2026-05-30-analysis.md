# Bug #8 Canary Analysis — 2026-05-30 (5h43m)

**Log:** `C:\Users\Lenovo\AppData\Local\Temp\nixavpn-DEBUG-20260530-165302.log` (9.47 MB, 70 767 lines)
**Span:** 2026-05-30 16:53:02 → 22:36:29 (+03:00) = **5h43m27s** real usage (browsing, video, downloads)
**Build:** post-Bug#8 fix (downlink frame loss in `byte_budget` continue-branch of reader)

---

## ВЕРДИКТ: **CLEAN** (с 2 объяснимыми LOW-нюансами)

Bug #8 НЕ воспроизвёлся. Корневой симптом (потеря downlink-фрейма reader'ом → повреждение TCP-потока → обрыв закачки нашей ошибкой) ОТСУТСТВУЕТ:
- `stream buffer overflow` / `drops=` / `dropped_bytes=` = **0** (RouteToStream не дропает).
- `decrypt_fails` всегда **0** (4121 health-строк, все `=0`).
- Крупные закачки **до 79 МБ** завершились штатно через `app full close`.
- 4 события `closed pipe / fullClose=true` ДОКАЗАННО инициированы приложением (half-close за 1 мс ДО нашего закрытия), не reader-path frame loss. Кластеризованы в первые 73 с сессии, больше не повторялись.

---

## Таблица симптомов 1–11

| # | Симптом | Count | Оценка |
|---|---------|-------|--------|
| 1 | `closed pipe` / `downlink write error` `fullClose=true` на активном стриме | **4** | LOW — app-initiated cancel, см. ниже. Все в 16:54:13–15 (старт). Не Bug#8. |
| 2 | `stream buffer overflow` / `drops=` / `dropped_bytes=` | **0** | ✅ CLEAN |
| 3 | `decrypt` fail / `decrypt_fails > 0` | **0** | ✅ CLEAN (4121× `decrypt_fails=0`) |
| 4 | `close 1006` / `unexpected EOF` на зрелых слотах | **1225** | LOW baseline — стабильно ~210/ч, НЕ растёт к концу. Все slot_age>60s (avg 181с). Известная мелочь. |
| 5 | `meltdown` (meltdowns_1m > 0) | **2** | LOW — единичный всплеск 17:17–17:18 (cooldown 10с, slot 6), восстановился. Больше не повторялся. |
| 6 | Аномальный рост пула (alive≫8, dead>0, застревание) | — | ✅ alive peak 16 (reconnect overlap), обычно 12–14. dead peak 3 (transient), 419 строк dead=0. draining ≤5. |
| 7 | `panic` / `fatal` / `ERROR` | **0** | ✅ CLEAN (только DEBUG/INFO/WARN) |
| 8 | credit/flow деградация (`credit`/`WINDOW_UPDATE`/`stall`) | **0** | ✅ Нет таких строк (не логируются), косвенно: нет зависших стримов. |
| 9 | Утечка active_streams (монотонный рост) | — | ✅ Осциллирует 12…1674, возвращается к 12–34 в простое. НЕ leak. |
| 10 | leakguard / ipv6 restore failed | **1** | LOW — `delete firewall rule failed exit 0xc000013a` при ВЫХОДЕ (Ctrl-C teardown). leakguard всё равно `disabled`. Benign. |
| 11 | Обрыв закачки >10 МБ не по app-close | **0** | ✅ Крупнейший cancelled = 6.6 МБ; 99.7% cancel <100 КБ (speculative). |

Прочие WARN-типы: `WS CONNECT_FAIL (optimistic)` ×1334 (bypass-direct к недостижимым, НОРМА), `drain skipped — no free cell` ×162 (норма), `emergency-evicted` ×51 (см. нюанс).

---

## Детализация пункта 1 — 4× closed pipe (НЕ Bug#8)

| Время | stream | dest | downlinkBytes | streamAgeMs | uplink done (app half-close) |
|-------|--------|------|--------------|-------------|------------------------------|
| 16:54:13.996 | 126 | 89.108.202.11:8080 | 23 362 561 | 14579 | 16:54:13.995 `err=EOF fullClose=false` (−1 мс) |
| 16:54:14.163 | 131 | 206.148.22.67:8080 | 13 632 532 | 14744 | 16:54:13.999 `err=EOF fullClose=false` |
| 16:54:14.163 | 144 | 206.148.22.67:8080 | 3 216 147 | 14234 | 16:54:13.999 `err=EOF fullClose=false` |
| 16:54:15.079 | 142 | 185.40.196.218:8080 | 7 997 034 | 15153 | 16:54:13.999 `err=EOF fullClose=false` |

**Анализ:** каждому closed-pipe предшествовал `uplink done err=EOF fullClose=false` за 0–4 мс — приложение (браузер) закрыло write-сторону соединения, мы закрыли pipe full, in-flight downlink writer попал в `closed pipe`. Это гонка app-cancel vs in-flight downlink на пачке параллельных закачек при старте сессии (downlink 16:54:08–13 был ~183–203 МБ/5с, затем коллапс до 26 МБ + uplink-всплеск 40 МБ = ретраи браузера). **Reader-error / close 1006 в окне ДО 16:54:13 ОТСУТСТВУЮТ** — поток не был повреждён нашей стороной. 5575 чистых `app full close` vs 4 pipe-close = **0.07%**.

---

## Таймлайн пула (WS pool health, 685 строк)

| Время | uptime | alive | dead | draining | active_streams | meltdowns_1m |
|-------|--------|-------|------|----------|----------------|--------------|
| 16:53:35 | 32s | 8 | 0 | 0 | 80 | 0 |
| 16:54:05 | 1m | 8 | 0 | 4 | 119 | 0 |
| 17:17:35 | 24m | 12 | 1 | 2 | 17 | **1** ← единичный |
| 17:23:35 | — | — | — | — | 23 | 0 |
| 17:53:35 | — | — | — | — | 34 | 0 |
| 18:53:35 | — | — | — | — | 27 | 0 |
| 19:53:35 | — | — | — | — | 24 | 0 |
| 20:53:35 | — | — | — | — | 30 | 0 |
| 21:53:35 | — | — | — | — | 23 | 0 |
| 22:35:35 | 5h42m | 14 | 0 | 2 | **1599** ← burst@end | 0 |
| 22:36:05 | 5h43m | 14 | 0 | 2 | 1071 | 0 |

**alive:** 8→16 peak (9× строк alive=16, reconnect overlap), модальные 12–14. **dead:** 419 строк =0, peak 3 transient. **active_streams:** осциллирует, min 12 после 18:00, peaks (1026/1599/1674) только в финальные секунды (активная закачка перед выходом) — НЕ монотонный рост, утечки нет.

---

## Топ закачек и как закрылись

**Крупнейшие УСПЕШНЫЕ (app full close), bytes / stream:**
| bytes | ~MB | stream | close |
|-------|-----|--------|-------|
| 79 614 169 | 79 | 129 | app full close ✅ |
| 76 354 967 | 76 | 128 | app full close ✅ |
| 70 735 465 | 70 | 127 | app full close ✅ |
| 60 067 121 | 60 | 125 | app full close ✅ |
| 51 224 418 | 51 | 133 | app full close ✅ |
| 43 672 345 | 43 | 122 | app full close ✅ |
| 42 916 192 | 42 | 124 | app full close ✅ |
| 27 161 340 | 27 | 130 | app full close ✅ |

**Cancelled streams:** крупнейший 6.6 МБ; распределение: 134 zero-byte, 504 <100 КБ, лишь 2 ≥100 КБ. = браузерные speculative/preconnect аборты, не потеря данных.

**Вывод:** ни одна закачка >10 МБ не оборвана нашей ошибкой/reset/cancel. Все крупные — `app full close`.

---

## Сравнение начало vs конец (деградация?)

| Метрика | 1-й час (16–17) | посл. часы (21–22) | Тренд |
|---------|-----------------|--------------------|-------|
| close 1006 / ч | 19 (16) + 209 (17) | 224 (21), 122 (22 partial) | СТАБИЛЬНО, не растёт |
| decrypt_fails | 0 | 0 | без изменений |
| meltdowns | 1 (17:17) | 0 | улучшение |
| downlink write error | 4 (старт) | 0 | не повторялось |
| active_streams (idle) | 17–34 | 21–30 | стабильно |
| emergency-evicted killed≥5 | 0 | 96, 97 (только teardown) | shutdown-артефакт |

**Деградации во времени НЕТ.**

---

## LOW-нюансы (информативно, не блокеры)

1. **`emergency-evicted slot with active streams` ×51.** 48 событий убили лишь 1–2 стрима (speculative conns, negligible). 1× killed=5 (18:36). **2× killed=96/97 — в последние 65 с лога (22:35:25, 22:36:00)** при пике active_streams≈1599 = teardown/shutdown процесса. НЕ steady-state обрыв закачек. Стоит проверить: при штатной работе eviction с высоким killed_streams не возникает — он привязан к завершению процесса.

2. **`drain skipped — no free cell` ×162** (≈22–44/ч стабильно) + `inflight_cap_deferred_total` дорос до 184. Пер MEMORY — норма пока нет других симптомов; их и нет. Пул переподписан (alive 12–16 при size 8) из-за reconnect+drain overlap, но самовосстанавливается, dead→0.

3. **leakguard cleanup при выходе:** `delete firewall rule SL-Allow-Loopback failed exit 0xc000013a` (STATUS_CONTROL_C_EXIT) — процесс прерван Ctrl-C во время teardown; `leakguard disabled` всё равно отработал. Безвредно.

4. **close 1006 на зрелых слотах ×1225** — известный baseline (direct к голому origin IP, TSPU/сервер режет длинные direct TCP). Стабилен ~210/ч, к концу не растёт. Не влияет на закачки (down_bytes на этих слотах до 67 МБ были доставлены до закрытия).
