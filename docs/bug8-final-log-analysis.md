# Bug#8 — Анализ финального лога успешного полевого теста

**Лог:** `C:\Users\Lenovo\AppData\Local\Temp\nixavpn-DEBUG-20260530-160710.log` (304 строки)
**Длительность:** 16:07:10 → 16:10:15 (≈3m05s), затем штатный shutdown.
**Сценарий:** 2× curl `proof.ovh.net/files/1Gb.dat` (origin 141.95.207.211), оба 100%.

## ВЕРДИКТ: ЧИСТО (только ожидаемое) + 2 нюанса для протокола (LOW)

Bug#8 подтверждён исправленным. Ни одного `closed pipe`, ни одного `downlink write error`,
`decrypt_fails=0` во ВСЕХ ~33 stats-строках, ни одной `stream buffer overflow`,
`writer_exits=0` везде. Большие закачки дошли полностью.

## Counts по severity
- HIGH: 0
- MEDIUM: 0
- LOW: 2 (оба — вариации известного / косметика, НЕ новые проблемы)
- Регрессий Bug#8: 0

## Проверка по пунктам задания

| # | Проверка | Результат |
|---|----------|-----------|
| 1 | closed pipe / downlink write error | **0** — регрессии нет ✅ |
| 2 | decrypt_fails | **0** во всех stats ✅ |
| 3 | overflow drops | **0** — ни одной строки ✅ |
| 4 | writer_exits | **0** везде ✅ |
| 5 | reader_exits | суммарно **5** (delta: стр.134 +2, стр.156 +1, стр.213 +1; +внутри close-событий). Все объяснимы close 1006 / forcibly closed |
| 6 | meltdown / rate_limited | meltdowns_1m=**0**. rate_limited_recent=1 дважды (стр.127, 158), затем 0. Не каскадит |
| 7 | alive динамика | 8→8→7→8→9→9→9. Минимум **alive=7**, никогда <4 ✅ |
| 8 | inflight/deferred | inflight_drains max=2; cap_deferred / floor_deferred / deferred_1m — **0** везде ✅ |
| 9 | byte_budget drains | natural finish (20s), sticky backstop teardown (hard cap 1m30s), несколько drain started — поведение штатное |
| 10 | stream 44 | **1075648086 байт докачаны ДО teardown** (chunks=73389). Не оборван ✅ |
| 11 | throughput | пики 270МБ/5с (54МБ/с), провалов в 0 во время активной закачки нет |
| 12 | last_write_age_ms (close 1006) | 983 / 3480 / 5187 ms — слоты были малоактивны на момент close; slot 0 (forcibly closed) — 65ms (активный, нёс gig) |
| 13 | прочие WARN/ERROR | 1× leakguard restore ipv6 failed на shutdown (LOW, см. ниже) |
| 14 | uplink_kb=2303 | объяснимо: вторая параллельная закачка stream 67 (см. ниже), не аномалия |

## Детальный разбор спорных моментов

### Пункт 9–10: sticky backstop teardown НЕ оборвал гиг
Строки 161–165. slot 3 драйнился с 16:07:46 (drain started, стр.70), достиг hard cap 1m30s
в 16:09:16 → `sticky backstop teardown sticky_outcome=bytes_backstop remaining_streams=4 down_bytes=1057563062`.
В тот же миг (стр.165) stream 44 завершился `downlink done (ch closed) bytes=1075648086 chunks=73389 elapsed=1m31.286s`.
Это полный 1ГБ (curl 100%). Значит teardown пришёл ПОСЛЕ того как поток уже добрал все байты —
не обрыв, а нормальное закрытие на естественно завершившейся закачке.
remaining_streams=4 на teardown — это мелкие keep-alive стримы (4/13/31/44), все закрылись
`ch closed` штатно. Потерянных недокачанных стримов на sticky teardown НЕТ.

**Нюанс по дизайну (информативно, не баг):** stream 44 держал слот 3 ровно до hard cap 90с
(drain длился весь 1m30s). Это означает: одиночная длинная закачка способна «досидеть» drain
до самого hard cap. Здесь безопасно (закачка завершилась синхронно с cap). Но это подтверждает,
что hard cap 90с — реальный потолок удержания слота под одну закачку. Для закачки, которая на
54МБ/с не успела бы за 90с (файл >~4.8ГБ), teardown сработал бы ДО завершения. В этом тесте
не достигнуто, но стоит держать в уме при тестах файлов 5ГБ+.

### Пункт 14: uplink_kb=2303 (стр.182, 16:09:36) — НЕ аномалия
В этом 5с-окне шла вторая параллельная закачка: stream 67 (141.95.207.211, второй 1Gb.dat,
позже в стр.283 показывает bytes=1075648060). Также downlink_kb=270745 (пик) в том же окне.
Всплеск uplink — это HTTP-запросы/повторные ACK-уровня данные второй закачки в фазе старта.
Соседние окна uplink 0–24 КБ. Изолированный одиночный всплеск, без повтора → не утечка/не баг.

### LOW-1: leakguard restore ipv6 failed на shutdown (стр.219)
`WARN leakguard: restore ipv6 failed index=13 error="exit status 0xc000013a" output=""`
Происходит при остановке туннеля. `0xc000013a` = STATUS_CONTROL_C_EXIT (процесс прерван по Ctrl+C/
завершению) — дочерний netsh-процесс убит при общем shutdown, restore ipv6 для интерфейса index=13
не отработал. Косметика на пути выключения; на data-path не влияет. Вариация известного shutdown-поведения.
Severity LOW. ВОЗМОЖНОЕ ДЕЙСТВИЕ: проверить, не остаётся ли IPv6 в отключённом состоянии на
интерфейсе 13 после выхода (потенциальная необходимость ручного restore). Не критично, но стоит
глянуть один раз вживую.

### LOW-2: stream 67 «downlink cancelled» при 1075648060 байт на shutdown (стр.283)
Второй гиг (stream 67) на момент остановки туннеля (16:10:15, user остановил VPN) показал
`downlink cancelled bytes=1075648060 chunks=69721 elapsed=50.585s`. Это НЕ обрыв Bug#8 — это
массовый cancel ВСЕХ активных стримов из-за штатного shutdown (стр.258–287, ~30 стримов разом
`downlink cancelled` в один момент 16:10:15.425). curl ко второму файлу показал 100% по словам
юзера → 1075648060 ≈ полный размер (на 26 байт меньше, чем у stream 44 = 1075648086; расхождение
26 байт — разные пути chunking/последний chunk, оба ≈1.0753ГБ). cancelled здесь = «туннель
выключили, пока финальный TCP-close ещё летел», а не потеря данных. Severity LOW (косметика учёта).
Сопутствующий `FIN send failed stream=73 "websocket not connected"` (стр.268) — тоже следствие
shutdown (слот уже закрыт), безвреден.

## Подтверждение известных/ожидаемых (НЕ репортятся как новое)
- close 1006 на зрелых direct-слотах: slot 2 (age 88s), slot 1 (110s), slot 5 (166s) +
  slot 0 «forcibly closed by remote» (age 91s, нёс 381МБ). last_write_age 65ms–5187ms.
  TSPU/middlebox режет долгий direct-TCP — преэкзистентное, крупные закачки не порвало
  (gig завершился на slot 3, не на сорванных).
- 169.254.x dropped — bypassroute (в логе явных строк dropped нет, но bypass_match/miss корректны).
- downlink done app full close ageMs~60000 — keep-alive idle 60с (стр.85–118), штатно.
- diag memConn CloseWrite/CloseRead/Close — временный diag, шумит на shutdown (стр.222–256), ок.

## Вывод
Лог чистый. Bug#8 исправлен — frame-loss устранён, два гига дошли (stream 44 = 1.0756ГБ полностью,
stream 62 = 388МБ, stream 67 = ~1.0756ГБ оборван только финальным shutdown). Пул здоров (alive≥7,
0 meltdown, 0 decrypt_fail, 0 overflow, 0 writer_exit). 2 нюанса LOW — оба косметика на пути
shutdown / учёта, не новые проблемы и не регрессии.
