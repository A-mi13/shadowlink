# Bug #9 — Независимое опус-ревью спеки Stream Migration

**Дата:** 2026-05-31
**Ревьюер:** независимый (не участвовал в дизайне)
**Спека:** `docs/superpowers/specs/2026-05-31-bug9-stream-migration-design.md`
**Код проверен:** server/websocket.go, server/handler.go, client/ws_pool.go, client/client.go, core/chunk.go, core/flowctl.go, core/session.go, proxy/socks5/tcp.go

---

## ВЕРДИКТ: NOT-READY

Спека архитектурно здравая и корень доказан корректно, но **главный риск (порядок байт при переключении, seqBarrier) НЕ закрыт** — это BLOCKER. Спека сама признаёт это open question #1 и не даёт решения. Дополнительно: HMAC-proof имеет дыру в защите от replay/hijack для случая «тот же clientID», и капабилити-негоциация имеет окно неопределённости при апгрейде. Эти три пункта надо закрыть В СПЕКЕ до writing-plans. После их закрытия → READY-WITH-CHANGES.

---

## Таблица находок по severity

| # | Severity | Секция спеки | Находка |
|---|----------|--------------|---------|
| F1 | **BLOCKER** | §5 поток A, OQ#1 | seqBarrier недостаточен. Downlink стрима демультиплексируется на клиенте в ОДИН per-stream channel (`streamChans[streamID]`, slot-agnostic). При миграции reader слота A и reader слота B оба пушат в этот канал. Порядок прихода из двух сокетов недетерминирован → переупорядочивание байт. seqBarrier на сервере не помогает — он только решает «когда сервер ПЕРЕСТАЁТ слать по A», но in-flight данные A могут прийти на клиент ПОСЛЕ первых данных B. Нет per-stream sequence на проводе для реассемблинга. |
| F2 | **BLOCKER** | §4 proof | HMAC streamSecret НЕ привязан к слоту/сессии-получателю. Злоумышленник с тем же clientID (укравший токен клиента, или второе устройство того же аккаунта) знает serverPerClientKey-derived secret для своих стримов, но streamSecret для ЧУЖОГО streamID он не знает — ОК. ОДНАКО: nonce берётся из relayEntry после смерти оригинальной сессии (OQ#3), и спека не определяет, как клиент-злоумышленник НЕ может перебрать streamID (uint16, всего 65536) c valid proof. Проблема: если два устройства делят один clientID (device-limit допускает несколько сессий на clientID — `ratelimit.go` activeSessions[userID]), то serverPerClientKey ОДИН на оба → устройство B может вычислить streamSecret устройства A, зная только streamID и session_nonce. session_nonce передаётся в ответе на CONNECT по зашифрованному каналу устройства A — устройство B его не видит. Но спека НЕ указывает энтропию session_nonce и НЕ требует, чтобы он был непредсказуем. Если nonce = session.ID (uint32, последовательный) → перебор тривиален. Надо: session_nonce ≥ 16 байт из crypto/rand, явно. |
| F3 | **HIGH** | §3 capability, §6 compat | Новый клиент шлёт MIGRATE (FlagMigrate=0x0B) старому серверу. Старый сервер: `default:` case в reader switch → `h.metrics.UnknownFlag.Add(1)` и фрейм молча игнорируется (websocket.go:929-930). Клиент НЕ получит ни OK ни FAIL → зависнет в ожидании MIGRATE_OK таймаут. Спека говорит «capability off → не шлём», но НЕ определяет fail-safe, если capability определена ошибочно (race: capability пришла, но сервер откатили). Нужен timeout на MIGRATE_OK с деградацией к обрыву (как сейчас). |
| F4 | **HIGH** | §5, §4 | Гонка reassociate vs downlink-reader активной старой сессии. Сервер меняет `boundSession` под per-entry lock, но relay-goroutine на сервере (websocket.go:828 `tc.Read` loop) захватывает `session` через замыкание (`session.EncryptChunk` на :831) — это сессия СТАРОГО слота, НЕ читается из relayEntry.boundSession динамически. Чтобы переключение работало, relay-loop ДОЛЖЕН читать boundSession на каждой итерации (под lock или atomic). Спека не описывает этот рефакторинг relay-loop — а это центральная механика. Без него boundSession-смена не имеет эффекта: байты продолжат шифроваться ключом мёртвого слота. |
| F5 | **HIGH** | §5 grace, §4 DoS | Worst-case память не посчитана. maxOrphanedPerClient=32 × maxOrphanedTotal=4096 → до 4096 осиротевших relay одновременно. Каждый держит: open egress-TCP (FD + kernel buffers ~64-256KB) + downBuffer (1 flow-окно). Flow-окно Bug#8 — проверить размер; если 256KB-1MB, то 4096 × (256KB downBuffer + ~128KB kernel) ≈ 1.5-5 GB + 4096 FD. На сервере с обычным ulimit (1024-65536 FD) это исчерпает FD раньше памяти. Нужен явный budget и FD-учёт. LRU eviction по clientID может выселить легитимный длинный стрим того же clientID, который как раз мигрирует — конфликт цели. |
| F6 | **HIGH** | §4 DoS, §5 grace | Grace-окно создаёт НОВЫЙ класс атаки: клиент открывает N стримов, читает медленно (или не читает), роняет WS → сервер держит relay+downBuffer grace-период, продолжая читать с dest в буфер. Атакующий с одним clientID ограничен 32, но с автоматизацией ротации clientID (если whitelist допускает или open-mode) обходит per-client лимит, упираясь только в 4096 global. Это amplification: дешёвый WS-drop заставляет сервер держать дорогой egress-TCP + буфер. Сейчас WS-смерть мгновенно чистит всё — это свойство теряется (отмечено в research-доке, но в спеке риск недооценён). |
| F7 | **MEDIUM** | §5 OQ#2, §4 анти-DPI | Корреляционный сигнал упреждающей миграции. «Слот A замолкает + слот B оживает в Δt» — спека предлагает age-jitter. Но jitter по ВОЗРАСТУ слота не размазывает корреляцию для middlebox, наблюдающего ПАРУ (down на A, up на B) в коротком окне. Если миграция всегда происходит за ~Δt до реза, middlebox видит периодичный паттерн «перед смертью слота всегда оживает соседний». Это может стать сигнатурой хуже текущего поведения (сейчас reconnect происходит ПОСЛЕ реза, не до). Нужно: рандомизировать не только момент, но и то, сразу ли B берёт нагрузку, + распределить миграции стримов одного слота по времени, а не залпом. |
| F8 | **MEDIUM** | §5 грани | RESUME vs grace-expiry гонка. Спека упоминает per-entry lock для MIGRATE vs close, но НЕ для RESUME vs grace-timer expiry. Если grace-таймер сработал (`tc.Close()`, удаление entry) в тот же момент, что RESUME прилетел — RESUME найдёт удалённый entry → RESUME_FAIL(grace_expired). Это корректно деградирует, НО: если таймер ВЫИГРАЛ частично (закрыл tc, но ещё не удалил entry), RESUME может реассоциировать уже-закрытый tc → silent dead stream. Нужна атомарная state-машина orphaned→{resumed|expired}, single-winner. |
| F9 | **MEDIUM** | §5, Bug#8 | Кредиты flow-control «переезжают с relay» (§5 «не меняется»). Но кредиты на СЕРВЕРЕ хранятся в `credits map[uint16]*streamCredit` — ЛОКАЛЬНОЙ переменной runWebSocketSession (websocket.go:502), как и streams. При смене WS-conn новая runWebSocketSession создаёт ПУСТУЮ credits-мапу. Стрим 42 на новом слоте не имеет credit-bucket → `waitForCredit` вернёт 0 → relay-return (websocket.go:820-822). Спека утверждает что кредиты переезжают, но код показывает что они тоже WS-conn-scoped. Нужно: либо credits переезжают в relayEntry, либо при RESUME пересоздаётся credit с правильным остатком. Не описано. |
| F10 | **MEDIUM** | §5, Bug#6 OQ#4 | sticky-drain vs упреждающая миграция. Спека утверждает что миграция снимает стримы со слота ДО drain → sticky видит пустой слот = natural finish. Но порядок НЕ гарантирован: drain может стартовать (по byte-budget/возрасту) ПОКА миграция в полёте (MIGRATE отправлен, MIGRATE_OK не пришёл). Тогда стрим в состоянии «migrating» на drain-слоте → handleSlotDeath(drainTeardown) закроет его streamChan (ws_pool.go:3067-3081) → обрыв до завершения миграции. Нужна явная блокировка drain слота с migrating-стримами или приоритет миграции. |
| F11 | **LOW** | §3 формат | streamID uint16 (2 байта) в формате фрейма. streamID per-session на сервере (research-док B вопрос 2), но relayRegistry ключуется (clientID, streamID). Два разных слота одного clientID могут переиспользовать один streamID (per-session counter стартует с 0 на каждой сессии) → коллизия в registry. Нужен глобально-уникальный streamID per-clientID, не per-session. Спека говорит «глобальный ID стрима» (§3), но код client AssignStream назначает streamID per-pool, надо проверить уникальность across сессий одного clientID. |
| F12 | **LOW** | §4 метрики | constant-time сравнение proof УПОМЯНУТО («сверяет constant-time») — хорошо. Но не указано использовать `hmac.Equal`/`subtle.ConstantTimeCompare`. Зафиксировать явно в спеке как требование. |
| F13 | **LOW** | §5 dest-closed | Случай «сайт закрыл соединение во время grace» (§5) — relayEntry «dest-closed», RESUME отдаёт FIN+остаток. Корректно, но взаимодействие с downBuffer переполнением (backpressure тормозит dest, dest может таймаутить) не описано. |

**Counts:** BLOCKER=2, HIGH=5, MEDIUM=4, LOW=4. Итого 15 находок.

---

## Явный ответ по 9 фокус-пунктам

### 1. Порядок байт при переключении (seqBarrier) — BLOCKER (F1)
**НЕ закрыт.** Проверено кодом: клиентский downlink-демукс (`client.go:932 RouteToStream` + `ws_pool.go:2631 slotReaderWithClient`) пушит данные стрима в ЕДИНЫЙ `streamChans[streamID]` независимо от слота. При миграции reader слота A и reader слота B одновременно живы и оба вызывают `RouteToStream(42, ...)`. Канал сохраняет порядок ВСТАВКИ, но порядок вставки из двух независимых сокетов (A in-flight vs B new) недетерминирован. seqBarrier на сервере определяет только момент, когда сервер перестаёт писать по A — но байты, уже ушедшие в A (в CF/nginx/TCP буферах), могут прийти на клиент ПОСЛЕ первых байт B. Результат: переупорядочивание в TCP-потоке приложения = повреждение.

**Что нужно (обязательно в спеку):** per-stream monotonic sequence number НА ПРОВОДЕ (внутри зашифрованного payload, рядом со streamID), и client-side реассемблер, который буферизует out-of-order и отдаёт в `conn.Write` строго по порядку. Это то самое «per-stream sequence поверх session-seq», которое называет research-док (строка 162) как «самое тонкое место» — спека его потеряла. БЕЗ этого миграция повреждает данные. Явный ACK от клиента (OQ#1) НЕ решает проблему сам по себе — нужен sequence для реассемблинга, плюс ACK как барьер для освобождения буфера A.

### 2. Гонки — частично (F4, F8, F10)
- MIGRATE vs close A: спека даёт per-entry lock + state-машину — концептуально ОК, но F4 показывает что переключение boundSession бессмысленно без рефакторинга relay-loop (читать boundSession динамически).
- RESUME vs grace-expiry: НЕ закрыто (F8) — нужна single-winner state-машина.
- Два MIGRATE на B и C почти одновременно: спека не рассматривает. Идемпотентность «уже на B» (§5) не покрывает случай B затем C — последний выигрывает, но in-flight на B теряется без sequence (см. F1).
- reassociate vs downlink-reader: F4 — главная нераскрытая механика.

### 3. HMAC proof — частично (F2, F11, F12)
Защита от ВНЕШНЕГО злоумышленника (другой clientID): да, serverPerClientKey разный → не подделать. Защита от replay: relayEntry удаляется при закрытии → ОК концептуально. **Дыры:** (а) энтропия session_nonce не специфицирована — если предсказуем (session.ID последовательный), перебор streamID+nonce тривиален (F2); (б) несколько устройств на одном clientID делят serverPerClientKey (F2); (в) streamID коллизии per-session (F11); (г) constant-time только упомянут, не зафиксирован как hmac.Equal (F12). serverPerClientKey/session_nonce — НОВЫЕ конструкты, в коде их нет (проверено grep) — надо проектировать с нуля, KDF от master-ключа описать.

### 4. DoS / лимиты — НЕ достаточно (F5, F6)
Worst-case память НЕ посчитан в спеке. 4096 orphaned × (downBuffer 1 flow-окно + egress-TCP FD + kernel buffers). FD-исчерпание вероятнее памяти. Per-clientID лимит обходится ротацией clientID (если whitelist это допускает). Amplification: дешёвый WS-drop → дорогой server-side hold. LRU eviction может убить легитимный мигрирующий стрим. Нужен: явный budget (память+FD), отдельный учёт FD, защита от clientID-ротации, eviction-политика, не бьющая по active-migrating.

### 5. Анти-DPI (OQ#2) — НЕ закрыт (F7)
age-jitter недостаточен. Корреляция «A замолкает → B оживает за Δt ДО реза» — потенциально новая сигнатура, ХУЖЕ текущего (сейчас reconnect ПОСЛЕ реза). Это критично для протокола, вся суть которого — маскировка. Нужно глубже: рандомизация не только момента старта миграции, но и распределение миграций стримов одного слота во времени + чтобы B не брал нагрузку залпом синхронно с замолканием A.

### 6. Совместимость / capability — частично (F3)
Negotiation off → как сейчас: концептуально ОК. НО fail-safe при ошибочной capability (откат сервера, race) не определён: старый сервер молча дропнет FlagMigrate (default→UnknownFlag), клиент зависнет. Нужен timeout MIGRATE_OK/RESUME_OK с деградацией к текущему обрыву.

### 7. Bug#8 / Bug#6 взаимодействие — НЕ закрыто (F9, F10)
- Bug#8 кредиты: спека утверждает «переезжают с relay», код показывает что credits — WS-conn-scoped локальная мапа (websocket.go:502). НЕ переезжают автоматически. Надо явно перенести в relayEntry или пересоздать при RESUME (F9).
- Bug#6 sticky-drain: гонка drain-старт vs migration-в-полёте может оборвать мигрирующий стрим (F10).

### 8. Реалистичность утверждений о коде — ПОДТВЕРЖДЕНО (с уточнением F4/F9)
- egress-TCP закрывается на websocket.go:780-781 (`<-done → tc.Close()`) и :946-953 (финальный cleanup) — **ВЕРНО**, проверено.
- крипто per-slot (ws_pool.go:2421-2452 SessionForStream/WriteMessageForStream докстринги) — **ВЕРНО**.
- streams — локальная мапа runWebSocketSession (websocket.go:523) — **ВЕРНО**.
- relayRegistry МОЖЕТ вынести tc из-под WS-conn lifecycle — **ДА, архитектурно возможно**, НО спека недооценивает объём: надо отвязать relay-goroutine от `done` (сейчас :766-784 watchdog закрывает tc на `<-done`), читать boundSession динамически в relay-loop (F4), вынести credits (F9). Это глубже, чем «вынести streams в registry».

### 9. Open questions #1-5
- **OQ#1 (seqBarrier/ACK):** BLOCKER. seqBarrier НЕдостаточен. Нужен per-stream wire sequence + client реассемблер + ACK как барьер освобождения буфера A. См. F1.
- **OQ#2 (анти-DPI корреляция):** Реальный риск, age-jitter недостаточен. См. F7. Требует углублённого дизайна распределения, не просто jitter.
- **OQ#3 (session_nonce в relayEntry):** Хранить в relayEntry — ДА, +память приемлема (16-32 байта × orphaned, ничтожно vs downBuffer). НО энтропия nonce ДОЛЖНА быть crypto/rand ≥16 байт, не session.ID. См. F2.
- **OQ#4 (sticky-drain конфликт):** КОНФЛИКТУЮТ при гонке. См. F10. Нужна координация: migrating-стрим блокирует drain-teardown или миграция приоритетна.
- **OQ#5 (UDP вне scope V1):** СОГЛАСЕН — UDP stateless, переподключение дёшево, вне scope V1. Зафиксировать явно. Единственное: SOCKS5 UDP ASSOCIATE привязан к слоту (CLAUDE.md udpMinReadySlots) — убедиться что смерть слота с UDP не ломает migration-логику TCP-стримов.

---

## Что ОБЯЗАТЕЛЬНО исправить в спеке до writing-plans

1. **[BLOCKER F1]** Добавить per-stream monotonic sequence на проводе + client-side реассемблер out-of-order + явный ACK как барьер. Без этого данные повреждаются. Это центральная переработка §5.
2. **[BLOCKER F2]** Специфицировать session_nonce: ≥16 байт crypto/rand, непредсказуем. Описать KDF serverPerClientKey от master. Решить проблему shared clientID между устройствами (либо привязать proof к session_nonce конкретного устройства, либо per-device key).
3. **[HIGH F4]** Описать рефакторинг server relay-loop: читать boundSession динамически (atomic/lock) на каждой итерации Read→Encrypt. Без этого boundSession-смена не работает.
4. **[HIGH F9]** Описать перенос/пересоздание Bug#8 credit-bucket при миграции (credits сейчас WS-conn-scoped).
5. **[HIGH F3]** Добавить timeout на MIGRATE_OK/RESUME_OK с fail-safe деградацией к обрыву (для старого сервера / capability race).
6. **[HIGH F5/F6]** Посчитать worst-case память+FD, добавить FD-budget, защиту от clientID-ротации, eviction-политику не бьющую по active-migrating.
7. **[MEDIUM F7]** Углубить анти-DPI дизайн: распределение миграций во времени, не залп; B не оживает синхронно с замолканием A.
8. **[MEDIUM F8]** Single-winner state-машина orphaned→{resumed|expired} для RESUME vs grace-expiry.
9. **[MEDIUM F10]** Координация drain vs migration-в-полёте.
10. **[LOW F11/F12]** streamID уникальность across сессий одного clientID; зафиксировать hmac.Equal.

Рекомендация research-дока (строки 251-262) измерить долю длинных vs коротких стримов ПЕРЕД полным A — здравая. Стоит сохранить как pre-flight: если большинство обрывов — короткие стримы, дешёвый retry даёт основной выигрыш за S-M без BLOCKER-рисков F1/F2.
