# Stream Migration (QUIC-style) — проектный документ и честная оценка

**Дата:** 2026-05-29
**Вопрос:** делать ли крупную переделку протокола, чтобы длинный стрим (большая закачка) переживал ротацию WS-слота БЕЗ обрыва?
**Контекст:** Bug #6 в таск-листе ("ротация слота рвёт большие файлы >90s закачки").

**TL;DR вердикт:** Полную stream migration делать НЕ стоит. Это недели работы, серверная переделка модели сессий/тоннелей, и — главное — она **ухудшает скрытность** (объединяет N TCP под один crypto-контекст, рушит модель "каждый слот = отдельная браузерная вкладка", которая является ядром mimicry). При этом проблема **уже на 90% решена** существующим graceful drain (slot не рвётся при ротации, пока на нём есть активные стримы — drainHardCap=90s). Рекомендуемый путь — **Вариант 1 (sticky slot для больших стримов) + увеличение/адаптация backstop**, это дни работы, ноль изменений на проводе, ноль риска для скрытности.

---

## 1. Что сейчас привязано к слоту vs клиенту

### Crypto-сессия — ПЕР-СЛОТ. Это факт, подтверждённый кодом.

- `client/ws_pool.go:214` — «poolSlot is a single WebSocket connection in the pool **with its own crypto session**».
- `client/ws_pool.go:222-224` — `poolSlot{ transport; session *core.Session; token []byte; ... }`. Каждый слот держит свой `*core.Session`.
- `client/ws_pool.go:1485-1536` — `connectSlot` делает ОТДЕЛЬНЫЙ handshake на каждый слот (`core.CompleteHandshake` → `slot.session = session`), получает новый `session.ID` и свой `token`.
- `client/ws_pool.go:1418` — явный комментарий: «Each slot has its own crypto session — must use slot.session, not global client session.»
- `client/ws_pool.go:2211-2223` `SessionForStream` — стрим → слот → `slot.session`. Старый fallback «на сессию первого слота» УДАЛЁН (spec 2026-05-20 §2.5, C4 review), потому что давал silent decrypt-fail: **сервер кеирует сессии пер-слот**.

Каждая `core.Session` (`core/session.go:33-97`) несёт собственные `SendKey/RecvKey`, GCM-эпохи (`sendEpochPtr`), `sendSeq`, anti-replay bitmap (`recvBitmap`), `MimicrySession` (sticky next_poll lambda). То есть **ключи, seqnum и mimicry-состояние — всё пер-слот**.

### Почему пер-слот (история, не случайность)

1. **Mimicry.** `core.MimicrySession` (`core/mimicry_session.go:28-32`) хранит sticky `NextPollLambda` (Pareto α=1.5). Каждая сессия = «отдельная аналитическая сессия браузера» со своим polling-ритмом. См. `CLAUDE.md` § «Analytics Mimicry Engine»: «Session rotation: 2-8 min rotation … to mimic browser sessions». Несколько WS = несколько вкладок/сессий GA4/Mixpanel.
2. **Безопасность handshake.** Сервер привязывает один WS = одна сессия через `authenticateFirstFrame` (`server/websocket.go:144-164`): первый кадр несёт `[hint(4) || enc_token(32) || enc_chunk]`, по hint резолвится сессия, дальше ВСЕ кадры этого WS дешифруются ЭТОЙ сессией (`server/websocket.go:583`). `Tunnel.WSAttached` CAS (`server/handler.go:111-117`) запрещает двум транспортам делить одну сессию (audit A3-S-HIGH-2) — иначе seq-num exhaustion и недетерминированный CONNECT-routing.
3. **Параллелизм seqnum.** Каждый слот инкрементит свой `sendSeq` лок-фри (`core/session.go:307-326`, A1-M2 fix). N слотов = N независимых nonce-counter, ноль contention.

### Можно ли сделать ОДНУ client-level сессию для всех слотов?

Технически да (общий `core.Session`, ключи живут на клиенте, не на слоте). Но это и есть «полная stream migration» со всеми её минусами (см. §3, §7). Это не локальная правка — это смена несущей модели.

---

## 2. Wire-format сейчас и что изменилось бы

Текущий провод (`docs/protocols/body-prefix-v1.md`, `core/chunk.go`):

- Данные едут в analytics-конверте `{"events":[{"type":"page_view","data":"<base64>"}]}`.
- WS-кадр: `[tokenWithHint(36B)] [encrypted_chunk]`. `tokenWithHint = 4B XOR hint || 32B AES-GCM(token)`.
- `encrypted_chunk` = `core.Chunk` = `sess_id(4) + seq_num(4) + flags(1) + payload`, всё под AES-256-GCM (`core/chunk.go:35-40`, `HeaderSize=9`).
- `streamID` — это **первые 2 байта payload** ВНУТРИ шифротекста (`core/chunk.go:190-197` `NewStreamDataChunk`, `ParseStreamID` :232). DPI его не видит — он зашифрован.
- Сервер демультиплексирует: WS → сессия (по hint, один раз в первом кадре) → внутри одной сессии `streamID` маршрутизирует в `StreamConn` (`server/websocket.go:593-599`, `server/handler.go:90-95`).

**КЛЮЧЕВОЕ:** `streamID` — пер-сессия (= пер-слот, = пер-WS), НЕ глобальный per-client. Каждый WS имеет свою локальную `streams map[uint16]*StreamConn` (`server/websocket.go:594-595`).

### Что изменилось бы на проводе при единой сессии

- Один `sess_id` появился бы на N разных TCP-соединениях одновременно. Сейчас один `sess_id` живёт строго на одном TCP.
- Anti-replay window (16384, `core/session.go:19`) пришлось бы держать общим на все слоты — он уже спроектирован под это («Per-stream WS mode: 80+ concurrent goroutines share one session» — но это про **один** WS с мультиплексом, НЕ про N WS с одним sess_id). Серверу пришлось бы принимать seq из одной сессии с N TCP — out-of-order разброс вырос бы кратно.
- `streamID` пришлось бы поднять до **глобального per-client** пространства, и сервер должен был бы маршрутизировать стрим в upstream-TCP независимо от того, с какого WS пришёл кадр.

Сам зашифрованный envelope на байтовом уровне **не меняется** (DPI и так не видит sess_id/streamID — они внутри GCM). Новый detectable-паттерн НЕ появляется на уровне байтов конверта. Риск скрытности — НЕ в байтах, а в **корреляции** (см. §3).

---

## 3. СКРЫТНОСТЬ — главный вопрос. Честная оценка: единая сессия УХУДШАЕТ скрытность.

Это не байтовый сигнал (GCM скрывает sess_id), а **поведенческая корреляция**, и она работает против нас.

### Текущая модель = сильная

Каждый WS-слот — независимая «аналитическая сессия»:
- свой sticky polling-ритм (`MimicrySession.NextPollLambda`, Pareto),
- свой byte-budget рандомизированный в полосе 4-30 MiB (`ws_pool.go:277-300`) — специально размазан, чтобы наши ротации не давали бимодальный кластер (комментарий :289-295 прямо ссылается на Citizen Lab «Stranger DPI in Russia» Aug 2024 и per-flow byte counters как detection vector),
- свой stagger-offset (`ws_pool.go:302-321`) для FFT-смазывания моментов ротации,
- jittered keepalive (`±30%`, F-NEW-1/NEW-4),
- ротация 2-8 мин «как закрытие вкладки браузера».

Для DPI это выглядит как **браузер с несколькими открытыми вкладками аналитики**, каждая со своей независимой сессией и жизненным циклом. Это и есть phantom-персона.

### Единая сессия = слабее

Если все N TCP делят один `sess_id` и один crypto-контекст:
- Один логический поток **размазан по N TCP с одинаковым crypto-контекстом** — это уже **не** «N независимых вкладок», а «один long-lived поток, мультиплексированный по N соединениям». Ближе к QUIC connection migration — а это ровно тот паттерн, который TSPU умеет ловить (MASQUE/QUIC-migration сейчас активно режется в РФ, см. MEMORY `quic-blocking-rf-2026`).
- Ротация WS перестаёт быть «закрытием вкладки» — становится «миграцией пути одного соединения». Появляется корреляционный сигнал: TCP_A умирает → ровно тот же логический поток мгновенно продолжается на TCP_B без нового handshake. Это **path-validation-like** поведение, узнаваемое.
- Sticky-mimicry (`MimicrySession`) пришлось бы делать общим — теряется разнообразие polling-ритмов между «вкладками».

**Вывод по §3 (честно):** Полная stream migration — это шаг ОТ «выглядим как браузер с вкладками» К «выглядим как QUIC-migration-туннель». Для РФ-DPI 2026 это движение в сторону более детектируемого класса, а не от него. Это весомый аргумент ПРОТИВ. Если делать миграцию — пришлось бы дополнительно маскировать «эстафету» под новый handshake, что съедает весь выигрыш по скорости/бесшовности.

---

## 4. Как сервер должен принять мигрированный стрим (объём серверной переделки)

Сейчас (`server/handler.go`, `server/websocket.go`):
- `tunnels map[uint32]*Tunnel` keyed by `session.ID` (`handler.go:63`, :579).
- Внутри WS-read-loop живёт локальная `streams map[uint16]*StreamConn`, и **upstream TCP (`StreamConn.TargetConn`, `handler.go:90-92`) физически создаётся и живёт в этой goroutine**.
- Стрим 42 на слоте N = `TargetConn` в тоннеле сессии N, в goroutine этого WS.

Для миграции «стрим 42 теперь приходит со слота M» серверу нужно:
1. **Глобальный per-client streamID** (не per-session). Сейчас streamID живёт в пространстве одной сессии — пришлось бы ввести client-identity поверх sessions и общий реестр стримов.
2. **Отвязать upstream TargetConn от WS-goroutine/сессии** — вынести в client-level реестр `map[globalStreamID]*StreamConn`, чтобы кадр с любого WS мог дописать в тот же upstream-сокет. Сейчас это намертво local-scope (`websocket.go:594-598`).
3. **Переписать relay-модель**: upstream→client запись сейчас идёт в `Tunnel.Outgoing`/download-stream конкретной сессии. При миграции downstream-кадры стрима 42 должны уметь уехать в активный WS, а не в умирающий.
4. **Разрулить anti-replay/seqnum на едином пространстве** при N конкурентных TCP.
5. **«Принять эстафету» без нового handshake** — иначе бесшовности нет; а это и есть детектируемый сигнал из §3.

Это не «добавить поле» — это переписать ядро server-side multiplexing (`handler.go` ~80KB, `websocket.go` ~31KB) и client-side pool/stream-routing (`ws_pool.go` ~120KB). Оценка только серверной части — 1.5-2.5 недели + риски в крипто-инвариантах (nonce/replay), которые уже стоили серии audit-фиксов.

---

## 5. Альтернатива попроще — Вариант 1: sticky slot для больших стримов. Это НЕ «из говна и палок».

**Важнейший факт: бесшовность при ротации УЖЕ В ОСНОВНОМ есть.** Graceful drain (`SHADOWLINK_GRACEFUL_DRAIN`, **ON since 2026-05-20**) уже реализует «слот с активными стримами не рвётся мгновенно»:

- `WriteMessageForStream` (`ws_pool.go:2241-2260`) — стрим, привязанный к слоту, продолжает слать кадры через него ДАЖЕ когда слот в `slotDraining`. Фоллбэк на другой слот запрещён (другая crypto-сессия → decrypt-fail на сервере). Комментарий :2228-2236 это прямо фиксирует.
- `drainWatchdog` (`ws_pool_drain.go:557-643`) держит дренируемый слот живым, опрашивая `streams.Load()` каждые `drainPollInterval`, и рвёт его ТОЛЬКО когда стримов 0 (natural finish) ИЛИ истёк `drainHardCap` (default **90s**).
- Канарейки показали natural-finish ratio 53-55% (MEMORY), pool здоров.

То есть проблема Bug #6 **сводится к одному**: закачка, которая длится дольше `drainHardCap` (90s) И дольше, чем готов ждать backstop, рвётся при hard-cap teardown. Это уже не «ротация рвёт всё», а «ротация рвёт стримы длиннее 90s».

**Вариант 1 = достроить уже существующий механизм, а не строить новый:**

1. **Per-stream hard-cap exemption / «sticky big stream»:** слот, на котором висит активный стрим с большим объёмом (используя уже существующий `downBytes`/`byteBudget` per-slot и `streamEntry.lastWriteNs`), НЕ форсит teardown по hard-cap, пока этот стрим жив и активен (`allStreamsIdle` уже умеет отличать активные от idle, `stream_entry.go:122-145`).
2. **Adaptive backstop:** растянуть/снять `drainHardCap` для слота с одним длинным активным download-стримом (это уже `time.Duration` env `SHADOWLINK_DRAIN_HARD_CAP`, тюнится без редеплоя). Риск: слот живёт дольше → анти-TSPU байт-бюджет на ЭТОМ слоте не срабатывает → возможен middlebox-kill около ~200MB. Но это **частичный** проигрыш скрытности на ОДНОМ слоте при активной большой закачке, а не системный (остальные N-1 слотов ротируются как обычно). Для пользователя «файл докачался» > «слот ротировался по графику».
3. **Cap по числу/возрасту sticky-слотов:** не более 1-2 слотов в режиме sticky одновременно, чтобы не выродиться в «всё липкое».

Честное сравнение:

| | Полная миграция | Вариант 1 (sticky + adaptive backstop) |
|---|---|---|
| Объём | 3-5 недель (client+server+crypto), высокий риск регрессий | 2-5 дней, достройка существующего drain |
| Провод | меняется (глобальный streamID, общий sess) | НЕ меняется |
| Скрытность | **ухудшается** (QUIC-migration-паттерн, §3) | нейтрально/чуть хуже на 1 sticky-слоте при большой закачке; остальные чисты |
| Скорость | риск seqnum-contention (§7) | без изменений |
| Решает Bug #6 | да, полностью | да, для подавляющего большинства (закачка не рвётся, пока активна) |
| Откат | сложный | тривиальный (env flag) |

**Вывод §5:** Вариант 1 — это не костыль, это правильная достройка graceful drain, который и был задуман как «GOAWAY-style draining, active streams survive rotation» (CLAUDE.md, env-таблица). Полная миграция решает редкий хвост (стрим >90s, который backstop не дотянул) ценой недель работы и потери скрытности.

---

## 6. QUIC reference — применимо ли?

QUIC решает это через Connection ID (стрим привязан к connection, не к 4-tuple/path) + path validation при смене пути. Аналог для нас = «client connection ID» поверх слотов, общая сессия, эстафета стрима между TCP.

Применимо технически, но:
- Это и есть «полная миграция» из §1/§4 — общий sess_id поверх N TCP.
- Главное: QUIC connection migration **сам по себе является детектируемым паттерном для TSPU** (§3, MEMORY `quic-blocking-rf-2026` — TSPU режет QUIC). Копировать механизм, который цензор уже умеет ловить, в протокол, чья ЕДИНСТВЕННАЯ ценность — незаметность, — стратегически сомнительно.
- Объём: эквивалентен §4 (3-5 недель) + дополнительная работа замаскировать «эстафету» под легитимный браузерный паттерн, чтобы не словить QUIC-migration-сигнатуру. Этот «дополнительный» кусок, скорее всего, и есть самый дорогой и рискованный.

**Вывод §6:** QUIC-модель — правильный академический ответ на «бесшовная миграция», но для нашей угрозы (РФ-DPI, маскировка под браузер-аналитику) она тянет за собой ровно тот fingerprint, от которого мы прячемся.

---

## 7. СКОРОСТЬ — влияет ли миграция/единая сессия на throughput?

Сейчас параллелизм максимальный:
- Каждый слот = свой `core.Session` = свой лок-фри `sendEpoch.nonce.Add(1)` (`core/session.go:312-315`). N слотов = N независимых atomic-счётчиков, ноль contention.
- `EncryptChunk` лок-фри по дизайну (A1-M2 fix, `session.go:301-326`) — но nonce-counter всё равно один atomic НА СЕССИЮ.

При единой сессии:
- **Один atomic seqnum/nonce-counter на ВСЕ слоты.** Под высокую параллельную нагрузку (80+ goroutine, как описано в `session.go:14-19`) это единая точка contention на `nonce.Add(1)`. Atomic.Add дешёвый, но при десятках конкурентных upload-goroutine на одном счётчике появляется cache-line bouncing. Это измеримо, хотя и не катастрофа.
- Anti-replay: единый `recvBitmap` под `s.mu` (`session.go:137-166` `AcceptSeqNum` берёт `s.mu.Lock()`). Сейчас это per-slot — N независимых локов. При единой сессии — ОДИН лок на приём со всех N TCP. Вот это уже **реальный bottleneck**: каждый принятый кадр со всех слотов сериализуется на одном мьютексе. Сейчас приём параллелен по слотам.
- Out-of-order разброс seqnum со всех TCP кратно вырастает → больше работы в `shiftBitmap`.

**Вывод §7:** Единая сессия — это регресс по параллелизму приёма (общий `s.mu` в `AcceptSeqNum`), который сегодня распараллелен пер-слот. Не фатально, но это работа против текущей оптимизации (вся серия A1-M2 / C11 фиксов била именно в lock-free hot-path). Вариант 1 не трогает этот путь вообще.

---

## Итоговая рекомендация

1. **НЕ делать** полную stream migration сейчас. Причины: ухудшение скрытности (§3, §6 — движемся к QUIC-migration-сигнатуре), регресс параллелизма приёма (§7), 3-5 недель серверно-клиентской переделки крипто-ядра с высоким риском регрессий в уже стабилизированных nonce/replay-инвариантах (§4).
2. **Сделать Вариант 1** (sticky slot для активных больших стримов + adaptive `drainHardCap`), 2-5 дней. Это достройка уже работающего graceful drain, ноль изменений на проводе, тривиальный откат через env. Решает Bug #6 для подавляющего большинства случаев.
3. **Замерить остаточный хвост** перед любым разговором о миграции: сколько РЕАЛЬНЫХ обрывов даёт hard-cap на стримах >90s в канарейке. Если после Варианта 1 хвост близок к нулю — миграция не нужна вовсе. Если значим — обсуждать миграцию ТОЛЬКО с явным планом маскировки «эстафеты» (иначе теряем главное — незаметность).

### Файлы (file:line) для исполнителя Варианта 1
- `client/ws_pool_drain.go:557-643` — `drainWatchdog`, hard-cap teardown (точка вставки sticky-exemption).
- `client/ws_pool_drain.go:645+` — `emitHardCapLog`.
- `client/stream_entry.go:122-145` — `allStreamsIdle` (уже умеет active vs idle).
- `client/ws_pool.go:222-330` — `poolSlot` (`downBytes`, `byteBudget`, `streams`, `rotationDeferredNs`).
- `client/ws_pool.go:2241-2260` — `WriteMessageForStream` (стрим уже переживает `slotDraining`).
- env `SHADOWLINK_DRAIN_HARD_CAP` (CLAUDE.md, Phase B+ таблица) — уже тюнится в поле.

### Файлы (file:line), доказывающие минусы полной миграции
- `client/ws_pool.go:214,222-224,1418,1485-1536,2211-2223` — сессия пер-слот (по дизайну).
- `core/session.go:19,137-166,307-326` — единый `s.mu` в `AcceptSeqNum` = bottleneck при общей сессии.
- `core/mimicry_session.go:28-32` + CLAUDE.md «Analytics Mimicry Engine» — sticky per-session mimicry = модель «вкладки».
- `server/handler.go:63,90-124,579` + `server/websocket.go:144-164,583-599` — upstream TCP namertvo bound к per-session WS-goroutine; глобальный streamID отсутствует.
- `client/ws_pool.go:277-300` — per-flow byte-budget рандомизация (Citizen Lab anti-detection) ломается при общей сессии.
