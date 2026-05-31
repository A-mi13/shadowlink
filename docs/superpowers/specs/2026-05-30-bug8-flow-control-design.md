# Bug #8 — Per-Stream Flow Control Design (v2 — переписан после опус-ревью)

**Дата:** 2026-05-30
**Статус:** DESIGN v4 — **READY** (3 опус-пасса; последний BLOCKER NV1 закрыт §4.6; остатки MV1/MV2/LV1 — в план)
**Корень бага:** доказан
**1-й ревью:** `docs/bug8-spec-review-opus.md` (3 BLOCKER + 5 HIGH + 5 MED + 3 LOW — закрыты в v2)
**2-й ревью:** `docs/bug8-spec-review-opus-v2.md` (B1 закрыт без регрессий; 2 NEW BLOCKER + 2 NEW HIGH — закрыты в v3)
**3-й ревью:** `docs/bug8-spec-review-opus-v3.md` (NB2/NH1/NH2/M-rot verified closed; 1 NEW BLOCKER NV1 — закрыт в v4 §4.6; MV1/MV2/LV1 → план)

> **История:** v1 этого дизайна целил серверную сторону в POST/SplitHTTP путь
> (`relayStreamFromTarget` + `tunnel.Outgoing`). Опус-ревью доказало (B1), что
> продакшен-закачки идут по **WebSocket-пути** (`server/websocket.go::runWebSocketSession`),
> у которого иная структура. v2 переписан под WS-путь + сменил модель негоциации
> на in-band feature поверх v1-ключей (H1). Все находки 1-го ревью учтены — см. §13.

---

## 1. Проблема (доказанный корень)

Быстрые закачки (>~70 МБ) рвутся с "Ошибка сети" в Chrome. Корень установлен
debug-логом 10:12 (`stream buffer overflow drops=50 dropped_bytes=750744`) +
анализом кода, после отсева 5 неверных гипотез (молодой стрим, эвикция слота,
сеть, TSPU, сервер pl1 — все отвергнуты фактами).

**Механизм потери байт (клиент):**

```
WS slot reader (slotReaderWithClient — 1 goroutine на слот, ws_pool.go:2719/2721)
  └─ ReadMessage → decrypt → RouteToStream(streamID, data)        ← ЗДЕСЬ дроп
       └─ incomingCh (cap 512 фреймов, client.go:695)             ← буфер 1
            └─ downlink goroutine (tcp.go:778) → conn.Write(data)
                 └─ memConn.wr (memBuffer cap 256 KiB, memconn.go:32) ← буфер 2, БЛОКИРУЕТ при заполнении
                      └─ tun2socks appConn.Read → TUN → приложение
```

На быстрой закачке producer (`RouteToStream`) наполняет `incomingCh` быстрее,
чем downlink-goroutine успевает `conn.Write` в memConn. `conn.Write` блокирует,
когда memBuffer (256 KiB) полон. Пока downlink-goroutine заблокирована в
`conn.Write`, она не читает `incomingCh`. Канал (512) переполняется →
`RouteToStream` срабатывает `default: recordBufferOverflow` (client.go:917-918)
→ **байты теряются**. Для TCP-потока потеря фатальна: tun2socks отдаёт
повреждённый поток → full close appConn → "downlink write error closed pipe"
(tcp.go:778) → Chrome "Ошибка сети".

**Корень-строка:** `client.go:917-918` non-blocking `default: drop`. Корректен
для UDP, смертелен для TCP-закачки.

**Где сервер физически шлёт лишнее (носитель бага — WS-путь):**

`server/websocket.go::runWebSocketSession` (websocket.go:470) — продакшен hot-path
для WS-pool клиента:
- reader-loop (websocket.go:555): `conn.ReadMessage → decrypt → switch chunk.Flags`
  (switch без `default`).
- per-stream downlink relay (websocket.go:752-769): отдельная goroutine на стрим,
  `tc.Read(buf) → EncryptChunk → writeMsg(writer.Enqueue)`. **Читает target и шлёт
  без всякого ограничения скорости** — это сторона, которую надо притормозить.
- общий писатель `core.NewWSAsyncWriter(conn, 512)` (websocket.go:480) на сессию.
- per-stream state — локальная карта `streams map[uint16]*wsStream` +
  `streamsMu` внутри `runWebSocketSession` (websocket.go:485), инициализируется
  при `FlagConnect` (websocket.go:627), чистится при teardown (websocket.go:827-834).

**Архитектурное ядро:** `RouteToStream` (клиент) — единый демультиплексор ОДНОГО
WS-слота. Блокирующая запись в нём → HoL всех стримов слота. На сервере reader-loop
тоже единый на сессию. Поэтому нужен настоящий flow control, а не блокировка в
демультиплексоре.

---

## 2. Принцип решения

Как в HTTP/2 / yamux: **переполнение не должно наступать** — per-stream receive
window + credit. Отправитель (серверная per-stream relay-goroutine) не читает
target и не шлёт больше, чем получатель (клиент) подтвердил, что потребил.

**Инварианты (прибиты гвоздями — нарушения = баг):**

- **I1.** Клиентский reader-loop слота (`slotReaderWithClient`) НИКОГДА не
  блокируется. Демукс всегда дренирует сокет.
- **I2.** Серверный reader-loop (`runWebSocketSession`) НИКОГДА не блокируется на
  flow control. WINDOW_UPDATE обрабатывается синхронно и быстро (bookkeeping +
  Signal), отправка downlink — в отдельных goroutine.
- **I3.** Отправка WINDOW_UPDATE клиентом НИКОГДА не блокирует downlink-goroutine
  (B2-фикс): downlink-goroutine только делает `atomic.Add` в аккумулятор; реальную
  отправку делает отдельный **per-client** sender через **неблокирующий**
  `TryEnqueueControl` (новый API в `core/wsasyncwriter.go`, с `default:`). При
  «не влезло» delta остаётся накопленным (аддитивность) — sender НИКОГДА не
  блокируется (NB2/NH1-фикс).
- **I4.** Credit-gate на сервере стоит ПЕРЕД `tc.Read` (H3): стрим без credit
  вообще не читает target → не давит на общий writer.
- **I5.** `flowControlEnabled` строго = согласованная capability (см. §4). Никакого
  второго источника истины.

**Поток данных после фикса:**

```
СЕРВЕР per-stream relay (websocket.go:753): waitForCredit ПЕРЕД tc.Read
        (блокирует ТОЛЬКО эту goroutine) → читает min(32K, available) → EncryptChunk
        → writeMsg → available -= n
   ↓ WS (≤ window=1 MiB неподтверждённых байт на стрим)
КЛИЕНТ slotReader → RouteToStream → incomingCh (НЕ переполняется by design)
        → downlink goroutine → conn.Write(memConn) [блокирующий backpressure уже есть]
        → atomic.Add(pendingDelta[streamID], n)  [НЕ блокирует]
   ↑ credit-sender (отдельный, неблокирующий, coalescing): когда pendingDelta>=window/2
        → swap(pendingDelta,0)=delta → отправить FlagWindowUpdate(streamID, delta)
СЕРВЕР reader-loop case FlagWindowUpdate → handleWindowUpdate: available += delta;
        cond.Signal() → relay разблокируется
```

---

## 2a. Решения, принятые с пользователем

| Параметр | Выбор |
|---|---|
| Объём фикса | Client + сервер (полный flow control) |
| Размер окна | **1 MiB по умолчанию, настраиваемый** (env/config) |
| Политика WINDOW_UPDATE | **порог 50% окна** (как yamux/HTTP2 default) |
| Совместимость | негоциация capability на handshake, fallback на текущее поведение |

---

## 3. Wire-формат

Новый флаг в `core/chunk.go`:

```go
FlagWindowUpdate byte = 0x0A   // payload: [StreamID(2 BE)][delta(4 BE)] = 6 байт
```

- `delta uint32` — приращение credit (байт потреблено клиентом с прошлого
  update). Всегда положительное. НЕ абсолют.
- Шлётся клиентом по uplink, через `session.EncryptChunk` → на проводе неотличим
  от обычного зашифрованного фрейма.
- **`StreamID=0` НЕ используется** для session-wide (L3: 0 занят legacy/poll).
  Session-wide flow control в V1 не делаем (YAGNI, §11 вопрос про Outgoing закрыт
  тем, что WS-путь не имеет session-wide bottleneck на чтении — см. §6.4).

Конструкторы/парсеры:
```go
func NewWindowUpdateChunk(sessID, seq uint32, streamID uint16, delta uint32) *Chunk
func ParseWindowUpdate(payload []byte) (streamID uint16, delta uint32, err error)
   // L1: len(payload) < 6 → error (no panic), как ParseUDPChunk
```

---

## 4. Негоциация: in-band feature поверх v1-ключей (H1 — модель b)

### 4.1 Почему НЕ новая crypto-версия

v1 дизайна предлагал v2-версию протокола с version-bid в `ClientHello`. Опус-ревью
(H1) доказало:
- `ClientHello` парсится по фикс-константам `EphemeralPub[32] || encClientID[65] ||
  padding` без length-prefix (handshake.go:11-16). Вставка bid ломает парсер
  старого сервера ИЛИ требует bump формата.
- `protoVersion` входит в `DeriveSessionKeys` (downgrade-защита) → несогласованная
  версия = разные ключи = сломанная связь. Это делает серверо-инициированный
  апгрейд опасным.
- cleartext-bid = новый DPI-признак на handshake.

**Решение: flow control — опциональная feature ВНУТРИ существующей v1-сессии, НЕ
новая crypto-версия.** Ключи остаются v1 (никакой смены `DeriveSessionKeys`).
Capability согласуется in-band после handshake, в аутентифицированном канале.

### 4.2 Где согласуется capability (per-WS-conn = per-slot)

**Критичный факт топологии (NB1):** WS-pool делает отдельный handshake на КАЖДЫЙ
слот (`connectSlot` → `NewClientHello`, ws_pool.go:1600). **Каждый слот = своя
`core.Session`** («Each slot has its own crypto session», ws_pool.go:1532).
Серверный `runWebSocketSession` запускается per-WS-conn (websocket.go:463), а
`tunnel.WSAttached.CompareAndSwap` (websocket.go:188) гарантирует **1 conn на
сессию**. Значит: 1 слот = 1 `core.Session` = 1 conn = 1 `runWebSocketSession`.
Стрим живёт целиком внутри одного слота/сессии и **НЕ мигрирует между серверными
relay на лету** (Bug#6 sticky продлевает жизнь СТАРОГО слота до конца его стримов;
новые CONNECT идут на новый слот как новые стримы). → capability и credit-state
честно **per-WS-conn**, согласуются на каждом слоте отдельно.

Первый фрейм после WS-upgrade — `FlagKeepalive` (`authenticateFirstFrame`,
websocket.go:144-202: принимает только FlagKeepalive; payload chunk'а НЕ
инспектируется — проверено кодом). Используем его, capability **в зашифрованном
`Chunk.Payload`** этого keepalive (NH2 — НЕ в `[token]`-префиксе, чтобы не дать
cleartext DPI-признак):

- **Клиент:** в `Chunk.Payload` первого `FlagKeepalive` кладёт
  `["FLOWCTL"(7)][window(4 BE)]` (всё внутри AES-GCM шифрования chunk'а). Пустой
  payload (как сейчас) = клиент не поддерживает → off.
- **Сервер ЯВНО эмитит ack (NV1-фикс):** `authenticateFirstFrame` сейчас
  потребляет первый keepalive и возвращает session **БЕЗ отправки чего-либо**
  (websocket.go:202) — keepalive-ack-ветка reader-loop (websocket.go:781) до
  первого keepalive НЕ доходит (он уже съеден). Поэтому сервер обязан **явно**
  сформировать и синхронно записать FLOWCTL-ack: когда в расшифрованном payload
  первого keepalive есть маркер И сервер умеет flow control →
  `effectiveWindow = min(clientWindow, serverMaxWindow)`, пишет
  `Chunk{Flags:FlagAck, Payload:["FLOWCTL"(7)][effectiveWindow(4 BE)]}` через
  `session.EncryptChunk` + `conn.WriteMessage` **ДО** `runWebSocketSession`
  (до async writer'а/reader-loop'а) — симметрично тому, как клиент пишет первый
  кадр синхронным `conn.WriteMessage`. См. §4.6 (серверная сторона).
- **Сервер без маркера / старый клиент:** НЕ шлёт FLOWCTL-ack (как сейчас).
- **Клиент читает ack СИНХРОННО (§4.5)** — ТОЛЬКО если сам послал маркер.

### 4.5 Синхронное чтение ack в UpgradeToWS (NB1-фикс)

`UpgradeToWS` (ws_transport.go:308) сейчас: шлёт первый keepalive синхронным
`conn.WriteMessage` (ws_transport.go:512), затем СРАЗУ создаёт `WSAsyncWriter`
(525) и возвращает — НЕ читая ответ. Slot reader потребляет ack позже асинхронно.
Это несовместимо с синхронной негоциацией.

**Фикс:** между отправкой первого фрейма (519) и созданием async writer'а (525) —
пока `conn` ещё «голый», slot reader НЕ стартовал (подтверждено кодом: connectSlot
ставит slotReady только ПОСЛЕ возврата UpgradeToWS, ws_pool.go:1712; reader
стартует только для slotReady) — вставить, **ТОЛЬКО если клиент послал FLOWCTL-маркер**:
```go
conn.SetReadDeadline(time.Now().Add(negotiationAckTimeout)) // 500ms (MV1)
msgType, data, err := conn.ReadMessage()
conn.SetReadDeadline(time.Time{})
// decrypt(session) → если Flags==FlagAck && payload начинается с "FLOWCTL":
//     slot.flowWindow = parse(payload); slot.flowControlEnabled = true
// timeout/ошибка/не-FLOWCTL (старый сервер ack не шлёт вовсе — NV1):
//     slot.flowControlEnabled = false; Stats.FlowNegotiationTimeout.Add(1)
// slot reader стартует ПОСЛЕ (со следующего кадра) — НЕ перечитывает ack.
```
- Если клиент НЕ шлёт маркер (env off) — чтение пропускается полностью, поток не
  меняется (нулевой риск).
- `slot.flowControlEnabled`/`slot.flowWindow` — поля `poolSlot` (per-conn capability).
- **MV1 (compat):** старый сервер на маркер НЕ отвечает ничем (NV1) → клиент ждёт
  до `negotiationAckTimeout` и решает off. Чтобы compat-штраф был мал:
  `negotiationAckTimeout = 500ms` (не 2s) + метрика `flow_negotiation_timeout_total`
  + **staged rollout: сервер pl1 деплоится ПЕРВЫМ**, клиенты с маркером раздаются
  после. На pl1 это управляемо (один сервер, деплою сам). Пока сервер не
  подтверждён новым — клиентский env по умолчанию может держать flow control off.
- Единственный «съеденный» синхронным чтением кадр — ack первого keepalive; данных
  стримов ещё нет (CONNECT идёт после ready). Безопасно.

### 4.6 Серверная эмиссия FLOWCTL-ack (NV1-фикс, серверная сторона)

`authenticateFirstFrame` (websocket.go:144-202) расшифровывает первый keepalive и
возвращает session. Добавляем: при `chunk.Flags==FlagKeepalive` проверить payload
на маркер `"FLOWCTL"`; если есть И сервер умеет flow control:
- вычислить `effectiveWindow = min(clientWindow, serverMaxWindow)` (с клампом §5.5);
- записать ack **синхронно** через `conn.WriteMessage(BinaryMessage,
  EncryptChunk(Chunk{Flags:FlagAck, Payload:["FLOWCTL"][effectiveWindow]}))` —
  ДО возврата session / до `runWebSocketSession` (reader-loop ещё не стартовал,
  conn «голый», симметрия с клиентским first-frame write);
- вернуть session + флаг `flowEnabled=true` + `effectiveWindow` в `handleWebSocket`,
  который передаст их в `runWebSocketSession` (для инициализации credits).
- Нет маркера / сервер не умеет → НЕ писать ack (как сейчас), `flowEnabled=false`.

**Почему синхронно и здесь, а не в reader-loop keepalive-case:** первый keepalive
НЕ доходит до reader-loop (его съел authenticateFirstFrame). Значит ack на него
надо эмитить именно в момент аутентификации, до старта цикла. Альтернатива
(направить первый keepalive в общий цикл) сломала бы auth-семантику — отвергнута.

### 4.3 Почему это безопасно (закрывает B3)

- Источник истины ОДИН (I5): обе стороны включают flow control ⟺ обе увидели
  маркер в keepalive + ack. Криптографически аутентифицировано (сессионный ключ).
- Старый сервер: получает keepalive с непустым payload — `authenticateFirstFrame`
  payload не инспектирует, аутентифицирует и НЕ шлёт ack на первый keepalive вовсе
  (NV1/3-й ревью). → клиент не дождётся FLOWCTL-ack за `negotiationAckTimeout`
  (500мс) → flow control off + `flow_negotiation_timeout_total++`. Связь работает
  как сейчас (разовый 500мс штраф на слот; смягчается staged rollout — §4.5 MV1).
- Старый клиент: шлёт пустой keepalive → сервер не видит маркер, не шлёт ack,
  клиент не читает (маркер не послан) → flow control off, поток без изменений.
- Ключи НЕ меняются ни в одном случае → нет downgrade-через-ключи, нет ломки
  ClientHello, нет нового DPI-признака на самом handshake.
- `authenticateFirstFrame` сейчас принимает ТОЛЬКО `FlagKeepalive` и проверяет
  токен; добавление payload-маркера не меняет тип фрейма, не ослабляет auth.

### 4.4 default в WS switch (B3)

Добавляем `default:` в reader-switch (websocket.go:591) при добавлении нового
case — no-op + метрика `unknown_flag_total`, чтобы будущие флаги были наблюдаемы.
Для compat это безопасно: старый сервер без нового case просто проваливает
неизвестный флаг (фрейм отбрасывается, соединение живёт) — но т.к. capability
согласована (§4.3), старый сервер НИКОГДА не получит FlagWindowUpdate (клиент его
не шлёт при flow control off).

---

## 5. Клиентская сторона

### 5.1 Состояние (новый файл `client/stream_flow.go`)

```go
// per-stream аккумулятор потреблённых, но ещё не подтверждённых байт.
type streamFlowState struct {
    pendingDelta atomic.Uint64 // байт записано в memConn с прошлого WINDOW_UPDATE
    window       uint64        // effectiveWindow (read-only после негоциации)
}
```

Карта `Client.streamFlow map[uint16]*streamFlowState` под `streamMu` (тот же
lifecycle, что `streamChans`). **Capability per-slot** (§4.2): окно стрима берётся
из слота, на котором стрим открыт — `poolSlot.flowControlEnabled`/`poolSlot.flowWindow`
(выставлены в §4.5 при чтении ack). `streamFlowState.window` инициализируется
значением окна слота этого стрима в момент `RegisterStream`. Если слот стрима имеет
`flowControlEnabled=false` (старый сервер / маркер не подтверждён) — стрим работает
без flow control (OnStreamConsumed no-op для него).

### 5.2 Учёт потребления (I3 — НЕ блокирует)

В downlink goroutine `tunnelTCPStream` (tcp.go:778) — после успешного
`conn.Write(data)`:

```go
if _, err := conn.Write(data); err != nil { ... }
cl.OnStreamConsumed(streamID, len(data))   // только atomic.Add — НИКОГДА не блокирует
```

`OnStreamConsumed`: `st.pendingDelta.Add(n)`. Всё. Никакой отправки отсюда.
v1 → no-op.

### 5.3 Credit-sender (B2/NB2/NH1 — per-client, неблокирующий coalescing)

Отдельный механизм отправки WINDOW_UPDATE, развязанный с downlink-goroutine.

**Вариант (исправлен после 2-го ревью): ОДНА per-client credit-sender goroutine**
(не per-slot — NH1). Per-slot терял бы стрим в окне миграции между слотами
(Bug#6 sticky), т.к. `pendingDelta` привязан к стриму (`Client.streamFlow`), а
стрим резолвит текущий слот динамически. Per-client sender итерирует ВСЕ стримы
`Client.streamFlow` независимо от слота:

```
тик (лёгкий тикер ~5-10мс с jitter):
  для каждого streamID в Client.streamFlow:
    threshold := jitter(window, 0.4, 0.6)        // §16: порог 40-60%, не ровно 50%
    d := st.pendingDelta.Load()
    if d >= threshold:
        if trySendWindowUpdate(streamID, d):      // TryEnqueueControl — НЕблокирующий
            st.pendingDelta.Add(-d по CAS-семантике) // забрать ТОЛЬКО при успехе
        // при неудаче (control полон ИЛИ слот не готов) — delta НЕ трогаем,
        // следующий тик дошлёт накопленную сумму (аддитивность)
```

- **Отправка через `WriteControlMessageForStream`** (ws_pool.go:2383) → резолвит
  ТЕКУЩИЙ слот стрима → следует за миграцией стрима автоматически (NH1-фикс).
  Внутри использует **новый `TryEnqueueControl`** (NB2): `select { case
  control<-msg: ok; default: not-sent }` — НИКОГДА не блокирует.
- **NB2:** существующий `EnqueueControl` (wsasyncwriter.go:215) БЛОКИРУЕТ при
  полном cap-64 (нет `default`). Поэтому добавляем НОВЫЙ метод `TryEnqueueControl`
  в `core/wsasyncwriter.go` с `default:` веткой → неблокирующий. Без него I3
  невыполним. `WriteControlMessageForStream` получает неблокирующий вариант.
- **Обнуление pendingDelta строго после успешной отправки** (H4): `CompareAndSwap`
  / atomic вычитание ровно отправленного `d`. Параллельный `OnStreamConsumed.Add`
  добавит к остатку — ни потери, ни задвоения (M-rot: гонка race-free на атомиках).
- **Триггер — тикер** (не сигнал): гарантирует, что downlink-goroutine делает
  ТОЛЬКО `Add` и никогда не трогает отправку (I3). Тикер один на клиента, дёшево.

### 5.4 RouteToStream при v2

При flow control on дроп не должен наступать. `select default:
recordBufferOverflow` ОСТАВЛЯЕМ как детектор инварианта: дроп при flow-control-on
→ WARN + метрика (это баг credit-синхронизации). v1 — как сейчас.

### 5.5 cap incomingCh ↔ окно (M2)

Окно конфигурируемо. Инвариант: `cap(incomingCh) >= effectiveWindow / minChunkSize`.
Поскольку chunk ~12 KiB, при окне ≤ 6 MiB cap 512 достаточно. Чтобы не было
скрытой мины: **клампим effectiveWindow сверху** так, чтобы
`effectiveWindow/minChunk <= cap(incomingCh)`; либо вычисляем cap из окна при
старте. Выбор: клампить окно (проще, cap не трогаем). serverMaxWindow по умолчанию
1 MiB → 85 фреймов ≪ 512, запас огромный; кламп — страховка от env-переконфига.

### 5.6 Половина B2 на клиенте — закрыта

Downlink-goroutine только `atomic.Add` (I3). Отправка — отдельный неблокирующий
sender. Downlink никогда не блокируется на uplink-писателе → `incomingCh` всегда
дренируется → нет вторичного переполнения. Credit-deadlock-петля разорвана.

---

## 6. Серверная сторона (WS-путь — B1-фикс)

### 6.1 Состояние (новый файл `server/stream_credit.go`)

```go
type streamCredit struct {
    mu        sync.Mutex
    cond      *sync.Cond
    available int64
    closed    bool
}
func (c *streamCredit) waitForCredit(done <-chan struct{}) int64 // ≤0 = выйти
func (c *streamCredit) consume(n int)                            // available -= n
func (c *streamCredit) add(delta uint32, window int64)           // += clamp; Signal
func (c *streamCredit) close()                                   // closed=true; Signal (под mu)
```

Карта `credits map[uint16]*streamCredit` **локальная в `runWebSocketSession`**
(рядом со `streams`/`streamsMu`), НЕ в `Tunnel`. **Это корректно именно потому,
что `runWebSocketSession` = per-WS-conn = per-`core.Session` = per-slot** (см.
§4.2): relay-goroutine стрима и его `credits[streamID]` всегда живут в ОДНОМ
инстансе `runWebSocketSession`, стрим не мигрирует между инстансами на сервере
(NB1). Инициализируется при `FlagConnect` (websocket.go:627, где создаётся
`pendingStream`) значением `effectiveWindow`. Флаг `flowControlEnabled` — локальная
переменная сессии, выставлена при чтении FLOWCTL-маркера в первом keepalive (§4.2),
до старта relay-loop.

### 6.2 Credit-gate ПЕРЕД tc.Read (H3, I4)

В per-stream relay (websocket.go:753-769):

```go
for {
    if flowControlEnabled {
        got := credit.waitForCredit(done)      // блокирует ТОЛЬКО эту goroutine
        if got <= 0 { return }                  // стрим/сессия закрыты
        limit = min(len(buf), int(got))
    } else {
        limit = len(buf)                         // v1: как сейчас
    }
    n, err := tc.Read(buf[:limit])
    if n > 0 {
        // ... EncryptChunk → writeMsg (как сейчас) ...
        if flowControlEnabled { credit.consume(n) }
    }
    if err != nil { return }
}
```

Стрим без credit не читает target → target-сокет сам придержит отправителя (TCP
backpressure) → не кладёт в общий `WSAsyncWriter(512)` → меньше давления на общую
очередь. Это и есть цель (H3).

### 6.3 handleWindowUpdate (I2 — синхронно, быстро)

Новый `case core.FlagWindowUpdate` в reader-switch (websocket.go:591):

```go
case core.FlagWindowUpdate:
    streamID, delta, err := core.ParseWindowUpdate(chunk.Payload)
    if err != nil { continue }
    streamsMu.Lock(); c := credits[streamID]; streamsMu.Unlock()
    if c != nil { c.add(delta, effectiveWindow) }  // available += delta (clamp); Signal
    h.metrics.FlowWindowUpdatesRecv.Add(1)
```

Никаких блокировок в reader-loop (I2). `add` делает быстрый `mu.Lock; += ; clamp;
Signal; Unlock`.

### 6.4 Почему WS-путь НЕ имеет session-wide bottleneck на ЧТЕНИИ (закрывает H2/§11)

На POST-пути был общий `tunnel.Outgoing` ПЕРЕД энкодом — узкое место. На WS-пути
каждый стрим читает свой `tc` и пишет в общий `WSAsyncWriter` ПОСЛЕ энкода.
Credit-gate стоит ПЕРЕД `tc.Read` → стрим без credit вообще не читает. Общий
writer (512) остаётся, но: (1) downlink-throughput ограничен сокетом, не нашей
логикой; (2) блокировка на `Enqueue` — per-goroutine, не блокирует reader-loop
(I2); (3) per-stream credit ограничивает, сколько каждый стрим вообще прочитает.
Session-wide credit (StreamID=0) НЕ нужен в V1 — обоснование числовое: окно 1 MiB,
writer 512 фреймов × ~12 KiB ≈ 6 MiB суммарного буфера, что покрывает несколько
полных окон; реальный потолок — пропускная способность сокета, а её делит TCP
честно. **POST/SplitHTTP путь flow control НЕ покрывает** (он не носитель бага для
WS-pool клиента) — явно задокументировано в §12.

### 6.5 Граничные: teardown / closed / done (M4, M5)

`sync.Cond` не селектится на канал → нужен явный wake на teardown:
- При cleanup сессии (websocket.go:827-834, цикл по streams) — для каждого
  `credits[id]` вызвать `c.close()` (`mu.Lock; closed=true; cond.Signal; mu.Unlock`).
- В per-stream relay defer (websocket.go:742-751) — `credits[sid].close()` +
  `delete(credits, sid)` под `streamsMu`.
- `FlagFin` case (websocket.go:772) — `credits[id].close()` + delete.
- `close` и `Signal` ВСЕГДА под `c.mu` → happens-before гарантирует: waiter,
  севший в Wait, увидит `closed` (M4 — нет потерянного сигнала).
- `waitForCredit` цикл: `for available<=0 && !closed { cond.Wait() }`; при `closed`
  возвращает -1. `done` интегрируется так: cleanup-путь на `<-done` проходит по
  всем credits и закрывает их (а не через сам Cond) → relay выходит. Нет
  goroutine-leak (M5).

### 6.6 Кламп (M1)

`add` клампит `available <= 2*effectiveWindow`. Кламп не теряет байт (relay не
читает target без credit; кламп лишь ограничивает верх in-flight). Метрика
`credit_wait_seconds_total` поймает, если кламп душит throughput. Документируем:
кламп влияет только на верхнюю границу, дропов не создаёт.

### 6.7 Совместимость

`flowControlEnabled=false` (старый клиент / нет маркера) → relay работает как
сейчас (без waitForCredit), credits не инициализируются. Ноль изменений.

---

## 7. Жизненный цикл credit при смерти слота / на хвосте закачки (H4 + NB1 + M-rot)

**Серверная сторона (NB1-уточнение):** стрим НЕ мигрирует между серверными relay.
Каждый слот = своя `core.Session` = свой `runWebSocketSession` со своей
credit-картой. Если слот умирает — его `runWebSocketSession` завершается, relay'и
его стримов закрываются (credit.close, §6.5), сессия рвётся. Стрим на этом слоте
просто заканчивается — нет «осиротевшего серверного credit, ждущего вечно».
Bug#6 sticky drain держит СТАРЫЙ слот живым, пока его стримы доигрывают, ровно
чтобы закачка не оборвалась при ротации — credit-state живёт вместе со слотом.

**Клиентская сторона:**
- `pendingDelta` в `Client.streamFlow[streamID]` — привязан к **стриму**.
- Per-client credit-sender (§5.3) шлёт через `WriteControlMessageForStream`,
  который резолвит ТЕКУЩИЙ слот стрима (ws_pool.go:2383) → следует за стримом.
- Обнуление pendingDelta только после успешной `TryEnqueueControl` (CAS). Неудача
  (слот не готов / control полон) → delta остаётся, следующий тик дошлёт.

**M-rot (credit-rebase):** поскольку стрим на сервере НЕ переживает смену слота
(новый слот = новый стрим = новый credit с полного окна), вопрос «ребейза
pendingDelta при миграции» снимается: в рамках жизни ОДНОГО стрима слот не
меняется на серверном уровне (стрим заканчивается на своём слоте). Клиентский
`pendingDelta` живёт ровно жизнь стрима и удаляется в `UnregisterStream`. Нет
сценария «клиент потребил N на старом credit, а новый server-credit = полное окно»
в пределах одного `streamID` — потому что новый слот = новый `streamID`.

**Страховочный watchdog (хвост закачки):** на «хвосте» закачки (данных меньше
порога 40-60%, но стрим ещё ждёт последние байты) накопленный `pendingDelta` может
не достичь порога → update не уйдёт → сервер ждёт credit, которого нет → stall.
Watchdog: если `pendingDelta>0` и не отправлялся дольше T (напр. 200мс) — форсить
попытку отправки независимо от порога. Чинит классический yamux-late-update stall.
Реализуется в том же per-client sender (поле `lastSentNs` на стрим).

---

## 8. Half-close (H5)

При HTTP keep-alive download приложение делает `appConn.CloseWrite` (half-close):
uplink-goroutine `tunnelTCPStream` выходит (tcp.go:684), **downlink-goroutine
продолжает** (tcp.go:717-818). Отправитель WINDOW_UPDATE — credit-sender (§5.3),
который пишет в WS-слот через `WSAsyncWriter` (uplink-направление WS), физически
независимое от appConn uplink half-close. WS-слот открыт на чтение И запись
независимо от half-close приложения. → путь для update жив.

**Инвариант (зафиксирован):** WS uplink-направление слота не зависит от appConn
half-close; credit-sender шлёт WINDOW_UPDATE независимо от того, что uplink-goroutine
приложения завершилась. **Тест обязателен** (§9.6).

---

## 9. Тестирование (TDD, по слоям)

1. **core wire:** round-trip `FlagWindowUpdate`; `ParseWindowUpdate` (валид / <6
   байт → error, не паника — L1).
2. **negotiation (§4):** клиент-маркер + сервер-умеет → сервер синхронно шлёт
   FLOWCTL-ack (§4.6) → клиент on, effectiveWindow=min; клиент-маркер + сервер-старый
   (ack НЕ приходит) → клиент off за negotiationAckTimeout + timeout-метрика;
   клиент-старый (пустой keepalive) → off. Ключи v1 во всех случаях (не меняются).
   **Синхронное чтение ack (§4.5):** UpgradeToWS читает FLOWCTL-ack ДО старта slot
   reader; slot reader НЕ перечитывает этот кадр; при env-off чтение пропускается.
   Маркер строго в зашифрованном Chunk.Payload (NH2) — тест что cleartext-части
   кадра не изменились. **Server-эмиссия (§4.6, NV1):** тест что authenticateFirstFrame
   с маркером пишет ack ДО runWebSocketSession; без маркера — не пишет.
2a. **TryEnqueueControl (NB2):** новый метод НЕ блокирует при полном control-канале
   (cap 64) — возвращает «не влезло», `default:` ветка; контраст с блокирующим
   EnqueueControl. Per-client sender при «не влезло» сохраняет pendingDelta.
2b. **server ack-эмиссия (NV1):** authenticateFirstFrame с FLOWCTL-маркером в
   payload → синхронно пишет FLOWCTL-ack в conn ДО runWebSocketSession; без маркера
   → не пишет (старый клиент не виснет). Клиент: маркер послан, ack пришёл → on;
   маркер послан, ack НЕ пришёл за 500мс → off + flow_negotiation_timeout_total++.
3. **client flow-state:** `OnStreamConsumed` = только Add (не блокирует, не шлёт);
   credit-sender — порог 50%, delta верный, Swap-обнуление только после успеха,
   неблокирующ при полном control-канале; watchdog форсит хвост; v1 → no-op.
4. **server credit:** `waitForCredit` блокирует при 0, будится Signal после add;
   closed/done → ≤0; кламп 2×window; close под mu не теряет сигнал (M4).
5. **integration (ГЛАВНЫЙ, доказывает фикс):** быстрая закачка, producer льёт
   быстрее медленного consumer'а. **flow on: 0 дропов** (`StreamBufferOverflowsTotal`
   не растёт), байты в порядке. Контраст: flow off → дропы (статус-кво).
6. **half-close (H5):** half-close после первого запроса + большая закачка → 0
   дропов, update'ы продолжают идти.
7. **HoL:** два стрима на одном слоте; один consumer застрял → второй качает без
   задержки (клиент: reader-loop не блокируется; сервер: relay стрима 1 ждёт
   credit, relay стрима 2 нет).
8. **slot-rotation (H4):** стрим мигрирует на новый слот в момент закачки →
   pendingDelta не теряется, закачка не зависает.
9. **teardown (M5):** разрыв сессии под активной закачкой → нет goroutine-leak
   (все credits закрыты, relay'и вышли).
10. **race:** `go test -race -count=3 ./client/ ./server/ ./core/` на flow-control
    путях (CI/Linux — Windows без gcc).

---

## 10. Метрики (hand-rolled atomic)

```
shadowlink_flow_window_updates_sent_total         # client
shadowlink_flow_window_updates_recv_total          # server
shadowlink_flow_stream_credit_waits_total          # server: сколько раз relay ждал credit
shadowlink_flow_stream_credit_wait_seconds_total   # server: суммарный простой (окно мало?)
shadowlink_flow_sessions_active                    # gauge: число сессий с flow on (L2 — не 0/1)
shadowlink_unknown_flag_total                      # server: неизвестный флаг в WS switch (B3)
shadowlink_flow_negotiation_timeout_total          # client: ack не пришёл за negotiationAckTimeout (MV1 — старый сервер)
shadowlink_flow_window_update_dropped_total        # client: TryEnqueueControl не влез, delta перенесён (MV2 наблюдаемость)
```

---

## 11. Обработка ошибок

- WINDOW_UPDATE на закрытый/несуществующий стрим → no-op (не лог-спам).
- Дроп в RouteToStream при flow on → WARN (нарушен инвариант) + метрика.
- Битый/короткий/нулевой delta → `ParseWindowUpdate` error → continue; add(0) → no-op.
- Неизвестный флаг на сервере → default no-op + `unknown_flag_total` (B3).

---

## 12. Область применения (явно)

- **Покрывается:** WebSocket-путь (`runWebSocketSession`) — носитель Bug#8 для
  WS-pool клиента (продакшен).
- **НЕ покрывается:** POST/SplitHTTP download-stream путь (`relayStreamFromTarget`
  + `tunnel.Outgoing`). Он не используется WS-pool клиентом. Там остаётся
  статус-кво (`default: drop`). Если в будущем SplitHTTP CDN-режим станет
  актуален — отдельная задача.

---

## 13. Конфигурируемость

```
serverMaxWindow default 1 MiB; server flag/config
client desiredWindow: env SHADOWLINK_FLOW_WINDOW (байт; 0 → клиент не шлёт маркер → off)
effectiveWindow = min(client, server), клампится так, что effectiveWindow/minChunk <= cap(incomingCh) (M2)
порог update = effectiveWindow/2 (производный)
```

---

## 14. Файловая структура

| Файл | Изменение |
|---|---|
| `core/chunk.go` | `FlagWindowUpdate`, `NewWindowUpdateChunk`, `ParseWindowUpdate` (≥6 байт) |
| `core/wsasyncwriter.go` | **новый `TryEnqueueControl`** (неблокирующий, `select default:`) — NB2 |
| `client/stream_flow.go` (новый) | `streamFlowState` (pendingDelta atomic); `OnStreamConsumed` (Add-only); **per-client** credit-sender goroutine + watchdog + порог-jitter |
| `client/client.go` | streamFlow map в Register/Unregister; per-client sender lifecycle; RouteToStream-детектор инварианта |
| `client/ws_transport.go` | §4.5: синхронное чтение FLOWCTL-ack в `UpgradeToWS` ДО старта slot reader; capability-маркер в первом keepalive payload |
| `client/ws_pool.go` | `poolSlot.flowControlEnabled`/`flowWindow` (per-slot); `WriteControlMessageForStream` через `TryEnqueueControl` |
| `proxy/socks5/tcp.go` | вызов `OnStreamConsumed` после `conn.Write` (downlink goroutine) |
| `server/stream_credit.go` (новый) | `streamCredit`: waitForCredit/consume/add/close |
| `server/websocket.go` | FLOWCTL negotiation: читать маркер в `authenticateFirstFrame`, **синхронно эмитить FLOWCTL-ack ДО runWebSocketSession** (§4.6); передать flowEnabled/effectiveWindow в runWebSocketSession; `credits` map per-conn; credit-gate перед `tc.Read`; `case FlagWindowUpdate` + `default` no-op (LV1); teardown close-all |
| `server/metrics.go` | новые counters/gauge |
| `shadowlink/docs/protocols/flow-control-v2.md` | wire-спека фрейма + capability negotiation |

---

## 15. Карта закрытия находок 1-го ревью

| Находка | Где закрыта |
|---|---|
| B1 (неверный путь POST→WS) | §1, §6 целиком переписаны под `runWebSocketSession` |
| B2 (uplink-deadlock) | §5.3 credit-sender (Add-only downlink, неблокирующая отправка); I3 |
| B3 (тихий разнобой версий) | §4.3 единый источник истины; §4.4 default в switch; I5 |
| H1 (ClientHello/cleartext bid) | §4 — модель (b): in-band feature поверх v1-ключей, ClientHello не трогаем |
| H2 (tunnel.Outgoing bottleneck) | §6.4 — WS-путь не имеет session-wide bottleneck на чтении; POST out of scope |
| H3 (общий writer) | §6.2 — credit-gate ПЕРЕД tc.Read; I4 |
| H4 (потеря update при ротации) | §5.3 Swap-обнуление после успеха; §7 watchdog |
| H5 (half-close) | §8 — инвариант + тест §9.6 |
| M1 (кламп) | §6.6 — кламп не теряет байт, документирован |
| M2 (cap↔окно) | §5.5 — кламп окна под cap(incomingCh) |
| M3 (DPI uplink-всплеск) | §16 ниже |
| M4 (cond signal/closed) | §6.5 — close+Signal под mu |
| M5 (teardown leak) | §6.5 — close-all на teardown |
| L1 (ParseWindowUpdate ≥6) | §3, §9.1 |
| L2 (flow_enabled gauge) | §10 — sessions_active counter |
| L3 (StreamID=0 коллизия) | §3 — StreamID=0 не используется для session-wide |

### Карта закрытия 2-го ревью (v3)

| Находка 2-го ревью | Где закрыта в v3 |
|---|---|
| NB1 (негоциация несовместима с WS-pool: ack не синхронный, per-conn scope) | §4.2 (per-WS-conn=per-slot, стрим не мигрирует на сервере) + §4.5 (синхронное чтение ack в UpgradeToWS до slot reader) + §6.1 (credits per-conn корректно) + §7 (серверный lifecycle переписан) |
| NB2 (EnqueueControl блокирует — «неблокируемость» ложна) | §5.3 + I3 + §14: новый `TryEnqueueControl` в core/wsasyncwriter.go с `default:` |
| NH1 (per-slot sender теряет мигрирующий стрим) | §5.3: sender сделан **per-client**, итерирует Client.streamFlow, шлёт через WriteControlMessageForStream (следует за стримом) |
| NH2 (место маркера не зафиксировано) | §4.2: маркер строго в зашифрованном `Chunk.Payload` keepalive, НЕ в token-префиксе |
| NH3 (half-close зависит от §5.3) | закрыт автоматически после NB2/NH1; §8 инвариант + тест §9.6 |
| M-rot (credit-rebase при ротации) | §7: стрим не меняет слот на сервере в пределах своего streamID → ребейз не нужен |

### Карта закрытия 3-го ревью (v4 — READY)

| Находка 3-го ревью | Где закрыта в v4 |
|---|---|
| NV1 (сервер не шлёт ack на первый keepalive) | §4.2 + §4.6: сервер синхронно эмитит FLOWCTL-ack в authenticateFirstFrame ДО runWebSocketSession; §4.5 клиент читает только если послал маркер |
| MV1 (2s compat-stall) | §4.5: negotiationAckTimeout=500ms + метрика flow_negotiation_timeout_total + staged rollout (сервер первым) |
| MV2 (control-канал делится update/pong) | §10: метрика flow_window_update_dropped_total; pong через приоритетный drain не голодает; план мониторит |
| LV1 (default в WS switch) | §4.4 + §14: case FlagWindowUpdate + default no-op |
| NB2/NH1/NH2/M-rot + §4.5 клиентский interplay + NB1-архитектура | verified closed против кода (3-й ревью) |

---

## 16. Стеганография (M3)

Порог 50% при быстрой закачке → ~36 мелких uplink-фреймов/сек, коррелированных с
downlink. Меры:
1. **Jitter порога:** не ровно 50%, а случайно 40-60% — ломает регулярность.
2. **Пиггибэк на uplink data-фреймы:** когда приложение само шлёт uplink-данные
   (двусторонняя сессия), credit-sender проверяет — если в очереди есть uplink
   data, не слать отдельный update-фрейм этот тик (данные и так идут, сервер
   получит credit со следующим обычным фреймом... — НЕТ, credit отдельный флаг;
   пиггибэк в смысле «слать update в том же burst'е, не отдельным тиком» — снижает
   изоляцию мелкого фрейма). Точную форму пиггибэка фиксируем в плане; минимум —
   jitter порога (п.1) обязателен.
3. **Размер фрейма:** payload 6 байт + AES-GCM overhead (nonce 12 + tag 16 + header
   9) = ~43 байта зашифрованного фрейма — мал и может быть аномален. Проверить
   против padding-сэмплера; при необходимости падить update-фрейм до типичного
   размера (как keepalive уже падится). Решаем в плане на основе фактического
   распределения.

> M3 — единственная находка, часть которой («идеальная» форма пиггибэка/паддинга)
> вынесена в план как открытый под-вопрос. Минимум (jitter порога) — в дизайне.
