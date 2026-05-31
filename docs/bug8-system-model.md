# Bug #8 — Единая модель data-path при быстрой закачке (>100 МБ)

Дата: 2026-05-30. Бинарь со всеми 4 фиксами. Цель: одна модель всей цепочки,
одна первопричина, одно архитектурное решение. НЕ очередной точечный патч.

---

## 0. TL;DR (для нетерпеливых)

**Первопричина не в буферах и не в flow-control.** Все 4 фикта разгоняли
скорость и обнажали следующий предел, потому что лечили *симптомы пропускной
способности*, а реальный обрыв — это **RST app-side gVisor-эндпоинта**,
который инициирует САМ tun2socks: после того как аплинк-копия (запрос Chrome)
завершилась, `unidirectionalStream` делает `originConn.CloseRead()`
(= `ep.Shutdown(ShutdownRead)`), помечая приёмную сторону приложения
закрытой. Для крупной закачки запрос — крошечный и уходит за миллисекунды,
а тело ответа ещё льётся секунды. Как только приложение (Chrome, reused
keep-alive socket) шлёт в этот эндпоинт ЛЮБОЙ байт (новый pipelined-запрос,
TLS-renegotiation, повторный GET по тому же соединению), gVisor видит сегмент
на `RcvClosed=true`-эндпоинт и отвечает **RST** → app-side endpoint в error
state → downlink-копия `io.CopyBuffer(originConn, memConn)` падает на
`originConn.Write` → tun2socks делает полный `appConn.Close()` → у нас
`fullClose=true`, "downlink write error closed pipe". `overflow drops=2`,
`closed pipe=4`, `streamAgeMs` 1.9/5.7/8.5с — ВСЕ объясняются этим, а не
backpressure.

**Решение (одно, архитектурное):** перестать относиться к EOF аплинка как к
сигналу "закрыть чтение app-эндпоинта" на in-process пути. Это не наш код —
это поведение `tun2socks/tunnel.unidirectionalStream`. Бьём в первопричину
тем, что **не отдаём io.CopyBuffer управлять half-close нашего memConn так,
чтобы он транслировался в gVisor ShutdownRead до завершения downlink** —
конкретно: memConn.CloseRead (вызываемый tun2socks на src после копии)
не должен ронять активную закачку, а сам RST в gVisor рождается уже ВНУТРИ
стека на приёме данных от приложения. Поскольку прямого доступа к gVisor
endpoint у нас нет (его держит tun2socks), правильное место — **разорвать
связь "uplink EOF ⇒ CloseRead app-эндпоинта"**: это можно сделать, только не
дав unidirectionalStream завершить origin→remote копию преждевременно, ЛИБО
форкнуть/обернуть tun2socks dialer так, чтобы аплинк-полузакрытие не делало
ShutdownRead на gVisor (см. §7, Вариант A — единственный, что бьёт в корень).

Уверенность: **высокая по механизму RST** (доказано кодом gVisor + tun2socks +
наши trace-факты), **средняя по тому, что это ОСНОВНОЙ, а не сопутствующий
обрыв** — нужно подтвердить одним полевым замером (см. §8) до реализации.

---

## 1. Полная карта буферов (downlink сервер→приложение) и их лимиты

Цепочка downlink (сервер читает target → ... → Chrome):

```
[target TCP на сервере]
  │  server/websocket.go: tc.Read(buf[:limit])   buf=32768, limit=min(32768, credit)
  ▼
[server per-stream relay goroutine]
  │  EncryptChunk → writeMsg → WSAsyncWriter.outbound (cap 512 ФРЕЙМОВ)   ← B1
  ▼
[WS / nginx / CF / TSPU / интернет]    ← сетевой RTT 50-100мс, окно flow гейтит объём
  ▼
[client slotReaderWithClient]  ReadMessage → DecryptChunkSafe → RouteToStream
  │
  ▼
[incomingCh per-stream]  make(chan []byte, 512)  cap 512 ФРЕЙМОВ (~512×8КБ=4МиБ)  ← B2
  │  client.go:710. ДРОП при переполнении (RouteToStream select/default → recordBufferOverflow)
  ▼
[downlink goroutine tcp.go:778]  conn.Write(data)   conn = ourConn (memConn relay-end)
  │  → cl.OnStreamConsumed(streamID, len(data))   tcp.go:807  ← КРЕДИТ ВОЗВРАЩАЕТСЯ ЗДЕСЬ
  ▼
[memConn d2]  memPipeBufferSize = 256 KiB  (memconn.go:33)  ← B3. БЛОКИРУЮЩИЙ Write (backpressure, не дроп)
  ▼
[tun2socks unidirectionalStream "remote->origin"]
  │  io.CopyBuffer(originConn=gVisor gonet.TCPConn, remoteConn=memConn)  relay buf 20 KiB
  ▼
[gVisor TCP endpoint send-buffer]  Default = 1 MiB, Max = 4 MiB  ← B4
  │  tun2socks v2.6.0 option.go WithDefault → WithTCPSendBufferSizeRange(4KiB, 1MiB, 4MiB)
  │  core/tcp.go setSocketOptions: ep.SetSendBufferSize(Default=1MiB)
  │  WithTCPModerateReceiveBuffer = FALSE (авто-тюнинг ВЫКЛ)
  │  gonet TCPConn.Write на полном буфере = БЛОКИРУЕТСЯ (ErrWouldBlock → ждёт WritableEvents),
  │  возвращает ОШИБКУ только если endpoint в error state (RST).  ← КЛЮЧ
  ▼
[gVisor TCP stack → TUN/Wintun MTU 1400 → реальный сетевой стек ОС → Chrome]
```

Flow-control credit:
- client advertises `flowWindowFromEnv(1<<20)` = **1 МиБ** (clamp maxFlowWindow=6МиБ), stream_flow.go:15.
- server `-flow-max-window` default **1 МиБ** (cmd/shadowlink-server/main.go:68).
- эффективное окно = `negotiateFlowWindow(min(client, server))` = **1 МиБ/стрим**.
  (История "1→4МиБ" — это было через env; текущий дефолт 1МиБ.)
- server credit `available` cap = 2×window = 2 МиБ (stream_credit.go:79).
- creditFlushFloor 32 КиБ (stream_flow.go:88) → клиент шлёт WINDOW_UPDATE
  каждые ~32 КиБ потреблённого.

### Где узкое место на 150 Мбит/с?

150 Мбит/с = 18.75 МБ/с. На один стрим:
- gVisor 1 МиБ send-buffer drains со скоростью реального ACK от Chrome через TUN.
  При RTT TUN→Chrome ≈ 0 (loopback in-host), 1 МиБ окна хватает (BDP крошечный).
- memConn 256 КиБ — drains со скоростью io.CopyBuffer (20КиБ/итерация) в gVisor.
  Пока gVisor не блокирует — memConn проскакивает.
- incomingCh 512 фреймов × ~8 КБ = 4 МиБ — больше окна (1 МиБ), так что при
  нормальной работе НЕ должен переполняться (окно не даёт серверу нашлёпать
  >1МиБ неподтверждённого).

**ВЫВОД по буферам:** при штатной работе ни один буфер не является
бутылочным горлышком — flow window (1МиБ) < incomingCh (4МиБ), а memConn и
gVisor блокируют (backpressure), не дропают. overflow drop=2 — это РЕДКИЙ
всплеск (см. §3), вторичный к описанному ниже RST, а не первопричина.

---

## 2. gVisor send-buffer — проверено, НЕ первопричина

Подозрение из брифа (gVisor reset при переполнении) — **опровергнуто кодом**:

- `gonet.TCPConn.Write` (gvisor adapters/gonet/gonet.go:360): на полном
  send-buffer возвращает `ErrWouldBlock`, регистрирует `WritableEvents` и
  **БЛОКИРУЕТСЯ** до освобождения места или дедлайна. Дедлайн на downlink-
  направлении НЕ ставится (tun2socks ставит ReadDeadline только на dst после
  завершения копии, причём dst тут = origin лишь в аплинк-горутине). Значит
  переполнение gVisor send-buffer = **тихий блок, НЕ ошибка, НЕ RST**.
- Ошибку (`default:` ветка switch) Write вернёт ТОЛЬКО если endpoint уже в
  error state — т.е. соединение СБРОШЕНО (RST), а не "буфер полон".

Поэтому "увеличить gVisor send-buffer" НЕ устранит обрыв — оно лишь чуть
сдвинет порог, как и предыдущие 4 фикса. Это паллиатив.

PR #336 (SetSendBufferSize) в tun2socks: в v2.6.0 `engine.Key` НЕ имеет поля
для буфера (cmd/nixavpn-client/tunnel.go ставит только Device/Proxy/LogLevel/
MTU/UDPTimeout). Буфер фиксирован дефолтом 1МиБ. Менять его через CreateStack
Options мы не можем без форка/обёртки. Но это и не нужно (см. выше).

---

## 3. overflow drop (НОВОЕ, drops=2) — вторичный симптом, не корень

`incomingCh` cap 512. Overflow (`RouteToStream` select/default →
`recordBufferOverflow`) случается, только если downlink-горутина
(tcp.go:733) перестала ЧИТАТЬ из incomingCh быстрее, чем reader кладёт.
Downlink-горутина стопорится на `conn.Write(data)` (memConn) ИЛИ уже ушла в
"drain-loop" после ошибки записи (tcp.go:795 — пустой цикл, который ЧИТАЕТ и
выбрасывает, чтобы не блокировать демукс).

Последовательность, дающая drops=2:
1. app-side gVisor endpoint получает RST (см. §4) → `conn.Write` (memConn→
   tun2socks→gVisor) падает → tcp.go:778 ошибка → горутина уходит в
   drain-loop (tcp.go:795).
2. Между моментом RST и входом в drain-loop reader успевает положить ещё
   пару фреймов в полный incomingCh → 2 дропа.

Т.е. drops=2 — это ХВОСТ обрыва, а не его причина. (Контраст с памятью
29-30 мая, где drops=50 трактовались как корень: с flow-control окно теперь
гейтит объём, поэтому переполнение стало редким — drops упали с 50 до 2, но
**обрыв остался**, потому что обрыв — это RST, не дроп.)

---

## 4. ПЕРВОПРИЧИНА: tun2socks делает ShutdownRead app-эндпоинта по EOF аплинка

### 4.1. Механика (доказано исходниками)

tun2socks `tunnel/tcp.go`:
```go
func pipe(origin, remote net.Conn) {
    go unidirectionalStream(remote, origin, "origin->remote") // UPLINK: src=origin
    go unidirectionalStream(origin, remote, "remote->origin") // DOWNLINK: src=remote
}
func unidirectionalStream(dst, src net.Conn, ...) {
    io.CopyBuffer(dst, src, buf)   // 20KiB
    if cr, ok := src.(CloseRead); ok { cr.CloseRead() }   // ← на src!
    if cw, ok := dst.(CloseWrite); ok { cw.CloseWrite() }
    dst.SetReadDeadline(now + 60s)
}
```

UPLINK-горутина: `src = originConn` (gVisor app endpoint). Когда приложение
(Chrome) дослало свой HTTP-запрос и сделало TCP half-close (или просто
io.Copy увидел, что больше читать нечего и соединение полузакрылось), копия
origin→remote завершается → tun2socks вызывает **`originConn.CloseRead()`**
= `ep.Shutdown(tcpip.ShutdownRead)` на app-эндпоинте.

Для GET крупного файла запрос — десятки байт, уходит мгновенно. Тело ответа
льётся секунды. Значит app-эндпоинт получает `RcvClosed=true` в первые
миллисекунды, ЗАДОЛГО до конца закачки.

### 4.2. Где рождается RST

gVisor `endpoint.go shutdownLocked` (стр. 2542): чистый ShutdownRead
**сам по себе RST не шлёт** — он лишь ставит `RcvClosed=true` и нотифицирует
EventRdHUp. НО: после `RcvClosed=true`, когда в endpoint ПРИХОДИТ входящий
сегмент с данными (приложение шлёт байты на полузакрытую-на-чтение сторону),
gVisor на приёме отвечает **RST** (стр. 2600 "keep handling incoming
segments by replying with RST"; и общий путь обработки сегмента на
RcvClosed-эндпоинте). Источники таких байт при keep-alive закачке:
- Chrome переиспользует TCP-соединение (HTTP/1.1 keep-alive, HTTP/2 на одном
  сокете) и шлёт СЛЕДУЮЩИЙ запрос/служебные байты, пока качается текущий ответ.
- TLS-уровень: ack-и записи, session ticket, renegotiation.
- Любой prefetch/pipelined запрос браузера по тому же соединению.

Как только прилетел RST → app-эндпоинт в error state →
downlink-горутина `io.CopyBuffer(originConn, memConn)` на ближайшем
`originConn.Write` получает ошибку (gonet `default:` ветка) → tun2socks
`handleTCPConn` defer'ы закрывают всё → `appConn.Close()` (полный) →
`peerFullClose` → у нас `fullClose=true`, "downlink write error closed pipe".

### 4.3. Почему streamAgeMs РАЗНЫЕ (1.9 / 5.7 / 8.5с), не 60с

Потому что RST прилетает не по таймеру, а когда Chrome решает дослать байт по
переиспользуемому соединению — это зависит от паттерна загрузки страницы
(сколько ресурсов, когда следующий запрос). Поэтому возраст обрыва — случайная
величина в секундах, НЕ привязан ни к 60с half-close timeout, ни к ротации.

### 4.4. Почему 171МБ stream63 ОДИН РАЗ дошёл

Соединение, по которому Chrome НЕ дослал ничего после запроса (одиночная
закачка, не reused, либо сервер прислал Connection: close) — app-эндпоинт с
RcvClosed=true никогда не получает входящих байт → RST не рождается → закачка
доходит. Это объясняет "большинство рвётся, но изредка проходит".

---

## 5. Рассинхронизация OnStreamConsumed vs реальное потребление (ключ из брифа §5)

Бриф верно подметил: `OnStreamConsumed` (tcp.go:807) вызывается СРАЗУ после
`conn.Write(data)` в memConn (256 КиБ), а НЕ после реального чтения
приложением из gVisor. Т.е. кредит возвращается, когда данные легли в memConn,
хотя они ещё стоят в memConn→gVisor send-buffer→TUN.

**Оценка:** это РЕАЛЬНАЯ неточность модели потока, но она НЕ первопричина
обрыва. Последствие рассинхронизации — сервер может держать "в полёте" чуть
больше, чем приложение реально приняло (до 256КиБ memConn + 1МиБ gVisor сверх
окна). Это могло бы переполнять incomingCh — но окно 1МиБ < incomingCh 4МиБ
оставляет запас 3МиБ, поэтому overflow редкий (drops=2, §3). Если бы обрыв был
от overflow — да, привязка кредита к gVisor-потреблению помогла бы. Но обрыв
от RST (§4), а RST не зависит от объёма в полёте. **Поэтому "привязать кредит к
gVisor" — тоже паллиатив для overflow, мимо корня.**

---

## 6. chunk_size мелкий (6-10КБ) — следствие flow-control, влияет на overhead, не на обрыв

Server downlink relay (websocket.go:828): `tc.Read(buf[:limit])`,
`limit = min(32768, credit)`. credit оборачивается малыми порциями
(creditFlushFloor 32КиБ, consume декрементит) → `tc.Read` берёт мелкие срезы →
фреймы 6-10КБ. На 150Мбит/с при 8КБ/фрейм = ~2300 фреймов/с/стрим: каждый
проходит decrypt + RouteToStream + lock(streamMu) + select. Это нагружает CPU
и lock-контеншн, увеличивает avg credit-wait (135мс — всё ещё >RTT), но
**сам по себе обрыв не вызывает**. Это эффективность, не корректность.

---

## 7. Варианты решения — оценка по «бьёт в первопричину»

| Вариант | Бьёт в RST-корень? | Вердикт |
|---|---|---|
| **A. Развязать "uplink EOF ⇒ ShutdownRead app-эндпоинта"** на in-process пути | **ДА — прямо в корень** | **РЕКОМЕНДОВАН** |
| B. Увеличить gVisor send-buffer (+chunk +incomingCh) | НЕТ (gVisor блокирует, не ресетит) | паллиатив, 5-й виток гонки |
| C. Привязать flow credit к реальному gVisor-потреблению | НЕТ (лечит только overflow drops=2) | паллиатив |
| D. Убрать/упростить flow | частично (вернёт overflow, см. историю drops=50) | регресс |

### Вариант A — детали (единственный архитектурно верный)

Проблема в стороннем коде: `tun2socks/tunnel.unidirectionalStream` безусловно
делает `src.CloseRead()` на app-эндпоинте, когда аплинк-копия видит EOF. Для
in-process пути (memConn) мы НЕ хотим, чтобы завершение аплинка транслировалось
в ShutdownRead gVisor app-эндпоинта, пока downlink активен.

Мы НЕ можем влезть в `unidirectionalStream` (это их relay поверх dialer).
НО мы контролируем dialer (inProcessDialer) и memConn. Корень в том, что
ShutdownRead делается на `originConn` (gVisor), а origin — это НЕ наш объект,
его создаёт tun2socks core. Значит точка вмешательства — **не дать
io.CopyBuffer(remote, origin) завершиться раньше времени**, т.е. не дать нашему
memConn (=remote, dst аплинка) выглядеть так, будто запрос закончен, когда на
самом деле соединение keep-alive.

Реально исполнимые под-варианты A:

- **A1 (форк relay).** Заменить tun2socks `pipe`/`unidirectionalStream` на свой
  in-process relay, который для memConn НЕ делает `CloseRead` на gVisor
  app-эндпоинте по EOF аплинка (только CloseWrite в сторону target). Требует
  доступа к origin endpoint в нашем коде — а его держит tun2socks. Значит
  форкать надо `core/tcp.go withTCPHandler` + `tunnel/tcp.go`, передав наш
  handler, который сам гоняет pipe без преждевременного ShutdownRead.
  → Самый чистый, но требует обёртки tun2socks engine (мы и так дёргаем
  engine.Insert/Start — можно подменить TransportHandler).

- **A2 (отключить RST-on-unread в gVisor).** Через CreateStack Options выставить
  поведение, при котором ShutdownRead с приходящими данными НЕ ведёт к RST.
  gVisor такого тумблера штатно не даёт (RST на RcvClosed — by design). Не
  подходит.

- **A3 (подавить ShutdownRead на memConn-стороне).** Поскольку tun2socks
  вызывает `src.CloseRead()` где src=originConn (gVisor), а НЕ наш memConn —
  переопределить наш memConn.CloseRead бесполезно: ShutdownRead идёт в gVisor,
  не в memConn. → НЕ работает. (Важно: это развеивает иллюзию, что фикс на
  стороне memConn спасёт.)

**Вывод A:** правильное вмешательство — **A1: подменить TransportHandler/relay
tun2socks так, чтобы для TCP мы сами управляли парой (origin, remote) и НЕ
делали ShutdownRead на origin до реального full-close**, а half-close аплинка
транслировали только как "перестать читать из приложения", оставляя downlink
жить. Это ровно зеркало того, что мы УЖЕ сделали в `tunnelTCPStream` для
uplink-EOF (tcp.go:679 — half-close не отменяет downlink), но проблема в том,
что ShutdownRead app-эндпоинта делает СЛОЙ ВЫШЕ (сам tun2socks pipe), до того
как байты дойдут до нашего relay. Поэтому фикс обязан быть на уровне
tun2socks-handler, а не в наших socks5/relay-горутинах.

---

## 8. Что измерить/проверить ДО реализации (подтверждение корня)

1. **Прямой тест RST-гипотезы (решающий).** Запустить закачку >100МБ, и в
   момент обрыва снять `netstat`/Wireshark на TUN/Wintun: ожидаем увидеть
   **RST от 198.18.x (gVisor app endpoint) в сторону приложения** ПОСЛЕ того
   как приложение дослало байт по keep-alive соединению. Если RST есть и
   предшествует "downlink write error" — корень подтверждён.
2. **Корреляция fullClose с reused-соединением.** В trace уже есть
   `fullClose=true` + `streamAgeMs`. Добавить лог в inProcessDialer/relay:
   делал ли app `CloseWrite` (half-close, uplink EOF) РАНЬШЕ, чем пришёл RST.
   Ожидаем: для ВСЕХ оборвавшихся стримов CloseWrite (half-close) случился за
   секунды до обрыва, а downlinkBytes продолжали расти между ними. Для
   дошедшего stream63 — CloseRead app-эндпоинта тоже был, но входящих байт от
   приложения после него не было.
3. **A/B без keep-alive.** Скачать тем же клиентом файл с `Connection: close`
   (или curl одиночным запросом) vs браузером с переиспользованием. Если
   `Connection: close` / одиночные запросы доходят, а keep-alive рвётся —
   подтверждает §4.4 и корень.
4. **Контроль gVisor-блокировки (отвергнуть B).** Залогировать в обёртке
   memConn, блокировался ли `conn.Write` (d2 полон 256КиБ) перед обрывом.
   Ожидаем: чаще НЕ блокировался (обрыв от RST, не от backpressure). Если
   блокировался часто — пересмотреть вес Варианта B.
5. Проверить фактически негоциированное окно в поле (лог
   `effectiveWindow`/slot.flowWindow): 1МиБ или 4МиБ (env). Это влияет на §5,
   но не на выбор Варианта A.

Если (1)+(3) подтверждают RST-механизм — реализуем A1. Если вдруг (4) покажет
массовый block memConn без RST — корень иной (backpressure), тогда C+B.

---

## 9. Резюме одной страницей

- **Цепочка буферов:** target→[server credit-gated read 32КБ]→WSAsyncWriter
  512→WS/CF→incomingCh 512(=4МиБ)→memConn 256КиБ(блок)→gVisor send 1МиБ(блок)→
  TUN→Chrome. Flow window 1МиБ/стрим гейтит объём в полёте.
- **НИ ОДИН буфер не дропает при штатной работе** (window<incomingCh; memConn и
  gVisor блокируют, не дропают). overflow drops=2 — хвост обрыва, не причина.
- **gVisor send-buffer переполнение = тихий блок, НЕ RST** (gonet.Write ждёт
  WritableEvents). Увеличивать буфер бессмысленно для обрыва.
- **Первопричина:** tun2socks `unidirectionalStream` по EOF аплинка делает
  `originConn.CloseRead()` = `ShutdownRead` gVisor app-эндпоинта. Для крупной
  keep-alive закачки запрос крошечный → ShutdownRead срабатывает в первые мс →
  когда Chrome дошлёт байт по переиспользуемому соединению, gVisor отвечает
  **RST** на RcvClosed-эндпоинт → app endpoint в error → downlink io.CopyBuffer
  `originConn.Write` падает → full Close → "downlink write error closed pipe",
  fullClose=true. streamAgeMs случайные (когда Chrome дошлёт байт), не 60с.
- **Решение (одно):** Вариант A1 — подменить tun2socks TCP-handler/relay так,
  чтобы half-close аплинка НЕ транслировался в ShutdownRead app-эндпоинта, пока
  downlink жив (зеркало того, что мы уже сделали в socks5/tcp.go для uplink-EOF,
  но на правильном слое — внутри tun2socks pipe, а не в наших relay-горутинах).
- **Паллиативы (отвергнуты как корень):** B (gVisor buffer), C (credit↔gVisor),
  D (убрать flow) — каждый сдвинет порог = 5-й виток гонки.
- **Подтвердить до кода:** Wireshark RST на TUN в момент обрыва + A/B
  keep-alive vs Connection:close.
