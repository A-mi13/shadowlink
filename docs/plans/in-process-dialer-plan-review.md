# Адверсариальное ревью: In-Process tun2socks Dialer Plan

Дата ревью: 2026-05-29. Ревьюер: code-reviewer (адверсариальный проход по реальному коду).
Объект: `D:\NIXAVPN\shadowlink\docs\plans\in-process-dialer-plan.md`
Версия tun2socks: **v2.6.0** (`C:\Users\Lenovo\go\pkg\mod\github.com\xjasonlyu\tun2socks\v2@v2.6.0`).

## Вердикт: НУЖНЫ ПРАВКИ перед реализацией

Корневой диагноз плана **верен** (P1/P2/P3 направление корректное), но в плане есть один
**BLOCKER** (двойной routing + потеря hostname-based bypass), один **BLOCKER** по wiring
(Tunnel не имеет доступа к cl/stream/router — там interface, не concrete), и несколько HIGH,
которые при буквальной реализации сломают UDP, half-close FIN и backpressure. Самый рискованный
участок — UDP (как и заявлено), но и TCP-half-close семантика tun2socks v2.6.0 в плане не учтена.

---

## Подтверждённые утверждения плана (verified OK)

1. **Диагноз data-path точен.** `server.go:250-256` dispatch: `PerStreamWS != nil` → per-stream;
   `WST != nil` → `HandleTCPConnectWS`; иначе poll. В direct/default режиме
   `engine_shadowlink.go:579-587` ставит `WST: e.stream`, где `e.stream` = `WSPoolTransport`
   (`engine_shadowlink.go:471`). Per-stream — только при `NIXAVPN_FORCE_PER_STREAM_WS=1`
   (`engine_shadowlink.go:239`). **Значит рефакторить надо именно `HandleTCPConnectWS` (tcp.go:411-721) — план прав.**

2. **proxy.Dialer контракт точен.** `proxy/proxy.go:19-22`:
   `DialContext(context.Context, *M.Metadata) (net.Conn, error)` + `DialUDP(*M.Metadata) (net.PacketConn, error)`.
   Plan верно цитирует.

3. **DstIP всегда конкретный IP.** `metadata/metadata.go:13` — `DstIP netip.Addr`;
   `DestinationAddress()` = `netip.AddrPort.String()` = "ip:port". Hostname в metadata **никогда не приходит** —
   это важно (см. BLOCKER-1).

4. **net.Conn достаточно, реальный сокет не нужен.** `tunnel/tcp.go:32-43` — tun2socks берёт
   возвращённый conn, оборачивает в `statistic.NewTCPTracker` и гоняет через `pipe()` →
   `io.CopyBuffer`. Никаких syscall'ов на сокете. Plan прав.

5. **SetDialer на singleton.** `tunnel/tunnel.go:108-112` — `SetDialer` под RWMutex,
   `t2tunnel.T().SetDialer(bypass)` (`tunnel.go:311`) уже используется. Свап inner — валиден.

---

## BLOCKER

### BLOCKER-1 — Двойной routing + полная потеря hostname-based bypass/block в in-process пути
**Severity: BLOCKER**

План P2 говорит: `DialContext: dst=m.DestinationAddress(); router.Decide (block→err)`.
Но routing **уже** делается выше по стеку, в `BypassDialer.DialContext` (`client/bypassroute/dialer.go:45-56`),
который и есть `inner`-владелец. Архитектура такая:

```
tun2socks → BypassDialer.DialContext (IP-trie bypass) → inner (сейчас Socks5, план: InProcessDialer)
```

Проблемы:

1. **`Router.Decide` на IP бесполезен для hostname-правил.** `routing.go:30-42`:
   `*.ru`/`*.рф`/`*.by`/… matchers сравнивают `strings.HasSuffix(host, ".ru")`.
   В loopback-SOCKS5 пути `destAddr` приходил из SOCKS5 CONNECT-заголовка и **мог быть hostname**
   (приложение само резолвит или передаёт имя). В TUN-пути `m.DestinationAddress()` = **только IP**
   (`metadata.go:13` netip.Addr). Значит `*.ru` bypass через `Router.Decide` в новом dialer'е
   **молча перестанет работать** для hostname-правил — а defaultBypass (`engine_shadowlink.go:556-564`)
   целиком состоит из `*.ru/*.рф/*.su/*.by/*.kz/*.ua/*.am`. Block-правила (`Routing.Block`) на hostname —
   тоже мёртвы.

   > ВАЖНО: в **текущем** TUN-пути hostname-bypass УЖЕ не работает (loopback SOCKS5 получает IP от
   > tun2socks, не hostname). RU-bypass в TUN держится на **IP-trie** в `BypassDialer.shouldBypass`
   > (`dialer.go:71-93`, embedded RU CIDR snapshot + Yandex DNS на TUN → RU-сайты резолвятся в RU-IP).
   > Поэтому добавлять `Router.Decide` в InProcessDialer — это **новый, дублирующий и вводящий
   > в заблуждение слой**, который ничего не блокирует (block-on-IP редко срабатывает) и создаёт
   > иллюзию что `*.ru` block/bypass работает.

2. **ActionDirect в InProcessDialer недостижим/неверен.** Если `Router.Decide` вернёт `ActionDirect`
   (теоретически на IP-CIDR bypass-правиле), InProcessDialer должен сделать **direct**-дозвон через
   физический NIC — но это уже зона ответственности `BypassDialer.direct` (`proxy.NewDirect()`).
   Дублирование direct-логики в двух местах = два разных пути с разным bind-поведением.

**Как исправить план:**
- Убрать `router.Decide` из InProcessDialer **полностью** ИЛИ оставить только `ActionBlock`
  (вернуть err) и явно задокументировать что bypass/direct остаётся за `BypassDialer` (IP-trie).
- Зафиксировать в плане: **hostname-based routing в TUN-режиме не поддерживается ни сейчас, ни после
  рефактора** — это свойство tun2socks (IP-only metadata), не регрессия. Если hostname-bypass нужен —
  это отдельная фича (sniff SNI/DNS), вне scope этого плана.
- `tunnelTCPStream` (P1 extracted core) **не должен** содержать вызов `router.Decide` — он уже ПОСЛЕ
  router.Decide в исходнике (tcp.go:421-428 — Decide; tcp.go:432+ — relay). Это в плане сформулировано
  верно ("ПОСЛЕ router.Decide"), но P2 повторно вызывает Decide. Несогласованность P1↔P2.

---

### BLOCKER-2 — Tunnel не имеет доступа к cl/stream/router/*Server; eng — это interface
**Severity: BLOCKER**

План P4: "installBypassDialer получает cl/stream/router. inner = engine.NewInProcessDialer()".
Но в реальном коде:

- `Tunnel` создаётся как `NewTunnel(eng.SOCKSAddr(), cfg.ProxyUser, cfg.ProxyPass, serverIPs)`
  (`main.go:220`) — он знает **только строку SOCKS-адреса**, ничего про `*Client`/`*WSPoolTransport`/`*Router`.
- `eng` имеет статический тип `Engine` (`engine.go:10`, interface с 4 методами:
  `Connect/SOCKSAddr/Name/Close`). `*ShadowLinkEngine` приходится type-assert'ить.
- `installBypassDialer` (`tunnel.go:297`) живёт в пакете `main`, но строит `proxy.NewSocks5`
  из `t.socksAddr` — у него **нет** ссылки на engine internals.
- Все нужные поля (`cl`, `stream`, `socks *socks5.Server` с его `connectSem`, `router`) — приватные
  поля `*ShadowLinkEngine` (`engine_shadowlink.go:23-44`). `router` вообще локальная переменная в
  `Connect` (`engine_shadowlink.go:573`), наружу не выставлена.

**Как исправить план:**
- Добавить в план явный шаг: расширить интерфейс `Engine` (или ввести опциональный интерфейс
  `InProcessDialerProvider { NewInProcessDialer() proxy.Dialer }`), реализованный только
  `*ShadowLinkEngine`. `main.go` делает type-assert и передаёт dialer в `Tunnel` через
  новый `WithInProcessDialer(d proxy.Dialer)`.
- `*ShadowLinkEngine.NewInProcessDialer()` строит dialer из своих `e.cl`, `e.stream`, `e.socks`
  (для connectSem) — но `e.socks` создаётся **после** `e.stream` и **внутри** `Connect`; нужно
  убедиться что к моменту `tun.Start()` (`main.go:223`, после `eng.Connect` на `main.go:146`)
  все они инициализированы. Порядок: `eng.Connect` (строит socks+stream) → `tun.Start` → ok.
- `router` надо сохранить как поле `e.router` (сейчас локальная переменная) чтобы dialer мог
  его взять (или, по BLOCKER-1, вообще не брать).
- ВНИМАНИЕ к VLESS-engine: `Engine` реализует и `*VLESSEngine`. Новый метод должен быть
  опциональным (interface assertion), иначе VLESS не скомпилируется / TUN для VLESS сломается.

---

## HIGH

### HIGH-1 — TCP half-close (CloseRead/CloseWrite) — memconn ОБЯЗАН их реализовать, иначе FIN/EOF полу-сломаны
**Severity: HIGH**

`tunnel/tcp.go:57-73` (`unidirectionalStream`) после `io.CopyBuffer` делает:
```go
if cr, ok := src.(interface{ CloseRead() error }); ok { cr.CloseRead() }
if cw, ok := dst.(interface{ CloseWrite() error }); ok { cw.CloseWrite() }
dst.SetReadDeadline(time.Now().Add(tcpWaitTimeout)) // 60s
```
`statistic.tcpTracker` (`tracker.go:78-90`) **проксирует** CloseRead/CloseWrite на нижележащий conn
(наш memconn). План (риск "session FIN на Close") предполагает что `tun2socks закрывает conn → memconn Close`.
**Это неточно:** tun2socks сначала вызывает `CloseWrite()` (half-close, не full Close), и только
`defer remoteConn.Close()` (tcp.go:40) закрывает полностью при выходе из `handleTCPConn`.

Последствия для memconn-дизайна (план P0):
- memconn ДОЛЖЕН реализовать `CloseWrite()` — это сигнал "uplink закончился" (EOF приложения).
  Без `CloseWrite()` тип-ассершн в tun2socks не сработает (graceful) — half-close проигнорируется,
  и наш uplink-reader в `tunnelTCPStream` (бывш. tcp.go:594 `conn.Read`) **никогда не получит EOF**
  → idle-grace не запустится корректно → стрим висит до ctx-таймаута/hard-cap.
- memconn ДОЛЖЕН реализовать `CloseRead()` — иначе downlink-направление при завершении download'а
  не получит сигнал и downlink goroutine может зависнуть на `conn.Write`.
- `SetReadDeadline` ОБЯЗАН работать на memconn (tun2socks ставит 60s после half-close). План это
  упоминает ("SetDeadline*"), но не связывает с tcpWaitTimeout=60s — добавить тест на 60s drain.

**Как исправить план:** В P0 явно: memconn реализует `CloseRead() error` и `CloseWrite() error`
(не только `Close()`), где `CloseWrite` шлёт EOF на read-сторону peer'а, `CloseRead` — отбрасывает
дальнейшие записи peer'а. Тест: после `CloseWrite()` на стороне app, `tunnelTCPStream`'s `conn.Read`
возвращает io.EOF и запускает idle-grace.

### HIGH-2 — UDP: symmetricNATPacketConn дропнет ВСЕ ответы, если ReadFrom не вернёт from == dst
**Severity: HIGH**

`tunnel/udp.go:45,96-115`: возвращённый из `DialUDP` PacketConn оборачивается в
`symmetricNATPacketConn`, чей `ReadFrom` **дропает пакет если `from.String() != pc.dst`**
(`udp.go:108`), где `pc.dst = metadata.DestinationAddress()` = "IP:port".

Это значит: наш `streamPacketConn.ReadFrom` ОБЯЗАН возвращать `net.Addr`, у которого
`String() == "<dstIP>:<dstPort>"` (тот же IP:port, что tun2socks передал в DialUDP).
В текущем серверном UDP-протоколе ответ несёт `addr` из `ParseUDPChunk` (`chunk.go:265-277`,
`udp.go:158`) — это **серверо-сообщённый source** ответного датаграма, который для DNS/большинства
UDP равен dst, НО:
- для некоторых UDP-сервисов source ответа != запрошенному dst (DNS обычно ок, но не всегда;
  QUIC/STUN/multi-homed — нет);
- формат `addr` в чанке может быть hostname или другой формат → `from.String()` не совпадёт с
  numeric "IP:port" → **молчаливый дроп всех ответов** → UDP "работает на отправку, но не получает".

**Как исправить план:** P3 должен ЯВНО возвращать из `streamPacketConn.ReadFrom` фиксированный
`from = metadata.UDPAddr()` (тот же dst, переданный в DialUDP), а НЕ addr из chunk'а. Источник
датаграма для tun2socks всегда один (per-5-tuple PacketConn). Игнорировать chunk.addr на чтении.
Добавить тест: ReadFrom возвращает from с `String()==dst`, иначе symmetric NAT дропнет.

### HIGH-3 — UDP: connectSem / PoolReadiness gate / lifecycle per-5-tuple не покрыты планом детально
**Severity: HIGH**

1. **PoolReadiness gate теряется.** `HandleUDPAssociateWS` (`udp.go:47-56`) при старте проверяет
   `pr.ReadyCount() < udpMinReadySlots(2)` и отклоняет ASSOCIATE. В новом `DialUDP` этой проверки
   нет в плане — без неё UDP-стрим привяжется к слоту, который может не recover'нуть (тот самый
   cascade, ради которого C12 F6 и делали). План должен перенести gate в `DialUDP`
   (вернуть err если `e.stream.(PoolReadiness).ReadyCount() < 2`).

2. **Lifecycle: RegisterStream/UnregisterStream/FIN per DialUDP.** План говорит "register/FIN
   per 5-tuple". Верно, но: tun2socks создаёт **новый PacketConn на каждый dst-5-tuple**
   (udp.go:29) и закрывает его по `udpTimeout` (default 30s, `engine.Key.UDPTimeout` в tunnel.go:150,
   `copyPacketData` ставит deadline на каждый ReadFrom — udp.go:73). Значит `streamPacketConn.Close()`
   ДОЛЖЕН: UnregisterStream + послать UDP-FIN. Иначе при активном DNS (десятки доменов = десятки
   5-tuple за секунды) стрим-слоты (max 256/session, `maxClientStreams`) **утекут за минуты**.
   Это эквивалент TCP-stream-leak, но для UDP гораздо острее (DNS взрывает число 5-tuple).

3. **Нет CONNECT для UDP в текущем протоколе.** В `HandleUDPAssociateWS` НЕТ `StreamConnectChunk` —
   первый `NewUDPDataChunk` сам несёт target addr (`udp.go:135`). План P3 это учитывает
   ("WriteTo: NewUDPDataChunk+encrypt"), но надо явно: stream регистрируется (RegisterStream →
   incomingCh) при первом WriteTo, демультиплексор сервера (RouteToStream для FlagUDP,
   ws_pool.go:2604) кладёт **полный** chunk.Payload (со StreamID!) в incomingCh, а наш ReadFrom
   парсит его через ParseUDPChunk. Подтверждено: для FlagUDP в incomingCh лежит payload С
   2-байтным StreamID-префиксом (ws_pool.go:2605 `cl.RouteToStream(streamID, chunk.Payload)`),
   тогда как для TCP — БЕЗ префикса (`chunk.Payload[2:]`, ws_pool.go:2607). **Не перепутать**:
   в UDP ReadFrom надо ParseUDPChunk(payload) который ожидает StreamID в payload[0:2]
   (`chunk.go:269`). Это в плане не зафиксировано — легко ошибиться.

**Как исправить план:** P3 расширить: (a) PoolReadiness gate в начале DialUDP; (b) Close →
UnregisterStream + FIN; (c) явно описать что incomingCh для UDP содержит StreamID-префикс
(ParseUDPChunk ожидает его), в отличие от TCP-демукса.

### HIGH-4 — connectSem (srv.AcquireConnect) — план полагается на shared *Server, но это меняет семантику throttle
**Severity: HIGH**

`HandleTCPConnectWS` берёт `srv.AcquireConnect(10s)` (tcp.go:446) — глобальный семафор на
`maxConcurrentConnects=32` (server.go:100) ПЕНДИНГ-CONNECT'ов, и освобождает его сразу после
отправки CONNECT-чанка (tcp.go:551-554, optimistic). `AcquireConnect`/`ReleaseConnect` nil-safe
(server.go:166-187 — если `connectSem==nil` → true/no-op). План (риск "connectSem ownership")
говорит шарить listener's `*Server`.

Проблемы:
1. `s.connectSem` инициализируется **только** в `ListenAndServe` (server.go:110). Если loopback
   listener остаётся для non-TUN (план P4), то `*Server` запущен и `connectSem != nil` — ок.
   Но если в TUN-режиме listener НЕ слушает (план "вывести loopback из TUN data-path"), а dialer
   шарит тот же `*Server`, то `ListenAndServe` всё равно должен быть вызван чтобы `connectSem`
   создался — иначе nil → throttle отключён (32-лимит не действует) → может вернуться cascade,
   от которого connectSem и защищает.
2. Семафор на 32 проектировался под **loopback-burst** (приложения ретраят отклонённые CONNECT).
   В in-process пути нет отдельного listener-accept; `DialContext` вызывается напрямую из множества
   tun2socks-горутин (`handleTCPConn` per-conn goroutine, tunnel.go:78). Семантика "wait вместо
   reject" (tcp.go:444-450) сохранится, но 10s wait на DialContext, при том что tun2socks ставит
   `tcpConnectTimeout=5s` на ctx (proxy.go:14, tunnel/tcp.go:29) → **AcquireConnect(10s) превысит
   ctx-дедлайн 5s** → dial всегда будет падать по ctx до того как семафор отпустит. Несогласованность
   таймаутов: внешний ctx 5s, внутренний Acquire 10s.

**Как исправить план:**
- Зафиксировать: `tunnelTCPStream` принимает `srv *Server` и вызов AcquireConnect должен уважать
  `ctx` (использовать `ctx`-aware acquire, не фиксированные 10s), т.к. tun2socks DialContext ctx = 5s.
- Решить: оставлять ли connectSem вообще в in-process пути. Optimistic CONNECT + отсутствие
  loopback-retry-storm может означать что семафор больше не нужен (или нужен с другим лимитом).
  Явно описать в плане, не оставлять на догадку.
- Если `*Server` шарится без `ListenAndServe` — инициализировать `connectSem` отдельно.

### HIGH-5 — DialContext ctx живёт только 5s; relay переживает его — нельзя завязывать relay на dial-ctx
**Severity: HIGH**

`tunnel/tcp.go:29` — `ctx, cancel := context.WithTimeout(..., tcpConnectTimeout(5s)); defer cancel()`.
Этот ctx передаётся в `DialContext` и **отменяется через 5s ИЛИ при выходе из dial** (defer cancel
срабатывает... нет — `handleTCPConn` держит cancel до конца функции, т.е. до конца relay через pipe).
Перечитываем: `defer cancel()` на tcp.go:30 — отменяется при **возврате handleTCPConn**, т.е. после
`pipe()` (весь relay). НО `context.WithTimeout(5s)` всё равно **истечёт через 5s независимо**.

Значит: если `tunnelTCPStream` использует переданный из DialContext `ctx` для relay-горутин
(uplink/downlink), они получат `ctx.Done()` через 5 секунд → relay умрёт через 5s.
В loopback-пути `HandleTCPConnectWS` получает `ctx` от `s.handleConn` ← `ListenAndServe` ←
долгоживущий engine-ctx (server.go:137), а внутри делает `ctx2, cancel := context.WithCancel(ctx)`
(tcp.go:572) — без таймаута. В in-process пути `ctx` из DialContext = 5s-таймаут.

**Как исправить план:** InProcessDialer.DialContext НЕ должен прокидывать свой 5s-ctx в
`tunnelTCPStream` relay-горутины. Запускать relay с `context.WithCancel(engineCtx)` (долгоживущий
ctx движка, e.cancel/ctx2), а dial-ctx использовать ТОЛЬКО для фазы установки (RegisterStream +
отправка CONNECT-чанка). Иначе ВСЕ TCP-стримы будут рваться через 5s. Это критично и в плане
вообще не упомянуто.

---

## MEDIUM

### MEDIUM-1 — net.Conn.LocalAddr() обязан вернуть валидный "ip:port", иначе MidIP/статистика мусор
**Severity: MEDIUM**

`tunnel/tcp.go:37` и `udp.go:34`: `metadata.MidIP, metadata.MidPort = parseNetAddr(conn.LocalAddr())`.
`parseNetAddr` (addr.go:11) nil-safe, и при не-AddrPort-адресе зовёт `parseAddrString(addr.String())`
→ `netip.ParseAddrPort` (addr.go), который вернёт zero-Addr при ошибке (не паника). Значит memconn
с произвольным `LocalAddr().String()` не уронит tun2socks, но даст мусорную статистику/логи.
План перечисляет `Local/RemoteAddr` в P0 — ок, но стоит вернуть синтетический валидный
`127.0.0.1:0`-подобный addr чтобы parseAddrString не плевался. LOW-impact, но дешёво сделать чисто.

### MEDIUM-2 — io.CopyBuffer использует 20KB буфер; net.Pipe-замена и 256KB обоснование
**Severity: MEDIUM**

`tunnel/tcp.go:59` — `buffer.Get(buffer.RelayBufferSize)`, `RelayBufferSize = 20<<10` (20KB).
tun2socks копирует **через io.CopyBuffer** (не byte-by-byte), т.е. за один Write отдаёт до 20KB.
План прав что `net.Pipe` синхронный (Write блокирует до Read) — на 460Мбит это пинг-понг.
НО: tun2socks уже буферизует на своей стороне (20KB чанки) и uplink/downlink — отдельные горутины
(`pipe` → 2× `unidirectionalStream`). Реальный вопрос — НЕ throughput самого memconn, а то что
наш `tunnelTCPStream` на другом конце memconn читает 32KB-буфером (tcp.go:590
`buf := make([]byte, 32768)`) и шлёт в WS. С synchronous net.Pipe: tun2socks Write(20KB) блокируется
пока tunnelTCPStream.Read не заберёт — а тот сразу шлёт в WS (может блокировать на WS-write).
Цепочка блокировок → деградация, но не deadlock (отдельные горутины на направление).

**Оценка:** buffered memconn разумен, 256KB/направление — нормальный старт (8× tun2socks-чанк).
Но план должен **обосновать число бенчмарком против реального WS-throughput**, а не throughput
самого memconn (memconn никогда не bottleneck — WS через CF/TLS медленнее). Риск backpressure-дизайна:
если memconn-буфер полон и tunnelTCPStream медленно сливает в WS — tun2socks Write заблокируется,
что есть **правильный** backpressure (не теряем данные). 256KB ок. Снизить приоритет тревоги в плане:
главное — корректность Close/EOF (HIGH-1), не размер буфера.

### MEDIUM-3 — relay-ядро: что именно переносится в tunnelTCPStream — список неполон
**Severity: MEDIUM**

План P1: "tunnelTCPStream = всё из HandleTCPConnectWS ПОСЛЕ router.Decide". Проверил tcp.go:432-720.
Что ОБЯЗАТЕЛЬНО должно переехать (план перечисляет частично):
- `client.Stats.SocksConnects.Add(1)` (tcp.go:432) — иначе counter врёт.
- isDNS-проверка + AcquireConnect/ReleaseConnect (tcp.go:436-459) — см. HIGH-4.
- `NextStreamID` + `RegisterStream` + `defer UnregisterStream` (нет — defer CloseStream, tcp.go:471).
- `defer cl.CloseStream(streamID, wst)` (tcp.go:471) — FIN. КРИТИЧНО (риск утечки стримов).
- PoolAware.AssignStream (tcp.go:474-477) + PendingTracker.IncrPending/DecrPending (tcp.go:483-485,
  656-661) — иначе ломается pool distribution / cold-start метрики (риск в плане отмечен).
- **Split-ветка (tcp.go:490-526)**: `wst.(*SplitTransport)` путь с SendChunkSync. В TUN-режиме
  e.stream может быть SplitTransport (fallback, engine_shadowlink.go:525)! План НЕ упоминает что
  tunnelTCPStream должен сохранить и Split-ветку, иначе SplitHTTP-fallback в системном VPN сломается.
- `cl.MarkFirstStream()` (tcp.go:563) — cold-start gauge.
- optimistic CONNECT через StreamWriteControl (tcp.go:544) vs Split SendChunkSync.
- lastDownlinkNs + waitForIdleOrCancel (tcp.go:583-605) — idle-grace (риск отмечен).
- downlink overflow-drain loop при `conn.Write` error (tcp.go:690-711) — без него demux блокируется
  на полном канале (cap 512).

**Как исправить план:** P1 должен явно перечислить Split-ветку как часть переносимого ядра, ИЛИ
зафиксировать что in-process dialer работает ТОЛЬКО с WSPoolTransport и Split-fallback в TUN-режиме
отключается/не поддерживается. Сейчас неоднозначно.

### MEDIUM-4 — Конкурентность DialContext: streamMu / NextStreamID под нагрузкой
**Severity: MEDIUM**

tun2socks вызывает `DialContext` из per-conn горутины (`tunnel.go:78` `go t.handleTCPConn`).
Под системным VPN — десятки/сотни одновременных DialContext. `NextStreamID` (client.go:669) и
`RegisterStream` (client.go:686) уже под `streamMu` — потокобезопасны. `MarkFirstStream` —
sync.Once. ОК. Но план должен зафиксировать что InProcessDialer **не держит своего состояния**
с гонками (stateless, всё через cl/wst, которые thread-safe). Если dialer кэширует что-либо
(session pointer) — гонка с reconnect (см. client.go:946 Snapshot про H4). Рекомендация:
в DialContext брать `cl.Snapshot()` или `StreamSession(wst,...)` свежим на каждый dial, не кэшировать.

### MEDIUM-5 — Утечка горутин relay при ошибке установки
**Severity: MEDIUM**

В loopback-пути при ошибке (CONNECT write fail, tcp.go:545) функция возвращается ДО запуска
relay-горутин — чисто. В in-process: если `DialContext` запускает `go tunnelTCPStream(...)` ПЕРЕД
тем как вернуть appConn (план P2: "go tunnelTCPStream(ctx,ourConn,...); return appConn"), и затем
tun2socks решит что dial failed (например ctx уже истёк) — appConn вернётся, но tun2socks может
его сразу Close'нуть. Нужно гарантировать что Close на appConn → memconn EOF → tunnelTCPStream
видит EOF на uplink Read → idle-grace → CloseStream FIN → горутина выходит. Это цепочка HIGH-1.
Если memconn Close НЕ разблокирует tunnelTCPStream'овский Read — горутина + стрим-слот утекут
(план это отмечает как риск, но решение зависит от корректного memconn — связать явно с P0 тестом
"Close разблокирует заблокированный Read обеих сторон").

---

## LOW

### LOW-1 — IPv6 молча не туннелируется
`BypassDialer.shouldBypass` (dialer.go:80-82): `if !addr.Is4() { return false }` → IPv6 идёт в
inner (tunnel). Но split-routes (tunnel.go) только IPv4 (0.0.0.0/1). LeakGuard отключает IPv6
(CLAUDE.md). Так что IPv6 в TUN скорее всего не приходит. План не трогает IPv6 — ок, но стоит
зафиксировать что in-process dialer наследует IPv4-only поведение (DstIP.Is4() гейт остаётся в
BypassDialer выше).

### LOW-2 — Loopback listener для non-TUN: рефактор P1 не должен его сломать
План P4: "Loopback listener ОСТАВИТЬ для non-TUN". `HandleTCPConnectWS` остаётся тонкой обёрткой
над `tunnelTCPStream` (P1). Пока обёртка вызывает ту же extracted-функцию с теми же аргументами
(`conn, cl, wst, router, destAddr, srv`) — listener-путь идентичен. Существующие тесты
(udp_pool_gate_test.go, idle_grace_test.go) должны остаться зелёными. Риск низкий ЕСЛИ P1
действительно behavior-preserving. Golden-тест из плана (harness connPipe) — правильный подход.

### LOW-3 — Метрики bypass_match/socks_connects
`SocksConnects` (tcp.go:432) и bypass counters (`IncBypassMatch/Miss`, dialer.go via WithMetrics)
останутся корректными если перенести `Stats.SocksConnects.Add(1)` в tunnelTCPStream. Bypass-метрики
не затрагиваются (живут в BypassDialer слое). Низкий риск, упомянуть в P1 checklist.

### LOW-4 — graceful shutdown engine.Stop() vs активные in-process relay-горутины
`Tunnel.Stop` (tunnel.go:235) зовёт `engine.Stop()` — tun2socks закрывает TUN, перестаёт звать
dialer. Активные `tunnelTCPStream` горутины завязаны на engine-ctx (e.cancel в Close,
engine_shadowlink.go:735). При `eng.Close()` ctx отменяется → relay-горутины выходят. Порядок в
main.go: shutdown зовёт tun.Stop затем eng.Close (надо проверить — не входило в scope ревью).
Рекомендация: убедиться что memconn'ы закрываются при ctx-cancel чтобы tun2socks-side io.Copy
не висел.

---

## Counts по severity

| Severity | Count | IDs |
|----------|-------|-----|
| BLOCKER  | 2     | BLOCKER-1 (двойной routing + потеря hostname-bypass), BLOCKER-2 (Tunnel/Engine wiring) |
| HIGH     | 5     | HIGH-1 (CloseRead/Write half-close), HIGH-2 (symmetric NAT дроп UDP), HIGH-3 (UDP gate/lifecycle/префикс), HIGH-4 (connectSem+таймаут), HIGH-5 (5s dial-ctx убивает relay) |
| MEDIUM   | 5     | MEDIUM-1 (LocalAddr), MEDIUM-2 (буфер/бенч), MEDIUM-3 (Split-ветка в ядре), MEDIUM-4 (конкурентность/snapshot), MEDIUM-5 (утечка горутин) |
| LOW      | 4     | LOW-1 (IPv6), LOW-2 (loopback non-TUN), LOW-3 (метрики), LOW-4 (shutdown) |

## Резюме для автора плана

Направление верное, диагноз корректен (проверено по коду: dispatch, WST=WSPoolTransport,
proxy.Dialer контракт, io.Copy relay). Но перед стартом исправить в плане:

1. **BLOCKER-1**: убрать дублирующий `router.Decide` из InProcessDialer; зафиксировать что
   hostname-bypass в TUN невозможен (IP-only metadata), RU-bypass держится на IP-trie в BypassDialer.
2. **BLOCKER-2**: расширить `Engine` опциональным интерфейсом для передачи dialer из
   `*ShadowLinkEngine` в `Tunnel`; вынести `router` в поле; сохранить совместимость с VLESS-engine.
3. **HIGH-5**: relay-горутины запускать на engine-ctx, НЕ на 5s dial-ctx (иначе все TCP рвутся за 5s).
4. **HIGH-1**: memconn реализует CloseRead/CloseWrite (TCP half-close), не только Close.
5. **HIGH-2/HIGH-3**: UDP ReadFrom возвращает from==dst (symmetric NAT), перенести PoolReadiness
   gate, Close→Unregister+FIN, учесть StreamID-префикс в UDP incomingCh.
6. **MEDIUM-3**: решить судьбу SplitTransport-ветки в tunnelTCPStream.
