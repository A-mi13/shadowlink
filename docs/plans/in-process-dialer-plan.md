# План: In-Process tun2socks Dialer (устранение Windows ephemeral port exhaustion)

Дата: 2026-05-29. Статус: **ОТРЕВЬЮЕН опусом, исправлен — готов к реализации** (Bug #5).
Ревью: `in-process-dialer-plan-review.md` (2 BLOCKER + 5 HIGH + 5 MEDIUM + 4 LOW, все интегрированы ниже).

## КРИТИЧЕСКИЕ ПОПРАВКИ ИЗ РЕВЬЮ (читать первыми)

- **[BLOCKER-1] НЕ вызывать `router.Decide` в InProcessDialer.** Routing уже сделан выше в
  `BypassDialer` (IP-trie). metadata = только IP (не hostname), поэтому hostname-bypass (`*.ru`)
  в TUN невозможен в принципе — он держится на IP-trie + Yandex DNS (RU→RU-IP). InProcessDialer
  получает ТОЛЬКО tunnel-bound dst. Допустимо оставить лишь `ActionBlock`-обработку. `tunnelTCPStream`
  (P1) — уже ПОСЛЕ Decide, Decide туда не входит.
- **[BLOCKER-2] Wiring через опциональный интерфейс.** `Tunnel` знает только строку SOCKS-addr;
  `eng` имеет тип-интерфейс `Engine` (Connect/SOCKSAddr/Name/Close). Ввести
  `InProcessDialerProvider { NewInProcessDialer() proxy.Dialer }`, реализовать ТОЛЬКО на
  `*ShadowLinkEngine`. `main.go` type-assert'ит и передаёт в `Tunnel.WithInProcessDialer(d)`.
  `router` вынести в поле `e.router`. VLESS-engine НЕ должен сломаться (опциональный assert).
- **[HIGH-5] Relay на engine-ctx, НЕ на dial-ctx.** tun2socks даёт DialContext ctx с
  `tcpConnectTimeout=5s` → если завязать relay-горутины на него, ВСЕ TCP рвутся через 5с.
  Relay запускать с `context.WithCancel(engineCtx)`; dial-ctx использовать ТОЛЬКО для фазы
  установки (RegisterStream + CONNECT-чанк).
- **[HIGH-1] memconn реализует CloseRead()/CloseWrite()** (TCP half-close), не только Close().
  tun2socks делает `CloseWrite()` (uplink EOF) + `CloseRead()`, full Close — только в defer.
  Без half-close uplink-reader не получит EOF → idle-grace не стартует → стрим висит.
  SetReadDeadline обязан работать (tun2socks ставит tcpWaitTimeout=60s после half-close).
- **[HIGH-2] UDP ReadFrom возвращает from == metadata.dst.** tun2socks оборачивает в
  `symmetricNATPacketConn`, который ДРОПАЕТ пакет если `from.String() != dst`. Возвращать
  фиксированный dst (переданный в DialUDP), НЕ addr из chunk'а — иначе UDP шлёт, но не получает.
- **[HIGH-3] UDP lifecycle:** перенести PoolReadiness gate (ReadyCount<2 → err) в DialUDP;
  Close → UnregisterStream + UDP-FIN (иначе утечка стрим-слотов на DNS-буре, max 256/session);
  incomingCh для FlagUDP содержит payload С 2-байтным StreamID-префиксом (ParseUDPChunk ждёт его),
  в отличие от TCP (там payload[2:] без префикса) — НЕ перепутать.
- **[HIGH-4] connectSem:** AcquireConnect должен уважать dial-ctx (не фикс 10s > 5s ctx);
  решить нужен ли семафор вообще в in-process (нет loopback-retry-storm). connectSem != nil только
  после ListenAndServe — если listener в TUN не слушает, инициализировать отдельно ИЛИ убрать sem.
- **[MEDIUM-3] Split-ветка:** e.stream может быть SplitTransport (fallback). Решить:
  tunnelTCPStream сохраняет Split-ветку (tcp.go:490-526) ИЛИ in-process работает только с
  WSPoolTransport и Split-fallback в TUN отключается. Зафиксировать явно.
- **[MEDIUM-1] memconn LocalAddr()** возвращает валидный "127.0.0.1:0"-подобный addr (parseNetAddr).
- **[MEDIUM-4] InProcessDialer stateless** — не кэшировать session, брать свежий на каждый dial.

## Корень (подтверждён в коде)

`cmd/nixavpn-client/tunnel.go::installBypassDialer` (305-311) строит `proxy.NewSocks5(t.socksAddr, ...)` как `BypassDialer.inner` через `t2tunnel.T().SetDialer(bypass)`. v2 `Socks5.DialContext` (proxy/socks5.go:53) делает `net.Dial("tcp","127.0.0.1:PORT")` — **один loopback-сокет на каждое app-TCP-соединение**. На 460 Мбит/с выжигает 16384 эфемерных порта Windows → "Only one usage of each socket address" → файлы не качаются.

Data-path direct-mode: TUN → tun2socks → BypassDialer.inner (SOCKS5 loopback) → наш listener Server.handleConn → **HandleTCPConnectWS** (т.к. e.stream = WSPoolTransport, НЕ per-stream). Per-stream WS — opt-in только (NIXAVPN_FORCE_PER_STREAM_WS=1).

## Ключевые факты
- proxy.Dialer контракт: `DialContext(ctx,*Metadata)(net.Conn,error)` + `DialUDP(*Metadata)(net.PacketConn,error)`. `Metadata.DestinationAddress()` = "ip:port" = текущий destAddr. DstIP всегда конкретный IP (packet-level).
- Переиспользовать ЯДРО `HandleTCPConnectWS` (tcp.go:411-721): AcquireConnect sem, RegisterStream→incomingCh, CloseStream FIN (471), AssignStream/PendingTracker, optimistic CONNECT chunk, uplink/downlink relay, idle-grace (waitForIdleOrCancel + lastDownlinkNs). Всё работает на net.Conn — реальный сокет НЕ нужен.
- net.Pipe синхронный (Write блокирует до Read) — НЕ годится на 460Мбит. Нужна буферизованная in-memory net.Conn (своя, в проекте/deps нет).

## Фазы (TDD, gate на каждой)

**P0 — буферизованный memconn** (`proxy/socks5/memconn.go`): `newMemPipe()(a,b net.Conn)`, bounded buffer (~256KB/направление), Read/Write/Close + **CloseRead()/CloseWrite() [HIGH-1]** + SetDeadline*/SetReadDeadline/SetWriteDeadline/Local/RemoteAddr. LocalAddr/RemoteAddr возвращают валидный "127.0.0.1:0"-подобный [MEDIUM-1]. Write не блокирует пока буфер не полон (backpressure). Close→io.EOF peer'у. CloseWrite→EOF на read-сторону peer'а; CloseRead→отбрасывает дальнейшие записи peer'а. Тесты: concurrent throughput, deadline (вкл. 60s drain после half-close), **CloseWrite→peer Read EOF [HIGH-1]**, **Close разблокирует заблокированный Read обеих сторон [MEDIUM-5]**, benchmark vs net.Pipe.

**P1 — извлечь relay-ядро** (`proxy/socks5/tcp.go`): `tunnelTCPStream(relayCtx, conn, cl, wst, srv, destAddr)` = всё из HandleTCPConnectWS ПОСЛЕ router.Decide. **relayCtx — ДОЛГОЖИВУЩИЙ (engine), НЕ 5s dial-ctx [HIGH-5].** Перенести ПОЛНОСТЬЮ [MEDIUM-3]: Stats.SocksConnects.Add, AcquireConnect/ReleaseConnect (ctx-aware [HIGH-4]), NextStreamID+RegisterStream+defer CloseStream(FIN), AssignStream+Incr/DecrPending, **Split-ветка tcp.go:490-526 [MEDIUM-3]**, MarkFirstStream, optimistic CONNECT, lastDownlinkNs+waitForIdleOrCancel (idle-grace), downlink overflow-drain loop. HandleTCPConnectWS → тонкая обёртка (listener path идентичен). Тест: existing SOCKS5 тесты зелёные + golden (harness connPipe).

**P2 — in-process TCP dialer** (`proxy/socks5/dialer.go` или `client/`): реализует proxy.Dialer. DialContext(dialCtx, m): dst=m.DestinationAddress(); **БЕЗ router.Decide [BLOCKER-1]** (только опц. ActionBlock→err); appConn,ourConn:=newMemPipe(); **relayCtx:=context.WithCancel(engineCtx) [HIGH-5]**; используя dialCtx ТОЛЬКО для установки (Register+CONNECT); `go tunnelTCPStream(relayCtx, ourConn, ...)`; return appConn. stateless, session свежий на каждый dial [MEDIUM-4]. Нужны cl/stream/srv + engineCtx от ShadowLinkEngine. Тест: DialContext→conn; uplink→mock wst; downlink→appConn; relay переживает >5s [HIGH-5]; appConn.Close→FIN [HIGH-1/MEDIUM-5].

**P3 — in-process UDP dialer** (DialUDP): streamPacketConn. **PoolReadiness gate в начале [HIGH-3]** (ReadyCount<2→err). tun2socks драйвит WriteTo/ReadFrom (НЕ SOCKS5 UDP framing). Первый WriteTo: RegisterStream + горутина incomingCh→**ParseUDPChunk (payload С StreamID-префиксом! [HIGH-3])**→очередь для ReadFrom. **ReadFrom возвращает from = metadata.dst (НЕ addr из chunk) [HIGH-2]** — иначе symmetricNAT дроп. WriteTo: NewUDPDataChunk+encrypt+wst.WriteMessage. **Close: UnregisterStream + UDP-FIN [HIGH-3]** (иначе утечка слотов на DNS-буре). Тест: round-trip через mock wst (from==dst); Close→Unregister+FIN; DNS:53 smoke.

**P4 — wire** (`tunnel.go` + `engine_shadowlink.go` + `engine.go` + `main.go`): **[BLOCKER-2]** ввести `InProcessDialerProvider` interface, реализовать на *ShadowLinkEngine (NewInProcessDialer из e.cl/e.stream/e.socks/e.ctx); вынести router в e.router; main.go type-assert + Tunnel.WithInProcessDialer. installBypassDialer: inner = in-process dialer вместо proxy.NewSocks5 (когда provider есть); direct остаётся proxy.NewDirect. VLESS-engine не ломается (опц. assert). Loopback listener ОСТАВИТЬ для non-TUN, вывести из TUN data-path. Тест: netstat 127.0.0.1:PORT не растёт под нагрузкой; 460Мбит скачка без "Only one usage".

**P5 — интеграция + field**: build windows/amd64, soak download, ephemeral port flat, bypass RU direct, UDP/DNS ok.

## Тесты (TDD-порядок)
1. memconn_test.go: throughput, backpressure, deadlines, Close→EOF, bench.
2. tunnelTCPStream refactor: golden что listener output не изменился (harness connPipe в udp_pool_gate_test.go).
3. dialer TCP: DialContext conn; uplink→mock wst; downlink→app.
4. dialer routing: block→err.
5. dialer UDP: WriteTo/ReadFrom round-trip; FIN на Close.

## Риски
- **UDP shape (highest):** DialUDP ≠ SOCKS5 UDP handler. НЕ переиспользовать SOCKS5 UDP header. Lifecycle per 5-tuple (register/FIN) — иначе утечка stream-слотов (max 256/session).
- **idle-grace перенос:** lastDownlinkNs+waitForIdleOrCancel должны переехать в tunnelTCPStream целиком — иначе вернётся 15s-баг.
- **session FIN на Close:** tun2socks закрывает conn → memconn Close → uplink Read EOF → grace → CloseStream FIN. Если memconn Close не разблокирует reader — утечка стримов.
- **Backpressure/latency:** bounded buffer (~256KB старт) — мало throttle, много RAM. Бенчить.
- **connectSem ownership:** на *Server. dialer нужен srv для Acquire/ReleaseConnect. Шарить listener's *Server.
- **Relay поведение:** извлечённая функция вызывается идентично (MarkFirstStream, AssignStream) — иначе ломается pool distribution/cold-start метрики.

## Критичные файлы
- shadowlink/proxy/socks5/tcp.go (извлечь tunnelTCPStream из HandleTCPConnectWS 411-721)
- cmd/nixavpn-client/tunnel.go (installBypassDialer 297-316 — swap inner)
- cmd/nixavpn-client/engine_shadowlink.go (owns cl/e.stream/router/*Server; expose NewInProcessDialer ~444/579)
- client/bypassroute/dialer.go (BypassDialer.inner target; proxy.Dialer контракт)
- shadowlink/proxy/socks5/udp.go (chunk-протокол для DialUDP)
