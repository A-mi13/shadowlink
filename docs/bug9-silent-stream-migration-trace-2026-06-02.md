# Bug #9 — трассировка миграции «тихих» долгих стримов (long-poll). Откуда 60s. 2026-06-02

Цель: точно локализовать механику, из-за которой downlink-половина «тихого» долгого
стрима (long-poll к Anthropic) закрывается РОВНО через 60 секунд после uplink-EOF
(симптом в полевом логе: `downlink done (migration)` через ~60с после `uplink done err=EOF`,
chunks≈2). Это НЕ баг в коде миграции ShadowLink. Это **TCP half-close timeout самого
tun2socks (`tcpWaitTimeout = 60s`)**, который ShadowLink-овский memConn честно исполняет.

---

## TL;DR (корень)

Когда приложение (Claude long-poll) дослало запрос и сделало TCP half-close (CloseWrite своей
upload-половины, оставив download-половину открытой в ожидании ответа), tun2socks в
`unidirectionalStream` после EOF на upload-направлении вызывает
**`dst.SetReadDeadline(time.Now().Add(tcpWaitTimeout))` с `tcpWaitTimeout = 60 * time.Second`**
(`tun2socks/v2@v2.6.0/tunnel/tcp.go:72`, константа в `tunnel/tunnel.go:19`). `dst` здесь —
это relay-сторона стрима (наш `memConn`), из которой читает downlink-горутина tun2socks. Если
за 60с от сервера не пришло НИ одного downlink-байта (а у тихого long-poll именно так — пауза
до ответа часто >60с), `memConn.read` отдаёт `timeoutError{}`, tun2socks-овский downlink
`io.CopyBuffer` завершается, half-close таймаут срывает download-половину → приложение видит,
что соединение закрылось. Сам ShadowLink-relay при этом завершает downlink не по своему таймеру,
а потому что `memConn` (наш `conn`) получил Close/полу-Close от tun2socks → срабатывает
`peerFullClose` / EOF, и печатается `downlink done (migration)`.

То есть **держит downlink ровно 60 секунд таймер tun2socks `tcpWaitTimeout`, не код ShadowLink.**
Миграция стрима тут работает корректно и к симптому прямого отношения не имеет — она лишь
сохраняет байты при резе слота; но она НЕ продлевает 60-секундный half-close дедлайн tun2socks,
потому что у тихого long-poll downlink-активности нет, а именно downlink-активность —
единственное, что могло бы переустановить дедлайн (а переустанавливать его в v2.6.0 некому: он
ставится ОДИН раз после upload-EOF и больше не двигается).

---

## 1. Все найденные таймеры/дедлайны ~60s на пути закрытия/миграции стрима (file:line + назначение)

| # | file:line | значение | назначение | релевантность симптому |
|---|-----------|----------|------------|------------------------|
| **A** | `tun2socks/v2@v2.6.0/tunnel/tunnel.go:19` | `tcpWaitTimeout = 60 * time.Second` | TCP half-close timeout tun2socks | **ЭТО КОРЕНЬ** |
| **A'** | `tun2socks/v2@v2.6.0/tunnel/tcp.go:72` | `dst.SetReadDeadline(now + tcpWaitTimeout)` | арм 60s дедлайна на relay-стороне ПОСЛЕ upload-EOF | **исполнитель корня** |
| B | `shadowlink/proxy/socks5/memconn.go:23` (doc) | «SetReadDeadline honored (60s half-close drain timeout)» | комментарий, фиксирующий что memConn ОБЯЗАН чтить 60s дедлайн от tun2socks | подтверждает A |
| B' | `shadowlink/proxy/socks5/memconn.go:104` | `if b.timedOut(b.rdeadline) { return 0, timeoutError{} }` | memConn.read отдаёт timeout когда дедлайн (выставленный A') истёк | **механизм срабатывания A на нашей стороне** |
| B'' | `shadowlink/proxy/socks5/memconn.go:265` | `SetReadDeadline(t) { c.rd.setReadDeadline(t) }` | точка входа, куда tun2socks (A') кладёт 60s | мост A→B' |
| C | `shadowlink/client/migrate_watchdog.go:37` | `migrationThresholdDefault = 60 * time.Second` | порог ВОЗРАСТА слота, при котором watchdog УПРЕЖДАЮЩЕ мигрирует стримы | совпадение значения, НЕ причина закрытия downlink |
| D | `shadowlink/client/ws_pool.go:2478` | `time.NewTimer(60 * time.Second)` | декремент метрики `meltdowns1m` через 60с (rolling-window счётчик) | НЕ относится к жизни стрима |
| E | `tun2socks/v2@v2.6.0/tunnel/tunnel.go:21` | `udpSessionTimeout = 60 * time.Second` | таймаут UDP-сессии | не TCP long-poll |

Дополнительно (НЕ 60s, но на пути закрытия — для полноты):
- `shadowlink/client/ws_transport.go:632` — `migrateAckTimeout = 1500 * time.Millisecond` (окно ожидания MIGRATE/RESUME-ack; **не 60s**).
- `shadowlink/proxy/socks5/idle_grace.go:19` — `downlinkIdleGrace = 15 * time.Second` (idle-grace, **только на loopback-SOCKS5 пути `socks5Replies=true`**; in-process tun2socks путь его НЕ использует — см. §3).
- `shadowlink/proxy/socks5/tcp.go:422` — `reassemblyGapTimeoutDefault = 2 * time.Second` (backstop по «дырке» в seq при миграции; срывает стрим при незакрытой дыре, **не 60s, и только при реальном gap**).
- `shadowlink/client/client.go:1288` — `base = float64(60 * time.Second)` (база backoff/anomaly, не путь стрима).

---

## 2. Полная цепочка вызовов (как 60s доходит до тихого стрима)

### 2.1 Кто кому net.Conn (inprocess.go)

`inProcessDialer.DialContext` (`shadowlink/proxy/socks5/inprocess.go:66-86`):
```go
appConn, ourConn := newMemPipe()       // appConn = app-конец, ourConn = relay-конец
go func() { defer ourConn.Close(); d.runRelay(relayCtx, ourConn, dst) }()  // relay владеет ourConn
return appConn, nil                    // tun2socks получает appConn
```
`runRelay` → `tunnelTCPStream(ctx, ourConn, ..., socks5Replies=false)` (`inprocess.go:58`).

Внутри tun2socks (`tunnel/tcp.go:17-44`):
- `remoteConn, _ := t.Dialer().DialContext(...)` → `remoteConn == appConn` (наш app-конец memPipe).
- `originConn` — TCP-поток приложения в TUN.
- `pipe(originConn, remoteConn)` (`tcp.go:43`).

### 2.2 Что происходит при upload-EOF тихого long-poll (tun2socks/tunnel/tcp.go:46-73)

`pipe` поднимает 2 горутины:
```go
go unidirectionalStream(remote=remoteConn, src=originConn, "origin->remote")   // UPLINK
go unidirectionalStream(origin=originConn, src=remoteConn, "remote->origin")   // DOWNLINK
```

UPLINK-горутина: `io.CopyBuffer(remoteConn, originConn)`. Long-poll-клиент шлёт запрос и затем
**делает CloseWrite своей upload-половины** (типично для HTTP-клиента, который дослал запрос и
ждёт тело ответа). `io.CopyBuffer` получает EOF и возвращается. Дальше (tcp.go:64-72):
```go
src.CloseRead()                                   // originConn.CloseRead()
dst.CloseWrite()                                  // remoteConn.CloseWrite()  → appConn.CloseWrite()
dst.SetReadDeadline(time.Now().Add(tcpWaitTimeout))   // remoteConn.SetReadDeadline(now+60s)  ← ТАЙМЕР A'
```

- `remoteConn.CloseWrite()` = `appConn.CloseWrite()` → закрывает upload-направление memPipe (`d1`).
  На relay-стороне `ourConn.Read` получает `io.EOF` → ShadowLink печатает `uplink done err=EOF`
  (`shadowlink/proxy/socks5/tcp.go:861`). Поскольку это **half-close** (writeClosed()==false),
  uplink-горутина ShadowLink просто `return` без `cancel()` (`tcp.go:882-888`) — downlink-горутина
  ShadowLink остаётся жить (правильно для keep-alive/long-poll).
- `remoteConn.SetReadDeadline(now+60s)` = `appConn.SetReadDeadline` → ложится в
  `memConn.SetReadDeadline` (`memconn.go:265`) → `c.rd.setReadDeadline` на DOWNLINK-направлении
  (`d2`), из которого читает DOWNLINK-горутина tun2socks. **Это 60-секундный взвод.**

### 2.3 Истечение 60s (downlink молчит)

DOWNLINK-горутина tun2socks: `io.CopyBuffer(originConn, remoteConn)` — читает из `remoteConn`
(= `appConn`, направление `d2`). У тихого long-poll сервер 60+ секунд не шлёт ничего →
`memConn.read` крутится в `cond.Wait()`, пока `startDeadlineTimerLocked` (`memconn.go:152-166`)
не разбудит по дедлайну → проверка `b.timedOut(b.rdeadline)` (`memconn.go:104`) истинна →
возврат `timeoutError{}` (`memconn.go:277-281`, `Timeout()==true`). `io.CopyBuffer` завершается
ошибкой → DOWNLINK-горутина tun2socks делает `originConn.CloseWrite()` (tcp.go:68-69) →
приложение видит, что download-половина закрылась → long-poll «завис/оборвался».

### 2.4 Почему ShadowLink печатает `downlink done (migration)` ровно тогда же

Когда downlink-горутина tun2socks завершилась, `pipe` → `wg.Wait()` отдаёт, и
`handleTCPConn` defer'ом закрывает `remoteConn=appConn` ПОЛНОСТЬЮ (`tcp.go:18,40`). Полный
`appConn.Close()` (`memconn.go:216-225`) на app-конце:
```go
c.wr.close(); c.rd.close()
if c.isAppEnd { c.fullCloseOnce.Do(func(){ close(c.peerFullClose) }) }   // memconn.go:220-222
```
закрывает оба направления и **закрывает `peerFullClose`**. ShadowLink-овская downlink-горутина
(миграционный путь `downlinkReassemblyLoop`) ловит это через `case <-peerFullClose: return`
(`tcp.go:578-580`), управление выходит и печатается `downlink done (migration)` (`tcp.go:1041-1042`)
с тем `chunks`, что успели прийти (отсюда `chunks=2`: CONNECT_OK + 1 порция данных long-poll до
наступившей 60-секундной тишины). Таким образом ~60с между `uplink done` и `downlink done (migration)`
— это в точности окно `tcpWaitTimeout`.

---

## 3. Обработка половинного закрытия в ShadowLink (uplink-EOF, downlink жив)

Ключевой комментарий и ветвление — `shadowlink/proxy/socks5/tcp.go:858-899`:
```go
n, err := conn.Read(buf)        // conn == ourConn (relay-конец memPipe)
if err != nil {                 // EOF после appConn.CloseWrite()
    slog.Info("uplink done", ... "err", err)              // tcp.go:861
    if !socks5Replies && hasWriteCloseDetector {          // in-process путь
        if connWriteClosed.writeClosed() {                // memConn.writeClosed()
            cancel()                                      // ПОЛНЫЙ close → рвём весь стрим
        }
        return                                            // HALF-close → uplink молча выходит,
    }                                                     // downlink-горутина живёт дальше
    // (loopback путь) waitForIdleOrCancel(...15s...); cancel()   // tcp.go:896 — НЕ in-process
}
```
- `writeClosed()` (`memconn.go:255`) различает half-close (`CloseWrite`, `d1` закрыт, `d2` открыт →
  `false`) и full-close (`Close`, оба закрыты → `true`).
- На in-process пути (`socks5Replies=false`) при half-close uplink-горутина ShadowLink НЕ делает
  `cancel()` и НЕ запускает idle-grace — это намеренно (long-poll/keep-alive должны жить). Значит
  **ShadowLink сам по себе тихий стрим не рвёт** ни по 15s, ни по какому-либо своему таймеру.
- Единственные сигналы teardown для downlink тихого стрима на in-process пути: `peerFullClose`
  (full Close от приложения), `ctx2.Done()` (отмена движка/full-close uplink-ом), закрытие
  `incoming`-канала, reassembly gap-timeout (2s, только при реальной дырке) или overflow.
- Поскольку ShadowLink не рвёт, а tun2socks по `tcpWaitTimeout` рвёт **app-сторону**, инициатива
  закрытия приходит СВЕРХУ (от tun2socks через `appConn.Close` → `peerFullClose`), а не снизу от
  туннеля. Это объясняет, почему лог показывает чистый `downlink done (migration)` (а не
  `downlink cancelled` или write-error): стрим закрылся «штатно» по FIN от приложения.

`peerFullClose` создаётся в `newMemPipe` (`memconn.go:197-201`), стреляет только на app-конце
(`isAppEnd`) при полном `Close` (`memconn.go:220-222`), и читается downlink-горутиной ShadowLink
в обоих путях (`tcp.go:578` миграционный, `tcp.go:1117` legacy).

---

## 4. Как RESUME находит мигрированный стрим и где тихий стрим может «не подхватиться»

- Ключ переноса — `streamID` + 32-байтный **proof**. Proof приходит в CONNECT_OK
  (`"CONNECT_OK"+proof`), парсится `ParseConnectOKProof` и сохраняется
  `cl.StoreStreamProof(streamID, proof)` (`shadowlink/proxy/socks5/tcp.go:962-963`). Без proof
  `sendMigrate` сразу возвращает `migrateResultNoSend` (`shadowlink/client/migrate_send.go:109-112`)
  — миграция не пытается выйти на провод.
- Реактивный путь при резе слота: `handleSlotDeath` → `resumeStreamOnDeath`
  (`shadowlink/client/ws_pool.go:3690-3727`): выбирает живой слот `selectYoungTargetSlot`,
  CAS `migrating false→true`, шлёт `FlagResume` через `sendMigrateOrHook`; при OK —
  `rebindStreamToSlot` (перепривязка + перенос счётчика); при FAIL/timeout — `resumeOutcomeBreak`
  → `closeStream` (закрытие чан-а).
- **Где тихий стрим НЕ подхватывается и висит до таймера:** упреждающий watchdog
  (`migrate_watchdog.go:169-213 scheduleSlotMigration` → `migrateStream`) арм-ит миграцию только
  для стримов, которые в `streamMap` числятся на стареющем слоте, и переносит их ПРЕВЕНТИВНО при
  возрасте слота ≥ `migrationThresholdNs` (≈60s × U(0.7,1)). Но:
  1. Превентивная миграция и RESUME сохраняют **uplink-маршрут и байты**, они НЕ трогают
     60-секундный half-close дедлайн tun2socks. После переноса downlink тихого стрима всё равно
     молчит → дедлайн A' истекает по расписанию.
  2. Если на момент истечения 60s downlink реально пуст, никакой RESUME «не сработавший» тут не
     виноват — стрим закрывает tun2socks, а не отказ миграции. В логе это и видно: `migrate_ok`,
     `resume_ok`, `bad_proof=0` — миграция отрабатывает, но симптом остаётся, потому что причина
     в дедлайне, не в миграции.
- Тонкость, усугубляющая «тихий» случай: дедлайн A' ставится **один раз** в `unidirectionalStream`
  после upload-EOF и больше не переустанавливается tun2socks v2.6.0. Downlink-байты, если бы шли,
  продлевали бы его косвенно (каждый успешный Read до дедлайна, далее новый Read без нового
  дедлайна — фактически дедлайн «съедается» первой же длинной паузой). Для long-poll с паузой
  >60с до первого/следующего ответа это гарантированный обрыв.

---

## 5. Перенос downlink-данных «в полёте» при миграции и риск зависания

- В миграционном режиме downlink идёт через `downlinkReassemblyLoop`
  (`shadowlink/proxy/socks5/tcp.go:493-591`): кадры seq-тэгированы, переупорядочиваются по
  `downSeq`, дырки закрываются backstop-таймером `reassemblyGapTimeout` (2s, tcp.go:422,566,572-577).
  При резе старого слота кадры, бывшие «в полёте», могут прийти позже на новом слоте — reassembler
  их доупорядочит; реальная незакрытая дырка рвёт стрим через 2s (это НЕ 60s-симптом).
- Uplink-барьер (`WaitStreamMigrateBarrier`, `shadowlink/client/migrate_send.go:210-241`) держит
  только UPLINK на время in-flight MIGRATE/RESUME (ограничен `migrateAckTimeout=1.5s`), чтобы
  uplink-байты не ушли на старый слот после переноса. Он **не** держит и не закрывает downlink.
- Может ли downlink «зависнуть в ожидании RESUME, пока приложение считает стрим мёртвым»: нет,
  downlink не ждёт RESUME-ack — он просто читает из `incomingSeqCh`/пишет в `conn`. «Мёртвым» стрим
  делает именно tun2socks по `tcpWaitTimeout`, после чего closes `appConn` → `peerFullClose` →
  downlink-горутина ShadowLink выходит. То есть приложение «считает стрим мёртвым» РОВНО потому, что
  tun2socks его таким сделал по 60-секундному дедлайну, а ShadowLink-downlink лишь следует за этим
  закрытием.

---

## 6. Явный ответ на главный вопрос

**Что держит downlink тихого стрима 60 секунд и почему long-poll Claude видит это как зависание?**

Downlink держит не ShadowLink, а **tun2socks**: после того как приложение сделало TCP half-close
(дослало запрос long-poll и закрыло свою upload-половину), tun2socks в
`tunnel/tcp.go:72` ставит на relay-сторону (наш `memConn`) read-дедлайн
`now + tcpWaitTimeout`, где `tcpWaitTimeout = 60s` (`tunnel/tunnel.go:19`). Это «TCP half-close
drain timeout»: tun2socks готов ждать ответный поток максимум 60с после того, как upload-сторона
закрылась. У тихого long-poll сервер в эти 60с ничего не присылает (пауза до ответа длиннее), поэтому
`memConn.read` отдаёт `timeoutError` (`memconn.go:104`), downlink-горутина tun2socks завершается,
half-close таймаут рвёт download-половину, и приложение Claude получает обрыв соединения — для
long-poll, который как раз и рассчитан на длинную тишину перед ответом, это выглядит как
«зависло и оборвалось через минуту». ShadowLink-овская миграция и RESUME при этом работают
корректно (байты и uplink-маршрут сохраняются при резе слота), но они НЕ продлевают и не сбрасывают
60-секундный half-close дедлайн tun2socks — а именно он, при отсутствии downlink-активности, и
закрывает тихий стрим ровно через 60 секунд после uplink-EOF.

Возможные направления фикса (НЕ реализуем — только указание места): продлевать/снимать дедлайн
A' для tunnel-стримов (например, чтобы memConn игнорировал read-дедлайн на in-process пути, либо
форк tun2socks с бо́льшим/отключаемым `tcpWaitTimeout`, либо переустановка дедлайна на каждый
downlink-кадр). Любой такой фикс должен сохранить честный teardown по реальному FIN
(`peerFullClose`) и не сломать освобождение слотов сервера.
