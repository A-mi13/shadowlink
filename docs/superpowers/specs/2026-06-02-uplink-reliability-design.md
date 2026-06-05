# Uplink reliability (tail-resend on slot death) — design

**Date:** 2026-06-02
**Status:** DESIGN — pending self-review + user review → plan
**Класс:** фича уровня Bug #8/#9 (client + server + wire). Зеркало существующего downlink tail-resend.

## Симптом (полевой факт)

Через ShadowLink Claude Code зависает на «Frosting… думал и не ответил», **сайты при этом
работают**. Лог `nixavpn-DEBUG-20260602-113941.log`: единственный стрим к Anthropic API
(`stream=51`, `dest=160.79.104.10:443`) — **uplink 1 054 952 байта / 208 uploads, downlink
всего 6225 байт**, прожил 6m16s и закрылся только когда юзер вручную отключил VPN. Короткое
сообщение → аномальный 1 МБ uplink. Фон: жёсткое TSPU age-cut давление (14 резов слотов за 7
мин, `close 1006 cause=age_cut`, `ws async writer exit: aborted by software in your host
machine`).

Предыдущий фикс (60s half-close, 2026-06-02) **подтверждён рабочим** в этом же логе: stream=51
прожил 6 минут вместо смерти на 60с — downlink-обрыва по таймеру больше нет. Но симптом остался
по **другой** причине.

## Корневая причина (асимметрия uplink vs downlink при резе слота)

ShadowLink защищает **downlink** от реза WS-слота, но **не защищает uplink**:

| Направление | Защита при резе слота | Где |
|-------------|----------------------|-----|
| downlink (server→client) | ✅ `unackedTail` boundedBuffer + downSeq-тег + RESUME-on-death переотправка + клиентский reassembler дедуп по downSeq + FlagStreamAck эвиктит хвост | `server/relay_registry.go`, `proxy/socks5/tcp.go downlinkReassemblyLoop`, `client/client.go SendStreamAckThrottled` |
| uplink (client→server) | ❌ НИЧЕГО — клиент не буферизует отправленное, при резе слота in-flight uplink-чанки ТЕРЯЮТСЯ (`proxy/socks5/tcp.go:847-928`); сервер пишет в origin напрямую без upSeq/dedup/ack (`server/websocket.go:820-861`) | — |

**Цепочка симптома:**
1. Claude Code шлёт запрос/токены в stream=51 (один долгий стрим, keep-alive).
2. Слот под ним режется TSPU (каждые 10-30с).
3. Uplink-чанки, бывшие «в полёте» на умершем слоте, **теряются** (нет переотправки — подтверждено
   `bug9-uplink-resend-trace-2026-06-02.md` §1.3: «чанк ПОТЕРЯН, а не продублирован»).
4. Запрос на сервере Anthropic неполный/битый → Anthropic не отвечает → downlink почти пустой.
5. Прикладной слой (TLS/HTTP-2 поверх туннеля) повторяет потерянное → uplink раздувается до 1 МБ,
   но каждый повтор снова рискует попасть на режущийся слот → запрос так и не доходит целиком.

**Почему сайты работают, Claude — нет:** сайты — короткие независимые запросы, переживают рез
легко. Claude Code — один долгий стрим, обязанный жить минутами через постоянно режущиеся слоты.

**Статус доказательства:** корень выведен из (а) кода (uplink не имеет resend, downlink имеет),
(б) лога (1 стрим, 1МБ uplink / 6КБ downlink, нет ретрай-стримов к тому же IP), (в) непокрытого
теста `TestE2E_UplinkAfterMigration_NoByteLoss` (тестирует только живой слот A, НЕ смерть с
in-flight uplink). Прямой DEBUG-замер потери НЕ делался по решению юзера — фикс строится на
сильной, но не инструментально замеренной улике. **Риск принят явно:** если после фикса симптом
останется, корень был шире.

## Решение — зеркало downlink tail-resend для uplink

Полная симметрия. Wire-формат уже направление-агностичен (`[streamID(2)][seq(8)][data]`,
`core/chunk.go:215` `NewStreamDataChunkSeq`/`ParseStreamDataSeq`) — переиспользуем как есть.

### Компоненты

**1. core (`core/chunk.go`)**
- `FlagUplinkAck = 0x0E` (следующий свободный после `FlagStreamAck=0x0D`; коллизий нет).
- `BuildUplinkAckFrame(streamID uint16, ackedUpSeq uint64) []byte` / `ParseUplinkAckFrame([]byte)
  (streamID uint16, ackedUpSeq uint64, err error)` — 10-байтовое тело, идентичное StreamAck-паре.
- Uplink-данные тегируются upSeq через **существующий** `NewStreamDataChunkSeq` (тот же helper,
  что downlink) — новых wire-форм не нужно. Активно только при negotiated migration.

**2. client uplink-горутина (`proxy/socks5/tcp.go:847-928`)**
- Per-stream `unackedUpTail *boundedBuffer` (переиспользуем тип из server, вынесем в общее место
  или дублируем — решить в плане; byte-cap зеркалит downlink).
- На каждый `conn.Read` под migration: присвоить монотонный upSeq, обернуть в
  `NewStreamDataChunkSeq`, **push в unackedUpTail ДО `StreamWrite`**, затем отправить.
- Backpressure: при полном `unackedUpTail` блокировать `conn.Read` (зеркало
  `relay_registry.go routeDownFrame`). Bug #8 credit — downlink-only, конфликта нет (подтверждено
  recon §4).
- Non-migration путь — без изменений (byte-for-byte legacy, как у downlink).

**3. client demux + resume (`client/ws_pool.go`, `client/migrate_watchdog.go`)**
- `client/ws_pool.go:3230` demux: `case FlagUplinkAck` → `resolveUplinkAck(streamID, ackedUpSeq)`
  → `unackedUpTail.evictUpTo(ackedUpSeq)`.
- `rebindStreamToSlot` (`migrate_watchdog.go:276`) + `resumeStreamOnDeath` (`ws_pool.go:3690`):
  после `migrateResultOK` **переотправить uplink-tail** на новый слот (зеркало серверного resendTail).

**4. server uplink-приём (`server/websocket.go:820-861`, `server/relay_registry.go:100`)**
- `relayEntry`: добавить `lastUpSeq atomic.Uint64`.
- Приём FlagData (seq-tagged): если upSeq ≤ lastUpSeq → **дубликат, дропнуть** (дедуп
  переотправленного хвоста); иначе `targetConn.Write(data)`, обновить lastUpSeq, отправить
  `FlagUplinkAck` клиенту (throttled, как downlink ack).
- Origin-byte-stream целостность: дедуп по upSeq гарантирует, что в origin не уйдёт дубль (recon
  §4: сейчас сервер НЕ дедуплицирует — это часть фикса).

### Что НЕ входит (YAGNI / out-of-scope)
- POST-path uplink (`server/handler.go:877`) — не мигрирует, не трогаем (recon §7).
- Non-migration транспорты (single-WS, SplitTransport) — uplink-tail активен только при
  negotiated migration (как downSeq).

## Тесты (TDD)
- **core:** round-trip `BuildUplinkAckFrame`/`ParseUplinkAckFrame`; FlagUplinkAck не конфликтует.
- **client:** unackedUpTail push/evict по ack; backpressure при полном буфере; переотправка хвоста
  на resume; non-migration путь не буферизует.
- **server:** dedup по lastUpSeq (повторный upSeq → один Write в origin); UplinkAck отправляется.
- **e2e:** расширить `TestE2E_UplinkAfterMigration_NoByteLoss` (`server/migrate_e2e_test.go:638`):
  убить слот A с in-flight uplink-чанками → проверить, что ВСЕ uplink-байты дошли до origin
  ровно по разу, без потерь и без дублей. **Это тест, прямо воспроизводящий корень.**

## Объём / деплой
- Файлы: `core/chunk.go`, `proxy/socks5/tcp.go`, `client/ws_pool.go`, `client/migrate_watchdog.go`,
  `server/websocket.go`, `server/relay_registry.go` + тесты.
- **Сервер pl1 ПРИДЁТСЯ передеплоить** (staged: сервер первым, как Bug #8/#9). Протокол
  обратносовместим: старый клиент не шлёт seq-tagged uplink → сервер не ack'ает → деградация в
  текущее (небезопасное) поведение, не поломка.
- ENV-флаг: рассмотреть `SHADOWLINK_UPLINK_RELIABILITY` (default on при migration) для
  emergency-отката, по образцу прочих флагов.

## Проверка перед ship
- `go test ./...` зелёный (core/client/server).
- `go build ./...`, `go vet` чисты.
- `go test -race -count=3 ./client/ ./server/ ./proxy/...` на pl1 (Linux+gcc).
- Полевой ретест под TSPU-давлением: Claude Code — короткое сообщение получает ответ; uplink к
  Anthropic больше не раздувается до МБ; downlink приходит.
