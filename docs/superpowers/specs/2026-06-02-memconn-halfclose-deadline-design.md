# memConn half-close read-deadline ignore — design

**Date:** 2026-06-02
**Status:** APPROVED (design), pending spec review → plan
**Bug:** long-poll / streaming downlink (Claude Code, SSE, agent keep-alive) рвётся ровно через 60 с тишины после того, как приложение полу-закрыло uplink.

## Симптом (полевой факт)

Через ShadowLink (system-VPN, in-process dialer) Claude Code «зависает» после 1-2
сообщений на минуты, потом обрыв. Через VLESS Reality (сторонний клиент, свой
tun2socks) и без VPN — стабильно. Обычные сайты и закачки через ShadowLink не
страдают.

Лог `nixavpn-DEBUG-20260602-103954.log`: группы стримов к Anthropic
(`160.79.104.10:443`) получают uplink `err=EOF` (приложение закрыло отправку
запроса), а соответствующий `downlink done (migration)` происходит РОВНО через
60.000 с после uplink-EOF, `chunks=2` — то есть данные пришли в начале, потом
~60 с тишины, потом принудительное закрытие. 16 стримов убиты синхронно по таймеру.

## Корневая причина (доказано тремя слоями)

| Слой | Действие | Файл:строка |
|------|----------|-------------|
| tun2socks (vendored v2.6.0) | После того как одна половина relay закрылась (`io.CopyBuffer` вернулся), делает `dst.SetReadDeadline(now + tcpWaitTimeout)` на ДРУГОЙ половине. `tcpWaitTimeout = 60s` | `tunnel/tcp.go:72`, `tunnel/tunnel.go:19` |
| наш memConn | Честно соблюдает read-deadline: `d2.read` (downlink, который app читает) отдаёт `timeoutError` через 60 с тишины | `proxy/socks5/memconn.go:104` |
| результат | tun2socks завершает `unidirectionalStream` по timeout → `pipe` `wg.Wait` разблокируется обеими сторонами → `originConn.Close()` → relay видит EOF → стрим закрыт | `tunnel/tcp.go:18,54` |

**Почему именно long-poll:** обычный HTTP-ответ приходит быстро (downlink активен в
пределах 60 с). Long-poll/SSE/agent-stream: приложение отправляет запрос, полу-закрывает
uplink (`CloseWrite`), затем downlink МОЛЧИТ пока модель «думает» — эта тишина
легитимна, но tun2socks трактует её как зависший half-open и рвёт через 60 с.

**Что НЕвиновно (проверено чтением кода):** наш relay `tunnelTCPStream`
(`proxy/socks5/tcp.go:882-888`) уже корректно оставляет downlink живым при half-close
(`writeClosed()==false` → uplink-горутина просто `return`, downlink продолжает). Bug #9
миграция чиста (`migrate_fail=0`, `bad_proof=0`, `decrypt_fails=0`). Убивает downlink
исключительно чужой 60-секундный half-close дедлайн, наложенный на наш memConn.

**Почему VLESS Reality не страдает:** идёт через сторонний клиент (sing-box/Nekoray/
Hiddify) с ДРУГИМ tun2socks/TUN-стеком и другим (или отсутствующим) half-close
таймаутом. Только наш бинарь содержит vendored tun2socks v2.6.0 с `tcpWaitTimeout=60s`.

## Решение (Вариант A — выбран)

memConn **полностью игнорирует** read-deadline на своей downlink-стороне ПОСЛЕ того,
как его uplink-направление было полу-закрыто (`CloseWrite`), пока соединение не получит
настоящий full close.

Семантика memConn (memconn.go:181-202): `appConn` (app end, отдан tun2socks) читает из
`rd = d2`. tun2socks ставит `SetReadDeadline` → `appConn.SetReadDeadline` →
`d2.setReadDeadline`. d2 — это downlink (relay пишет, app читает). После того как app
полу-закрыл uplink, tun2socks вызвал `appConn.CloseWrite()` → закрылся `wr = d1`. То
есть состояние «uplink полу-закрыт» детектируется как `appConn.wr.isClosed() == true`
(это уже существующий `writeClosed()`), при этом full close (`peerFullClose`) НЕ
сработал.

В этом состоянии `d2.read` (downlink read) должен ТРАКТОВАТЬ read-deadline как
не-наступающий (zero), так что тишина downlink не приводит к `timeoutError`.

### Точка реализации

`memBuffer.read` (memconn.go:91-110) проверяет `b.timedOut(b.rdeadline)`. Нужно, чтобы
для downlink-направления app-end этот дедлайн игнорировался, когда uplink уже
полу-закрыт. Реализация: memConn знает обе половины (`rd`, `wr`) и флаг `isAppEnd`.
Условие игнорирования read-deadline на app-end:

```
isAppEnd && wr.isClosed() && peerFullClose НЕ закрыт
```

Чистый способ — не менять сигнатуру `memBuffer.read`, а сделать так, чтобы
`SetReadDeadline` на app-end в состоянии half-close был no-op, И чтобы уже
взведённый ранее дедлайн нейтрализовался при `CloseWrite`. Конкретно:

1. `memConn.CloseWrite()` (app-end): после `c.wr.close()` — снять активный
   read-deadline downlink (`c.rd.setReadDeadline(time.Time{})`) и пометить
   downlink как «deadline-immune» (sticky-флаг на app-end downlink memBuffer).
2. `memConn.SetReadDeadline()` (app-end): если downlink уже помечен immune
   (half-close произошёл) — игнорировать (no-op), не записывать новый дедлайн.
3. Full close (`appConn.Close()`) по-прежнему рвёт через `c.rd.close()` /
   `peerFullClose` — на этот путь immune-флаг не влияет.

Relay-end (`ourConn`, `isAppEnd==false`) — без изменений; его дедлайны не армит
tun2socks.

### Почему это безопасно (нет goroutine leak)

Все легитимные teardown идут НЕ через этот дедлайн:

- **Real FIN от приложения** → gVisor `gonet.TCPConn.Read`→EOF в tun2socks uplink-half
  → `appConn.Close()` → `peerFullClose` закрывается → наш downlink-loop выходит
  (`tcp.go:1117` / `:578`). ✅
- **WS-стрим/слот умер без миграции** → `incomingCh`/`incomingSeqCh` закрывается →
  downlink-loop выходит (`tcp.go:1049` / `:526`). ✅
- **ctx2 отменён** (full-close ветка uplink-горутины) → выход (`tcp.go:1126` / `:581`). ✅
- **Reassembly gap timeout** (миграция, 2 с) — независимый backstop, не трогаем. ✅

60s read-deadline — ЕДИНСТВЕННЫЙ путь, ошибочно рвущий живой long-poll. Его
игнорирование в half-close-состоянии не убирает ни одного из реальных teardown.

### Отвергнутые варианты

- **B (поднять `tcpWaitTimeout`)** — патч чужого vendored кода (хрупко при обновлении),
  паллиатив (любой конечный таймаут сработает на очень долгом ожидании), глобально
  ломает легитимную защиту от мёртвых half-open для НЕ-туннельных потоков.
- **C (keep-alive прогрев downlink)** — загрязняет прикладной TCP-поток (нельзя слать
  мусор внутрь TLS-сессии Claude), хрупко.

## Тесты (TDD, перед реализацией)

Расширяют существующий `proxy/socks5/memconn_halfclose_test.go`:

1. **Red:** app-end делает `CloseWrite()`, затем `SetReadDeadline(now+50ms)`, downlink
   молчит 200ms → `appConn.Read` НЕ должен вернуть timeout (сейчас вернёт). После
   фикса — блокируется/ждёт данные.
2. Уже взведённый дедлайн ДО `CloseWrite`: `SetReadDeadline(now+50ms)` → `CloseWrite()`
   → ждём 200ms → `Read` не таймаутит (дедлайн снят на CloseWrite).
3. **Регресс — full close всё ещё рвёт:** после `CloseWrite()` затем `Close()` →
   `appConn.Read` возвращает EOF немедленно (full close побеждает immune-флаг).
4. **Регресс — без half-close дедлайн работает:** app-end БЕЗ `CloseWrite`,
   `SetReadDeadline(now+50ms)`, тишина → `Read` таймаутит как раньше (не сломали
   обычный deadline для не-half-closed соединений).
5. **Регресс — relay-end не затронут:** `ourConn.SetReadDeadline` работает штатно.
6. **Регресс — downlink-данные доставляются:** после `CloseWrite` relay пишет данные →
   app `Read` получает их (immune не блокирует доставку, только timeout).

## Объём изменений

Один файл продакшена: `proxy/socks5/memconn.go` (+ sticky-флаг на app-end downlink,
правки `CloseWrite`/`SetReadDeadline`). Один файл тестов:
`proxy/socks5/memconn_halfclose_test.go`. Без env-флага (поведение строго корректнее,
откатывать нечего; emergency-откат = revert файла). Без протокольных изменений, сервер
не трогаем. Бинарь клиента пересобрать.

## Проверка перед ship

- `go test ./proxy/socks5/...` зелёный (новые + существующие half-close тесты).
- `go build ./...`, `go vet ./...` чисты.
- `go test -race -count=3 ./proxy/socks5/` на Linux/CI (sticky-флаг под mutex).
- Полевой ретест: Claude Code через ShadowLink — длинный ответ модели (>60 с
  «раздумий») не обрывается; обычные сайты/закачки не регрессировали.
```
