# Для Codex: анализ регрессии ShadowLink через CF CDN

## TL;DR

ShadowLink — custom steganographic VPN через HTTPS. Два режима работы:

| Режим | URL-флаг | Скорость | Статус |
|---|---|---|---|
| **Direct** (прямо на origin IP) | `&origin=104.222.177.67` | **225 Mbps ↓ / 188 Mbps ↑** | ✅ работает |
| **CF CDN** (через Cloudflare) | без `origin`, только `cdn=domain` | ~10-20 KB/s | ❌ не работает |

**13 апреля** через CF CDN работало нормально. **14 апреля** ввели «per-stream WS» путь в `cmd/nixavpn-client/engine_shadowlink.go` — режим CF стал катастрофически медленным, сайты не грузятся (белый экран).

15 апреля я откатил ветку `viaCF` обратно на `WSPoolTransport` (как до 14 апреля). **Стало лучше, но всё равно через CF CDN нестабильно**: все 8 slot'ов pool массово умирают с `read timeout` через 20-40 секунд активного браузинга, pool уходит в meltdown cooldown, декрипты падают до 0.

Direct-режим (минуя CF) остался 225 Mbps, доказывая что **клиент и сервер здоровы, проблема именно на участке клиент ↔ CF ↔ сервер**.

## Что нужно от Codex

Найти почему **WS Pool через Cloudflare Free plan** стабильно работал 13 апреля, но теперь пулу становится плохо после ~20 секунд нагрузки. Это не про скорость setup и не про shared session (мы это проверили) — это про то, почему **все WS connection'ы к CF edge массово получают read timeout одновременно**.

Гипотезы которые я НЕ смог подтвердить/опровергнуть:
1. **CF rate-limiting на handshake POSTы**: каждый slot делает свой handshake POST через `client.transport` → сервер создаёт 8 sessions. Может CF считает это burst'ом.
2. **Tail-drop на Cloudflare edge** под нагрузкой browser'а (20-30 параллельных CONNECT'ов).
3. **MTU / fragmentation** через CF для WS frames ~32KB.
4. **nginx на origin** (`proxy_pass http://unix:/run/shadowlink.sock`) — возможно какой-то buffering rule убивает WS под нагрузкой.
5. **Meltdown в ws_pool.go**: срабатывает слишком агрессивно и блокирует reconnect, усугубляя каскад.

Что я уже исключил:
- shared session contention (`decrypt_fails=0` всегда, mutex не узкое горлышко)
- cover traffic storm (`cover_posts=0-1/5s`, не проблема)
- UDP poll storm (`udp_polls=0` в WS Pool mode, poll выключен)
- handshake latency / setup cost (CONNECT_OK за 30-100ms всегда)

## Репозиторий

`git clone https://github.com/A-mi13/shadowlink.git`

Там всё: исходники + готовые бинарники `bin/nixavpn-client.exe`, `bin/shadowlink-server-linux`, скрипты `connect-vpn-direct.bat` / `connect-vpn-cdn.bat`, cf-scanner для поиска оптимального CF edge IP.

Сервер задеплоен: `104.222.177.67` (домен `datacanvases.com`, за CF orange cloud, TLS Full Strict, nginx → unix socket → shadowlink-server). Менять сервер Codex'у не надо — проблема в клиентской части либо в way-как-клиент-говорит-через-CF.

## Ключевые файлы для анализа

### 1. Выбор режима и инициализация pool
`cmd/nixavpn-client/engine_shadowlink.go` — функция `Connect`, блок `if (e.cfg.SystemVPN || slCfg.WebSocket) && ...`. Тут текущая логика режимов после отката 14-апр регрессии. `viaCF` флаг управляет `MaxStreamsPerSlot=4`, `MaxPendingPerSlot=2`. Pool создаётся через `client.NewWSPoolTransport`.

### 2. WS Pool сам
`client/ws_pool.go` — 8 slot'ов с своими sessions, per-slot handshake, meltdown detection (`recordSlotDeath`, `meltdownWaitDuration`), reconnect loop, rotation. **Здесь же потенциальный баг: meltdown cooldown 10s при threshold=4 deaths/5s может быть слишком жёстким для CF, когда один edge отваливается и остальные синхронно падают.**

### 3. WS upgrade / uTLS fingerprint
`client/ws_transport.go` — `UpgradeToWS`, uTLS fingerprint (Chrome 133 / Safari 16 / Firefox), ALPN patching на `http/1.1` (WS требует), SNI override и CFIP routing. Здесь может быть где-то не учтён edge case для CF.

### 4. Session + async writer
`core/session.go` (sliding window 16384, anti-replay) + `core/wsasyncwriter.go` (priority channels control > data).

### 5. Server-side
`server/websocket.go` — handler'ы WS, per-WS streams map (**внимание**: каждый WS имеет свою map — если клиент шлёт FlagData на stream'е которого нет в этой map, data silently дропается). `server/handler.go` — HTTP POST handshake, dispatch по Content-Type.

## Как воспроизвести регрессию

```bash
# На Windows (где запускается клиент):
cd bin
# CDN режим (ломается):
./connect-vpn-cdn.bat        # ← от Администратора, 30-60 секунд браузинга
# Direct режим (работает):
./connect-vpn-direct.bat     # ← от Администратора
```

CDN-URL: `sl://f60ab13060efc8cefca431f0f847add47e5c913627a37c62835fd90c3779af51@datacanvases.com:443?tls=1&cdn=datacanvases.com`
Direct-URL: тот же + `&origin=104.222.177.67`

В логах клиента смотреть:
- `shadowlink client stats (delta)` каждые 5s — если `decrypts=0` на фоне растущего `encrypts` = сервер не отвечает = проблема
- `WS pool slot reader error ... wsarecv: A connection attempt failed ...` = TCP от CF edge умер
- `WS pool meltdown detected` = каскад смертей slots

## Что именно хочется от Codex

1. **Корневая причина** `read timeout` каскада через CF CDN (не через origin)
2. **Fix или workaround** который делает CF-режим пригодным как fallback когда TSПУ заблокирует direct IP
3. Если что-то **архитектурно не так** (shared session через 8 WS, per-slot handshake flood, meltdown logic) — предложение как переделать

Не нужно:
- Переписывать весь проект
- Трогать сервер (уже работает, деплой процесс отдельный)
- Заморачиваться с шифрованием / анти-DPI / LeakGuard — это другие подсистемы, они OK

## Нестабильное состояние кода

Форточка широко открыта: `client/stats.go` — debug counters (можно удалить в проде), `client/ws_ready_pool.go` — экспериментальный pool для per-stream режима (opt-in через `NIXAVPN_FORCE_PER_STREAM_WS=1`, по умолчанию выключен). Если Codex решит их убрать — это ок, это diagnostic-инструменты от сегодняшней отладки.

Основные изменения в `engine_shadowlink.go` за 15 апреля — в `git log --oneline` видно под коммитом `84ef181`.

---

_Собрано 2026-04-15 после серии неудачных попыток починить CF-режим._
