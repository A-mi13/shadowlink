---
name: mimicry-model
description: Use when touching TLS fingerprints, uTLS profiles, decoy site, cover traffic, JSON envelope, wire format, or when considering CDN/domain-fronting/randomization. Hard boundaries of the masking model — what is intentional and must NOT be "improved".
---

# Модель маскировки — границы, которые нельзя двигать

Противник — **TSPU** (DPI РКН). Всё ниже выглядит как «недоделка», но является
осознанным решением. Прежде чем «улучшать» — прочитать причину.

## Категорические запреты

| Запрет | Причина |
|---|---|
| **НЕ предлагать CDN / domain fronting / Cloudflare** | РКН режет диапазоны CF/CDN целиком. Прод = DIRECT к голому origin IP (`?origin=<IP>`, dial по литеральному IP, SNI = домен, без DNS на data-path) |
| **НЕ рандомизировать TLS fingerprint** | Рандомный FP = уникальный FP = сигнал. uTLS прибит к **Chrome 133** намеренно |
| **НЕ добавлять Firefox/Safari в hot-path pool** | РКН банит их первыми. FP-diversity — только внутри Chrome (120/131/133) |
| **НЕ переводить data-path на JSON** | Горячий путь = WebSocket **binary** frames (`conn.WriteMessage(BinaryMessage,…)`) |
| **НЕ заменять decoy на vanilla HTML** | Decoy = полноценный per-persona React+Vite SPA. Разнородный стек на одном IP = cluster signal |
| **НЕ запускать сервер без nginx** | Go `net/http` шлёт non-browser HTTP/2 SETTINGS = JA3/H2-fingerprint риск |

## Где что живёт

- `skins/browser/profile.go` — fingerprint registry, веса пула
- `skins/browser/fingerprint.go` + `fingerprint_lock.go` — **lockstep всех 4 wire-поверхностей**: при смене FP все четыре должны двигаться синхронно, иначе рассинхрон сам становится сигналом
- `skins/browser/cover.go`, `urls.go` — cover-запросы, реалистичные пути
- `skins/browser/padding.go`, `shaping.go`, `response_size.go` — inflation / shaping размеров
- `skins/browser/decoy_interval.go` — bimodal интервалы decoy-трафика
- `server/decoy*.go` — decoy router, snapshots, timing, логирование

## JSON envelope — точная область применения

JSON-envelope в стиле аналитики используется **только** на:
1. handshake POST
2. cover-трафике

Персона стороннего SDK **отменена** (2026-04-28; вычищена из кода 2026-08-08).
TSPU не расшифровывает тела, поэтому сходство с чьим-то форматом не покупает
ничего: работают метаданные (пути, размеры, тайминги), а не содержимое.
Ставить JSON на горячий путь = платить за то, что противник не читает.

⚠ Следствие для путей: cover/warmup-пути должны быть **first-party**. Пути
вендорских SDK (`/decide`, `/lib.min.js`, `/tag.js`, `/pixel.gif`) удалены
2026-08-08 — браузер берёт их с origin вендора, а мы слали их same-origin с
собственными `Origin`/`Referer`, чего в природе не бывает. Сторож —
`TestDefaultCoverPaths_NoThirdPartySDKPaths`.

⚠ Следствие для размеров: диапазоны паддинга ([600,3000] данные / [200,800]
handshake) держатся на собственном обосновании — правдоподобная зона для
JSON-тела и расхождение двух распределений, — а НЕ на сходстве с вендором.
Не возвращать «калибровку по эталонному захвату»: эталона нет и цели нет.
Сторож — `TestPaddingBands_NoVendorPersonaReference`.

## Routing (`server/handler.go`)

- `POST` + `application/json` → VPN-сессия
- `Upgrade: websocket` → WS transport
- всё остальное → decoy site

## Версионный потолок

`utls v1.8.3` (`github.com/refraction-networking/utls`) — потолок Chrome **133**.
Профилей 135/140 в нём нет. Прежде чем поднимать целевую версию Chrome —
проверить, что профиль реально существует в upstream, а не «должен бы быть».

## Откат без передеплоя

- `SHADOWLINK_FP_POOL=0` → форс Chrome 100%, игнор весов и persist
- `SHADOWLINK_TLS_PQ=0` → cold-path uTLS без MLKEM keyshare (hot-path всегда
  Chrome_133 по F2 lockstep)
