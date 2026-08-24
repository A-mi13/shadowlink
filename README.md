<div align="center">

# ShadowLink

**Privacy-focused VPN protocol with advanced traffic obfuscation**

<a href="#english">English</a> | <a href="#russian">Русский</a>

![Go](https://img.shields.io/badge/Go-1.26-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)
![Audit](https://img.shields.io/badge/Security_Audits-18_rounds-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20macOS%20|%20Linux%20|%20Android%20|%20iOS-lightgrey)

</div>

---

<!-- ENGLISH -->
<details open id="english">
<summary><h2>🇬🇧 English</h2></summary>

### About

ShadowLink is a custom VPN protocol designed for maximum privacy and network compatibility. It wraps encrypted traffic in standard HTTPS/WebSocket sessions, making VPN connections indistinguishable from regular web browsing.

Built for scenarios where traditional VPN protocols may be unreliable due to network restrictions, corporate firewalls, or limited connectivity environments.

### Key Features

- **Browser-identical TLS** — Chrome fingerprints via uTLS (Chrome 133/131/120
  population mix, persisted per user). Non-Chrome profiles were retired in
  2026-05; a Firefox profile survives behind the `sl_firefox` build tag for
  experiments outside RU, and is a no-op in the default build
  (`skins/browser/profile_firefox_ru.go`)
- **WebSocket transport** — multiplexed full-duplex relay over standard HTTPS, direct to the origin
- **Slot pool with rotation** — 8 pooled connections rotated on measured age/byte budgets, with graceful drain
- **Decoy website** — unauthenticated visitors see a normal website
- **Domain-based routing** — configurable bypass/force/block rules (split tunnelling by domain)
- **Leak protection** — DNS/IPv6/kill-switch on Windows, macOS, Linux
- **Strong crypto** — X25519 ECDH + HKDF-SHA256 + AES-256-GCM, forward secrecy, replay protection

### Architecture

```
App → SOCKS5 → ShadowLink Client → uTLS (Chrome) → direct origin IP :443
    → nginx (TLS termination + decoy site) → ShadowLink Server → Internet
```

### Transport

Production is **direct to a bare origin IP**, with the domain carried in the
TLS SNI. There is no CDN mode in the supported configuration.

| Mode | When | Method |
|------|------|--------|
| **Full-direct (default)** | Production | WS pool over uTLS to the origin IP, SNI = domain |
| **Single WS** | Pool unavailable | One WebSocket upgrade over HTTPS |
| **SplitHTTP** | Fallback only | Fresh TCP per POST |

> The `cdn` config key is retained for URL-format compatibility only. Setting it
> without `sni`/`origin` **switches the transport** away from the WS pool — see
> `docs/operations/configuration.md` §8.1.

### Quick Start

**Generate keys:**
```bash
shadowlink-server --gen-key
```

**Run server:**
```bash
shadowlink-server --config /etc/shadowlink/config.yaml
```

**Validate a server config without starting anything:**
```bash
shadowlink-server --validate-config /etc/shadowlink/config.yaml
```

**Run client:**
```bash
nixavpn-client --config nixavpn.yaml
```

**Import from URL:**
```bash
nixavpn-client --import "sl://PUBKEY@HOST:PORT?tls=1&ws=1&auto=1&sni=DOMAIN"
```

### Configuration

Every setting — 40 environment flags, the client and server YAML schemas, the
CLI flags, the `sl://` query parameters and the mobile facade fields — is
documented with file:line references in
**[`docs/operations/configuration.md`](docs/operations/configuration.md)**.

Read its section 1 before touching any timing value: the rotation, drain and
keepalive constants are field-measured against DPI, and a green test suite will
not reveal a regression in them.

### Platform Setup

<details>
<summary><b>Windows</b></summary>

**Browser only:**
```
nixavpn-client.exe --config nixavpn.yaml
```
Set the SOCKS5 proxy printed at startup in your browser settings (the client
binds a random loopback port by default and generates per-run credentials).

**System VPN:** run as Administrator with `--system-vpn`. `wintun.dll` must sit
next to the executable; tun2socks is embedded as a Go library, no external
binary is needed.
</details>

<details>
<summary><b>macOS</b></summary>

```bash
chmod +x nixavpn-client
xattr -d com.apple.quarantine nixavpn-client

# Browser only
./nixavpn-client --config nixavpn.yaml

# System VPN
sudo ./nixavpn-client --config nixavpn.yaml --system-vpn
```
See `README-mac.md` for the packaged bundle layout.
</details>

<details>
<summary><b>Linux</b></summary>

```bash
chmod +x nixavpn-client
./nixavpn-client --config nixavpn.yaml

# System VPN
sudo ./nixavpn-client --config nixavpn.yaml --system-vpn
```
</details>

<details>
<summary><b>Android / iOS</b></summary>

**The Go core is ready, the native apps are not** (status as of 2026-08-24).

What exists: `client/` and `engine/` cross-compile for `android/arm64` and
`ios/arm64`, tun2socks is embedded as a Go library, and the `mobile/` package
provides a gomobile facade. The `.aar` builds.

What does not: the apps themselves — `VpnService` (Android) and
`NEPacketTunnelProvider` (iOS) must be written by native teams on top of the SDK.

```bash
gomobile bind -androidapi 21 -target=android/arm64 -o shadowlink.aar ./mobile/
```

- **Android** — the `.aar` **builds** (verified: 9.18 MiB, Java API matches the
  spec). The SDK hands the app a SOCKS5 proxy on `127.0.0.1` with a random port
  and generated credentials; what the platform does with it is its own decision.
- **iOS** — `client/` and `engine/` cross-compile for `ios/arm64`, but building
  an `.xcframework` needs Xcode/macOS, so `gobind` for iOS is **unverified**.
  The `NEPacketTunnelProvider` memory budget is 50 MiB since iOS 15; whether an
  8-slot pool fits is **unmeasured**.

**Documentation for native teams — [`docs/integration/mobile-sdk.md`](docs/integration/mobile-sdk.md)**
(English): Kotlin quick start, full API, callback contract, what the app must
implement itself (DNS protection, `networkChanged()`, persisting the client ID),
building the `.aar`, troubleshooting.

Design rationale — `docs/superpowers/specs/2026-08-24-mobile-facade-design.md`
(⚠ a design document, not a description of current code); platform status —
`docs/plans/2026-08-21-native-readiness.md`.
</details>

### Decoy Site

The decoy is **your own site, kept outside this repository** — deliberately.
A decoy shipped with the protocol would be identical on every deployment, and
that sameness is itself a signature. Each server carries its own.

Routing is decided by the server (`server/handler.go`), not by URL path:

| Request | Served by |
|---|---|
| `POST` + `application/json` | VPN session |
| `Upgrade: websocket` | WS transport |
| everything else | decoy site |

Point the server at a directory of static files:

```bash
shadowlink-server --decoy /var/www/decoy       # CLI
```
```yaml
domain_decoy_map:                               # or per-Host, multi-domain
  "example.com": /var/www/decoy
```

⚠ **The page must carry a single-line JSON-LD block.** It is not decoration:
it is the carrier for rate-limit state.

```html
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","identifier":"rl-state ..."}</script>
```

Two constraints, both enforced by the client-side regexp
(`client/ratelimit_carriers.go:44`) and easy to break by accident:

1. **One line, flat object.** The pattern is `>(\{[^<]+\})</script>` — it
   survives neither line breaks with nesting nor a `<` inside the JSON.
   Pretty-printing this block silently kills the carrier.
2. **It must exist at all.** Without `--decoy` the server falls back to a
   built-in "under construction" page (`server/decoy.go:310`) that has **no**
   JSON-LD. Rate-limit feedback then has only the `X-SL-RL` response header
   left — a header no real website emits, i.e. a direct fingerprint for a
   probe. Acceptable for a connectivity check, not for production.

`install-server.sh` writes a minimal conforming template to `/var/www/decoy`
on first run and **never overwrites** an existing one — replace it with your
own site, keeping the JSON-LD block.

### Config Example

```yaml
protocol: shadowlink
shadowlink:
  server: "203.0.113.10:443"     # bare origin IP
  sni: "example.com"             # TLS ServerName
  pubkey: "64-char-hex-public-key"
  tls: true
  websocket: true
  routing:
    bypass:
      - "*.local"
      - "*.internal"
```

Full schema and defaults: [`docs/operations/configuration.md`](docs/operations/configuration.md).

### Performance

> ⚠ **Unverified.** No reproducible throughput benchmark exists in `docs/` —
> the figures below are carried over from an earlier README and no measurement
> backing them was found in this repository. What *is* measured and reproducible
> is field telemetry (connection-age distributions, timing phase on the wire,
> exposure counters) — see `docs/plans/2026-08-21-field-run-analysis.md`.
> Treat the table as a rough historical note, not a specification.

| Metric | Reported |
|--------|----------|
| Download | 196–548 Mbps |
| Upload | 28–137 Mbps |
| Latency overhead | ~10–15 ms |

### Project Structure

```
shadowlink/
  core/           — crypto, sessions, chunks, flow control, jitter
  server/         — HTTP handler, WebSocket, decoy, rate limiter, management API
  client/         — transports, WS pool, leakguard, split-DNS, bypass routing
  engine/         — portable transport engine (no TUN/CLI) — shared by CLI and mobile
  mobile/         — gomobile facade (.aar / .xcframework) over engine/
  proxy/          — SOCKS5 (+ UDP associate)
  skins/browser/  — mimicry engine (fingerprints, inflation, shaping, cover)
  cmd/            — server and client binaries, cf-scanner, metrics dump
  testutil/       — DPI emulator, integration helpers
  tools/          — analysis utilities (e.g. firstpackets: wire-phase measurement)
```

### Build

```bash
go build ./... && go vet ./...
go test ./... -count=1

# Client (Windows) and server (Linux)
bash build-client.sh          # → ./bin/nixavpn-client.exe
bash build-server.sh          # → ./bin/shadowlink-server-linux

# Cross-compile checks for the mobile core
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./client/ ./engine/
GOOS=ios     GOARCH=arm64 CGO_ENABLED=0 go build ./client/ ./engine/

# Android SDK
gomobile bind -androidapi 21 -target=android/arm64 -o shadowlink.aar ./mobile/
```

Releases are cut by pushing a tag — CI runs vet + tests, checks the mobile
cross-compile, builds both binaries, pins and verifies `wintun.dll` by SHA-256,
and publishes the GitHub Release:

```bash
git tag -a v0.2.0 -m "release v0.2.0" && git push origin v0.2.0
```

### Documentation

- [`docs/operations/configuration.md`](docs/operations/configuration.md) — every configurable parameter, with defaults read from the source
- [`docs/operations/server-install.md`](docs/operations/server-install.md) — server installation: nginx, systemd, keys
- [`docs/integration/mobile-sdk.md`](docs/integration/mobile-sdk.md) — Android/iOS SDK integration guide
- `docs/protocols/` — wire protocols: body-prefix-v1, flow-control-v2, live-decoy
- `docs/PHASES-CHANGELOG.md` — development and audit history

</details>

---

<!-- RUSSIAN -->
<details id="russian">
<summary><h2>🇷🇺 Русский</h2></summary>

### О проекте

ShadowLink — собственный VPN-протокол, разработанный для максимальной приватности и совместимости с различными сетевыми условиями. Оборачивает зашифрованный трафик в стандартные HTTPS/WebSocket сессии, делая VPN-соединение неотличимым от обычного веб-серфинга.

Создан для ситуаций, когда традиционные VPN-протоколы работают нестабильно из-за сетевых ограничений, корпоративных файрволов или ограниченного доступа к сети.

### Возможности

- **TLS как у браузера** — отпечатки Chrome через uTLS (популяционная смесь
  Chrome 133/131/120, персистится на пользователя). Не-Chrome профили сняты
  в мае 2026; профиль Firefox остался под build-тегом `sl_firefox` для
  экспериментов вне РФ и в дефолтной сборке является no-op
  (`skins/browser/profile_firefox_ru.go`)
- **WebSocket-транспорт** — мультиплексированный full-duplex поверх обычного HTTPS, напрямую к origin
- **Пул слотов с ротацией** — 8 соединений, ротация по измеренным бюджетам возраста и байт, graceful drain
- **Decoy-сайт** — неавторизованные посетители видят обычный сайт
- **Маршрутизация по доменам** — настраиваемые правила bypass/force/block (split tunneling)
- **Защита от утечек** — DNS/IPv6/kill-switch на Windows, macOS, Linux
- **Надёжная криптография** — X25519 ECDH + HKDF-SHA256 + AES-256-GCM, forward secrecy, защита от replay

### Архитектура

```
Приложение → SOCKS5 → ShadowLink Client → uTLS (Chrome) → прямо на origin IP :443
    → nginx (терминация TLS + decoy-сайт) → ShadowLink Server → Интернет
```

### Транспорт

Прод — **прямое соединение с голым origin IP**, доменное имя едет в TLS SNI.
Режима через CDN в поддерживаемой конфигурации нет.

| Режим | Когда | Метод |
|-------|-------|-------|
| **Full-direct (по умолчанию)** | Прод | Пул WS поверх uTLS на origin IP, SNI = домен |
| **Одиночный WS** | Пул недоступен | Один WebSocket-upgrade поверх HTTPS |
| **SplitHTTP** | Только fallback | Свежий TCP на каждый POST |

> Ключ конфига `cdn` оставлен исключительно ради совместимости формата ссылки.
> Заданный без `sni`/`origin`, он **меняет транспорт**, уводя его с пула WS —
> см. `docs/operations/configuration.md` §8.1.

### Быстрый старт

**Генерация ключей:**
```bash
shadowlink-server --gen-key
```

**Запуск сервера:**
```bash
shadowlink-server --config /etc/shadowlink/config.yaml
```

**Проверка серверного конфига без запуска:**
```bash
shadowlink-server --validate-config /etc/shadowlink/config.yaml
```

**Запуск клиента:**
```bash
nixavpn-client --config nixavpn.yaml
```

**Импорт из URL:**
```bash
nixavpn-client --import "sl://PUBKEY@HOST:PORT?tls=1&ws=1&auto=1&sni=DOMAIN"
```

### Конфигурация

Все настройки — 40 переменных окружения, схемы YAML клиента и сервера, флаги
CLI, query-параметры `sl://` и поля мобильного фасада — описаны со ссылками
`файл:строка` в
**[`docs/operations/configuration.md`](docs/operations/configuration.md)**.

Прочитайте её раздел 1 прежде чем менять любое тайминговое значение: константы
ротации, дренажа и keepalive выведены полевыми замерами против DPI, и зелёные
тесты регресс в них не покажут.

### Платформы

| Платформа | Browser mode | System VPN |
|-----------|-------------|------------|
| **Windows** | `nixavpn-client.exe --config nixavpn.yaml` | `--system-vpn` от администратора (нужен `wintun.dll` рядом) |
| **macOS** | `./nixavpn-client --config nixavpn.yaml` | `sudo ./nixavpn-client --config nixavpn.yaml --system-vpn` |
| **Linux** | `./nixavpn-client --config nixavpn.yaml` | `sudo ./nixavpn-client --config nixavpn.yaml --system-vpn` |
| **Android** | gomobile `.aar` — ✅ собирается (`./mobile/`) | VpnService API — ⚠ нативная часть не написана |
| **iOS** | `.xcframework` — ⚠ нужен Xcode/macOS, `gobind` не проверен | NEPacketTunnelProvider — ⚠ бюджет памяти 50 MiB не измерен |

tun2socks встроен как Go-библиотека — внешний бинарь не нужен.

Документация для нативных команд — [`docs/integration/mobile-sdk.md`](docs/integration/mobile-sdk.md).

### Decoy-сайт

Decoy — **ваш собственный сайт, и он намеренно не хранится в этом
репозитории**. Сайт, поставляемый вместе с протоколом, был бы одинаковым на
всех развёртываниях, а одинаковость сама по себе является сигнатурой. Каждый
сервер несёт свой.

Маршрутизацию решает сервер (`server/handler.go`), а не путь в URL:

| Запрос | Обслуживает |
|---|---|
| `POST` + `application/json` | VPN-сессия |
| `Upgrade: websocket` | WS-транспорт |
| всё остальное | decoy-сайт |

Указать серверу каталог со статикой:

```bash
shadowlink-server --decoy /var/www/decoy       # CLI
```
```yaml
domain_decoy_map:                               # либо по Host, для нескольких доменов
  "example.com": /var/www/decoy
```

⚠ **На странице обязан быть однострочный JSON-LD блок.** Это не украшение:
он служит носителем состояния rate-limit.

```html
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","identifier":"rl-state ..."}</script>
```

Два ограничения, оба следуют из клиентской регулярки
(`client/ratelimit_carriers.go:44`) и оба легко нарушить по невнимательности:

1. **Одна строка, плоский объект.** Шаблон `>(\{[^<]+\})</script>` не
   переживёт ни переносов с вложенностью, ни `<` внутри JSON. «Красивое»
   форматирование этого блока молча убьёт носитель.
2. **Он должен вообще быть.** Без `--decoy` сервер отдаёт встроенную заглушку
   «under construction» (`server/decoy.go:310`), в которой JSON-LD **нет**.
   Тогда у rate-limit остаётся только заголовок `X-SL-RL` — заголовок, которого
   не отдаёт ни один настоящий сайт, то есть прямая сигнатура для зонда.
   Годится для проверки связности, не для прода.

`install-server.sh` при первом запуске кладёт минимальный корректный шаблон в
`/var/www/decoy` и **никогда не перезаписывает** существующий — замените его
своим сайтом, сохранив блок JSON-LD.

### Пример конфига

```yaml
protocol: shadowlink
shadowlink:
  server: "203.0.113.10:443"     # голый origin IP
  sni: "example.com"             # TLS ServerName
  pubkey: "64-символьный-hex-ключ"
  tls: true
  websocket: true
  routing:
    bypass:
      - "*.local"
      - "*.internal"
```

Полная схема и дефолты: [`docs/operations/configuration.md`](docs/operations/configuration.md).

### Производительность

> ⚠ **Не подтверждено.** Воспроизводимого замера пропускной способности в
> `docs/` нет — цифры ниже перенесены из прежней версии README, и источника
> под них в репозитории не нашлось. Измерено и воспроизводимо другое: полевая
> телеметрия (распределения возрастов соединений, фаза таймингов на проводе,
> счётчики экспозиции) — см. `docs/plans/2026-08-21-field-run-analysis.md`.
> Читать таблицу как историческую заметку, а не как спецификацию.

| Метрика | Заявлено |
|---------|----------|
| Download | 196–548 Мбит/с |
| Upload | 28–137 Мбит/с |
| Задержка | ~10–15 мс |

### Структура проекта

```
shadowlink/
  core/           — криптография, сессии, чанки, flow control, джиттер
  server/         — HTTP handler, WebSocket, decoy, rate limiter, management API
  client/         — транспорты, пул WS, leakguard, split-DNS, bypass-роутинг
  engine/         — переносимый движок транспорта (без TUN/CLI) — общий для CLI и мобилок
  mobile/         — gomobile-фасад (.aar / .xcframework) поверх engine/
  proxy/          — SOCKS5 (+ UDP associate)
  skins/browser/  — движок мимикрии (отпечатки, inflation, shaping, cover)
  cmd/            — бинарники сервера и клиента, cf-scanner, дамп метрик
  testutil/       — DPI-эмулятор, хелперы интеграционных тестов
  tools/          — утилиты анализа (напр. firstpackets: замер фазы на проводе)
```

### Сборка

```bash
go build ./... && go vet ./...
go test ./... -count=1          # на Windows: без -race (нет gcc)

# Клиент (Windows) и сервер (Linux)
bash build-client.sh          # → ./bin/nixavpn-client.exe
bash build-server.sh          # → ./bin/shadowlink-server-linux

# Проверка кросс-компиляции мобильного ядра
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build ./client/ ./engine/
GOOS=ios     GOARCH=arm64 CGO_ENABLED=0 go build ./client/ ./engine/

# Android SDK
gomobile bind -androidapi 21 -target=android/arm64 -o shadowlink.aar ./mobile/
```

Релиз — пуш тега, больше ничего: CI сам прогоняет vet и тесты, проверяет
кросс-сборку под мобилки, собирает оба бинарника, скачивает `wintun.dll` с
закреплённой SHA-256 и публикует GitHub Release:

```bash
git tag -a v0.2.0 -m "release v0.2.0" && git push origin v0.2.0
```

### Документация

- [`docs/operations/configuration.md`](docs/operations/configuration.md) — все настраиваемые параметры, дефолты сверены с кодом
- [`docs/operations/server-install.md`](docs/operations/server-install.md) — установка сервера: nginx, systemd, ключи
- [`docs/integration/mobile-sdk.md`](docs/integration/mobile-sdk.md) — интеграция Android/iOS SDK
- `docs/protocols/` — протоколы на проводе: body-prefix-v1, flow-control-v2, live-decoy
- `docs/PHASES-CHANGELOG.md` — летопись разработки и аудитов

</details>

---

<div align="center">

**License:** Proprietary

</div>
