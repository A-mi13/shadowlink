<div align="center">

# ShadowLink

**Stealth VPN protocol that looks like a regular web application**

[English](#english) | [Русский](#russian)

![Go](https://img.shields.io/badge/Go-1.24-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)
![Audit](https://img.shields.io/badge/Security_Audits-17_rounds-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20|%20macOS%20|%20Linux%20|%20Android%20|%20iOS-lightgrey)

</div>

---

<a name="english"></a>

## What is ShadowLink?

ShadowLink is a custom VPN protocol that disguises encrypted traffic as ordinary web API requests. Designed to bypass deep packet inspection (DPI) systems, including advanced state-level censorship infrastructure.

### Why not existing protocols?

| Feature | VLESS+Reality | WireGuard | ShadowLink |
|---------|--------------|-----------|------------|
| TLS fingerprint | Go default (detectable) | N/A | **Chrome 133 via uTLS** |
| Active probing resistance | Proxy to third-party | None | **Built-in decoy website** |
| HTTP/2 fingerprint | Go default | N/A | **Browser-identical** |
| Whitelist bypass | None | None | **WB TURN relay** |
| Per-user fingerprint | None | None | **7-day persistent lease** |
| Domain-based bypass | None | None | **DNS router (.ru direct)** |

### How it works

```
Browser/App → SOCKS5 → ShadowLink Client → TLS (Chrome fingerprint)
    → nginx (decoy site) → WebSocket → ShadowLink Server → Internet
```

1. **TLS**: ClientHello identical to Chrome 133 (`refraction-networking/utls`)
2. **HTTP**: Requests look like `POST /api/v2/events` to an analytics API
3. **Data**: Encrypted VPN packets wrapped in JSON with base64 — indistinguishable from real API
4. **Decoy**: Unauthenticated visitors see a normal website

### Transport modes

| Mode | When | How |
|------|------|-----|
| **Direct** | Server reachable | HTTPS to server |
| **CDN** | Server IP blocked | Via Cloudflare |
| **WebSocket** | Full-duplex needed | WS upgrade after handshake |
| **WB TURN** | Whitelist-only network | KCP/yamux through Wildberries TURN relay |

**Probe Engine** auto-detects network conditions and selects the best transport.

### Security

- **17 rounds** of security audit (DPI adversarial, code quality, crypto review)
- X25519 ECDH + HKDF-SHA256 + AES-256-GCM
- Forward secrecy (ephemeral keys both sides)
- Replay protection (256-bit sliding window)
- Per-user uTLS fingerprint (Chrome/Firefox/Safari, 7-day lock)
- DNS/IPv6/kill-switch leak protection (LeakGuard)
- SSRF protection (SafeDial blocks private IP ranges)

### Quick start

**Generate server keys:**
```bash
shadowlink-server --gen-key
```

**Start server:**
```bash
shadowlink-server --listen :8443 --server-key server.key --enable-udp --udp-listen :56000
```

**Start client (YAML config):**
```bash
shadowlink-client --config config.yaml
```

**Start client (CLI flags):**
```bash
shadowlink-client --server example.com:443 --pubkey <HEX_KEY> --tls --ws --auto --socks 127.0.0.1:1080
```

**Import from URL:**
```bash
shadowlink-client --import "sl://PUBKEY@host:port?tls=1&ws=1&auto=1" --save config.yaml
```

### Platform setup

<details>
<summary><b>Windows</b></summary>

Download `tun2socks.exe` from [releases](https://github.com/xjasonlyu/tun2socks/releases).

**Browser only:**
```
shadowlink-client.exe --config config.yaml
# Set SOCKS5 proxy 127.0.0.1:7150 in browser
```

**System VPN (all traffic):** Run as Administrator:
```
connect-system-vpn.bat
```
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# Install tun2socks
brew install tun2socks
# or download from GitHub releases

# Remove quarantine
chmod +x shadowlink-client-mac
xattr -d com.apple.quarantine shadowlink-client-mac

# Browser only
./connect-browser-mac.sh

# System VPN (all traffic)
sudo ./connect-system-vpn-mac.sh
```
</details>

<details>
<summary><b>Linux</b></summary>

```bash
chmod +x shadowlink-client-linux
# Browser only
./shadowlink-client-linux --config config.yaml
# System VPN
sudo ./connect-system-vpn-linux.sh
```
</details>

<details>
<summary><b>Android / iOS (gomobile)</b></summary>

ShadowLink compiles to native libraries via `gomobile`:
- **Android**: `.aar` library → Kotlin/Java bridge
- **iOS**: `.xcframework` → Swift/ObjC bridge

```kotlin
// Android
ShadowLink.connect(configJSON)
ShadowLink.disconnect()
```

No external `tun2socks` needed — uses `VpnService` / `NEPacketTunnelProvider` directly.
</details>

### Config example (`config.yaml`)

```yaml
server: "example.com:443"
pubkey: "64-char-hex-public-key"
tls: true
websocket: true
auto: true
socks: "127.0.0.1:7150"

routing:
  bypass:
    - "*.ru"
    - "*.xn--p1ai"
    - "vk.com"
    - "*.vk.com"
```

### Performance (real server, Finland)

| Metric | Result |
|--------|--------|
| Download | **196-548 Mbps** |
| Upload | **28-137 Mbps** |
| WB TURN (whitelist bypass) | **86-145 Mbps** |
| Latency overhead | ~10-15ms |
| DPI bypass | Not detected |

### Project structure

```
shadowlink/
  core/           — crypto, sessions, chunks (transport-agnostic)
  server/         — HTTP handler, WebSocket, UDP, decoy, management API
  client/         — transports (Direct, CDN, WS, TURN), probe engine, leakguard
  skins/browser/  — HTTP API masking (JSON, fingerprints, URL rotation)
  skins/call/     — TURN relay for whitelist bypass
  cmd/            — server and client binaries
```

### Build

```bash
# Client (current platform)
go build ./cmd/shadowlink-client/

# Server (Linux)
GOOS=linux GOARCH=amd64 go build -o shadowlink-server-linux ./cmd/shadowlink-server/

# macOS client (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o shadowlink-client-mac ./cmd/shadowlink-client/

# Tests
go test ./...
go test -race ./...
```

---

<a name="russian"></a>

## Что такое ShadowLink?

ShadowLink — собственный VPN-протокол, маскирующий зашифрованный трафик под обычные API-запросы веб-приложения. Разработан для обхода DPI-систем, включая ТСПУ.

### Зачем, если есть другие протоколы?

| Возможность | VLESS+Reality | WireGuard | ShadowLink |
|-------------|--------------|-----------|------------|
| TLS fingerprint | Go default (палится) | Нет | **Chrome 133 через uTLS** |
| Active probing | Прокси к чужому сайту | Нет защиты | **Встроенный decoy-сайт** |
| HTTP/2 fingerprint | Go default | Нет | **Идентичный браузеру** |
| Обход белых списков | Нет | Нет | **WB TURN relay** |
| Per-user fingerprint | Нет | Нет | **7-дневная ротация** |
| Bypass .ru доменов | Нет | Нет | **DNS router (напрямую)** |

### Как работает

```
Браузер/Приложение → SOCKS5 → ShadowLink Client → TLS (Chrome fingerprint)
    → nginx (decoy сайт) → WebSocket → ShadowLink Server → Интернет
```

1. **TLS**: ClientHello идентичен Chrome 133 (`refraction-networking/utls`)
2. **HTTP**: Запросы выглядят как `POST /api/v2/events` аналитического API
3. **Данные**: Зашифрованные VPN-пакеты в JSON с base64 — неотличимы от настоящих
4. **Decoy**: Неавторизованные посетители видят обычный сайт

### Режимы транспорта

| Режим | Когда | Как |
|-------|-------|-----|
| **Direct** | Сервер доступен | HTTPS напрямую |
| **CDN** | IP заблокирован | Через Cloudflare |
| **WebSocket** | Full-duplex | WS upgrade после handshake |
| **WB TURN** | Белые списки | KCP/yamux через Wildberries TURN relay |

**Probe Engine** автоматически определяет тип сети и выбирает лучший транспорт.

### Безопасность

- **17 раундов** security audit (DPI, adversarial, code quality, crypto)
- X25519 ECDH + HKDF-SHA256 + AES-256-GCM
- Forward secrecy (эфемерные ключи с обеих сторон)
- Replay protection (256-бит sliding window)
- Per-user uTLS fingerprint (Chrome/Firefox/Safari, 7 дней)
- LeakGuard: DNS/IPv6/kill-switch защита от утечек
- SSRF-защита (SafeDial блокирует приватные IP)

### Быстрый старт

**Генерация ключей сервера:**
```bash
shadowlink-server --gen-key
```

**Запуск сервера:**
```bash
shadowlink-server --listen :8443 --server-key server.key --enable-udp --udp-listen :56000
```

**Запуск клиента:**
```bash
shadowlink-client --config config.yaml
```

**Импорт из URL:**
```bash
shadowlink-client --import "sl://PUBKEY@host:port?tls=1&ws=1&auto=1" --save config.yaml
```

### Платформы

| Платформа | Browser mode | System VPN |
|-----------|-------------|------------|
| **Windows** | `shadowlink-client.exe --config config.yaml` | `connect-system-vpn.bat` (от администратора) |
| **macOS** | `./connect-browser-mac.sh` | `sudo ./connect-system-vpn-mac.sh` |
| **Linux** | `./shadowlink-client-linux --config config.yaml` | `sudo ./connect-system-vpn-linux.sh` |
| **Android** | gomobile `.aar` | `VpnService` API |
| **iOS** | gomobile `.xcframework` | `NEPacketTunnelProvider` |

### Пример конфига (`config.yaml`)

```yaml
server: "example.com:443"
pubkey: "64-символьный-hex-публичный-ключ"
tls: true
websocket: true
auto: true
socks: "127.0.0.1:7150"

routing:
  bypass:
    - "*.ru"
    - "*.xn--p1ai"
    - "vk.com"
    - "*.vk.com"
```

### Производительность (реальный сервер, Финляндия)

| Метрика | Результат |
|---------|-----------|
| Download | **196-548 Мбит/с** |
| Upload | **28-137 Мбит/с** |
| WB TURN (обход белых списков) | **86-145 Мбит/с** |
| Задержка | ~10-15 мс |
| DPI bypass | Не обнаружен |

### Сборка

```bash
# Клиент (текущая платформа)
go build ./cmd/shadowlink-client/

# Сервер (Linux)
GOOS=linux GOARCH=amd64 go build -o shadowlink-server-linux ./cmd/shadowlink-server/

# macOS клиент (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o shadowlink-client-mac ./cmd/shadowlink-client/

# Тесты
go test ./...
```

### Структура проекта

```
shadowlink/
  core/           — криптография, сессии, чанки
  server/         — HTTP handler, WebSocket, UDP, decoy, management API
  client/         — транспорты, probe engine, leakguard, DNS router
  skins/browser/  — маскировка под HTTP API
  skins/call/     — TURN relay для whitelist bypass
  cmd/            — бинарники сервера и клиента
```

---

<div align="center">

**License:** Proprietary — NixaVPN internal project

</div>
