<div align="center">

# ShadowLink

**Privacy-focused VPN protocol with advanced traffic obfuscation**

<a href="#english">English</a> | <a href="#russian">Русский</a>

![Go](https://img.shields.io/badge/Go-1.24-blue)
![License](https://img.shields.io/badge/License-Proprietary-red)
![Audit](https://img.shields.io/badge/Security_Audits-17_rounds-green)
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

- **Browser-identical TLS** — Chrome/Firefox/Safari fingerprints via uTLS (per-user, persistent)
- **WebSocket transport** — full-duplex relay over standard HTTPS, compatible with any CDN or proxy
- **Decoy website** — unauthenticated visitors see a normal website
- **Smart transport selection** — auto-detects network conditions and picks the best path
- **Domain-based routing** — configurable bypass rules (split tunneling by domain)
- **Leak protection** — DNS/IPv6/kill-switch on Windows, macOS, Linux
- **TURN relay** — fallback transport through third-party TURN servers for restricted networks
- **Strong crypto** — X25519 ECDH + HKDF-SHA256 + AES-256-GCM, forward secrecy, replay protection

### Architecture

```
App → SOCKS5 → ShadowLink Client → TLS (browser fingerprint)
    → nginx (website) → WebSocket → ShadowLink Server → Internet
```

### Transport Modes

| Mode | Use Case | Method |
|------|----------|--------|
| **Direct** | Server reachable | HTTPS |
| **CDN** | Need extra layer | Via Cloudflare |
| **WebSocket** | Full-duplex | WS upgrade over HTTPS |
| **TURN relay** | Restricted network | KCP/yamux through TURN server |

### Quick Start

**Generate keys:**
```bash
shadowlink-server --gen-key
```

**Run server:**
```bash
shadowlink-server --listen :8443 --server-key server.key --enable-udp --udp-listen :56000
```

**Run client:**
```bash
shadowlink-client --config config.yaml
```

**Import from URL:**
```bash
shadowlink-client --import "sl://PUBKEY@host:port?tls=1&ws=1&auto=1" --save config.yaml
```

### Platform Setup

<details>
<summary><b>Windows</b></summary>

**Browser only:**
```
shadowlink-client.exe --config config.yaml
```
Set SOCKS5 proxy `127.0.0.1:7150` in browser settings.

**System VPN:** Run as Administrator:
```
connect-system-vpn.bat
```
Requires [tun2socks](https://github.com/xjasonlyu/tun2socks/releases).
</details>

<details>
<summary><b>macOS</b></summary>

```bash
chmod +x shadowlink-client-mac
xattr -d com.apple.quarantine shadowlink-client-mac

# Browser only
./connect-browser-mac.sh

# System VPN
sudo ./connect-system-vpn-mac.sh
```
System VPN requires [tun2socks](https://github.com/xjasonlyu/tun2socks/releases) (`brew install tun2socks`).
</details>

<details>
<summary><b>Linux</b></summary>

```bash
chmod +x shadowlink-client-linux
./shadowlink-client-linux --config config.yaml

# System VPN
sudo ./connect-system-vpn-linux.sh
```
</details>

<details>
<summary><b>Android / iOS</b></summary>

Compiles to native libraries via `gomobile`:
- **Android**: `.aar` → Kotlin/Java
- **iOS**: `.xcframework` → Swift/ObjC

No external tun2socks needed — uses native VPN APIs.
</details>

### Config Example

```yaml
server: "example.com:443"
pubkey: "64-char-hex-public-key"
tls: true
websocket: true
auto: true
socks: "127.0.0.1:7150"

routing:
  bypass:
    - "*.local"
    - "*.internal"
```

### Performance

| Metric | Result |
|--------|--------|
| Download | 196–548 Mbps |
| Upload | 28–137 Mbps |
| TURN relay | 86–145 Mbps |
| Latency overhead | ~10–15 ms |

### Project Structure

```
shadowlink/
  core/           — crypto, sessions, chunks
  server/         — HTTP handler, WebSocket, UDP, decoy, management API
  client/         — transports, probe engine, leakguard, DNS router
  skins/browser/  — HTTP API masking (fingerprints, URL rotation)
  skins/call/     — TURN relay transport
  cmd/            — server and client binaries
  testutil/       — DPI emulator, integration tests
```

### Build

```bash
go build ./cmd/shadowlink-client/
go build ./cmd/shadowlink-server/
GOOS=darwin GOARCH=arm64 go build -o shadowlink-client-mac ./cmd/shadowlink-client/
GOOS=linux GOARCH=amd64 go build -o shadowlink-server-linux ./cmd/shadowlink-server/
go test ./...
```

</details>

---

<!-- RUSSIAN -->
<details id="russian">
<summary><h2>🇷🇺 Русский</h2></summary>

### О проекте

ShadowLink — собственный VPN-протокол, разработанный для максимальной приватности и совместимости с различными сетевыми условиями. Оборачивает зашифрованный трафик в стандартные HTTPS/WebSocket сессии, делая VPN-соединение неотличимым от обычного веб-серфинга.

Создан для ситуаций, когда традиционные VPN-протоколы работают нестабильно из-за сетевых ограничений, корпоративных файрволов или ограниченного доступа к сети.

### Возможности

- **TLS как у браузера** — Chrome/Firefox/Safari fingerprints через uTLS (уникальный для каждого пользователя)
- **WebSocket транспорт** — full-duplex через стандартный HTTPS, совместим с любым CDN
- **Decoy-сайт** — неавторизованные посетители видят обычный сайт
- **Авто-выбор транспорта** — определяет условия сети и выбирает лучший путь
- **Маршрутизация по доменам** — настраиваемые bypass правила (split tunneling)
- **Защита от утечек** — DNS/IPv6/kill-switch на Windows, macOS, Linux
- **TURN relay** — запасной транспорт через сторонние TURN серверы для ограниченных сетей
- **Надёжная криптография** — X25519 ECDH + HKDF-SHA256 + AES-256-GCM, forward secrecy

### Архитектура

```
Приложение → SOCKS5 → ShadowLink Client → TLS (browser fingerprint)
    → nginx (сайт) → WebSocket → ShadowLink Server → Интернет
```

### Режимы транспорта

| Режим | Когда | Метод |
|-------|-------|-------|
| **Direct** | Сервер доступен | HTTPS |
| **CDN** | Нужен дополнительный слой | Через Cloudflare |
| **WebSocket** | Full-duplex | WS поверх HTTPS |
| **TURN relay** | Ограниченная сеть | KCP/yamux через TURN сервер |

### Быстрый старт

**Генерация ключей:**
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
| **Windows** | `shadowlink-client.exe --config config.yaml` | `connect-system-vpn.bat` (администратор) |
| **macOS** | `./connect-browser-mac.sh` | `sudo ./connect-system-vpn-mac.sh` |
| **Linux** | `./shadowlink-client-linux --config config.yaml` | `sudo ./connect-system-vpn-linux.sh` |
| **Android** | gomobile `.aar` | VpnService API |
| **iOS** | gomobile `.xcframework` | NEPacketTunnelProvider |

### Пример конфига

```yaml
server: "example.com:443"
pubkey: "64-символьный-hex-ключ"
tls: true
websocket: true
auto: true
socks: "127.0.0.1:7150"

routing:
  bypass:
    - "*.local"
    - "*.internal"
```

### Производительность

| Метрика | Результат |
|---------|-----------|
| Download | 196–548 Мбит/с |
| Upload | 28–137 Мбит/с |
| TURN relay | 86–145 Мбит/с |
| Задержка | ~10–15 мс |

### Структура проекта

```
shadowlink/
  core/           — криптография, сессии, чанки
  server/         — HTTP handler, WebSocket, UDP, decoy, management API
  client/         — транспорты, probe engine, leakguard, DNS router
  skins/browser/  — маскировка под HTTP API
  skins/call/     — TURN relay транспорт
  cmd/            — бинарники сервера и клиента
  testutil/       — DPI эмулятор, интеграционные тесты
```

### Сборка

```bash
go build ./cmd/shadowlink-client/
go build ./cmd/shadowlink-server/
GOOS=darwin GOARCH=arm64 go build -o shadowlink-client-mac ./cmd/shadowlink-client/
GOOS=linux GOARCH=amd64 go build -o shadowlink-server-linux ./cmd/shadowlink-server/
go test ./...
```

</details>

---

<div align="center">

**License:** Proprietary

</div>
