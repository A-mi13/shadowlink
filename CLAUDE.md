# ShadowLink Protocol — Reference

Steganographic VPN. Go 1.25, `module github.com/nixavpn/shadowlink`. Отдельный
проект (`D:\shadowlink`) со своим go.mod и git — **вне дерева NixaVPN**.
Противник — **TSPU** (DPI РКН); из этого растут все архитектурные решения.

## Hard rules

1. **НЕ предлагать CDN / Cloudflare / domain fronting.** Прод = DIRECT к голому
   origin IP. РКН режет диапазоны CDN целиком.
2. **НЕ рандомизировать TLS fingerprint.** uTLS прибит к Chrome 133 намеренно.
   Только Chrome (Firefox/Safari РКН банит первыми).
3. **Горячий путь = WebSocket binary frames.** JSON-envelope только на handshake
   POST + cover.
4. **nginx обязателен** — Go `net/http` шлёт non-browser HTTP/2 SETTINGS (JA3-риск).
5. **Серверный бинарь — единственная копия** `bin/shadowlink-server-linux` здесь.
   Вторая копия однажды дала silent «binary identical, skipping upload».
6. **Windows-dev: `-race` недоступен** (нет gcc). Зелёный локальный прогон ≠ нет гонки.
7. **Коммиты и push делает пользователь.** Не коммитить без явной просьбы.
8. Тайминговые константы — производные от TSPU age-окна ~130–190 с; не менять «на глаз».

## Architecture

```
App → SOCKS5 → Client → uTLS (Chrome 133) → direct origin IP :443
    → nginx (TLS term) → unix socket → Server → Internet
```
Routing (`server/handler.go`): `POST`+`application/json` → VPN-сессия ·
`Upgrade: websocket` → WS transport · всё прочее → decoy SPA.

Crypto: X25519 ECDH → HKDF-SHA256 → AES-256-GCM, forward secrecy, replay
protection. Стеганография на HTTP-уровне, не TLS-уровне.

## Packages

| Package | Purpose |
|---|---|
| `core/` | Crypto, session manager, слоты/миграция, flow control, jitter |
| `server/` | HTTP handler, tunnels, mux, decoy, rate limiter, auth, metrics, management |
| `client/` | DirectTransport, ConnManager, leakguard, dnsproxy (split-DNS), bypassroute |
| `proxy/` | SOCKS5 (+ UDP associate) |
| `skins/browser/` | Mimicry engine — inflation, shaping, cover, fingerprint registry |
| `cmd/shadowlink-server/` | Server entry + `export-client-config` |
| `cmd/nixavpn-client/` | Unified client CLI (ShadowLink + VLESS), tun2socks, tunnel.go |
| `testutil/`, `tools/` | Хелперы · утилиты |

## Dev commands

```bash
go test ./... -count=1          # Windows: без -race
go build ./... && go vet ./...
bash build-server.sh           # → bin/shadowlink-server-linux
bash build-client.sh           # → $CLIENT_BIN_DIR (default /d/NIXAVPN/bin)
```

## Triggers → load skills

| Задача | Skill |
|---|---|
| FP/uTLS, decoy, cover, wire-формат, «а если через CDN» | `mimicry-model` |
| Ротация слотов, drain, тайминги, `SHADOWLINK_*` флаги, cold start | `anti-tspu-tuning` |
| Сборка, деплой, nginx, systemd, server CLI, connection failures | `deployment` |
| Написание/отладка тестов, `-race`, fuzz, флейки под `-shuffle` | `testing-rules` |

## Isolation rules

- Весь ShadowLink-код — в этом репозитории. Docs/specs — `docs/`. Тесты
  colocated (`*_test.go`).
- В дерево NixaVPN идут только integration points (deploy orchestrator, config
  assembler, admin handlers). Путь резолвится через `internal/slpath` / env
  **`SHADOWLINK_DIR`** — хардкода пути быть не должно.

## Key docs

- `docs/PHASES-CHANGELOG.md` — летопись фаз/аудитов; читать при откате фичи
- `docs/protocols/` — `body-prefix-v1`, `flow-control-v2`, `live-decoy`
- `docs/strategy/2026-05-03-final-audit/MASTER.md` — последний полный аудит

## Planned work

1. **Embedded tun2socks** — сейчас внешний бинарь, встроить как Go-пакет.
2. **NixaVPN integration** — deploy orchestrator, config assembler, admin handlers.
3. **18-й раунд аудита** — многотрековый, с web-research (запрошен 2026-07-25).
