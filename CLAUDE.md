# ShadowLink Protocol — Reference

Steganographic VPN. Go 1.25, `module github.com/nixavpn/shadowlink`. Отдельный
проект (`D:\shadowlink`) со своим go.mod и git — **вне дерева NixaVPN**.
Противник — **TSPU** (DPI РКН); из этого растут все архитектурные решения.

## Hard rules

1. **НЕ предлагать CDN / Cloudflare / domain fronting.** Прод = DIRECT к голому
   origin IP. ⚠ Обоснование уточнено 2026-08-07: прежнее «РКН режет диапазоны CDN
   целиком» — форумное, peer-reviewed подтверждения нет. Более сильный довод —
   ACM IMC 2022: ТСПУ стоит **inline на краю каждого ISP**, а не на IX, поэтому
   природа origin не меняет того, что решение принимается на первом хопе от
   абонента. Domain fronting отдельно мёртв с 2018 — крупные CDN его отключили.
2. **НЕ рандомизировать TLS fingerprint.** Только Chrome. Рандомный FP уникален,
   а уникальность и есть сигнал — это довод самодостаточный, замера не требует.
   ⚠ Тезис «Firefox/Safari РКН банит первыми» — форумный и **оспорен**
   (Xray-core#6293, 2026-06: обратная рекомендация); не считать доказанным.
   ⚠ Chrome 133 — это **потолок uTLS**, а не выбор: профилей выше в библиотеке
   нет. Значит отпечаток неизбежно дрейфует относительно живого Chrome. Починить
   выбором версии нельзя; ранний сигнал — доля Chrome 133 в реальном трафике.
3. **Горячий путь = WebSocket binary frames.** JSON-envelope только на handshake
   POST + cover.
4. **nginx обязателен** — Go `net/http` шлёт non-browser HTTP/2 SETTINGS (JA3-риск).
5. **Серверный бинарь — единственная копия** `bin/shadowlink-server-linux` здесь.
   Вторая копия однажды дала silent «binary identical, skipping upload».
6. **Windows-dev: `-race` недоступен** (нет gcc). Зелёный локальный прогон ≠ нет гонки.
7. **Коммиты и push делает пользователь.** Не коммитить без явной просьбы.
8. Тайминговые константы — не менять «на глаз». ⚠ Окно ~130–190 с **НЕ
   подтверждено** и, по замеру 2026-08-07, **неверно**: наблюдаемое окно на
   рабочем AS — **84–118 с** (p10 84.1 / p50 97.6 / p90 118.0, n=222). Ось реза —
   **возраст**: CV 0.26 против 8.73 по байтам (в 33 раза плотнее); умирают и
   слоты с 0 КБ, поэтому триггер по объёму из net4people#490 на этом AS **не
   воспроизводится**. ⚠ И **глобальная константа неверна в принципе**:
   ACM IMC 2022 — ТСПУ неоднородна по регионам и операторам. Курс — адаптация
   per-AS на клиенте (`client/slotobs`).
   **Считать бюджет только через `WSPoolTransport.worstCaseTeardown()`.** Он
   складывает `base + stagger + sweep + teardown_cap`. До 2026-08-07 лог считал
   `base + sticky` и врал в 1.6 раза: выпадал `staggerOffsetCap` (до +48 с), из-за
   чего 8 ячеек из 16 имели порог ротации 114 с при p10 смертей 84 с и физически
   не доживали до собственной ротации. Никогда не складывать слагаемые по месту.
   ⚠ Выборка `slotobs` **цензурирована**: `Record` вызывается только на ошибке
   чтения (`ws_pool.go`), плановые ротации в неё не попадают. Поэтому доля
   «срезано посредником» из `by_close_kind` не выводится, а p10 смещён вверх.

## Architecture

```
App → SOCKS5 → Client → uTLS (Chrome 133) → direct origin IP :443
    → nginx (TLS term) → 127.0.0.1:10443 → Server → Internet
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
bash build-client.sh           # → $CLIENT_BIN_DIR (default ./bin = D:\shadowlink\bin)
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
