# ShadowLink Bypass Routing + Cold-Start Cascade — Design

**Дата:** 2026-05-02
**Кодовая фраза для возврата:** "bypass routing + cold-start rate-limit"
**Драйвер:** field test 2026-05-02 14:05 на pl1 (datacanvases.com) после wire-trigger
followup. См. memory `resume-bypass-and-coldstart.md`.

## 1. Мотивация

Полевое испытание production-клиента после `wire-trigger-followup-done` обнаружило
две взаимосвязанные проблемы UX:

1. **Bypass .ru routing не работает** — все запросы россиян к домашним сайтам
   (mail.ru, vk.com, yandex.ru, и т.д.) идут через VPS. Лишний трафик
   (~50-70% bandwidth) + жирный DPI sample на VPS → cluster analysis может
   выделить наш ShadowLink-узел из общего фона.

2. **Cold-start cascade** — 8 параллельных WS upgrades в первые ~2.5 секунды
   после connect триггерят server-side per-IP rate-limit (`WSUpgrade = 30/min`).
   Server возвращает декой HTML вместо handshake response. Клиент трактует это
   как handshake fail и реконнектит, зацикливая каскад. Юзер ощущает: "первые
   30 секунд VPN ничего не работает". В одном field-test 7 из 8 slots мертвы,
   только slot 2 несёт весь трафик 37+ concurrent streams.

Обе проблемы критические для production UX. Закрываем одной spec'ой.

## 2. Цели и не-цели

### Цели

- Возврат российского трафика на физический интерфейс (split routing) без
  потери совместимости с tun2socks system VPN режимом.
- Time-to-first-stream после connect: **p95 < 2 секунд** (сейчас: 30+ секунд
  при cascade), **p50 < 800ms**.
- All 6 slots в WSReadyPool ready в течение **5 секунд** после connect (сейчас:
  непредсказуемо, иногда никогда).
- Server burst-cap который держит scanners-protection, но не валит cold start
  легитимного клиента.
- Admin-управляемый список bypass CIDR через панель NixaVPN.
- Reference Grafana board + alert rules как deliverable (production scrape
  integration — explicit follow-up).

### Не-цели

- IPv6 bypass (LeakGuard на клиенте отключает IPv6 entirely).
- DNS-based bypass (ломается на DoH/DoT, не покрывает hardcoded IPs). Static
  CIDR + dial-hook покрывает всё.
- Aggregation supernet'ов /11-/12 (захватывает чужие IP — теряет precision).
- Production Prometheus scrape infrastructure (ops session отдельно).
- Tier S R.3 server-side resilience (frame anomaly classifier — уже сделан,
  не повторяем). См. memory `resume-shadowlink-tier-s-resilience.md`.

## 3. Архитектура — общая

5 phases, каждая дискретна по слою. Plan по этой spec'и subagent-driven с
параллельной работой по A-D, E финализирующая (зависит от counters wired
через все предыдущие phases).

```
                        ┌─ Phase A (client) ────────────────────────────┐
                        │ shadowlink/client/bypassroute/                │
NixaVPN system VPN flow │  - Trie (radix IPv4 CIDR)                     │
                        │  - Embedded snapshot (build-time gen RIPE)    │
                        │  - BypassDialer wraps proxy.Dialer            │
                        │  - Wired in cmd/nixavpn-client/tunnel.go      │
                        └────────────┬──────────────────────────────────┘
                                     │
                                     ▼ (Phase B merges into Trie at boot)
                        ┌─ Phase B (fullstack) ─────────────────────────┐
                        │ migration 071_shadowlink_bypass_cidrs         │
                        │ /api/admin/shadowlink/bypass-cidrs            │
                        │ Frontend ShadowLinkPage tab                   │
                        │ /api/v1/client/shadowlink/bypass (ETag)       │
                        │ Client merge logic + persistent local cache   │
                        └───────────────────────────────────────────────┘

                        ┌─ Phase C (server) ────────────────────────────┐
                        │ Token-bucket RateLimiter v2:                  │
                        │   - WSUpgrade: burst=18, refill=30/min        │
                        │   - Handshake: burst=50, refill=300/min       │
                        │ Per-clientID exemption on handshake POST:     │
                        │   - LRU 10k, TTL 1h                           │
                        │   - Soft-limit 60/min для known clientID      │
                        └───────────────────────────────────────────────┘

                        ┌─ Phase D (client) ────────────────────────────┐
                        │ WSReadyPool phased warmup:                    │
                        │   slot 0 → immediately                        │
                        │   slots 1-2 → +800ms                          │
                        │   slots 3-5 → +2400ms                         │
                        │ Default Size 8 → 6 across all configs         │
                        │ R.5 SOCKS5 dispatch debounce 50ms             │
                        │ MaxParallelHandshakes=2 semaphore             │
                        └───────────────────────────────────────────────┘

                        ┌─ Phase E (ops, reduced) ──────────────────────┐
                        │ Counters in stats.go + metrics.go             │
                        │ shadowlink-metrics-dump CLI helper            │
                        │ Reference docs/grafana/cold-start-bypass.json │
                        │ Reference docs/alerts/cold-start.yaml         │
                        └───────────────────────────────────────────────┘
```

## 4. Design decisions (rationale)

### 4.1 Bypass через in-process Trie + dialer hook (а не system routes / DNS)

**Решение:** Bypass решается полностью in-process: радикс-trie IPv4 CIDR в
памяти + custom `proxy.Dialer` который проверяет dst IP до того как передать
в SOCKS5. tun2socks v2 публикует `tunnel.T().SetDialer(d)` — это естественный
hook point.

**Почему не system routes** (изначальный план в resume note):

- 6000-8000 RIPE RU CIDR в Windows route table = ~50ms на `route add` × 6000
  = **5 минут до connect**. Linux немного быстрее, но всё равно секунды.
- Routes leak при крэше клиента → требует idempotent cleanup на старте.
- Routes конфликтуют с TUN split-route (`0.0.0.0/1` + `128.0.0.0/1`) — нужно
  выставлять metric vorrang на Windows.

**Почему не DNS-based bypass** (расширенный dnsrouter, который уже существует
в `client/dnsrouter/`):

- Ломается на DoH/DoT, IDN, hardcoded IPs.
- Требует перехвата системного DNS (Windows: меняем DNS на adapter).
- Не покрывает приложения с собственным DNS (browser DoH, mobile apps).

**Почему dialer hook работает универсально:**

- Каждый dial из tun2socks engine идёт через `proxy.Dialer.DialContext(ctx, metadata)`.
- `metadata.DstIP` — pre-resolved, IP-level. Работает с любым DNS upstream.
- При match в Trie — направляем dial через `proxy.NewDirect()` (встроенный
  в tun2socks: dials через physical interface bypass'ая TUN).
- При miss — направляем через существующий `proxy.NewSocks5(socksAddr, user, pass)`
  → ShadowLink VPN.
- Cold start: `Trie.Load()` + `tunnel.T().SetDialer(bypass)` ~10-50ms.

`dnsrouter` (`client/dnsrouter/`) **остаётся как есть** для shadowlink-client
(dev/standalone клиент использует его). Production client `cmd/nixavpn-client/`
переходит на dialer hook. Никаких удалений `dnsrouter`.

### 4.2 Embedded baseline + admin override (а не runtime fetch infrastructure)

Embedded snapshot RIPE delegated stats (`delegated-ripencc-extended-latest`)
покрывает ~99% живой картины RU IP space (RIR-level префиксы). Регенерируется
build-time скриптом в `tools/cidr-snapshot/`. Юзер-уровневое управление —
через NixaVPN admin: добавить/удалить отдельные CIDR (например для нового
российского хостинга, который ещё не в RIPE registry, или для whitelisted
зарубежного IP).

Client тянет admin-overrides через отдельный endpoint
`/api/v1/client/shadowlink/bypass?etag=<sha256>` с ETag-семантикой (304 Not
Modified при совпадении). Endpoint в `/api/v1/client/shadowlink/*` namespace
рядом с уже существующим `/config` (Domain Diversity Sub-phase C). Отдельно
от `/config` потому что bypass-overrides могут быть большими (десятки KB
через год накопления admin entries) — не хотим тянуть их на каждый /config
refresh.

Persistent cache на клиенте: `~/.nixavpn/bypass-overrides.bin` подписан HMAC
от server static key. На старте проверяем валидность подписи; невалидный кэш
игнорируется и идём только с embedded.

### 4.3 Server rate-limit: burst-cap + per-clientID на handshake

Текущая проблема: `WSUpgrade` лимит 30/min per-IP — слишком жёсткий для cold
start (8 slots в первые 2.5s = 60+/min).

Per-clientID exemption на WS upgrade физически невозможен: после Phase A
(2026-04-26) WS первый frame несёт auth → до first-frame сервер не знает
clientID. Нельзя exempt'нуть upgrade.

**Гибрид:**

- **Token bucket per-IP на WSUpgrade**: burst 18 (= 1.5x slot count для
  margin), refill rate 30/min. Cold start укладывается в burst (даже при
  full reconnect cascade in 30 sec).
- **Token bucket per-IP на handshake POST**: burst 50, refill 300/min.
- **Per-clientID exemption на handshake POST**: после успешного handshake
  сервер заносит clientID в LRU 10k entries TTL 1h. Дальнейшие handshake
  запросы от того же clientID — soft-limit 60/min независимо от burst-bucket
  (защищает от scanner который stole clientID, но не блокирует legitimate
  reconnect).

Sentinel header `X-SL-RL` (введён в May audit P0 §A2) расширяется метаданными
о буферах: `bucket=ws_upgrade,burst_left=4,refill_in=23s` — для diagnostic
purposes (тоже идёт через failClosedToDecoy под TLS, не leakable).

### 4.4 Client slow-start (фазированный warmup) вместо linear stagger

Текущий `WSReadyPool.worker(idx)` использует linear stagger 300ms × idx.
Это значит slot 0: 0ms, slot 7: 2.1s — 8 upgrade'ов в первые 2.5 секунды.
60+/min effective rate — превышает burst после Phase C тоже.

**Phased warmup:**

| Phase | Slots | Start time | Действие |
|-------|-------|------------|----------|
| 0 | slot 0 | 0ms | immediate; ждём slot 0 ready (handshake + first-frame) |
| 1 | slots 1-2 | +800ms | стартуют только после slot 0 success |
| 2 | slots 3-5 | +2400ms | стартуют только после slot 1-2 success |

Если фаза 0 не доходит до ready — фазы 1+2 не стартуют, retry slot 0 с backoff.
Если phase 1 fails — retry phase 1 с backoff, не обрушивая phase 2.

Преимущества:
- Cold-start профиль: 1 ready slot за ~700ms (handshake + WS upgrade), 3
  ready slots за ~1.5s, 6 ready slots за ~3.5s.
- Под server burst-cap (18) с большим запасом.
- При реальном handshake fail на edge (CF cold) — backoff на phase 0 не
  тратит burst tokens на phases 1+2.

Default `Size = 8` → `Size = 6`. Уменьшает burst даже без slow-start. 6 ready
slot достаточно для page-load с 6-8 параллельных browser conns (HTTP/2
multiplex одной браузерной соединение покрывает большинство).

### 4.5 R.5 SOCKS5 dispatch coalesce (50ms debounce)

При page-load браузер открывает 6-8 SOCKS5 CONNECT почти одновременно. Если
WSReadyPool частично заполнен (3/6), то 3 первых получают instant slots, а
остальные 3-5 ждут пока pool восполнится. Без coalesce'а 5 одновременных
`WSReadyPool.Acquire()` форсят 5 одновременных WS upgrades.

**R.5:** SOCKS5 dispatcher (`proxy/socks5/tcp.go`) при receiving CONNECT
debounce'ит на 50ms окно — если в окне ≥3 CONNECT, держит их в очереди
до конца окна. Pool за 50ms успевает refill 1-2 slot, и burst on upgrade
ниже.

Работает не на всю производительность (тестовый run page-load всё равно
блокируется), но снижает peak burst.

**Дополнительный дроссель:** `MaxParallelHandshakes = 2` semaphore — одновременно
не более 2 WS upgrade в полёте. Reconnect storm под throttle gracefully
serializes upgrades.

### 4.6 Phase E: reduced scope с explicit follow-up

`shadowlink/server/metrics.go` и `client/stats.go` — hand-rolled atomic counters
+ text exposition. **Не переходим на `prometheus/client_golang`** в этой
spec — это infrastructural change, требует ops session.

Phase E deliverables:

- Новые counters во всех phases (Trie matches, burst-cap consumed, slot
  warmup ms histogram буфер, decoy received counter, etc.).
- `cmd/shadowlink-metrics-dump` — CLI helper пинит /metrics endpoint и
  выводит pretty snapshot.
- `docs/grafana/cold-start-bypass-board.json` — reference Grafana board
  template (дашборд готов, но требует ops setup для production scrape).
- `docs/alerts/cold-start.yaml` — reference Prometheus alert rules.

**Explicit follow-up** (отдельная spec/session):
- prometheus/client_golang integration.
- Production scrape config + Grafana instance.
- Operationalize alerts (PagerDuty / Telegram).

## 5. Phase A — Bypass Routing (in-process trie + dialer hook)

### 5.1 Package structure

Новый пакет `shadowlink/client/bypassroute/`:

```
bypassroute/
├── trie.go              # Radix IPv4 CIDR trie
├── trie_test.go
├── embedded.go          # GENERATED — embedded RIPE snapshot (~6-8k entries)
├── embedded_test.go
├── loader.go            # Load embedded + merge admin overrides
├── loader_test.go
├── dialer.go            # BypassDialer wraps proxy.Dialer
├── dialer_test.go
└── REFRESH.md           # Procedure для обновления embedded snapshot
```

### 5.2 Trie API

```go
package bypassroute

// Trie is a radix tree of IPv4 CIDR prefixes. Lookups O(32) for any v4 IP.
// Concurrent reads are lock-free via copy-on-write semantics on Insert.
type Trie struct {
    root *node
}

func New() *Trie

// Insert adds a CIDR to the trie. Idempotent. Not safe for concurrent
// callers — Build the full trie at startup, then publish a *Trie pointer
// to the dialer.
func (t *Trie) Insert(cidr netip.Prefix)

// Match returns true if ip is covered by any inserted prefix.
func (t *Trie) Match(ip netip.Addr) bool

// Size returns number of inserted prefixes (not nodes).
func (t *Trie) Size() int
```

Реализация: standard radix tree, child[2] per node, leaf flag. Отказ от
`net/netip` нет — uses `netip.Addr` / `netip.Prefix` для zero-alloc match.

### 5.3 Embedded snapshot generator

`tools/cidr-snapshot/main.go` — CLI tool:

```bash
cd D:/NIXAVPN/shadowlink
go run ./tools/cidr-snapshot/ \
    --source https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest \
    --country RU \
    --out client/bypassroute/embedded.go
```

Tool:
1. Скачивает delegated stats (or reads --in <path> для offline build).
2. Парсит `ripencc|RU|ipv4|<start>|<count>|<date>|allocated` строки.
3. Конвертирует start+count в CIDR (count может быть не степень 2 → multiple
   CIDR, через `cidr-ranger`-стиль алгоритм). Опционально применяет cidr-merge
   для дальнейшей aggregation.
4. Эмитит Go file:

```go
// Code generated by tools/cidr-snapshot. DO NOT EDIT.
// Source: https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
// Generated: 2026-05-02T15:00:00Z
// Entries: 6824 (after merge)

package bypassroute

import "github.com/nixavpn/shadowlink/client/bypassroute/internal/cidrblob"

//go:embed embedded_ru.bin
var embeddedRU []byte

func loadEmbedded() ([]netip.Prefix, error) {
    return cidrblob.Decode(embeddedRU)
}
```

Фактический blob в binary format (4 bytes IP + 1 byte prefix = 5 bytes per
entry, ~35 KB total) — не Go literal (медленный compile).

### 5.4 Loader

```go
type Source struct {
    Embedded bool          // load embedded snapshot
    Override []netip.Prefix // admin-provided override (Phase B)
    Local    []netip.Prefix // user local file (future, not in this spec)
}

// Load builds a Trie from sources. Embedded baseline + override are merged
// (override CAN add OR exclude — Override entries with negative tag remove).
func Load(src Source) (*Trie, error)
```

### 5.5 BypassDialer

```go
package bypassroute

import (
    "context"
    "net"
    "github.com/xjasonlyu/tun2socks/v2/proxy"
    M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

type BypassDialer struct {
    inner  proxy.Dialer  // SOCKS5 to ShadowLink (default behavior)
    direct proxy.Dialer  // proxy.NewDirect() — physical interface
    trie   *Trie
    // metrics callbacks
    onMatch func()
    onMiss  func()
}

func NewBypassDialer(socksDialer proxy.Dialer, trie *Trie) *BypassDialer

func (d *BypassDialer) DialContext(ctx context.Context, m *M.Metadata) (net.Conn, error) {
    if d.shouldBypass(m) {
        if d.onMatch != nil { d.onMatch() }
        return d.direct.DialContext(ctx, m)
    }
    if d.onMiss != nil { d.onMiss() }
    return d.inner.DialContext(ctx, m)
}

func (d *BypassDialer) DialUDP(m *M.Metadata) (net.PacketConn, error) {
    if d.shouldBypass(m) {
        return d.direct.DialUDP(m)
    }
    return d.inner.DialUDP(m)
}

func (d *BypassDialer) shouldBypass(m *M.Metadata) bool {
    if m == nil { return false }
    addr := m.DstIP // tun2socks metadata.DstIP is netip.Addr in v2.6+
    if !addr.IsValid() || !addr.Is4() { return false } // IPv6: skip (LeakGuard disables v6)
    return d.trie.Match(addr)
}
```

### 5.6 Wiring в `cmd/nixavpn-client/tunnel.go`

После `engine.Start()` и до `setupRoutes`:

```go
// 1. Load bypass trie from embedded + admin override (cached locally).
trie, err := bypassroute.Load(bypassroute.Source{
    Embedded: true,
    Override: t.bypassOverride, // populated during connect from admin endpoint
})
if err != nil {
    slog.Warn("bypass trie load failed, continuing without bypass", "err", err)
} else {
    // 2. Build SOCKS5 dialer (the "inner") using same params engine uses.
    socks, err := proxy.NewSocks5(t.socksAddr, t.proxyUser, t.proxyPass)
    if err != nil {
        return fmt.Errorf("build SOCKS5 dialer for bypass: %w", err)
    }
    // 3. Wrap and install.
    bypass := bypassroute.NewBypassDialer(socks, trie)
    bypass.WithMetrics(stats.IncBypassMatch, stats.IncBypassMiss)
    tunnel.T().SetDialer(bypass)
    slog.Info("bypass routing активирован", "cidr_count", trie.Size())
}
```

### 5.7 Edge cases & gotchas

- **DstIP IPv4-mapped-v6** (`::ffff:1.2.3.4`): `addr.Unmap()` перед Match.
  В trie добавлено в `shouldBypass` через `addr.Is4()` check; v6-mapped
  unmaps to v4 via `Unmap()`.
- **DstIP private (RFC1918)**: НЕ bypass'аем — может conflict с ShadowLink
  control plane. Trie embedded НЕ содержит RFC1918 (RIPE filters эти blocks).
- **Loopback / link-local**: НЕ bypass'аем (опять-таки они не в trie).
- **Admin override содержит non-RU range** (например whitelisted CDN IP):
  допускаем — override merge'ится в trie напрямую.

### 5.8 Tests

- `trie_test.go`: insert/match basic, edge cases (`/32`, `/0`, прилегающие
  CIDR, longest-prefix-match), 10k random insert+lookup benchmark.
- `embedded_test.go`: load embedded, verify size > 5000, sample known RU IPs
  match (e.g. `213.180.193.0` Yandex, `87.250.250.0` mail.ru), sample known
  non-RU IPs miss (`1.1.1.1`, `8.8.8.8`, `13.107.0.0` MS).
- `dialer_test.go`: mock Dialer pair, assert routing decision matches trie
  state.
- Property test: random metadata generation, assert `BypassDialer` returns
  consistent direct/inner choice based on trie membership.

## 6. Phase B — Admin Override Fullstack

### 6.1 DB migration (NixaVPN, не shadowlink module)

`migrations/071_shadowlink_bypass_cidrs.sql`:

```sql
CREATE TABLE shadowlink_bypass_cidrs (
    id SERIAL PRIMARY KEY,
    cidr CIDR NOT NULL,
    -- 'add' = treat as RU; 'exclude' = explicit non-bypass even if embedded matches
    action TEXT NOT NULL CHECK (action IN ('add', 'exclude')),
    comment TEXT NOT NULL DEFAULT '',
    server_id INTEGER REFERENCES servers(id) ON DELETE CASCADE, -- NULL = global
    created_by_admin_id INTEGER REFERENCES admin_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ NULL,
    CONSTRAINT shadowlink_bypass_cidrs_uniq UNIQUE (cidr, server_id, action)
);

CREATE INDEX idx_shadowlink_bypass_cidrs_server ON shadowlink_bypass_cidrs(server_id, deleted_at);
CREATE INDEX idx_shadowlink_bypass_cidrs_action ON shadowlink_bypass_cidrs(action, deleted_at);
```

### 6.2 Backend admin handlers

`internal/admin/shadowlink_bypass.go`:

```go
// GET    /api/admin/shadowlink/bypass-cidrs?server_id=<id|global>
// POST   /api/admin/shadowlink/bypass-cidrs
// DELETE /api/admin/shadowlink/bypass-cidrs/:id
// PATCH  /api/admin/shadowlink/bypass-cidrs/:id  (update comment / action)
```

POST body:
```json
{ "cidr": "1.2.3.0/24", "action": "add", "comment": "...", "server_id": 42 }
```

Validators:
- CIDR parse + IPv4 only.
- Refuse RFC1918 / loopback.
- `action` ∈ {`add`, `exclude`}.

Все запросы под `AuthMiddleware + AdminMiddleware`. Audit log entry на каждое
изменение через существующий `internal/admin/audit.go`.

### 6.3 Frontend

Новая вкладка в `frontend/src/pages/ShadowLinkPage.tsx`:
- "Bypass CIDRs" таб.
- Table: cidr / action / comment / server (или Global) / created_at / created_by / actions.
- Add Wizard: input CIDR, action select, comment textarea, server scope select.
- Bulk actions: import .txt list (one CIDR per line), export.

API wrapper в `frontend/src/api/shadowlinkBypass.ts`. Type definitions в
`frontend/src/types/shadowlinkBypass.ts`.

### 6.4 Client API endpoint

`internal/client/shadowlink_bypass.go`:

```go
// GET /api/v1/client/shadowlink/bypass?etag=<sha256>
// 200 with body { etag, action, cidrs: [...] }  if etag mismatch
// 304 Not Modified                              if etag match
// Server scope is implicit from authenticated client's server assignment.
// Global rules merged with server-specific rules.
```

Client signature: response signed via HMAC-SHA256(server_static_key, body).
Header `X-Bypass-Signature: <hex>`. Client verifies before using.

### 6.5 Client merge logic

В `client/bypassroute/loader.go`:

```go
type AdminOverride struct {
    Etag    string
    Adds    []netip.Prefix
    Excludes []netip.Prefix
}

func (l *Loader) FetchAndCacheOverride(ctx context.Context, apiURL, token string) (*AdminOverride, error)

func (l *Loader) LoadCachedOverride(cacheDir string, hmacKey []byte) (*AdminOverride, error)
func (l *Loader) PersistOverride(cacheDir string, ov *AdminOverride, hmacKey []byte) error
```

При connect:
1. Try fetch from server (timeout 3s).
2. On success: persist to cache, use as override.
3. On fail: load cached (verify HMAC), use as override.
4. On both fail: continue with embedded only.

`Trie.LoadFromMerged(embedded, override)`:
- Insert all embedded.
- For each `add` in override: insert.
- For each `exclude` in override: tag node with exclude flag (Match returns
  false despite covered prefix).

Cache file: `~/.nixavpn/bypass-overrides.bin` (или Windows AppData).

### 6.6 Tests

- DB migration roundtrip.
- Admin handler CRUD with permissions check.
- Audit log entries on create/delete.
- Client fetch happy path + ETag 304 path.
- HMAC verification: tamper detection.
- Cache fallback on fetch failure.
- Trie merge with `exclude` semantics.

## 7. Phase C — Server Burst-Cap + Per-clientID Exemption

### 7.1 RateLimiter v2

Текущий `server/ratelimit.go` — sliding window per-IP. Нужно:

```go
package server

// TokenBucket — per-IP token bucket. Refill at constant rate, capacity = burst.
type TokenBucket struct {
    burst   int
    refill  time.Duration // time per token
    mu      sync.Mutex
    state   map[string]*tbState
    maxIPs  int
}

type tbState struct {
    tokens float64
    last   time.Time
}

func NewTokenBucket(burst int, refillRate float64 /* tokens per second */, maxIPs int) *TokenBucket
func (tb *TokenBucket) Allow(ip string) (allowed bool, remaining int, retryAfter time.Duration)
```

Replace `RateLimiter.Allow(ip)` → returns boolean still. Add new `AllowVerbose`
для X-SL-RL header info. Backwards-compat shim для existing callers через
old `RateLimiter` тип (delegated to `TokenBucket`).

Default config (in `RateLimiters`):

| Limiter | Burst | Refill | Effective rate |
|---------|-------|--------|----------------|
| WSUpgrade | 18 | 30/min | up to 18 burst, sustained 30/min |
| Handshake | 50 | 300/min | up to 50 burst, sustained 300/min |
| Data | 100 | 600/min | unchanged total budget |

`shadowlink_handlers.go` (NixaVPN-side YAML config) расширяется полями:

```yaml
rate_limit:
  ws_upgrade:
    burst: 18
    refill_per_min: 30
  handshake:
    burst: 50
    refill_per_min: 300
  client_id_lru_size: 10000
  client_id_ttl_min: 60
```

### 7.2 Per-clientID exemption на handshake POST

```go
type ClientIDExemption struct {
    cache *lru.Cache[string, time.Time]
    ttl   time.Duration
    softLimit int  // requests/min
    softWindow time.Duration

    softCounters sync.Map // clientID → *softCounter
}

// MarkSeen — после успешного handshake, mark clientID as exempt.
func (e *ClientIDExemption) MarkSeen(clientID []byte)

// Allow — при handshake POST с известным clientID, check soft-limit.
// If clientID unknown: fallthrough to bucket.Allow(ip).
func (e *ClientIDExemption) Allow(clientID []byte) bool
```

Wired in `server/handler.go::handleHandshakeNew`:

```go
// Existing: bucket per-IP check
if !rls.Handshake.Allow(ip) {
    failClosedToDecoy(w, r, "rate-limit handshake")
    return
}

// NEW: parse clientID early for exemption check
clientID, _ := parseClientIDFromHandshakePayload(body)

// If clientID known → check soft-limit and skip bucket.
if exemption.Allow(clientID) {
    // proceed
} else if !rls.Handshake.AllowVerbose(ip).allowed {
    failClosedToDecoy(...)
    return
}

// ... actual handshake processing ...

// On success:
exemption.MarkSeen(clientID)
```

### 7.3 X-SL-RL header extension

`writeRateLimitSentinel(w, info)` (existing) расширяется:

```
X-SL-RL: bucket=ws_upgrade,burst_left=4,refill_in=23s
X-SL-RL: bucket=handshake,burst_left=12,refill_in=8s,exempt=0
X-SL-RL: bucket=handshake,exempt=1
```

Sent inside `failClosedToDecoy` body — encrypted under TLS, не видно DPI.
Existing test `ratelimit_sentinel_test.go` расширяется на новые поля.

### 7.4 Tests

- TokenBucket: unit tests (burst, refill, single IP under sustained load).
- Map cap (10k entries) + LRU eviction.
- Concurrent Allow от 100 goroutines: no race, no overflow.
- Exemption: known clientID не консумит bucket tokens.
- Exemption soft-limit: 60 hits → 61st rejected.
- Sentinel header content для both buckets.

## 8. Phase D — Client Slow-Start + R.5 Coalesce

### 8.1 WSReadyPool phased warmup

Изменения в `client/ws_ready_pool.go`:

```go
type WSReadyPoolConfig struct {
    // ... existing fields ...

    // Warmup describes how slots come up. Empty = fall back to legacy
    // linear stagger of StaggerDelay × idx.
    Warmup []WarmupPhase
}

type WarmupPhase struct {
    Slots       []int         // slot indices in this phase
    Delay       time.Duration // delay AFTER previous phase succeeds
    RequireDone bool          // если true: phase blocks until ALL Slots ready
}

// Default warmup for size=6:
//   phase 0: [0],         delay=0,        RequireDone=true
//   phase 1: [1,2],       delay=800ms,    RequireDone=true
//   phase 2: [3,4,5],     delay=1600ms,   RequireDone=false
```

Worker logic: вместо `time.After(idx * stagger)`, координируется через
`phaseCoordinator`:

```go
type phaseCoordinator struct {
    phases []WarmupPhase
    done   []chan struct{} // done[i] closed когда phase i complete
}
```

`worker(idx)`:
1. Find which phase owns this slot.
2. Wait on `done[phase-1]` (если phase > 0).
3. Wait `delay` after that.
4. Begin upgrade attempts (с existing backoff).
5. On success: mark slot ready, contribute to phase done counter.
6. If `RequireDone` для этой phase: phase done только когда ALL slots в ней
   ready. Otherwise: phase done сразу после первого ready slot in this phase.

### 8.2 Default Size 8 → 6

Сейчас:
- `WSReadyPoolConfig.Size = 0` дефолтит на 6 (`ws_ready_pool.go:118-124`).
- В production вызовах конкретно может быть `Size = 8` — нужно искать.

```bash
grep -rn "WSReadyPoolConfig\|ReadyPool.*Size\b" D:/NIXAVPN/shadowlink/cmd/ D:/NIXAVPN/shadowlink/client/
```

Все callers: установить `Size: 6` или удалить explicit Size (полагаться на
дефолт). Дополнительно в `cmd/nixavpn-client/config.go` — если есть YAML
override, фиксируем дефолт 6.

### 8.3 R.5 SOCKS5 dispatch coalesce

В `proxy/socks5/tcp.go::handleConnect` (или wherever Acquire is called):

```go
type CoalescingDispatcher struct {
    pool   *WSReadyPool
    window time.Duration  // 50ms
    sem    chan struct{}  // MaxParallelHandshakes semaphore

    mu       sync.Mutex
    pending  []*pendingDispatch
    flushing bool
}

func (cd *CoalescingDispatcher) Acquire(ctx) (*WebSocketTransport, error)
```

Алгоритм:
1. Каждый Acquire попадает в очередь `pending`.
2. Если flushing уже идёт — блокируется на channel (in flush будет).
3. Если flushing нет:
   a. Запустить timer 50ms.
   b. До истечения timer'а: следующие Acquire join'ятся в pending.
   c. По истечении: flush(): для каждого in pending делаем `pool.Acquire()`.
4. Semaphore (`sem`) ограничивает одновременные WS upgrade в полёте до 2.

### 8.4 Tests

- Phased warmup: assert phase ordering, phase 1 не стартует до phase 0
  ready, retry policy на phase failure.
- Coalesce: 5 concurrent Acquire в окне 50ms group'аются in 1 flush.
- Semaphore: 10 simultaneous handshakes serialize до max 2 в полёте.
- Field equivalence: с `Warmup=nil` старый stagger behavior preserved (для
  обратной совместимости конфигов).

## 9. Phase E — Observability (reduced)

### 9.1 New counters

Client (`client/stats.go`):

```go
// Bypass routing
shadowlink_bypass_cidr_match_total       // counter, tagged by addr family
shadowlink_bypass_cidr_miss_total
shadowlink_bypass_admin_fetch_attempts_total{result}  // success|cached|fail
shadowlink_bypass_admin_override_size    // gauge

// Cold-start
shadowlink_first_stream_ms               // gauge (latest), histogram bucket counters
shadowlink_pool_warmup_ms                // gauge (until size=full)
shadowlink_pool_phase_ready_ms{phase}    // gauge per phase
shadowlink_handshake_decoy_received_total // hits = rate-limit reached
shadowlink_socks5_coalesce_grouped_total  // count of grouped CONNECTs
shadowlink_socks5_coalesce_groups_total   // count of flushes
```

Server (`server/metrics.go`):

```go
// Rate-limit v2
shadowlink_ratelimit_burst_consumed_total{path}    // path=ws_upgrade|handshake|data
shadowlink_ratelimit_burst_rejected_total{path}
shadowlink_ratelimit_clientid_exempted_total
shadowlink_ratelimit_clientid_softlimit_rejected_total
shadowlink_ratelimit_clientid_lru_evictions_total
```

### 9.2 shadowlink-metrics-dump CLI

`cmd/shadowlink-metrics-dump/main.go`:

```bash
$ shadowlink-metrics-dump --url https://datacanvases.com/metrics --auth $TOKEN

=== Server-side ===
Handshake bucket:    burst=42/50 (84%), refill_in=11s, exempted=234, softlimit_rejects=0
WS Upgrade bucket:   burst=14/18 (78%), refill_in=4s
ClientID LRU:        7421/10000 entries, evictions=12

=== Last 5min ===
ws_upgrade  rate: 24.3/min   burst_consumed: 4
handshake   rate: 287/min    burst_consumed: 51
```

### 9.3 Reference Grafana board

`shadowlink/docs/grafana/cold-start-bypass-board.json` — 16 панелей:

- Cold-start: first_stream_ms p50/p95/p99 over time, pool_warmup_ms histogram.
- Pool health: ready slot count gauge, slot reconnect attempts histogram,
  decoy_received counter.
- Bypass: match/miss ratio, admin fetch success rate, override size.
- Server: rate-limit burst consumption time series, clientID LRU size,
  exemption ratio.
- Anomalies: WS frame anomaly types histogram (existing from R.3a).

### 9.4 Reference alert rules

`shadowlink/docs/alerts/cold-start.yaml`:

```yaml
- alert: ShadowlinkColdStartSlow
  expr: histogram_quantile(0.95, shadowlink_first_stream_ms_bucket) > 5000
  for: 10m
- alert: ShadowlinkRateLimitCascade
  expr: rate(shadowlink_handshake_decoy_received_total[5m]) > 5
  for: 5m
- alert: ShadowlinkPoolStarved
  expr: shadowlink_pool_ready_count < 2
  for: 1m
```

Не deployable в текущей инфре (нет Prometheus scrape) — explicitly reference.

## 10. Migration & feature flags

| Phase | Feature flag | Default | Disable путь |
|-------|--------------|---------|--------------|
| A | `SHADOWLINK_BYPASS_ENABLED` | `1` (on) | `=0` skips bypass dialer install, falls back to plain SOCKS5 |
| B | `SHADOWLINK_ADMIN_OVERRIDE` | `1` (on) | `=0` skips fetch, embedded only |
| C | `SHADOWLINK_RL_TOKENBUCKET` | `1` (on, server) | `=0` falls back to legacy RateLimiter sliding window |
| C exempt | `SHADOWLINK_RL_CLIENTID_EXEMPT` | `1` (on, server) | `=0` skips exemption logic |
| D | `SHADOWLINK_PHASED_WARMUP` | `1` (on) | `=0` falls back to linear stagger |
| D coalesce | `SHADOWLINK_SOCKS5_COALESCE` | `1` (on) | `=0` direct Acquire |
| E | n/a (counters always emit, expose under existing /metrics) | — | — |

После 2 недель field stability — флаги retire'аются (default-on assumed).

## 11. Rollback per phase

- **Phase A:** revert `cmd/nixavpn-client/tunnel.go` SetDialer wrap, удалить
  `client/bypassroute/`. Embedded snapshot не используется без install — нет
  работающего state в проде.
- **Phase B:** migration 071 НЕ откатываем (data loss); admin endpoints
  возвращают 503; client endpoint возвращает empty list; client fallback to
  embedded.
- **Phase C:** flip `SHADOWLINK_RL_TOKENBUCKET=0` → fallback на старый
  RateLimiter. Per-clientID exemption auto-disabled (зависит от bucket).
- **Phase D:** flip `SHADOWLINK_PHASED_WARMUP=0` + `SHADOWLINK_SOCKS5_COALESCE=0`.
- **Phase E:** counters не имеют side effects, не нужно откатывать.

## 12. Open questions / explicit follow-ups

1. **Aggregation depth для embedded snapshot.** Default tool aggregation
  использует RIPE-prefixes как есть. Optional `--aggregate-min /24` параметр
  может уменьшить trie size (но накроет дополнительные IP). Эксперимент в
  Phase A с замерами (`Trie.Size()`, lookup time).

2. **Admin override — server-specific vs global semantics при конфликтах.**
  Если global добавляет `1.2.3.0/24` а server-specific exclude'ит `1.2.3.0/26`
  — что делает trie? Решение в spec'е: server-specific override > global. В
  тестах закрепляем.

3. **R.5 coalesce — 50ms окно или адаптивное?** Эмпирически 50ms — компромисс.
  В планах эксперимент: профилирование под page-load, если 50ms слишком короткий
  — расширить до 100ms.

4. **MaxParallelHandshakes = 2 vs adaptive?** Захардкожено 2 — закрывает
  cascade в общем случае. Адаптивный механизм (под throttle drop до 1) —
  follow-up, не в этой spec.

5. **prometheus/client_golang integration** — отдельная spec/session.
  Этот spec оставляет hand-rolled exporters и reference templates.

6. **Field test plan** — после implementation: 5 connect cycles на datacanvases.com,
  замерить first_stream_ms p95, decoy_received_total/min, time to 6/6 ready.
  Если KPI не выполнен → diagnostic before flip default-on.

## 13. References

- Resume: `MEMORY.md` → "bypass routing + cold-start rate-limit" / `resume-bypass-and-coldstart.md`.
- Tier S spec: `shadowlink/docs/strategy/2026-04-30-current-state-and-improvements.md`.
- Wire-trigger followup: `shadowlink/docs/audit/2026-05-02-wire-trigger-followup.md`.
- Legacy bypass memory: `shadowlink-bypass-routing.md` (DNS-based — superseded).
- Phase 0 (T1.4 default flip + Phase A bearer retire): `docs/superpowers/plans/2026-04-26-shadowlink-phase-0-debt-closure.md`.
- Phase 1 P1 helper extraction: `merge-or-regenerate-keys-extracted.md`.
- Domain Diversity (Sub-phase C `/shadowlink/config` endpoint, used by Phase B): `docs/superpowers/specs/2026-04-28-shadowlink-domain-diversity-design.md`.
- May audit: `docs/superpowers/plans/2026-05-01-may-audit-action-plan.md`, P0/P1/P2 closures.
- pl1 deploy: memory `pl1-canary-2026-05-02.md`, `feedback_pl1_manual_deploy.md` (юзер сам передеплоит).

## 14. Estimated scope

Тасков ~50-60. Время: 4-5 sessions субагент-driven. Зависимости между phases:

- A ⊥ C ⊥ D — independent (можно параллельно).
- B зависит от A (Loader merge logic).
- E зависит от A+B+C+D (counters wired через все).

Suggested execution order: stage 1 = A+C+D в parallel, stage 2 = B, stage 3 = E.

## 15. Success criteria (objective)

После full deploy на datacanvases.com:

- Bypass: на test resolve `vk.com`, `mail.ru`, `yandex.ru` traffic через
  physical interface (verify через WireShark capture and IP geolocation).
- Cold-start KPI:
  - `shadowlink_first_stream_ms` p95 < 2000ms over 24h
  - `shadowlink_pool_warmup_ms` (до 6/6 ready) p95 < 5000ms
  - `shadowlink_handshake_decoy_received_total` rate < 1/min sustained
- Bypass admin: добавление CIDR через UI, refresh через `client.shadowlink.config`,
  Trie reload не требует перезапуск VPN session (hot-reload через
  `bypassroute.Trie.Replace(newTrie)` published atomic).
- No regressions в Phase 2/3/may-audit/wire-trigger metrics.
