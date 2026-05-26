# Decoy Forward Pool with Admin Management — Design

**Author:** ShadowLink team
**Date:** 2026-05-26
**Status:** Draft
**Spec ID:** 2026-05-26-decoy-forward-pool
**Related:**
- Research forensics: `shadowlink/docs/superpowers/research/2026-05-26-canary-step2-forensics.md`
- Memory: `drain-direction-parked-2026-05-26.md`
- Existing live_blog spec: `shadowlink/docs/superpowers/specs/2026-04-23-t13-live-decoy-design.md`

---

## 1. Motivation

### 1.1 Что болит сегодня

Когда атакующий (passive scanner Censys / GreyNoise, active probe TSPU / GFW, любой curl-based reconnaissance) обращается на `https://datacanvases.com/<arbitrary-path>`, наш текущий код возвращает:

- **Path `/blog/*` или `/_cdn/*`** → reverse-proxy на `habr.com` с HTML rewriting под наш брендинг (`LiveBlogHandler`)
- **Любой другой path** → static SPA из `/var/www/decoy/` (`failClosedToDecoy → h.decoy.ServeHTTP`)

Проблема:
1. **Статический SPA имеет distinctive content signature.** Любой industrial scanner (Censys, GreyNoise) построит content-hash database за недели сканирования и пометит нас как known endpoint. Это **бесплатный** detection vector для атакующего.
2. **HTML branding rewriter** на `/blog/*` создаёт неестественные edge cases (логотип habr заменён на наш) — это рассогласование с реальным habr **может быть отличимо** при глубоком probing.
3. **Один target (habr) hardcoded.** Если habr изменит layout / включит anti-bot WAF / нас забанит — наш decoy сломается без возможности быстрого fix.
4. **Конфигурация только через YAML** + restart сервера. Ops change-control тяжёлый.

### 1.2 Что говорит research

Source: `shadowlink/docs/superpowers/research/2026-05-26-canary-step2-forensics.md` + 5 research отчётов 2026-05-26.

**Findings:**
- **Static decoy в 2026 — liability.** Reality / NaiveProxy / Trojan-Go все ушли на **forward to real upstream** именно из-за content-hash fingerprinting индустриальными сканерами.
- **Full Reality cert-level forward невозможен у нас** (research 1): требует ed25519 cert на target + replacement всего nginx+cert pipeline + Reality сам блокируется в Iran по volume heuristics. Не наш путь.
- **HTTP-level forward** к real upstream + sticky-per-IP rotation + sanitized headers — доминирующая best practice 2024-2026 (research 2).
- **Open-proxy abuse vector** реален но управляем (research 3): rate limit + path sanitize + bandwidth cap + header strip закрывают известные attack patterns.

### 1.3 Цель этого спека

Заменить static SPA decoy и hardcoded habr forwarder на:
1. **Rotation pool** из произвольного количества real-target sites
2. **Per-IP sticky** routing (один source IP → один target, sticky_ttl=24h)
3. **Admin UI** для управления pool (add/remove/enable/disable/weight) без рестарта сервера
4. **Embedded snapshot fallback** при недоступности всех targets
5. **Hardening** против open-proxy abuse

Это улучшение **anti-fingerprint defense** в смысле:
- Атакующий с одного IP видит **consistent** legit-site responses (sticky)
- Атакующий с разных IP видит **разные** legit sites (pool diversity)
- Content drift на upstream автоматически переносится к нам (no static signature)

### 1.4 Что НЕ в scope

- ❌ Full Reality cert-level TLS forward (см. research 1 verdict)
- ❌ Изменения TLS termination на nginx (остаёмся на Let's Encrypt RSA `datacanvases.com`)
- ❌ Geographic-IP routing target selection (отложено, может быть follow-up)
- ❌ CF orange cloud removal (CF остаётся как client-side fallback)
- ❌ Per-tenant target customization (один pool на всю инсталляцию)
- ❌ WebSocket forwarding к targets (probe path только HTTP)
- ❌ Volume-based blocking defense — отдельный класс задач (Iran volume heuristics, net4people #546)

---

## 2. Architecture Overview

### 2.1 Component diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                       Admin Panel (React)                            │
│   ┌──────────────────────────────────────────────────────────────┐   │
│   │  Settings → Decoy Targets tab                                │   │
│   │  • List targets: url, weight, enabled, health, response_ms   │   │
│   │  • Add/Edit/Delete/Toggle enabled                            │   │
│   │  • Test target (one-shot probe)                              │   │
│   │  • Warning callouts (legal/ToS risk per known domain)        │   │
│   └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ HTTPS
                               │
┌──────────────────────────────▼───────────────────────────────────────┐
│                    Admin Backend (Go, internal/admin)                │
│   ┌──────────────────────────────────────────────────────────────┐   │
│   │  GET/POST/PUT/DELETE /api/admin/decoy-targets                │   │
│   │  • CRUD against `decoy_targets` table (migration 119)        │   │
│   │  • POST /api/admin/decoy-targets/:id/test → one-shot probe   │   │
│   │  • After mutation: ping shadowlink-server mgmt /decoy/reload │   │
│   └──────────────────────────────────────────────────────────────┘   │
└──────────────────────────────┬───────────────────────────────────────┘
                               │ HTTP mgmt API (loopback or vpn-internal)
                               │
┌──────────────────────────────▼───────────────────────────────────────┐
│                  ShadowLink Server (Go, shadowlink/server)           │
│                                                                      │
│   ┌─────────────────┐                                                │
│   │ DecoyPool       │   ◄── reloads from admin via mgmt API          │
│   │ • targets[]     │       (POST /mgmt/decoy/reload)                │
│   │ • stickyMap     │   ◄── periodic health checks (30s)             │
│   │ • healthState   │   ◄── periodic snapshot refresh (24h)          │
│   │ • snapshot      │                                                │
│   └────────┬────────┘                                                │
│            │                                                         │
│   ┌────────▼────────┐   ┌──────────────────┐                         │
│   │ forwardToDecoy  │ → │ httpForwarder    │ → upstream target       │
│   │ (replaces       │   │ (sanitize, RL,   │   (habr, wiki, etc)     │
│   │  failClosed)    │   │  bandwidth cap)  │                         │
│   └─────────────────┘   └──────────────────┘                         │
└──────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data flow — happy path

```
Probe (IP=1.2.3.4) → GET https://datacanvases.com/foo
        │
        ▼
nginx (TLS terminate) → unix socket → shadowlink-server.handler.ServeHTTP
        │
        ▼
handler routes: not VPN (failed auth / wrong shape) → forwardToDecoy
        │
        ▼
DecoyPool.SelectTargetFor(IP=1.2.3.4):
  1. Check stickyMap[1.2.3.4] → expired/missing
  2. Pick target by weighted round-robin from enabled+healthy
  3. Persist stickyMap[1.2.3.4] = (target=T1, expires=now+24h)
        │
        ▼
httpForwarder.Forward(T1, request):
  - Strip headers: Cookie, Authorization, X-Forwarded-*, Upgrade
  - Block CONNECT/TRACE/PROPFIND → 444
  - Rate limit check (15 r/s per IP) → if exceeded: 503 from embedded snapshot
  - Bandwidth limit 256 KB/s
  - Open HTTPS to T1, copy request, stream response
        │
        ▼
Response → probe sees real habr.com headers, real HTML, real timing
```

### 2.3 Data flow — fallback path

```
Probe → forwardToDecoy → DecoyPool.SelectTarget
        │
        ▼
SelectTarget returns ErrNoHealthyTarget (all targets sick or pool empty)
        │
        ▼
forwardToDecoy serves DecoyPool.embeddedSnapshot (cached snapshot of last working T1)
        │
        ▼
If embeddedSnapshot empty too (first boot, network blip during snapshot):
  Return generic minimal HTML (404-like body, status 200, Server: nginx/1.18.0)
```

---

## 3. Server-side design (shadowlink/server)

### 3.1 New files

| File | Purpose |
|---|---|
| `server/decoy_pool.go` | `DecoyPool` struct, target selection, sticky map, health checks, snapshot management |
| `server/decoy_forwarder.go` | `httpForwarder.Forward` — actual HTTP proxy logic with hardening |
| `server/decoy_pool_test.go` | Unit tests for selection, sticky expiry, health transitions, snapshot lifecycle |
| `server/decoy_forwarder_test.go` | Unit tests for sanitization, rate limit, bandwidth cap, method block |
| `server/mgmt_decoy.go` | Mgmt API handlers `/mgmt/decoy/reload`, `/mgmt/decoy/status` |
| `server/embedded_fallback.go` | Snapshot encoder/decoder + minimal generic HTML constant |

### 3.2 Modified files

| File | Change |
|---|---|
| `server/handler.go` | Replace `h.decoy.ServeHTTP(...)` in `failClosedToDecoyWithReason` with `h.decoyPool.ServeProbe(w, r)`. Existing `failClosedTo*` synthetic-dispatch logic preserved — pool serve happens **after** timing pipeline. |
| `server/handler.go` | Replace `LiveBlogHandler` mount on `/blog/*` and `/_cdn/*` with pool dispatch — entire URL space handled uniformly. |
| `server/live_blog.go` | **DELETE** entire file. HTML rewriter, brand replacement, canary loop all retired. Migration: any operator who needs habr-only forward sets pool = [habr.com weight 1 enabled true]. |
| `server/html_rewriter.go` | **DELETE** — only used by live_blog. |
| `server/live_blog_canary.go` | **DELETE** — pool has its own health checks. |
| `server/live_blog_timing.go` | **DELETE** — sanity-check timing of habr fetches no longer relevant. |
| `server/config.go` | Add `DecoyPool DecoyPoolConfig` field. `LiveBlog` field retained but DEPRECATED — startup migrator translates `LiveBlog.UpstreamURL` to single-target pool if pool empty. |
| `server/metrics.go` | Add counters `shadowlink_decoy_forward_total{target,result}`, `shadowlink_decoy_health_status{target}`, `shadowlink_decoy_target_down_total{target}`, `shadowlink_decoy_fallback_served_total`, `shadowlink_decoy_rate_limited_total`, `shadowlink_decoy_sticky_evicted_total`, `shadowlink_decoy_snapshot_refresh_total{result}`. |
| `cmd/shadowlink-server/main.go` | Wire `DecoyPool` into `NewHandler`. Start mgmt API server if configured. |

### 3.3 `DecoyPool` type

```go
// DecoyPool manages a rotation pool of upstream decoy targets with
// per-source-IP sticky routing, health checks, and an embedded snapshot
// fallback. Thread-safe; mutated only via Reload() or internal health/
// snapshot goroutines.
type DecoyPool struct {
    mu             sync.RWMutex
    targets        []decoyTarget    // active set, swapped by Reload
    healthyTargets []int            // indices into targets[] currently healthy

    sticky         *expirable.LRU[string, stickyEntry]
                                    // key = source IP, value = (targetIdx, expiresAt)

    snapshot       atomic.Pointer[cachedSnapshot]
                                    // serves when all targets down

    forwarder      *httpForwarder
    cfg            DecoyPoolConfig
    metrics        *Metrics
    log            *slog.Logger

    ctx            context.Context
    cancel         context.CancelFunc
    wg             sync.WaitGroup
}

type decoyTarget struct {
    id          int64           // matches admin DB row id
    url         *url.URL        // upstream (https://habr.com)
    weight      int             // for weighted random selection
    description string          // admin-supplied note
}

type stickyEntry struct {
    targetIdx int
    // expiresAt managed by expirable.LRU TTL
}

type cachedSnapshot struct {
    body        []byte
    contentType string
    statusCode  int
    fetchedAt   time.Time
    targetURL   string  // for logging
}

type DecoyPoolConfig struct {
    StickyTTL          time.Duration // default 24h
    HealthInterval     time.Duration // default 30s
    HealthTimeout      time.Duration // default 5s
    SnapshotRefresh    time.Duration // default 24h
    RateLimitRPS       int           // default 15
    RateLimitBurst     int           // default 30
    BandwidthLimitBPS  int64         // default 262144 (256 KB/s)
    BodyLimitBytes     int64         // default 1_048_576 (1 MB)
    UpstreamTimeout    time.Duration // default 10s (probe doesn't wait long)
    DialTimeout        time.Duration // default 5s
    MaxStickyEntries   int           // default 10_000 (LRU evict)
    MgmtListen         string        // e.g. "127.0.0.1:9090" or "" (disabled)
    MgmtKey            string        // bearer for /mgmt/* endpoints
}
```

### 3.4 Target selection algorithm

```go
// SelectTargetFor returns the target index that should serve probes from
// the given source IP for the next stickyTTL period. Returns -1 if no
// healthy targets are available.
//
// Algorithm:
//   1. Look up source IP in sticky map. If found AND target is still
//      healthy → return cached index.
//   2. If sticky entry exists but target became unhealthy → evict, fall
//      through to step 3 (re-pick).
//   3. From healthyTargets[], pick a target via weighted random.
//      Weights come from decoyTarget.weight; defaults to 1 if all zero.
//   4. Persist (sourceIP → targetIdx) in sticky LRU with TTL=StickyTTL.
//   5. Return picked index. -1 if healthyTargets is empty.
func (p *DecoyPool) SelectTargetFor(sourceIP string) int {
    p.mu.RLock()
    defer p.mu.RUnlock()

    if len(p.healthyTargets) == 0 {
        return -1
    }

    if entry, ok := p.sticky.Get(sourceIP); ok {
        // Validate target still healthy
        for _, idx := range p.healthyTargets {
            if idx == entry.targetIdx {
                return entry.targetIdx
            }
        }
        // Sticky target turned unhealthy — evict, re-pick
        p.sticky.Remove(sourceIP)
        p.metrics.DecoyStickyEvicted.Add(1)
    }

    // Weighted random selection among healthy
    idx := p.pickWeighted()
    p.sticky.Add(sourceIP, stickyEntry{targetIdx: idx})
    return idx
}
```

**Weighted random:** stdlib `math/rand/v2` — sum weights, pick random in [0, sum), walk to find bucket. O(N) where N=pool size. For N≤10 typical, no need for tree.

**Source IP extraction:** `ClientIPFromRequest(r, h.config.BehindProxy)` already exists. Behind nginx with `-behind-proxy=true` reads X-Forwarded-For.

### 3.5 Health checks

Per-target goroutine, period = `HealthInterval` (30s):

```go
// healthCheckLoop pings the target with GET / and HEAD method, classifies
// result. Healthy = status ∈ {200, 301, 302, 304, 403, 404}, response in
// HealthTimeout. Unhealthy = network error, timeout, 5xx, or status 0.
//
// Transitions: 3 consecutive unhealthy → mark unhealthy. 1 healthy →
// mark healthy again (recovery is fast — being sick is the exception).
//
// Why 200/301/302/304/403/404 are ok: target SHOULD respond from probe's
// perspective. A 403 means "go away" but the wire shape is still real-
// site shape. 5xx + timeout = degraded target serving error pages, which
// would leak signature to probe. Conservative.
```

`healthyTargets` slice rebuilt atomically: take write lock, iterate `targets[]`, collect indices of healthy, swap. `SelectTargetFor` and `pickWeighted` see consistent set.

**Why not k8s-style readiness probe?** Targets are arbitrary external sites (habr.com). We cannot define their "ready" — just "responds reasonably." Probabilistic check.

### 3.6 Snapshot lifecycle

Embedded fallback = response of the first **enabled+healthy** target's GET /, cached in memory.

```go
// snapshotRefreshLoop runs once at startup then every SnapshotRefresh
// period. Strategy:
//   1. Pick first enabled+healthy target (deterministic — lowest id).
//   2. GET / with same hardening as a real probe forward.
//   3. If success → atomic swap atomic.Pointer[cachedSnapshot].
//   4. If failure → keep old snapshot, log warning.
//
// Initial boot:
//   - If first refresh succeeds → snapshot populated.
//   - If first refresh fails AND no prior snapshot → embeddedFallback
//     returns minimalHTML (constant 404-shape body) until next attempt.
```

`minimalHTML`:

```html
<!DOCTYPE html><html><head><title>404 Not Found</title></head>
<body><center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>
```

Identical to common nginx default 404. Status code 200 (not 404) — because real targets return 200 for `/`, and we want fallback to mimic the same status as probe would have gotten from real target.

**Why first target deterministic** (not random)? Snapshots are cached on disk between restarts (optional Phase 2 — see §11). Deterministic source = predictable snapshot content for given pool config. If random, restarts cause unrelated content jumps.

### 3.7 forwarder.Forward — hardening

```go
// Forward proxies the inbound request to target and writes the upstream
// response back. Applies all hardening from research 3:
//
//   1. Method whitelist: GET, HEAD, POST. Else 444 (silent drop — same
//      as caddy/nginx aggressive close).
//   2. Header sanitization: strip Cookie, Authorization, Upgrade,
//      X-Forwarded-*, X-Real-IP, X-Original-*, X-SL-*. The Host header
//      is forced to target.Host (NOT mirrored from request).
//   3. Body limit: io.LimitReader at BodyLimitBytes. Excess → 413 from
//      fallback snapshot.
//   4. Per-IP rate limit (golang.org/x/time/rate.Limiter, RPS+Burst). If
//      Allow=false → 503 from fallback snapshot. Limiter keyed by source
//      IP, LRU evict after 5min idle.
//   5. Bandwidth cap on response: io.CopyBuffer with throttle
//      (rate.NewLimiter for token-bucket on bytes). BandwidthLimitBPS.
//   6. Timeout: UpstreamTimeout for the entire forward (handshake +
//      headers + body stream). Excess → 504 from fallback snapshot.
//   7. Strip response headers that leak our infrastructure: Set-Cookie,
//      Strict-Transport-Security (we don't want target's HSTS pinning
//      datacanvases.com), Public-Key-Pins.
//   8. Block WebSocket: if request has Connection: upgrade or
//      Upgrade: websocket → return 426 from snapshot. WS over probe
//      path is anomalous.
//   9. SafeDial: NEVER dial to private/loopback/link-local IPs. Already
//      exists in server/safedial.go from live_blog migration.
```

**Why 444 for blocked methods (CONNECT/TRACE/PROPFIND) but 503 for rate limit?** 444 = nginx-specific "close without response" — caddy/nginx aggressive servers use this for malformed/abusive requests. It's a known fingerprint of nginx hardening. 503 = "service overloaded" — also matches real target behavior under load. Both are signature-friendly.

---

## 4. Database schema (migration 119)

```sql
-- migrations/119_decoy_targets.sql
BEGIN;

CREATE TABLE IF NOT EXISTS decoy_targets (
    id              BIGSERIAL PRIMARY KEY,
    url             TEXT NOT NULL,
    weight          INTEGER NOT NULL DEFAULT 1 CHECK (weight >= 0 AND weight <= 100),
    enabled         BOOLEAN NOT NULL DEFAULT true,
    description     TEXT NOT NULL DEFAULT '',
    risk_warning    TEXT NOT NULL DEFAULT '',
                    -- e.g. "ToS: scraping prohibited. Use at own risk."
                    -- Populated by client based on URL pattern; admin sees but cannot bypass.
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Live health state, updated by shadowlink-server reporting back via mgmt API:
    last_health_check_at  TIMESTAMPTZ,
    last_status           TEXT NOT NULL DEFAULT 'unknown',
                          -- 'healthy' | 'unhealthy' | 'unknown'
    last_response_time_ms INTEGER,
    consecutive_failures  INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX decoy_targets_url_uniq ON decoy_targets (lower(url));

CREATE OR REPLACE FUNCTION decoy_targets_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER decoy_targets_touch_updated_at
BEFORE UPDATE ON decoy_targets
FOR EACH ROW EXECUTE FUNCTION decoy_targets_touch_updated_at();

-- Seed with one safe default (admin can change later)
INSERT INTO decoy_targets (url, weight, enabled, description, risk_warning)
VALUES ('https://en.wikipedia.org', 1, true,
        'Wikipedia EN — default fallback target',
        '')
ON CONFLICT DO NOTHING;

COMMIT;
```

**Notes:**
- `weight` capped at 100 to prevent admin typos producing massive selection bias.
- `lower(url)` unique index — `https://habr.com` and `https://Habr.com` collapse to one entry.
- `risk_warning` populated automatically by admin handler when URL matches known-risky patterns (habr/lenta/rbc/vk/telegram).
- `last_*` fields written **only** by shadowlink-server via mgmt API — admin UI is read-only on these.

---

## 5. Admin Backend (internal/admin)

### 5.1 New endpoints

| Method | Path | Purpose | Auth |
|---|---|---|---|
| `GET`    | `/api/admin/decoy-targets`        | List all targets with current health state | admin JWT |
| `POST`   | `/api/admin/decoy-targets`        | Create new target | admin JWT |
| `PUT`    | `/api/admin/decoy-targets/:id`    | Update fields (url, weight, enabled, description) | admin JWT |
| `DELETE` | `/api/admin/decoy-targets/:id`    | Delete target | admin JWT |
| `POST`   | `/api/admin/decoy-targets/:id/test` | One-shot probe to target, return status+latency+body-hash | admin JWT |
| `POST`   | `/api/admin/decoy-targets/reload` | Trigger immediate pool reload on shadowlink-server | admin JWT |
| `GET`    | `/api/admin/decoy-targets/status` | Aggregated stats: total, healthy, unhealthy, last_refresh | admin JWT |

### 5.2 Request/response shapes

```typescript
// GET /api/admin/decoy-targets — list
type DecoyTargetListResponse = {
    targets: Array<{
        id: number;
        url: string;
        weight: number;
        enabled: boolean;
        description: string;
        risk_warning: string;
        created_at: string;  // ISO 8601
        updated_at: string;
        last_health_check_at: string | null;
        last_status: 'healthy' | 'unhealthy' | 'unknown';
        last_response_time_ms: number | null;
        consecutive_failures: number;
    }>;
    snapshot_age_seconds: number | null;
    pool_active: boolean;  // false if server reports pool reload failed
};

// POST/PUT body
type DecoyTargetWrite = {
    url: string;          // validated as valid HTTPS URL with non-empty host
    weight: number;       // 1..100
    enabled: boolean;
    description: string;  // max 500 chars
};

// POST /test response
type DecoyTargetTestResponse = {
    success: boolean;
    status_code: number | null;
    response_time_ms: number;
    body_hash_sha256: string | null;
    body_size_bytes: number | null;
    error: string | null;
};
```

### 5.3 Validation rules

- `url` MUST start with `https://` (admin warns on `http://` — never accepted)
- `url` MUST have valid host part
- `url` MUST NOT contain user/password (`https://user:pass@…` rejected)
- `url` MUST NOT resolve to private/loopback/link-local IP (DNS check at write time — re-check at use time via SafeDial)
- `url` host MUST be public-suffix-list valid TLD (no `https://localhost`, no `https://foo`)
- `weight` ∈ [1, 100]
- `description` max 500 chars, sanitized (no HTML)

### 5.4 Risk warning auto-population

When admin POST/PUT a target, server computes `risk_warning`:

```go
var riskPatterns = []struct {
    pattern *regexp.Regexp
    warning string
}{
    {regexp.MustCompile(`(?i)\b(habr|habrahabr)\.com\b`),
     "habr.com ToS prohibits scraping. WAF may ban our origin IP."},
    {regexp.MustCompile(`(?i)\b(lenta|rbc|kommersant)\.ru\b`),
     "RU commercial media. ToS uncertain. Risk: RKN classification, WAF block."},
    {regexp.MustCompile(`(?i)\b(vk|telegram|whatsapp)\.com\b`),
     "Major social platform. ToS prohibits proxying. RU legal risk."},
    {regexp.MustCompile(`(?i)\b(wikipedia|wikimedia|archive)\.org\b`),
     ""},  // CC-licensed, safe
    {regexp.MustCompile(`(?i)\b(golang\.org|docs\.python\.org|kernel\.org|mdn\.dev)\b`),
     ""},  // Open-source docs, safe
    // Default — no warning, but generic note about ToS due diligence
}
```

Warnings are **advisory** — admin can save anyway. UI displays them as yellow callout next to the target row.

### 5.5 Mgmt API call after mutation

After every POST/PUT/DELETE on `decoy-targets`, admin handler calls:

```
POST http://<shadowlink-mgmt-host>:<port>/mgmt/decoy/reload
Authorization: Bearer <SHADOWLINK_MGMT_KEY>
```

Best-effort: log warning if call fails but return 2xx to admin (admin's DB write succeeded — pool will pick up on next periodic refresh or next restart). Don't block admin response on mgmt RPC.

### 5.6 Test endpoint flow

`POST /api/admin/decoy-targets/:id/test`:

1. Load target from DB (must exist)
2. Resolve URL → SafeDial check
3. HTTP GET with same hardening as forward (10s timeout, 1MB body limit, header sanitize)
4. Compute SHA-256 of body bytes
5. Return status/latency/hash/size

**Why hash:** admin can spot-check that real target returns reasonable content (not a generic 404 page). If hash matches some known-bad signature (admin maintains expectation), they can spot upstream changes.

### 5.7 New files

| File | Purpose |
|---|---|
| `internal/admin/decoy_handlers.go` | All 7 endpoint handlers |
| `internal/admin/decoy_models.go` | DB struct + CRUD helpers |
| `internal/admin/decoy_risk_patterns.go` | Risk warning regex table |
| `internal/admin/decoy_mgmt_client.go` | Wrapper around mgmt API HTTP client |
| `internal/admin/decoy_handlers_test.go` | Handler unit tests with mock DB + mgmt |

### 5.8 Modified files

| File | Change |
|---|---|
| `internal/admin/handlers.go` | Register 7 new routes in `RegisterRoutes` |
| `internal/admin/openapi.yaml` | Document all 7 endpoints (CLAUDE.md requirement: new client endpoints MUST be in openapi.yaml — admin endpoints get same treatment for consistency) |
| `cmd/api/main.go` | Wire DB pool + mgmt client into admin handler constructor |

---

## 6. Frontend (frontend/src)

### 6.1 New components/pages

| File | Purpose |
|---|---|
| `frontend/src/pages/DecoyTargetsPage.tsx` | Main page (lazy-loaded route) |
| `frontend/src/components/decoy/DecoyTargetsTable.tsx` | Sortable table with inline edit |
| `frontend/src/components/decoy/DecoyTargetForm.tsx` | Modal form for add/edit |
| `frontend/src/components/decoy/DecoyTargetTestModal.tsx` | "Test target" results display |
| `frontend/src/components/decoy/HealthBadge.tsx` | Green/red/yellow indicator |
| `frontend/src/components/decoy/RiskWarningCallout.tsx` | Yellow box for risky targets |
| `frontend/src/api/decoyTargets.ts` | Typed fetch wrappers for 7 endpoints |
| `frontend/src/types/decoy.ts` | TS types matching backend shapes |

### 6.2 Modified files

| File | Change |
|---|---|
| `frontend/src/App.tsx` | Add lazy route `/decoy-targets` |
| `frontend/src/pages/SettingsPage.tsx` (or sidebar nav) | Add link "Decoy Targets" |
| `frontend/src/types/auth.ts` | Add role check helper if needed (admin-only) |

### 6.3 UX details

**Table columns:**
- ID (small, monospace)
- URL (clickable, opens in new tab for admin to verify)
- Weight (inline editable number 1-100)
- Enabled (toggle switch)
- Health (badge: ●Healthy / ●Unhealthy / ●Unknown + tooltip with response_time_ms + consecutive_failures)
- Risk (yellow ⚠ if risk_warning non-empty, click to show full text)
- Last checked (relative time: "30s ago")
- Actions (Test / Edit / Delete)

**Add target flow:**
1. Click "+ Add Target" button
2. Modal opens: URL input, weight slider (default 1), description textarea, enabled toggle
3. URL on-blur → frontend pre-validates HTTPS + host shape
4. On submit → POST to backend → if risk_warning returned, show callout before final save
5. On success → table refreshes, optimistic insert

**Test target flow:**
1. Click "Test" in row
2. Modal opens with loading spinner
3. Backend hits target, returns within ~10s
4. Show: status code, response time, body size, SHA-256 hash (first 12 chars + copy button), error if any
5. Color-code: green if 200-299, yellow if 3xx/4xx, red if 5xx/error

**Delete flow:**
1. Click "Delete"
2. Confirmation dialog: "Delete target X? Probe traffic currently using this target will fall over to embedded snapshot until rotation reassigns."
3. On confirm → DELETE backend → table refresh

**Empty pool warning:**
- If `enabled+healthy` target count = 0, show prominent **red** banner at top of page: "⚠ No active decoy targets. Probe traffic served from cached snapshot only. Add or enable targets immediately."

### 6.4 Permissions

Page accessible only to admin role (existing auth middleware). Read-only role (if exists) sees table but Add/Edit/Delete/Test buttons disabled.

---

## 7. Configuration

### 7.1 YAML config (`shadowlink/config.yaml`)

```yaml
# Existing fields preserved...

decoy_pool:
  enabled: true                  # false = fall back to legacy static decoy
  sticky_ttl: 24h
  health_interval: 30s
  health_timeout: 5s
  snapshot_refresh: 24h
  rate_limit_rps: 15
  rate_limit_burst: 30
  bandwidth_limit_bps: 262144    # 256 KB/s
  body_limit_bytes: 1048576      # 1 MB
  upstream_timeout: 10s
  dial_timeout: 5s
  max_sticky_entries: 10000
  mgmt:
    listen: "127.0.0.1:9090"
    key_file: "/etc/shadowlink/mgmt.key"

# DEPRECATED — kept for backward compat. Translated to single-target pool at boot if pool empty.
live_blog:
  enabled: false
```

### 7.2 ENV overrides (emergency only)

| ENV | Effect |
|---|---|
| `SHADOWLINK_DECOY_MODE=legacy_static` | Disable pool, route all to original static SPA (old behavior). For rollback only. |
| `SHADOWLINK_DECOY_DISABLE=1` | Disable pool AND legacy static — return minimal HTML for everything. For incidents. |

No other ENV. All tuning via YAML or admin UI.

### 7.3 Hot-reload semantics

When admin changes pool:
1. Admin handler writes to DB
2. Admin handler `POST /mgmt/decoy/reload` to shadowlink-server
3. Server fetches fresh list from DB (server has read-only DB credentials for pool reads — NOT for writes)
4. Server constructs new `targets[]` slice, runs immediate health check on new targets
5. Atomic swap inside DecoyPool — old sticky map preserved (entries pointing to removed targets get evicted on next access via the staleness check)
6. Response 200 to admin

**Failure modes:**
- Mgmt unreachable → admin save still succeeds (DB written), warning in response. Next periodic refresh (1h fallback) picks up.
- Health check on new target fails → target enters pool but stays in unhealthy state, won't be selected. Admin sees yellow indicator.

### 7.4 Periodic full reload (safety net)

Every 1h, even without admin trigger, server re-reads DB to catch:
- Mgmt API was down when admin made change
- Direct DB modification (psql edits)
- Migration applied between runtime updates

---

## 8. Metrics & Observability

### 8.1 New counters

```
shadowlink_decoy_forward_total{target,result}
    # result: success|upstream_error|timeout|rate_limited|method_blocked|body_too_large|ws_blocked

shadowlink_decoy_health_status{target}
    # gauge: 1=healthy, 0=unhealthy

shadowlink_decoy_health_check_total{target,result}
    # result: ok|timeout|status_5xx|network_error

shadowlink_decoy_target_down_total{target}
    # incremented on transition healthy→unhealthy

shadowlink_decoy_target_up_total{target}
    # incremented on transition unhealthy→healthy

shadowlink_decoy_fallback_served_total
    # served from embedded snapshot

shadowlink_decoy_minimal_served_total
    # served from minimalHTML constant (snapshot was empty too)

shadowlink_decoy_rate_limited_total
    # 503 returned due to per-IP rate limiter

shadowlink_decoy_sticky_evicted_total
    # sticky entry removed because its target turned unhealthy

shadowlink_decoy_sticky_size
    # gauge: current LRU size

shadowlink_decoy_snapshot_refresh_total{result}
    # result: success|target_down|network_error|empty_body

shadowlink_decoy_pool_reload_total{result}
    # result: success|db_error|empty_pool
```

### 8.2 Structured logs

```
INFO  "decoy pool reloaded" targets=5 healthy=4 disabled=1 changed_since_last=2
WARN  "decoy target unhealthy" target=habr.com consecutive_failures=3 err="dial tcp: i/o timeout"
INFO  "decoy target recovered" target=habr.com prev_failures=5
INFO  "decoy snapshot refreshed" source_target=wikipedia.org body_size=64231 fetched_in=812ms
WARN  "decoy snapshot refresh failed" source_target=wikipedia.org err="..." prev_snapshot_age=23h
WARN  "decoy rate-limited" source_ip=1.2.3.4 target=habr.com rps_window=15
DEBUG "decoy sticky assignment" source_ip=1.2.3.4 target=habr.com ttl=24h
```

Source IP in logs respects existing privacy policy (truncated to /16 for IPv4 if configured — match existing behavior in `failClosedToDecoyWithReason`).

### 8.3 Dashboard recommendations (operator docs)

For ops Grafana — not part of code, but documented:

- `rate(shadowlink_decoy_forward_total{result="success"}[5m])` — main throughput
- `rate(shadowlink_decoy_forward_total{result!="success"}[5m]) / rate(shadowlink_decoy_forward_total[5m])` — error ratio
- `shadowlink_decoy_health_status{target=~".+"}` — current up/down per target
- `shadowlink_decoy_fallback_served_total` — should stay near zero in healthy state; spikes signal pool issues
- `shadowlink_decoy_rate_limited_total` — spikes indicate active probing/scanning

---

## 9. Hardening summary table

| Vector | Mitigation | Detail |
|---|---|---|
| Open proxy abuse | Method whitelist | GET/HEAD/POST only; CONNECT/TRACE/PROPFIND → 444 |
| Open proxy abuse | Host header forced | `req.Host = target.Host`; client `Host:` ignored |
| Open proxy abuse | Header strip | Cookie, Authorization, X-Forwarded-*, X-Real-IP, X-Original-*, X-SL-*, Upgrade |
| Open proxy abuse | Body limit | 1 MB via io.LimitReader; excess → 413 from snapshot |
| Open proxy abuse | Bandwidth cap | 256 KB/s on response body (rate.Limiter token bucket) |
| Open proxy abuse | Per-IP rate limit | 15 r/s, burst 30, status 503 from snapshot |
| Probe fingerprinting | Sticky per IP | Single IP sees consistent target across 24h |
| Probe fingerprinting | Pool diversity | Different IPs see different targets (weighted) |
| Probe fingerprinting | Header pass-through | Target headers reach client 1:1 (minus our origin leaks) |
| Probe fingerprinting | No HTML rewriter | Old branding rewrite removed |
| SSRF | SafeDial | Refuses private/loopback/link-local IPs |
| SSRF | URL validation | Admin handler rejects user/password in URL, requires HTTPS, public TLD |
| WebSocket abuse | Upgrade header strip | WS handshake never reaches target |
| Timing oracle | Existing failClosedToDecoy synthetic | Still runs BEFORE pool dispatch — preserved |

---

## 10. Migration & rollback

### 10.1 Phase A — code ships, pool empty, legacy fallback active

- Migration 119 creates table, seeds Wikipedia EN
- Server starts with `decoy_pool.enabled=true`
- Pool reads from DB: 1 target (Wikipedia EN), healthy after first probe
- Old `live_blog.enabled=false` in config → live_blog code paths inactive (will be removed in Phase B)
- All existing routes work: `failClosedToDecoy` now goes through `DecoyPool.ServeProbe` → forwards to Wikipedia
- Admin UI deployed but only Wikipedia visible
- **Canary criterion:** 24h with 0 ERROR, decoy_forward_total{result="success"} grows, no health flapping, no fallback_served events except brief startup window

### 10.2 Phase B — admin populates pool, removes legacy code

- Admin adds 2-3 more targets via UI (e.g. archive.org, docs.python.org)
- Verifies all healthy
- Once stable for 7 days, schedule live_blog code deletion in next release
- Delete: `live_blog.go`, `html_rewriter.go`, `live_blog_canary.go`, `live_blog_timing.go`, related tests
- Delete: `/var/www/decoy/` static SPA (or move to backup location)
- Config `live_blog.enabled` field stays in struct but marked unused; removed in Phase C
- **Canary criterion:** 24h post-deletion, no regressions

### 10.3 Phase C — config cleanup

- `LiveBlog` field removed from `Config` struct
- Migration to drop deprecated fields in operator configs (operator action)
- Documentation update: NIKOLAY-README.md, deploy guides

### 10.4 Rollback strategies

| Scenario | Rollback |
|---|---|
| Pool unstable, want immediate restore | Set `SHADOWLINK_DECOY_MODE=legacy_static` in shadowlink-server env, restart. Reverts to `/var/www/decoy/` static SPA. Admin UI still visible but server ignores pool. |
| Single target causing issues | Admin toggles target.enabled=false in UI → next reload removes from pool |
| All targets external sites down (network blip) | Embedded snapshot serves automatically. Operator action: none. |
| Migration 119 deployed but pool code not yet in shadowlink-server | Table exists but unused. Server ignores it. No effect. Run prepared. |
| Want to fully revert post-Phase-B | Restore deleted files from git, redeploy. Costly — avoid. |

### 10.5 Backward compat

`live_blog.upstream_url` (single target) in operator's YAML → boot-time migrator:

```go
// In server boot, after pool load:
if len(pool.targets) == 0 && config.LiveBlog.Enabled && config.LiveBlog.UpstreamURL != "" {
    log.Warn("decoy pool empty, migrating live_blog.upstream_url to single-target pool")
    pool.AddRuntimeTarget(decoyTarget{
        url: config.LiveBlog.UpstreamURL,
        weight: 1,
    })
}
```

Runtime-added target NOT persisted to DB — operator should add via admin UI for permanence.

---

## 11. Testing

### 11.1 Unit tests (Go)

| Package | Test |
|---|---|
| `server/decoy_pool` | TestSelectTarget_StickyHit (IP returns same target twice) |
| `server/decoy_pool` | TestSelectTarget_StickyExpiry (after TTL → re-pick) |
| `server/decoy_pool` | TestSelectTarget_UnhealthyEviction (sticky target turns sick → evict, re-pick) |
| `server/decoy_pool` | TestSelectTarget_NoHealthy (empty healthy → returns -1) |
| `server/decoy_pool` | TestSelectTarget_WeightedDistribution (chi-square over 10k picks vs declared weights) |
| `server/decoy_pool` | TestHealthCheck_TransitionToUnhealthy (3 consecutive failures) |
| `server/decoy_pool` | TestHealthCheck_RecoveryFast (1 success → healthy) |
| `server/decoy_pool` | TestSnapshotRefresh_Success (snapshot updated) |
| `server/decoy_pool` | TestSnapshotRefresh_KeepOldOnFailure (refresh fails → old snapshot preserved) |
| `server/decoy_pool` | TestReload_AtomicSwap (no panic, healthy targets readable mid-swap) |
| `server/decoy_forwarder` | TestForward_BlocksConnect (CONNECT → 444) |
| `server/decoy_forwarder` | TestForward_StripsCookieAuth (request to target has empty Cookie/Authorization) |
| `server/decoy_forwarder` | TestForward_ForceTargetHost (request.Host = target.Host) |
| `server/decoy_forwarder` | TestForward_BodyLimit (request body > 1MB → 413) |
| `server/decoy_forwarder` | TestForward_BandwidthLimit (response stream throttled to 256 KB/s) |
| `server/decoy_forwarder` | TestForward_RateLimit (16th req in 1s → 503) |
| `server/decoy_forwarder` | TestForward_WSBlocked (Upgrade: websocket → 426) |
| `server/decoy_forwarder` | TestForward_SafeDial (private IP target → fallback) |
| `server/decoy_forwarder` | TestForward_HeadersPropagatedFromUpstream |
| `server/decoy_forwarder` | TestForward_StripsResponseHSTS |
| `internal/admin/decoy_handlers` | TestCreate_ValidatesHTTPS |
| `internal/admin/decoy_handlers` | TestCreate_RejectsUserInfoInURL |
| `internal/admin/decoy_handlers` | TestCreate_RejectsPrivateIPHost |
| `internal/admin/decoy_handlers` | TestCreate_PopulatesRiskWarning (habr URL → warning text) |
| `internal/admin/decoy_handlers` | TestUpdate_TriggersMgmtReload |
| `internal/admin/decoy_handlers` | TestDelete_TriggersMgmtReload |
| `internal/admin/decoy_handlers` | TestTest_TimeoutHandling |

### 11.2 Integration tests

- E2E: docker-compose with shadowlink-server + mock upstream (httptest) + admin-api stub
- Probe scenarios:
  - 100 requests from same IP → all hit same target (sticky verified)
  - Probe to disabled target → forwarded to next enabled
  - All targets disabled → 200 from snapshot
  - All targets disabled + no snapshot → 200 from minimalHTML
- Hot-reload: change pool via admin → next probe hits new target within 5s

### 11.3 Statistical tests

- `TestWeightedSelection_ChiSquare`: 10k picks against weights [1, 1, 1] → chi² < 5.99 (95% df=2)
- `TestWeightedSelection_BiasedWeights`: weights [1, 9] → ratio observed 0.05-0.15 vs 0.85-0.95
- `TestStickyDistribution_Uniform`: 10k unique IPs over 3-target pool → each target ~33% ± 3%

### 11.4 Hardening regression tests

Per CLAUDE.md May audit P0/P1/P2 closure pattern — test gates that lock the hardening invariants:

- `TestDecoyForward_NoOpenProxy_AllMethods` (CONNECT/TRACE/PROPFIND blocked)
- `TestDecoyForward_RateLimitMimicsOverload_503` (status code = 503, not 429)
- `TestDecoyForward_BandwidthCap_StaysWithinTolerance` (throughput < 300 KB/s averaged 10s)

### 11.5 Frontend tests (Vitest)

- `DecoyTargetsTable` renders rows correctly
- `DecoyTargetForm` validates URL on blur (HTTPS, no userinfo, public host)
- `DecoyTargetTestModal` shows loading → result → error states
- `RiskWarningCallout` shows when warning non-empty
- Empty-pool banner shows when healthy count = 0

### 11.6 Manual canary checklist

After Phase A deploy:
- [ ] Admin UI loads /decoy-targets, shows Wikipedia row
- [ ] curl `https://datacanvases.com/random-path` returns Wikipedia HTML
- [ ] Curl returns same content for 24h from same source IP
- [ ] Different source IP gets same Wikipedia (only 1 target — sticky degenerate)
- [ ] Add second target via UI (archive.org) — within 30s, some IPs route there
- [ ] Disable Wikipedia in UI — within 30s, all traffic routes to archive.org
- [ ] Disable all targets — within 30s, requests get embedded snapshot (last fetched archive.org body)
- [ ] No regression in pool health metrics (`alive=8-9`, 0 decrypt_fails, 0 ERROR)

---

## 12. Performance considerations

### 12.1 Hot path cost

`SelectTargetFor`:
- RLock + 1 LRU lookup + (worst case) 1 weighted random over N targets
- N typically 1-10
- Expected latency: <1μs

`Forward`:
- 1 HTTPS dial to upstream (~50-200ms on cold, ~0 on keep-alive)
- 1 read + 1 write per request
- Bandwidth cap enforced by token bucket — adds <1μs overhead per chunk

Compared to current `failClosedToDecoy` (3× X25519 + AES-GCM + ackJitter ≈ ~50ms total), the forward path is **faster** in steady state once keep-alive is warm.

### 12.2 Memory

- sticky LRU: 10k entries × ~40 bytes each ≈ 400 KB
- snapshot: typically 50-200 KB per fetched target page
- One snapshot in memory total (atomic pointer swap)
- Health goroutines: 1 per target, sleeping most of the time

Total ≈ <1 MB extra RSS for typical config.

### 12.3 Network

- Probe forward: 1:1 request volume to target
- Health checks: N targets × 1 GET / per 30s
- Snapshot refresh: 1 GET / per 24h
- Worst case 10 targets: 10 × (1 GET/30s) = 1.2k GET/h total to upstreams
- Within polite-crawler etiquette for any commercial site

---

## 13. Security considerations

### 13.1 Threat model

| Threat | Mitigation |
|---|---|
| Active prober (Censys/GreyNoise/TSPU): probes random paths, builds content DB | Forward returns real target content — no static signature to learn |
| Open proxy abuser: tries to use our server as free proxy | Header sanitization + bandwidth cap + rate limit + body limit |
| Probe → SSRF attempt via crafted Host | Host header forced to target.Host; user-supplied Host ignored |
| Probe → reconnaissance via custom headers | Headers stripped before forward |
| Insider threat: admin sets target to private IP / RFC1918 | URL validator + SafeDial double-check |
| Admin sets target to known-bad domain (CSAM, malware host) | Out of scope — admin trust assumed; risk_warning advisory |
| Target compromised by attacker, returns malicious content | Snapshot + per-IP sticky limits blast radius. Content is not interpreted by our server (just streamed); no Stored XSS into our app. |
| Sticky map memory exhaustion | LRU bound at MaxStickyEntries=10k |
| Snapshot poisoned by transient bad upstream response | Refresh every 24h; manual admin trigger if needed |
| Mgmt API key compromised | Mgmt API bound to loopback by default; bearer auth required |

### 13.2 Data privacy

- We do not log full source IP for forwarded requests (truncated to /16 in routine logs — match existing handler.go privacy pattern)
- No request bodies logged (we pass through)
- No response bodies logged (we stream)
- Sticky map keys: source IP. Cleared on TTL expiry. Not persisted to disk.

### 13.3 Legal / ToS

- Admin advisory warnings on known-risky domains (habr/lenta/vk)
- Admin bears responsibility for target choice
- We are NOT a circumvention service when serving probe — we are a passive reverse proxy of a public site
- For high-traffic abuse scenarios, individual target's WAF will throttle/ban our origin IP, which serves as natural circuit-breaker

---

## 14. Open questions / future work

### 14.1 Phase 2 candidates (NOT in this spec)

- **Disk-persisted snapshots** across restarts (avoid fetch on every boot)
- **Geographic-IP based selection** (RU source → RU target, EU → EU target) — needs GeoIP DB integration
- **Per-tenant target customization** — different operators run with different pools (currently single-pool-per-instance)
- **Smarter snapshot selection** — instead of "first target", round-robin snapshots across all healthy + serve the one matching probe's expected target by sticky
- **CDN-style asset proxying** — currently we proxy HTML only. Real legit site requests CSS/JS/images. Could re-proxy those too (more bandwidth, more complexity).
- **Authoritative response cache** — beyond snapshot, cache real responses per (target, path) with TTL — speeds up probe response, reduces upstream load

### 14.2 Operational follow-ups

- **Health check evasion** — what if target serves us a real-looking 200 OK that's actually a "you got banned" page? Need content sanity check (size, structure heuristic). Phase 2.
- **Coordinated target burnout** — when many ShadowLink installations all forward to habr.com, habr's WAF may aggressive-ban the **class** of behavior. Telemetry to detect this. Phase 2.

---

## 15. Acceptance criteria (Definition of Done)

- [ ] Migration 119 created, runs forward and backward
- [ ] `DecoyPool` type with full test coverage (selection, sticky, health, snapshot)
- [ ] `httpForwarder` with hardening regression tests passing
- [ ] 7 admin endpoints implemented + tested
- [ ] OpenAPI yaml updated
- [ ] Frontend page accessible, all flows functional (add/edit/delete/test/toggle)
- [ ] Hot-reload via mgmt API confirmed end-to-end
- [ ] Existing live_blog tests pass (Phase A — code retained)
- [ ] All 825+ existing tests still pass
- [ ] 4h+ canary on pl1 with pool active: 0 ERROR, 0 decrypt_fails, 0 force_evict, fallback_served_total = 0 (steady state)
- [ ] Documentation updated: shadowlink/CLAUDE.md, NIKOLAY-README.md
- [ ] Operator deploy guide updated with config snippet

---

## Appendix A — Why not full Reality (cited from research 2026-05-26)

Source: in-session research delegated 2026-05-26, agent-id a8e3e2a929c7a1d1b, "Reality cert forward deep research". Key findings summarized below; the full report was not persisted to a separate doc as conclusions are captured here and in §1.2.

Reality forward semantics (raw TCP I/O to target after Mirror-style ClientHello inspection) is incompatible with our nginx + Let's Encrypt RSA cert architecture. Migration would require:
- Removing nginx as TLS terminator (replacement with custom Go reality.Server listener)
- Choosing ed25519-cert target (vast majority of HTTPS targets are RSA — narrow target choice)
- Client rewrite (current shadowlink-client uses HTTP-level handshake, not Reality protocol)
- Discarding the entire `datacanvases.com` domain story (target's cert chain would show different CN)

Trade-off review (research-1 table): Reality gains probe-byte-identity vs target, loses domain consistency. Active probing is **not** the primary TSPU/RKN threat in RF 2026 — they bracket on volume + IP + entropy + TLS pattern. Static SPA replacement → forward-to-target gives us 90% of Reality's probe defense at <5% of Reality's migration cost.

---

## Appendix B — Glossary

- **Probe**: any HTTP request to our origin that is NOT a valid VPN client (failed auth, wrong body shape, random path scan)
- **Target**: an external website we reverse-proxy probe traffic to
- **Pool**: ordered set of enabled targets with weights
- **Sticky**: per-source-IP target binding cached for sticky_ttl
- **Snapshot**: cached body of one target's `GET /`, used when all targets unavailable
- **Forward**: HTTP-level reverse proxy operation (request → target → response back to probe)
- **Mgmt API**: shadowlink-server endpoint loopback-only for admin backend to trigger reload
