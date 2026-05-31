# ShadowLink Decoy Architecture — Verified Audit (R2 follow-up, 2026-05-26)

**Цель:** установить ground-truth архитектурную модель decoy-serving для ShadowLink path
ПЕРЕД написанием spec v3 polish. Spec v1/v2 строились на ошибочной модели
"nginx serves static" — это разрушает значительную часть polish goals, которые
проектировались под nginx-уровень.

Все ссылки на код — абсолютные пути + line numbers. Цитаты прямые из кода.

---

## 1. ShadowLink decoy serving — exact flow

### Что я нашёл

`shadowlink/server/decoy.go::DecoyHandler` — Go-уровневая обёртка вокруг
`http.FileServer(http.Dir(...))`. nginx **не видит** ни одного файла на ShadowLink
path: 100% запросов на ShadowLink-домены идут через unix socket к Go-процессу,
который сам сериализует HTML/CSS/JS из `/var/www/<domain>/` (или `DecoyDir`
default) с применением Go-уровневых headers.

### NewDecoyHandler — конструкция (`shadowlink/server/decoy.go:36-71`)

```go
func NewDecoyHandler(defaultDir string, domainMap map[string]string) *DecoyHandler {
    d := &DecoyHandler{
        defaultDir:    defaultDir,
        domainMap:     domainMap,
        perDirServers: make(map[string]http.Handler),
    }

    var defaultDirOK bool
    d.defaultServer, defaultDirOK = buildDirServer(defaultDir)
    // hasIndex semantics retained: true if defaultDir served real files with index.html OR fallback is in use.
    if defaultDirOK {
        _, idxErr := os.Stat(filepath.Join(defaultDir, "index.html"))
        d.hasIndex = idxErr == nil
    } else {
        d.hasIndex = true
    }

    // Pre-build per-dir servers for every unique directory referenced by domainMap.
    seen := map[string]bool{defaultDir: true}
    for host, dir := range domainMap {
        if dir == "" || seen[dir] { continue }
        seen[dir] = true
        srv, dirOK := buildDirServer(dir)
        if !dirOK { slog.Warn("decoy: configured directory unavailable, falling back to default page", ...) }
        d.perDirServers[dir] = srv
    }
    return d
}
```

`buildDirServer` (`decoy.go:76-84`):
```go
func buildDirServer(dir string) (handler http.Handler, dirOK bool) {
    if dir != "" {
        if info, err := os.Stat(dir); err == nil && info.IsDir() {
            srv := http.FileServer(http.Dir(dir))
            return srv, true
        }
    }
    return http.HandlerFunc(defaultDecoyPage), false
}
```

**Ключевая факт:** один `http.FileServer(http.Dir(dir))` инстанс кешируется per-directory
в `perDirServers`. Если directory не существует или пуст — fallback на
hardcoded `defaultDecoyPage` (`decoy.go:111-138`), который возвращает literal-string
HTML "Welcome / under construction" — это **минимальный fallback,
не production content**.

### ServeHTTP — flow (`shadowlink/server/decoy.go:88-104`)

```go
func (d *DecoyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Add headers that a real nginx/caddy would send
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "SAMEORIGIN")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

    server := d.defaultServer
    if d.domainMap != nil {
        dir := resolveDecoyDir(r.Host, d.domainMap, d.defaultDir)
        if dir != d.defaultDir {
            if srv, ok := d.perDirServers[dir]; ok {
                server = srv
            }
        }
    }
    server.ServeHTTP(w, r)
}
```

**Какие request properties проверяются:** только `r.Host` для маршрутизации к
`perDirServers[dir]`. **Никаких** проверок path / method / headers / referrer.
`r.URL.Path` идёт сырым в `http.FileServer`, который применяет стандартную
семантику `net/http`: stat→open→Content-Type из расширения через
`mime.TypeByExtension`, ETag не выставляется, Last-Modified из stat.

**Какие headers выставляются ServeHTTP:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `Referrer-Policy: strict-origin-when-cross-origin`

**Что добавляет `http.FileServer` (вне нашего контроля):**
- `Content-Type` — из `mime.TypeByExtension(filepath.Ext(name))` или sniffing первых 512 байт.
- `Last-Modified` — из `os.FileInfo.ModTime()`.
- `Accept-Ranges: bytes`.
- Для directory без `index.html` — auto-generated `<pre>`-листинг (**уязвимость UX: directory traversal**).

**Чего НЕТ:**
- Нет `Cache-Control` (кроме fallback page, которая ставит max-age=3600).
- Нет `ETag`.
- Нет `Content-Encoding: gzip/br`.
- Нет `Server` header (Go default — `Server: nginx` уже срабатывает на nginx уровне, но
  upstream Go response доходит к nginx и nginx-у нечего add (server_tokens off на frontend nginx).
  Точнее — frontend nginx **переписывает** Server header перед отдачей клиенту: `server_tokens off`
  в TrustTunnel конфиге, а в `nginx_shadowlink_template.go` для ShadowLink default — стандартное
  поведение nginx с upstream Server header forwarding или его подавления.)

### DomainMap — Host header routing (`shadowlink/server/decoy_router.go:19-36`)

```go
func resolveDecoyDir(host string, m map[string]string, defaultDir string) string {
    if len(m) == 0 {
        return defaultDir
    }
    h := host
    if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
        // Bare IPv6 literal, no port — leave as-is.
    } else if i := strings.LastIndex(h, ":"); i > 0 {
        h = h[:i]
    }
    h = strings.ToLower(h)
    if mapped, ok := m[h]; ok && mapped != "" {
        return mapped
    }
    return defaultDir
}
```

**Конфигурация source:** `Config.DomainDecoyMap` (`shadowlink/server/config.go:22-26`):
```go
// DomainDecoyMap maps Host header → decoy directory path for multi-domain serving.
// Empty/nil → use DecoyDir for all hosts (legacy behaviour).
DomainDecoyMap map[string]string `yaml:"domain_decoy_map,omitempty"`
```

Map keys должны быть lowercase (orchestrator-side normalization). Port в Host header
strip'ается через `LastIndex(":")` — IPv6 bracketed обрабатывается отдельно.

### perDirServers cache — singleton per directory

Built once в `NewDecoyHandler` (decoy.go:54-68). Каждая unique directory из
`domainMap.values()` получает свой `http.FileServer(http.Dir(dir))` — это
важно, потому что `http.FileServer` держит open file descriptors lazily,
и кеш предотвращает создание нового FileServer per request.

**Inference для spec v3:** добавление новых serving features (middleware
wrapping, header rewriting, response interception) должно происходить
**на уровне DecoyHandler.ServeHTTP**, не на уровне perDirServers — иначе
придётся wrap'ить каждый cached FileServer отдельно.

---

## 2. Decoy routing — request dispatch

### Что я нашёл

Routing dispatch живёт в `Handler.ServeHTTP` (`shadowlink/server/handler.go:375-410`).
Между VPN path и decoy path выбор делается по **HTTP-level heuristics**:
WebSocket upgrade header → WS handler; GET /blog/* (если live_blog enabled) → liveBlog;
POST + Content-Type=application/json → VPN body-prefix dispatcher; **всё остальное** →
`decoyWithTimingParity` (decoy.go:321-325 — wraps `runSyntheticDispatch` + `ackJitter` + `decoy.ServeHTTP`).

### Top-level dispatch (`handler.go:375-410`)

```go
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // WebSocket upgrade for full-duplex relay (Phase 1b).
    if r.Header.Get("Upgrade") == "websocket" {
        h.handleWebSocket(w, r)
        return
    }

    // LIVE-BLOG (T1.3): unauthenticated GET to /blog* or /_cdn/* → serve
    // reverse-proxied + brand-rewritten habr content.
    if h.liveBlog != nil && r.Method == http.MethodGet && h.liveBlog.Matches(r.URL.Path) {
        h.liveBlog.ServeHTTP(w, r)
        return
    }

    // Non-POST / non-JSON → decoy.
    if r.Method != "POST" || !isJSONContentType(r.Header.Get("Content-Type")) {
        h.decoyWithTimingParity(w, r)
        return
    }

    // POST + JSON → body-prefix path.
    h.metrics.NewPathHits.Add(1)
    h.handleNewFormatPost(w, r)
}
```

**Никаких hardcoded URL routes** на уровне Handler.ServeHTTP — все unauthenticated
запросы попадают либо в `decoyWithTimingParity` (всё non-POST/non-JSON), либо в
`handleWebSocket` (если есть Upgrade header — там IsAllowedWSPath проверяется).

### Scanner block / specific paths — где живут?

**Не в Go.** Проверка:
```
shadowlink/server/handler.go: НЕТ matches на ".php" / ".asp" / "/v2/health".
```

Эти роуты hardcoded **только в TrustTunnel nginx config** (`internal/deploy/steps_decoy.go::deployNginxConfig`,
lines 365-389) — это NOT ShadowLink path. На pl1 (ShadowLink) **scanner block отсутствует** —
`.php` запросы маршрутизируются через `decoyWithTimingParity` → `DecoyHandler.ServeHTTP` →
`http.FileServer` → 404 (если файл не существует) или 200 (если кто-то закинул `.php`
в /var/www/<domain>/).

### Rate-limit branch для SentinelEmitter.Emit

Два call sites (упомянуты в `shadowlink/server/sentinel_emitter.go:17-20`):

**1. handleHandshakeNew rate-limit reject** (`handler.go:469-497`):
```go
h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{
    Bucket:    "handshake",
    BurstLeft: remaining,
    RefillIn:  retryAfter,
    Exempt:    0,
})
```

**2. handleWebSocket rate-limit reject** (`websocket.go:411-418`):
```go
h.metrics.IncRatelimitBurstRejected("ws_upgrade")
h.failClosedToDecoyRateLimitedV2(w, r, RLSentinel{
    Bucket:    "ws_upgrade",
    BurstLeft: remaining,
    RefillIn:  retryAfter,
    Exempt:    0,
})
```

И один data-path call site из `handleNewFormatPost` (`handler.go:807-813`) для bucket=data.

`failClosedToDecoyRateLimitedV2` (`decoy_timing.go:238-288`) →
если `h.sentinelEmitter != nil`, делегирует `h.sentinelEmitter.Emit(w, info, "")`
(который читает snapshot по key "index.html" и инджектит rl-state в JSON-LD baseline),
иначе fallback на `writeRateLimitSentinelV2` (legacy header-only) + `failClosedToDecoyWithReason`.

**КРИТИЧЕСКИЙ инвариант для R1 H-1 understanding** (`sentinel_emitter.go:17-20`):
> Emit is called ONLY from rate-limit branches (handleHandshakeNew rate-limit,
> handleWebSocket rate-limit). NOT from auth_fail, replay_detected, malformed,
> unauth_visitor, max_clients_overload.

Это означает: JSON-LD baseline в demo HTML обязан существовать в **каждом**
template snapshot, который SentinelEmitter может выбрать (`LoadDecoySnapshots`
fail-fast валидирует все paths из списка при server startup). См. также инвариант в
`shadowlink/server/sentinel_trigger_isolation_test.go`.

---

## 3. failClosedToDecoy variants

### Что я нашёл

Три publicly invoked variants — все делегируют к одной общей timing pipeline через
`runSyntheticDispatch` + `ackJitter` + `decoy.ServeHTTP`. **Ни один из них не
генерирует HTML response самостоятельно** — они всегда форвардят request к
`h.decoy.ServeHTTP(w, ...)`, потенциально с sanitized placeholder request.

Расположение: `shadowlink/server/decoy_timing.go`.

### Variant 1: `failClosedToDecoy(w, r)` (`decoy_timing.go:169-176`)

```go
func (h *Handler) failClosedToDecoy(w http.ResponseWriter, r *http.Request) {
    // Backward-compat wrapper kept for existing tests + edge call paths that
    // have not yet been threaded with a reason.
    h.failClosedToDecoyWithReason(w, r, DecoyReasonUnspecified)
}
```

Тонкая обёртка над variant 2, помечает reason="unspecified" для observability.

### Variant 2: `failClosedToDecoyWithReason(w, r, reason)` (`decoy_timing.go:183-204`)

```go
func (h *Handler) failClosedToDecoyWithReason(w http.ResponseWriter, r *http.Request, reason DecoyReason) {
    // Step 1: observability
    if r != nil {
        clientIP := ClientIPFromRequest(r, h.config.BehindProxy)
        logDecoyServed(reason, r, clientIP)
    }
    h.metrics.IncDecoyServed(reason)

    // Step 2: timing-match pipeline
    h.runSyntheticDispatch()

    // Step 3: distribution-matched response jitter (Plan §C5 mixture).
    time.Sleep(ackJitter())

    h.metrics.TimingOracleHits.Add(1)
    // Sanitized placeholder: every failClosedToDecoy call resolves the decoy to
    // GET "/" so the response size is constant.
    h.decoy.ServeHTTP(w, httpPlaceholderRequest())
}
```

**Где живёт response generation:** `h.decoy.ServeHTTP(w, httpPlaceholderRequest())`.
`httpPlaceholderRequest()` (`handler.go:1992-1995`):
```go
func httpPlaceholderRequest() *http.Request {
    r, _ := http.NewRequest("GET", "/", nil)
    return r
}
```

**Не генерирует** свой response — всегда делегирует `DecoyHandler.ServeHTTP`
с **constant "/" path** (рационал: предотвратить body-length leak через URL echo).
Headers — те же, что `DecoyHandler.ServeHTTP` всегда выставляет (см. §1).

### Variant 3: `failClosedToDecoyRateLimitedV2(w, r, info)` (`decoy_timing.go:238-288`)

```go
func (h *Handler) failClosedToDecoyRateLimitedV2(w http.ResponseWriter, r *http.Request, info RLSentinel) {
    if h.sentinelEmitter != nil {
        // Dual-carrier path: body marker + X-SL-RL (semicolon format).
        h.sentinelEmitter.Emit(w, info, "")
        // Phase 1 timing parity
        time.Sleep(ackJitter())
        return
    }

    // Legacy fallback: header-only sentinel (comma format) + timing pipeline.
    writeRateLimitSentinelV2(w, info)
    h.metrics.RateLimitSentinelEmitted.Add(1)

    reason := decoyReasonForRLSentinel(info)
    h.failClosedToDecoyWithReason(w, r, reason)
}
```

**Здесь два разных code paths в зависимости от `sentinelEmitter != nil`:**

1. **`sentinelEmitter != nil`** (production на pl1): полный response пишется через
   `SentinelEmitter.Emit` — это **уникальный path где response generation
   НЕ делегируется DecoyHandler.ServeHTTP**. Emit сам пишет status 200,
   Content-Type, Content-Length и splice'нутый HTML body.
   После Emit — раннее `return` (нельзя chain'ить, response уже отправлен).
2. **`sentinelEmitter == nil`**: legacy path выставляет X-SL-RL header через
   `writeRateLimitSentinelV2`, потом chain'ит `failClosedToDecoyWithReason` → 
   `DecoyHandler.ServeHTTP(w, httpPlaceholderRequest())`.

### `decoyWithTimingParity` (`decoy_timing.go:321-325`)

Не variant failClosedToDecoy, но используется для direct decoy serves (GET / etc.):
```go
func (h *Handler) decoyWithTimingParity(w http.ResponseWriter, r *http.Request) {
    h.runSyntheticDispatch()
    time.Sleep(ackJitter())
    h.decoy.ServeHTTP(w, r)
}
```

**Отличие от failClosedTo*:** передаёт **оригинальный `r`** (не sanitized placeholder).
Это значит: GET /css/style.css → проходит до DecoyHandler с оригинальным path,
и FileServer обслуживает реальный файл. Это **корректное** поведение — DPI
наблюдает легитимный asset request.

### Кто вызывает каждый variant

- **failClosedToDecoy** (`decoy_timing.go:169`): только backward-compat tests.
- **failClosedToDecoyWithReason** (~25 call sites): все error branches —
  body-invalid, auth-fail, replay-detected, max-clients, backpressure,
  handshake-fail, device-limit, internal, stream-duplicate, protocol-unknown.
  См. handler.go:504, 509, 532, 545, 568, 577, 584, 625, 743, 748, 837, 1055, 1061, 1067 +
  websocket.go:426.
- **failClosedToDecoyRateLimitedV2** (3 call sites): handshake rate-limit,
  data rate-limit, ws_upgrade rate-limit.
- **decoyWithTimingParity** (1 call site): `Handler.ServeHTTP` non-POST/non-JSON fall-through
  (handler.go:400).

---

## 4. Existing decoy headers + response shape

### Что я нашёл

Headers выставляются в **трёх местах**, накладывающихся по приоритету:

1. `DecoyHandler.ServeHTTP` (Go) — security headers.
2. `http.FileServer` (Go stdlib) — Content-Type / Last-Modified / Accept-Ranges / Etag НЕТ.
3. `nginx upstream pass` — **не добавляет** заголовков в default config
   (см. nginx_shadowlink_template.go) кроме того что Server / Date / Connection
   nginx генерирует автоматически. **add_header не используется** в ShadowLink nginx
   template — это критично для понимания v3 polish scope.

### Decoy headers выставляемые Go кодом

#### Из DecoyHandler.ServeHTTP (`decoy.go:90-92`):
```go
w.Header().Set("X-Content-Type-Options", "nosniff")
w.Header().Set("X-Frame-Options", "SAMEORIGIN")
w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
```

#### Из defaultDecoyPage fallback (`decoy.go:117-118`):
```go
w.Header().Set("Content-Type", "text/html; charset=utf-8")
w.Header().Set("Cache-Control", "public, max-age=3600")
```
**Только** для fallback (decoyDir пустой/не существует). Для production
с реальным DecoyDir это НЕ срабатывает.

#### Из http.FileServer (stdlib):
Автоматически:
- `Content-Type: ...` через `mime.TypeByExtension` или sniff первых 512 байт.
- `Last-Modified: ...` из `os.FileInfo.ModTime()`.
- `Accept-Ranges: bytes`.
- НЕТ `ETag`.
- НЕТ `Cache-Control` (stdlib не выставляет).
- НЕТ `Content-Encoding` (compression не применяется).

### Headers выставляемые VPN path (для timing parity)

`setStandardHeaders` (`handler.go:336-343`) — применяется ТОЛЬКО к VPN responses:
```go
func setStandardHeaders(w http.ResponseWriter) {
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "SAMEORIGIN")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}
```

Note: F2 fix — все VPN responses должны иметь те же headers что DecoyHandler
для предотвращения oracle detection. `setStandardHeaders` зеркалит DecoyHandler
headers + добавляет VPN-specific `Content-Type: application/json` + `Cache-Control: no-cache`.

### Compression

**Нет gzip middleware в Go**. Грепы:
```
shadowlink\server\handler.go:1096: // stream without buffering through CF. Content-Encoding and
```

Это comment в writeStreamHeaders — наоборот предупреждает: **Content-Encoding NOT
set** для download stream (или CF будет буферизовать).

**Brotli — нет вообще.**

**nginx upstream gzip — не возможен:**
`nginx_shadowlink_template.go` (lines 27-36):
```nginx
location / {
    proxy_pass http://unix:/run/shadowlink.sock;
    proxy_set_header Host $host;
    ...
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

**Никаких `gzip on` директив.** nginx forwards Go response body 1:1.
Чтобы добавить gzip на nginx уровне для ShadowLink path:
```nginx
gzip on;
gzip_proxied any;
gzip_types text/html text/css application/javascript ...;
```

Это **possible** — nginx умеет gzip'ить upstream response. Но **в текущей конфигурации
не настроено**.

### Сравнение с TrustTunnel nginx (для контраста)

`steps_decoy.go::deployNginxConfig` (lines 328-401) — для TrustTunnel path:
```nginx
listen 127.0.0.1:8080;
root %s;  # decoyWebRoot
server_tokens off;

add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options    "nosniff" always;
add_header X-Frame-Options           "DENY" always;
add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
add_header X-Request-ID              $request_id always;
add_header X-Powered-By              "MetricsHub/2.4.1" always;
add_header X-Region                  "eu-west" always;

location / { try_files $uri $uri/ /index.html; ... }
location ~* \.(php|asp|aspx|jsp)$ { return 404; }
location = /v2/health { ... return 200 '{"status":"ok",...}'; }
location /v2/ { return 401 '{"error":"unauthorized",...}'; }
gzip on;
gzip_vary on;
gzip_types text/plain text/css application/json application/javascript text/javascript;
gzip_min_length 1024;
```

**Это совсем другая модель** — nginx serves static, делает try_files SPA fallback, имеет
gzip, custom error pages, scanner block. **На ShadowLink path всего этого НЕТ.**

---

## 5. Что НА САМОМ ДЕЛЕ нужно добавить для polish (Go-side)

### Что я нашёл

Все polish goals из R0/R1 spec выполнимы **только в Go middleware** на ShadowLink path.
nginx не может ни добавлять `add_header`, ни делать `try_files`, ни serving static
без перенастройки whole nginx config со сменой `proxy_pass` → `root + try_files`,
что **сломает VPN path** (handshake POST'ы перестанут доходить до Go).

| Goal | Go-side | Nginx-side |
|---|---|---|
| `/404.html` serving | DecoyHandler — wrap `http.FileServer` в кастомный handler, перехватить 404 status и serve `/404.html` файл вручную через ServeFile. http.FileServer сам не делает custom 404 page | — невозможно (nginx делает proxy_pass и видит только готовый response от Go, error_page работает только на nginx-generated 404, не upstream) |
| `/contact.html`, `/search.html` | Просто положить файлы в `/var/www/<domain>/contact.html` etc. — http.FileServer обслужит автоматически. **Никаких code changes.** | — |
| `/rss.xml`, `/.well-known/security.txt` | Файлы под `/var/www/<domain>/`. **Никаких code changes**, кроме mime.TypeByExtension для `.xml` (stdlib знает). `.well-known/` directory работает потому что http.FileServer не имеет блокировки на dot-prefixed (это URL component, не filename — http.FileServer проверяет filename starts-with-dot) | — |
| Tag/category stubs `/tag/<slug>/` | Если есть `/var/www/<domain>/tag/golang/index.html` — http.FileServer найдёт. Если нет — 404 от FileServer (без custom page). **Решение:** generate static directories с index.html во время build/deploy time (через расширенный `decoy_content_gen.go`) | — |
| SPA whitelist (deny `/admin.php` → 404 без timing parity к VPN) | Middleware в `decoy.go::DecoyHandler.ServeHTTP` — pre-FileServer check блок-листа suffixes (.php/.asp/.aspx/.jsp/.cgi), сразу serve 404.html и return | — невозможно (nginx не route'ит по path для unix socket upstream без блокирующего изменения proxy_pass) |
| `X-Powered-By` header rotation | DecoyHandler.ServeHTTP — добавить `w.Header().Set("X-Powered-By", randomFromPool)` перед `server.ServeHTTP`. Должен быть **поставлен ДО writes** | — невозможно (`add_header` в `location / { proxy_pass ... }` устанавливает header в **дополнение** к upstream headers, но upstream Go уже выставил свои headers; теоретически nginx `more_set_headers` mod-headers подходит, но `more_headers` не стандартный модуль на Ubuntu nginx — требует nginx-extras) |
| Brotli compression | Wrap DecoyHandler.ServeHTTP в Go middleware с `github.com/andybalholm/brotli` или `github.com/CAFxX/httpcompression`. Нужен `Vary: Accept-Encoding` header и проверка Accept-Encoding | — nginx с `proxy_pass` может gzip upstream response (см. `gzip_proxied any`), но **brotli требует ngx_brotli модуль**, который не из коробки. Лучше делать в Go (где брotli — pure Go) |
| gzip compression | То же что brotli — Go middleware с `gziphandler` (golang.org/x/net) | nginx с `gzip on; gzip_proxied any;` тоже подойдёт — простое изменение в nginx_shadowlink_template.go. Менее invasive |
| `Server: nginx` без версии | Уже работает: nginx default — `Server: nginx` (`server_tokens off` в текущем nginx_shadowlink_template НЕ установлен — это REGRESSION относительно TrustTunnel config). Go upstream не выставляет Server, nginx добавляет свой | nginx_shadowlink_template.go нужно добавить `server_tokens off;` в каждый server{} блок |
| `error_page 404` styled | Перехват 404 в Go (см. /404.html row). nginx `error_page 404 /404.html;` не сработает потому что upstream 404 не triggert nginx error_page (для этого нужен `proxy_intercept_errors on;` + `error_page 404 = @custom_404;` + named location — но named location всё равно должен либо serve static, либо proxy_pass; последнее снова к Go) | nginx — теоретически `proxy_intercept_errors on; error_page 404 /404.html;` + `location = /404.html { root /var/www/<domain>; internal; }` работает, но это серьёзный rewriting nginx config |
| ETag / Last-Modified | http.FileServer уже выставляет Last-Modified из stat. ETag — не выставляется stdlib. Решение: middleware с ETag generation на основе fileinfo hash | — |
| Cache-Control для статических assets | Go middleware: проверить path suffix (.css/.js/.png/.svg/.woff2) → `Cache-Control: public, max-age=31536000, immutable` для hash'нутых assets; `no-cache` для HTML | nginx может сделать в location blocks (как TrustTunnel), но требует rewrite nginx_shadowlink_template — снова risk |

### Architectural recommendation для spec v3

**Wrap `DecoyHandler.ServeHTTP` в middleware chain:**
```
DecoyHandler.ServeHTTP =
    securityHeaders (текущее)
  → randomXPoweredBy (new)
  → spaPathBlocker (new — .php/.asp early 404 → serve 404.html)
  → cacheControlByExt (new — Cache-Control based on file extension)
  → compressionMiddleware (new — gzip/brotli based on Accept-Encoding)
  → customNotFoundWrapper (new — intercepts FileServer 404, serves /404.html)
  → http.FileServer(http.Dir(dir))
```

**Никаких изменений в nginx_shadowlink_template.go** не требуется кроме одного:
добавить `server_tokens off;` в каждый server{} блок (closing config parity с
TrustTunnel template — текущая конфигурация ShadowLink leak'ает nginx version
в `Server:` header).

---

## 6. Cross-module integration

### Что я нашёл

`MakeBaselineValue` и `RLStateValueWidth` живут в `shadowlink/server/decoy_snapshots.go`
(verified lines 12-20, 240-243). Они принадлежат module `github.com/nixavpn/shadowlink`.
`internal/deploy/` принадлежит module `nixavpn`. Cross-import невозможен без
архитектурного changes.

### Verified location
```go
// shadowlink/server/decoy_snapshots.go:20
const RLStateValueWidth = 80

// shadowlink/server/decoy_snapshots.go:240-243
func MakeBaselineValue() string {
    core := "v1;bucket=none;refill_in=0;burst_left=100;exempt=0"
    return padToWidth(core, RLStateValueWidth)
}
```

Существующий call sites — только в `shadowlink/server/*_test.go` и
`shadowlink/server/sentinel_emitter.go::FormatRLStateValue`.

### Если deploy-time render demo HTML templates нужен в `internal/deploy/`

Текущий `internal/deploy/decoy_content_gen.go` (547 строк, generates static HTML
из pools) — **не использует** rl-state baseline. На pl1 (production) deploy
сейчас идёт без render generation: статические demo/* копируются как есть.

Если в spec v3 потребуется dynamically render template с embedded
canonical rl-state baseline (например, в hand-edited tag/category index.html
страницах с {{.SentinelBaseline}} placeholder), нужен механизм передачи
константы 80-byte string из `shadowlink/server/` → `internal/deploy/`.

### 4 варианта integration

#### Variant A: Hardcode constant в `internal/deploy/` + cross-check test

```go
// internal/deploy/decoy_baseline_const.go
package deploy

// SentinelBaselineValue — canonical 80-byte rl-state baseline, kept in lockstep
// with shadowlink/server/decoy_snapshots.go::MakeBaselineValue().
// Mirrored here (not imported) to preserve module isolation.
const SentinelBaselineValue = "v1;bucket=none;refill_in=0;burst_left=100;exempt=0;;;;;;;;;;;;;;;;;;;;;;;;;;"

// internal/deploy/decoy_baseline_const_test.go
package deploy_test

// Cross-module integrity test — verifies SentinelBaselineValue stays in sync.
// Living test in this module compares hardcoded const with the literal string
// MakeBaselineValue() produces. Test parses shadowlink/server/decoy_snapshots.go
// via AST and extracts MakeBaselineValue body to compute the canonical value.
// Test fails CI if drift.
```

**Pros:**
- Module isolation preserved.
- Простота: нет build-time codegen, нет file scanning во время run.
- Test catches drift at CI time.

**Cons:**
- Manual sync required при изменении MakeBaselineValue (rare — формат frozen).
- AST parsing для test — нетривиально (но решаемо `go/parser`).
- Альтернатива test'у: scan demo/<template>/index.html files и assert byte literal
  equals known canonical value.

#### Variant B: Replace в main go.mod

```go
// go.mod (root nixavpn module)
replace github.com/nixavpn/shadowlink => ./shadowlink
```

**Pros:**
- `internal/deploy/` может прямо `import "github.com/nixavpn/shadowlink/server"`.
- One-time configuration.

**Cons:**
- **НАРУШАЕТ feedback_shadowlink_isolation.md** — code в `shadowlink/` должен оставаться
  isolated. Это hard rule from memory.
- Pull constants из shadowlink/server также pull'ит весь transitive deps —
  `internal/deploy/` начинает зависеть от X25519, utls, etc. (хотя Go module
  dead-code-elimination это устранит на build time, конceptually это violation).
- Из feedback_shadowlink_isolation: ShadowLink остаётся **own go.mod, own deps**.

#### Variant C: Test сканирует demo/ из shadowlink/server/

```go
// shadowlink/server/decoy_baseline_external_test.go
package server_test

import (
    "os"
    "path/filepath"
    "regexp"
    "testing"
    "github.com/nixavpn/shadowlink/server"
)

func TestDemoTemplates_ContainCanonicalBaseline(t *testing.T) {
    baseline := server.MakeBaselineValue()
    demos := []string{"../../demo/saas-landing/index.html", ...}
    for _, p := range demos {
        body, err := os.ReadFile(filepath.Join("../..", p))
        require.NoError(t, err)
        require.Contains(t, string(body), baseline,
            "%s must contain canonical 80-byte rl-state baseline (mirror LoadDecoySnapshots invariant)", p)
    }
}
```

**Pros:**
- Polices content в demo/ files at PR time.
- НЕТ codegen, НЕТ replace, НЕТ cross-module imports.
- Demo files можно генерить как human-edited HTML, потом просто paste literal 80-byte string.

**Cons:**
- Test зависит от relative path `../../demo/*` — не portable если go test работает из
  другого working directory.
- Не помогает если `internal/deploy/decoy_content_gen.go` начнёт template-render'ить
  demo files **runtime** (build-time): pool-templated content нужно тоже валидировать.

#### Variant D: Build-time generator (`shadowlink/cmd/gen-baseline/`)

```go
// shadowlink/cmd/gen-baseline/main.go
// go generate'd via //go:generate go run ./shadowlink/cmd/gen-baseline -out internal/deploy/decoy_baseline_const.go
package main

import (
    "fmt"
    "os"
    "github.com/nixavpn/shadowlink/server"
)

func main() {
    // generates internal/deploy/decoy_baseline_const.go with literal const string
    baseline := server.MakeBaselineValue()
    fmt.Fprintf(os.Stdout, `// Code generated by shadowlink/cmd/gen-baseline. DO NOT EDIT.

package deploy

const SentinelBaselineValue = %q
`, baseline)
}
```

**Pros:**
- Single source of truth — `MakeBaselineValue()`.
- No manual sync — `go generate` rebuilds.
- Module isolation preserved (build-time tool generates const at boundary, не runtime import).

**Cons:**
- Усложняет build pipeline — нужен `go generate` step.
- Generated file нужно commit'ить (или regenerate каждый build, что добавляет CI noise).
- `shadowlink/cmd/gen-baseline/` import'ит `shadowlink/server` — это OK потому что cmd/ внутри
  same module.

### Рекомендация

**Variant C + Variant A в комбинации** — оптимально по trade-offs:

1. **Variant A** (hardcoded const в `internal/deploy/`) — для compile-time usage.
   Если render machinery в `decoy_content_gen.go` потребуется добавить {{.SentinelBaseline}}
   placeholder в Go-template, const доступен прямо.
2. **Variant C** (cross-validation test в `shadowlink/server/`) — для drift detection.
   Сканирует demo/*/index.html и assert'ит что hand-edited baseline literal matches
   MakeBaselineValue() output. Test упоминается в spec v2 review-r2.md, line 105
   как "Вариант D (на мой взгляд правильный)".

Avoid **Variant B** (нарушает ShadowLink isolation hard rule).
Avoid **Variant D** (build complexity без proportional benefit — baseline frozen format).

---

## TOP-3 architecturally critical findings

### 1. nginx делает ZERO routing/serving для ShadowLink path — всё в Go

Spec v1/v2 предположение "nginx serves static, Go handles VPN" **полностью неверно**
для ShadowLink. Verified в `internal/deploy/nginx_shadowlink_template.go:27-36`:
весь `location /` идёт через `proxy_pass http://unix:/run/shadowlink.sock` к Go.
Это значит:

- Всё что pre-`location /` (gzip, add_header, error_page, try_files) — **либо
  не работает с upstream response**, либо требует серьёзного nginx config rewrite
  (с риском сломать VPN handshake POST flow).
- **Все polish goals должны проектироваться как Go middleware** в
  `shadowlink/server/decoy.go::DecoyHandler.ServeHTTP`.
- Сравнение с TrustTunnel path (`steps_decoy.go::deployNginxConfig`, lines 328-401) —
  там nginx serves static с `root /var/www/...` напрямую, делает try_files,
  имеет custom location blocks для `/v2/health`, scanner block. **На ShadowLink этого
  всего нет** — это разные deployment paths.

**Impact на spec v3:** перевернуть всю архитектурную секцию — "Где реализовать?"
column в каждой polish-таблице должна быть Go middleware, не nginx директивы.
Существующий `defaultDecoyPage` fallback (`decoy.go:111-138`) показывает, что
паттерн "Go генерирует HTML inline" уже используется — Go-уровневая extension
естественна.

### 2. Существуют ДВЕ независимые response-generation модели на ShadowLink path

Verified в `decoy_timing.go:238-288`:

**Model A:** для rate-limit branches с `sentinelEmitter != nil` — `SentinelEmitter.Emit`
**сам пишет 200 status + Content-Type + Content-Length + body** (с splice'нутым
JSON-LD rl-state). DecoyHandler.ServeHTTP **не вызывается**. Это
"snapshot-based response" model с pre-loaded HTML.

**Model B:** для всех остальных error branches — `failClosedToDecoyWithReason` →
`decoy.ServeHTTP(w, httpPlaceholderRequest())`. Это runtime file serve через
`http.FileServer`.

**Impact на spec v3:** любой polish который трогает headers или response body
shape **должен учитывать оба paths**. Например, `X-Powered-By` rotation должен
применяться и к SentinelEmitter.Emit (там оно через `w.Header().Set` перед `WriteHeader`),
и к DecoyHandler.ServeHTTP. Любой custom 404 page handler должен учесть что Emit
никогда не возвращает 404 (всегда 200 со снапшотом). Snapshot HTML files (демо)
загружены в memory at startup и **byte-precise immutable** — нельзя добавить новые
headers внутрь HTML body без удвоения snapshot count или подобной memory penalty.

### 3. rl-state JSON-LD baseline — **обязательное** содержание каждого demo HTML; LoadDecoySnapshots fail-fast на startup

Verified в `decoy_snapshots.go:65-74` (6 hard invariants) +
`sentinel_emitter.go:17-20` (Emit invariants). Этот блок — **не fingerprint leak,
а функциональный signaling channel** для SentinelEmitter (Phase 1 ws-lifecycle 2026-05-14):

```html
<script type="application/ld+json">
{
  ...
  "identifier": {
    "@type": "PropertyValue",
    "propertyID": "rl-state",
    "value": "v1;bucket=none;refill_in=0;burst_left=100;exempt=0;;;;;;;;;;;;;;;;;;;;;;;;;;"  <!-- EXACTLY 80 bytes -->
  }
}
</script>
```

**Impact на spec v3:**

- Если spec v3 добавляет новые demo HTML templates (saas-landing-v2, blog-theme-X,
  contact-page-Y) — **каждый из них** обязан содержать этот baseline. Иначе
  pl1 не стартует после redeploy decoy (LoadDecoySnapshots fail-fast при server
  start).
- Если spec v3 предлагает refactor где `/contact.html`, `/search.html`,
  `/404.html` могут попасть в snapshot path для SentinelEmitter — каждый из них
  должен иметь JSON-LD baseline. **Это constraint на template design,
  не optional.**
- Опасность regression: если developer добавит template без baseline в
  config `LoadDecoySnapshots paths` list — все hand-written tests в
  `shadowlink/server/sentinel_*_test.go` пройдут (они используют корректные
  fixtures), но **production startup упадёт** с precise error
  `LoadDecoySnapshots <path>: Schema.org JSON-LD baseline validation failed`.

Spec v3 должна:
1. Документировать baseline как mandatory in spec text (R1+R2 review-r2.md уже это сделал).
2. Добавить cross-validation test (Variant C из §6) который сканирует
   `demo/<template>/index.html` файлы при тесте `shadowlink/server/...`.
3. Никогда не предлагать удаление JSON-LD блока (это блокер из R1+R2 review).

---

**Конец отчёта.**
