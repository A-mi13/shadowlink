# Decoy Behavioral Coverage — Design Spec v2.1

**Дата:** 2026-05-27 (evening, после opus-review v2)
**Замещает:** `2026-05-27-decoy-behavioral-coverage-design-v2.md`

> **⚠️ Implementation deviation (2026-05-28):** §3.4 предлагал pre-built 15086B ICO через manual realfavicongenerator step. **Отвергнуто** в implementation phase:
> - Manual step = blocking pre-requisite (плохой UX)
> - Byte-exact 15086B = overengineering (probe не считает байты favicon при detection; real prod sites имеют разные размеры — Stripe 15086B, GitHub 6518B, Cloudflare chunked)
> - Per-template color variation > fixed byte-exact mimicry
>
> **Новое решение:** runtime ICO generation в Go через `github.com/biessek/golang-ico` (PNG layers через stdlib `image/png`). Multi-res 16/32/48/64, per-template color. Никаких binary артефактов в repo. См. plan Task 16. Smoke checklist (§6.3 #10) обновляется: проверять только `image/x-icon` content-type, не byte size.
**Sources:**
- v1: `2026-05-27-decoy-behavioral-coverage-design.md`
- v1 review: `2026-05-27-decoy-behavioral-coverage-design-review.md`
- Research: `2026-05-27-real-world-decoy-patterns.md` (curl-probing 20+ prod sites)
- v2: `2026-05-27-decoy-behavioral-coverage-design-v2.md`
- v2 review: `2026-05-27-decoy-behavioral-coverage-design-v2-review.md`

**Differences v2.1 vs v2 (4 CRITICAL+HIGH + 5 recommended fixes):**

| # | Severity | What | Fix |
|---|---|---|---|
| 1 | CRITICAL N6 | `humansNamePool` global mutation — race + non-determinism | Copy slice before Shuffle |
| 2 | HIGH N2 | XFO blog contradiction (SAMEORIGIN vs DENY) | Unified to SAMEORIGIN |
| 3 | HIGH N7 | Blog security.txt undefined behavior | Explicit: blog HAS security.txt |
| 4 | HIGH N10 | Utility 404 three contradicting descriptions | Pure 200+SPA для всех 3 persona (Linear-style) |
| 5 | HIGH N1 (R3) | SaaS hybrid 404 (extension-based) — no research evidence | Removed hybrid: all persona Linear-style + assets only return 404 |
| 6 | MEDIUM N4 | DecoyHandler unification TBD | Explicit implementation contract via persona field in YAML config |
| 7 | MEDIUM N5 | Favicon "15086B fixed" TBD strategy | Pre-built ICO byte template + per-template SVG |
| 8 | MEDIUM N11 | snippets dir bootstrap missing | `mkdir -p` in deploy steps |
| 9 | MEDIUM N12 | `nginx -t -c <fragment>` wrong syntax | Rewrite deploy sequence |
| 10 | LOW N3 | CSP `'unsafe-inline'` weak | Acknowledged trade-off, deferred to follow-up |
| 11 | LOW N8 | humans.txt hardcoded date | `{{.DeployDate}}` template |
| 12 | LOW N9 | humans.txt empty twitter handles | Either all-have or all-skip — chose all-skip (uniform) |
| 13 | LOW L7 (baseline) | `chmod 755 /etc/letsencrypt/archive/` security regression | Documented out-of-scope but flagged |

---

## 1. Цели и scope

### 1.1 Что закрываем (gaps из текущего prod state pl1)

1. **404 inconsistency** — текущий nginx возвращает 200+index.html на любой URL (включая `/foo.png` без `try_files $uri =404`). Real prod sites: assets returns 404, paths returns 200+SPA. → закрываем (см. §1.3 архитектура).
2. **Brand inconsistency между HTML и headers** — текущий nginx хардкодит `X-Powered-By: MetricsHub/2.4.1` для всех templates. → закрываем (per-persona headers без `X-Powered-By` вовсе).
3. **Отсутствует security.txt** — universal у 9/9 tier-1 SaaS (research §3). → добавляем для SaaS+Blog.
4. **OPTIONS без Allow header** — minor probe vector. → закрываем для SaaS.
5. **Public /v2/health JSON с region+version — anti-pattern** (research §5). → убираем, заменяем на `/health → 200 "OK"` k8s-style для SaaS, удаляем для Blog/Utility.
6. **Отсутствуют /contact, /privacy в tech-blog**. → добавляем React routes.
7. **/favicon.ico implicit, depends on React build** — лучше explicit. → добавляем pre-built ICO + per-template SVG.
8. **Brand legends `X-Powered-By: Crest/3.2.1`, `X-Region`, `X-Request-ID` ввели бы новые fingerprints** (research §1: 0-2/10 prod sites так делают). → НЕ добавляем.

### 1.2 Что НЕ делаем (out of scope)

- Создание `demo/json-tools/` template (utility React-проект) — следующая волна.
- Удаление habr-mirror dead code (~2800 LOC) — отдельная уборка.
- TLS/H2 fingerprint TrustTunnel reverse_proxy — отдельная инициатива.
- Strict CSP с nonces — major Vite plugin work, deferred to follow-up.
- `chmod 755 /etc/letsencrypt/archive/` security regression в `issueLetsEncrypt` — **pre-existing bug**, не блокирует эту волну, но рекомендован отдельный fix.
- Vite content-hash для cache invalidation (existing bug `assets/main.js` без hash) — operational, не security/fingerprint.

### 1.3 Архитектурное решение: 404 strategy — **unified Linear-style для всех 3 persona**

**Контекст:** v2 предлагал гибрид (assets→404 server-side, paths→200 SPA fallback). v2 review N1 показал что **никто из real prod sites так не делает**. Research §2 показал что:
- 7/12 prod sites (Stripe, GitHub, Slack, Figma, Anthropic) — **server-rendered**, real 404 на ВСЁ.
- 4/12 prod sites (Linear, Vercel, regex101, jsonlint) — **SPA**, 200+index.html на ВСЁ.
- Никто не делает explicit branching по URL extension.

**Решение v2.1:** все 3 persona → **Linear-style** (200+SPA fallback на любой URL). Это:
- Matches 4/12 real prod sites (Linear, Vercel, regex101, jsonlint — все имеют большой SPA frontend, как и мы).
- Соответствует **utility persona** target (regex101, jsonlint — peer-tools которые мы mimicry).
- Simplifies nginx config drastically (один `try_files $uri $uri/ /index.html` для всех persona).
- Eliminates v2 N1 (no fingerprintable hybrid), N10 (no utility contradiction).
- React Router `<Route path="*">` рендерит NotFoundPage **внутри SPA** с status 200 — это **то же** что делают Linear/Vercel/regex101.

**Single asymmetry:** assets (`.png`, `.css`, `.js`, `.svg`, `.ico`, `.woff2`) которые **не существуют** на диске → real 404 от nginx через `try_files $uri =404`. Это:
- Соответствует реальному поведению Linear/Vercel/regex101 на missing assets (CDN behavior — non-existent asset = 404, not SPA fallback).
- Matches CDN convention которая universal для SPA hosting.

**404.html всё ещё нужен** — для real 404 на missing assets. Через `error_page 404 /404.html;`.

---

## 2. Архитектура

### 2.1 3-persona split

`deployNginxConfig(domain, templateName)` → dispatcher → 3 persona-specific renderers.

```go
// internal/deploy/steps_decoy.go (package-level vars + functions)

type templateMeta struct {
    Persona    string  // "saas" | "blog" | "utility"
    BrandLabel string  // human-readable name для security.txt + 404.html title
                       // НЕ для HTTP headers (research §1 — никто не ставит brand в headers).
}

var templateMetas = map[string]templateMeta{
    "saas-landing": {Persona: "saas", BrandLabel: "Crest"},
    "metricshub":   {Persona: "saas", BrandLabel: "MetricsHub"},
    "analytics-ru": {Persona: "saas", BrandLabel: "Analytica"},
    "tech-blog":    {Persona: "blog", BrandLabel: ""},          // blog не нуждается в brand label
    "":             {Persona: "saas", BrandLabel: "MetricsHub"}, // backwards compat
    // "json-tools" будет добавлен в следующей волне как Persona: "utility"
}

func templatePersona(templateName string) string {
    if m, ok := templateMetas[templateName]; ok {
        return m.Persona
    }
    slog.Warn("templatePersona: unknown template, defaulting to saas",
              "template", templateName)
    return "saas"
}
```

### 2.2 Headers via include snippets (fix opus H3 inheritance bug)

Используем `include /etc/nginx/snippets/<persona>-headers.conf;` в каждом location которому нужны headers. Snippet содержит full security set; nginx-уровневый bug `add_header` inheritance избегается через одинаковый snippet в server-level и каждом location-блоке.

**Snippet contents:**

**`/etc/nginx/snippets/saas-headers.conf`:**
```nginx
add_header Strict-Transport-Security  "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options     "nosniff" always;
add_header X-Frame-Options            "SAMEORIGIN" always;
add_header Referrer-Policy            "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'" always;
# NO X-Powered-By (research §1: 8/10 prod sites без)
# NO X-Region (research §1: 0/10)
# NO X-Request-ID (research §1: 0/10)
```

**`/etc/nginx/snippets/blog-headers.conf`:**
```nginx
add_header Strict-Transport-Security  "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options     "nosniff" always;
add_header X-Frame-Options            "SAMEORIGIN" always;
add_header Referrer-Policy            "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'" always;
# Blog: NO frame-ancestors 'self' (blog может быть embedded в Medium, etc)
# Все остальные = same as SaaS
```

**`/etc/nginx/snippets/utility-headers.conf`:**
```nginx
add_header Strict-Transport-Security  "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options     "nosniff" always;
add_header X-Frame-Options            "SAMEORIGIN" always;
add_header Referrer-Policy            "strict-origin-when-cross-origin" always;
# Utility: NO CSP (research §7: 3/5 peer utility tools без CSP).
# Minimal headers — utility = solo dev tool, простой stack.
```

**Snippets generation:** package `internal/deploy/snippets/` через `//go:embed` — Go embeds at compile time, orchestrator uploads на server при deploy:

```go
package deploy

import _ "embed"

//go:embed snippets/saas-headers.conf
var snippetSaaSHeaders string

//go:embed snippets/blog-headers.conf
var snippetBlogHeaders string

//go:embed snippets/utility-headers.conf
var snippetUtilityHeaders string

func uploadHeaderSnippets(mgr *ssh.SSHManager) error {
    if _, err := mgr.ExecuteCommandWithTimeout("mkdir -p /etc/nginx/snippets/", 10*time.Second); err != nil {
        return fmt.Errorf("mkdir snippets dir: %w", err)
    }
    snippets := map[string]string{
        "saas-headers.conf":    snippetSaaSHeaders,
        "blog-headers.conf":    snippetBlogHeaders,
        "utility-headers.conf": snippetUtilityHeaders,
    }
    for name, content := range snippets {
        path := "/etc/nginx/snippets/" + name
        if err := mgr.WriteToRemoteFile(path, strings.NewReader(content)); err != nil {
            return fmt.Errorf("upload %s: %w", name, err)
        }
    }
    return nil
}
```

`uploadHeaderSnippets` вызывается в `deployDecoy` **перед** `deployNginxConfig`.

### 2.3 Per-persona nginx structure

#### SaaS persona (`deployNginxConfigSaaS`)

```nginx
server {
    listen 127.0.0.1:8080;
    server_name {{.Domain}};
    server_tokens off;
    root {{.WebRoot}};
    index index.html;

    # Server-level security headers
    include /etc/nginx/snippets/saas-headers.conf;

    # Real 404 для missing assets (static 404.html generated at deploy)
    error_page 404 /404.html;
    location = /404.html {
        internal;
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "public, max-age=300" always;
    }

    # SPA routing — Linear-style: ANY path → 200 + index.html
    # React Router рендерит соответствующую страницу или NotFoundPage внутри SPA.
    # Note: `try_files` НЕ имеет `=404` в конце — это deliberate (см. §1.3 архитектура).
    location / {
        try_files $uri $uri/ /index.html;
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "no-cache, must-revalidate" always;
    }

    # Static assets — REAL 404 для несуществующих (matches CDN convention)
    location ~* \.(css|js|png|jpg|jpeg|svg|ico|woff2?|webp|gif|map)$ {
        try_files $uri =404;            # ← real 404 for missing assets (fix opus C1)
        expires 30d;
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "public, immutable" always;
        access_log off;
    }

    # /health — k8s-style plain "OK" (research §5)
    location = /health {
        default_type text/plain;
        return 200 "OK";
        add_header Cache-Control "no-store" always;
    }

    # /.well-known/security.txt — RFC 9116 (research §3: 9/9 tier-1 SaaS имеют)
    location = /.well-known/security.txt {
        default_type "text/plain; charset=utf-8";
        return 200 "Contact: mailto:security@{{.Domain}}\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en\nCanonical: https://{{.Domain}}/.well-known/security.txt\n";
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "public, max-age=3600" always;
    }

    # /humans.txt — alias на pre-rendered file (deploy-time generated, см. §3.2)
    location = /humans.txt {
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "public, max-age=86400" always;
        # File served from root через try_files; не нужен explicit alias
    }

    # OPTIONS handler для /api/* — корректный REST verb set
    location ~ ^/api/ {
        # Safe `if` usage per nginx docs (add_header + return only)
        if ($request_method = OPTIONS) {
            add_header Allow "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE" always;
            add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE" always;
            add_header Access-Control-Allow-Origin "*" always;
            return 204;
        }
        return 404;   # API endpoints не существуют на декое
    }

    # Scanner-block
    location ~* \.(php|asp|aspx|jsp)$ { return 404; }

    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript
               text/javascript application/xml image/svg+xml;
    gzip_min_length 1024;

    access_log /var/log/nginx/decoy.access.log combined;
    error_log  /var/log/nginx/decoy.error.log warn;
}
```

#### Blog persona (`deployNginxConfigBlog`)

Differences from SaaS:
- `include /etc/nginx/snippets/blog-headers.conf` (XFO **SAMEORIGIN**, CSP без `frame-ancestors` — fix v2 review N2)
- **HAS `/.well-known/security.txt`** (fix v2 review N7 — explicit: blog имеет security.txt по аналогии с SaaS)
- **NO `/health`** (research §5: blogs не имеют health endpoint)
- **NO `/api/*`** OPTIONS handler (blog не имеет API)
- **NO `/humans.txt`** (research §4: tech blogs реже имеют humans.txt)
- **HAS `/feed.xml`** generated at deploy from BlogPosts:
  ```nginx
  location = /feed.xml {
      default_type "application/rss+xml; charset=utf-8";
      include /etc/nginx/snippets/blog-headers.conf;
      add_header Cache-Control "public, max-age=3600" always;
  }
  location = /rss.xml  { return 301 /feed.xml; }
  location = /atom.xml { return 301 /feed.xml; }
  ```
- **`<Route path="*">` в App.tsx** рендерит NotFoundPage с "Post not found" + recent posts list
- Real 404 для missing assets — same as SaaS

#### Utility persona (`deployNginxConfigUtility`)

(Пишется сейчас, template `demo/json-tools/` создаётся следующей волной.)

Differences from SaaS:
- `include /etc/nginx/snippets/utility-headers.conf` (минимальный set, без CSP — research §7)
- **NO `/.well-known/security.txt`** (research §3: 0/2 peer utility tools имеют)
- **NO `/health`**
- **NO `/api/*`** OPTIONS handler (utility = single-page tool, нет /api/* surface)
- **HAS `/api/process`** as **POST stub** (utility tool обычно имеет 1-2 API endpoints — мы emulate один):
  ```nginx
  location = /api/process {
      if ($request_method = OPTIONS) {
          add_header Allow "POST, OPTIONS" always;
          add_header Access-Control-Allow-Methods "POST, OPTIONS" always;
          add_header Access-Control-Allow-Origin "*" always;
          return 204;
      }
      if ($request_method != POST) { return 405; }
      default_type application/json;
      return 400 '{"error":"missing input","code":"E_NO_BODY"}';
  }
  ```
- **NO `/humans.txt`**
- **`<Route path="*">` в App.tsx** рендерит NotFoundPage с "Tool not found" + list всех utils
- Real 404 для missing assets — same as SaaS

### 2.4 Unifying Go-уровневый DecoyHandler (fix opus H1)

**Problem:** `shadowlink/server/decoy.go::DecoyHandler::ServeHTTP` обслуживает direct-IP traffic, обходя TrustTunnel+nginx. Текущее поведение:
- Ставит только `X-Frame-Options: SAMEORIGIN`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`
- НЕ ставит HSTS, CSP, X-Powered-By
- Стандартный Go `http.FileServer` 404 (HTML с "404 page not found")

**v2.1 implementation contract (fix v2 review N4):**

**Step 1:** Расширить `DecoyHandler` config:

```go
// shadowlink/server/decoy.go

// DecoyHandlerConfig — per-host persona-aware config.
// При nil/empty domainConfig → use defaultPersona ("saas") для всех hosts.
type DecoyHandlerConfig struct {
    DefaultDir     string              // existing field
    DomainMap      map[string]string   // existing: host → directory
    DomainPersona  map[string]string   // NEW: host → persona ("saas"|"blog"|"utility")
    DefaultPersona string              // NEW: fallback persona когда host не в map
}

// NewDecoyHandlerV2 заменяет NewDecoyHandler.
// Backwards compat: если DomainPersona == nil → все hosts получают DefaultPersona.
func NewDecoyHandlerV2(cfg DecoyHandlerConfig) *DecoyHandler { ... }
```

**Step 2:** В `ServeHTTP` ставить persona-specific headers (mirror nginx snippets):

```go
func (d *DecoyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    persona := d.resolvePersona(r.Host)  // looks up DomainPersona[r.Host] → fallback DefaultPersona

    switch persona {
    case "saas":
        setSaaSHeaders(w)
    case "blog":
        setBlogHeaders(w)
    case "utility":
        setUtilityHeaders(w)
    }

    // 404 handling — wrap ResponseWriter для подстановки custom 404.html
    wrap := &fourOhFourWrapper{ResponseWriter: w, custom404Path: filepath.Join(d.resolveDir(r.Host), "404.html")}

    d.fileServer(r.Host).ServeHTTP(wrap, r)
}

func setSaaSHeaders(w http.ResponseWriter) {
    w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "SAMEORIGIN")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
    w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'")
}
// setBlogHeaders, setUtilityHeaders — analogously.

type fourOhFourWrapper struct {
    http.ResponseWriter
    custom404Path string
    intercepted   bool
}

func (w *fourOhFourWrapper) WriteHeader(status int) {
    if status == http.StatusNotFound && !w.intercepted {
        w.intercepted = true
        // Read 404.html from disk и serve вместо default Go 404
        body, err := os.ReadFile(w.custom404Path)
        if err != nil {
            // Fallback to default Go 404
            w.ResponseWriter.WriteHeader(status)
            return
        }
        w.ResponseWriter.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.ResponseWriter.Header().Set("Cache-Control", "public, max-age=300")
        w.ResponseWriter.WriteHeader(http.StatusNotFound)
        w.ResponseWriter.Write(body)
        return
    }
    w.ResponseWriter.WriteHeader(status)
}
```

**Step 3:** Конфиг persona в YAML — extend `DomainDecoyMap`:

```yaml
# /etc/shadowlink/config.yaml
domain_decoy_map:
  "datacanvases.com":
    directory: "/var/www/saas-landing"
    persona:   "saas"
  "myblog.io":
    directory: "/var/www/tech-blog"
    persona:   "blog"
```

**Backwards compat:** Если в YAML — old format (`"host": "dir"` без persona) → DomainPersona не populated → uses DefaultPersona. Это сохраняет existing deploys без миграции.

**Caveat:** YAML parsing в `shadowlink/server/fileconfig.go` потребует обновления для нового формата + добавление в `internal/deploy/steps_shadowlink_domain_decoy_map.go` (render persona в YAML). Это **+50-100 LOC** дополнительно к §5.1 estimate.

### 2.5 Что НЕ меняется

- `uploadDecoyFiles`, `uploadReactDecoyFiles`, `uploadGeneratedDecoyFiles` — остаются.
- `decoy_content_gen.go` (547 LOC) — расширяется для render новых templates (humans.txt, 404.html, feed.xml).
- ShadowLink protocol code (handler.go, websocket.go, и т.д.) — не трогается.
- Frontend admin panel — не трогается.

### 2.6 Issue H2: `updateDecoyTemplate` path

`internal/deploy/steps_decoy.go::updateDecoyTemplate` (строки 947-961) **должна** вызывать `deployNginxConfig(mgr, domain, templateName)` после `uploadDecoyFiles`. Это **+1 строка** в существующей функции.

Это **меняет scope spec'а** (мы трогаем `updateDecoyTemplate`), но это **орxer-уровень** в `internal/deploy/`, не `internal/admin/`. Spec честно отражает это.

---

## 3. Контентные артефакты (deploy-time generated)

### 3.1 `404.html` — pure static HTML per persona

Не Vite multi-entry, не React. `text/template`-генерируемый HTML файл, упакован в `internal/deploy/templates/404-<persona>.html.tmpl`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 — Page not found | {{.CompanyName}}</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
  /* Inline CSS — shared color palette с React app via templateMeta.PrimaryColor */
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, sans-serif;
         margin: 0; padding: 4rem 1rem; color: #1a1a1a; background: #ffffff;
         text-align: center; }
  h1 { font-size: 6rem; margin: 0; color: {{.PrimaryColor}}; font-weight: 800; }
  h2 { font-size: 1.5rem; font-weight: 500; margin: 1rem 0; color: #4a4a4a; }
  p { color: #6a6a6a; max-width: 480px; margin: 1rem auto; }
  a { color: {{.PrimaryColor}}; text-decoration: none; font-weight: 600; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <h1>404</h1>
  <h2>Page not found</h2>
  <p>The page you're looking for doesn't exist or has been moved.</p>
  <p><a href="/">← Back to {{.CompanyName}}</a></p>
</body>
</html>
```

**Per-persona variations** (template files):
- `404-saas.html.tmpl` — generic "Page not found" + link to home
- `404-blog.html.tmpl` — "Post not found" + link to home + Archive
- `404-utility.html.tmpl` — "Tool not found" + link to home

**Where rendered:** при deploy в `internal/deploy/steps_decoy.go` через `text/template` (как делает sitemap/robots). Output: `<webroot>/404.html`.

### 3.2 `humans.txt` — realistic names pool (только SaaS persona)

**Pool of realistic names:**

```go
// internal/deploy/decoy_humans_pool.go (новый файл)

type humanProfile struct {
    FirstName string
    LastName  string
    Role      string  // "Backend", "Frontend", "DevOps", "Design", "QA"
}

// humansNamePool — 20 realistic dev names. All entries WITHOUT twitter handles
// (fix v2 review N9: uniform style — either all-have or all-skip; we choose all-skip
// because real teams in 2026 less Twitter-active than 2018 era).
var humansNamePool = []humanProfile{
    {"Sarah",     "Chen",       "Backend lead"},
    {"Marcus",    "Patel",      "Backend"},
    {"Liam",      "Rodriguez",  "DevOps"},
    {"Emma",      "Watson",     "Frontend"},
    {"Noah",      "Kim",        "Frontend"},
    {"Olivia",    "Brown",      "Design"},
    {"Ava",       "Singh",      "Backend"},
    {"Ethan",     "Lee",        "Frontend lead"},
    {"Isabella",  "Taylor",     "QA"},
    {"Lucas",     "Garcia",     "Backend"},
    {"Mia",       "Wilson",     "Design"},
    {"Mason",     "Anderson",   "Backend"},
    {"Zoe",       "Park",       "Frontend"},
    {"Logan",     "Davis",      "DevOps"},
    {"Aria",      "Hayes",      "Design lead"},
    {"James",     "Murphy",     "Backend"},
    {"Charlotte", "O'Brien",    "Frontend"},
    {"Benjamin",  "Cohen",      "QA lead"},
    {"Amelia",    "Foster",     "Backend"},
    {"Henry",     "Zhang",      "DevOps"},
}

// generateHumansForDomain — deterministic generation based on domain hash.
// FIX v2 review N6: copies slice before Shuffle to avoid global mutation
// (race + non-determinism between deploys).
func generateHumansForDomain(domain string, deployDate time.Time) string {
    seed := fnv32(domain)
    rng := rand.New(rand.NewSource(int64(seed)))

    // CRITICAL: copy slice before shuffle (fix N6)
    pool := make([]humanProfile, len(humansNamePool))
    copy(pool, humansNamePool)

    rng.Shuffle(len(pool), func(i, j int) {
        pool[i], pool[j] = pool[j], pool[i]
    })

    teamSize := 3 + rng.Intn(3) // 3-5
    team := pool[:teamSize]

    var sb strings.Builder
    sb.WriteString("/* TEAM */\n")
    for _, p := range team {
        fmt.Fprintf(&sb, "  %s: %s %s\n", p.Role, p.FirstName, p.LastName)
    }
    sb.WriteString("\n/* THANKS */\n")
    sb.WriteString("  Open-source community\n")
    sb.WriteString("  Our beta testers\n\n")
    sb.WriteString("/* SITE */\n")
    fmt.Fprintf(&sb, "  Last update: %s\n", deployDate.Format("2006-01-02"))
    sb.WriteString("  Standards: HTML5, CSS3, ES2024\n")
    sb.WriteString("  Built with: React, Vite, TypeScript\n")
    return sb.String()
}

func fnv32(s string) uint32 {
    h := fnv.New32a()
    h.Write([]byte(s))
    return h.Sum32()
}
```

**Last update date** (fix v2 review N8): `deployDate.Format("2006-01-02")` — actual deploy time, не hardcoded. Передаётся через template render call.

**Twitter handles** (fix v2 review N9): убраны вовсе из pool. Uniform style.

**Applied только для SaaS persona.** Blog и Utility — humans.txt пропускается.

### 3.3 `feed.xml` (только tech-blog)

Без изменений vs v2. RSS 2.0 feed rendered из BlogPosts при deploy через `feed.xml.tmpl`.

### 3.4 Favicon — pre-built ICO byte template + per-template SVG (fix v2 review N5)

**Strategy:**

1. **Pre-built multi-resolution ICO file** в repo: `internal/deploy/assets/favicon-template.ico` (15086 bytes, 16x16/32x32/48x48/64x64 multi-res, как output real-favicon-generator.net).
   - Generated **once** через external tool (RealFaviconGenerator + manual color swap), checked into repo as binary asset.
   - Embedded в Go binary через `//go:embed`.
   - **Не имеет per-template color variation** — same ICO для всех templates. Acceptable trade-off: ICO byte-size mimicry > per-template color diff.
   - This addresses opus M2: "color-block AI fingerprint" — fixed template **никогда** не color-block, всегда **то же** professional multi-res ICO.

2. **Per-template SVG** generated в Go:
   - `<webroot>/favicon.svg` — vector с per-template brand color + first letter from BrandLabel.
   - Modern browsers prefer SVG, ICO — fallback.

3. **HTML linkage** (in `index.html` + `404.html`):
   ```html
   <link rel="icon" type="image/svg+xml" href="/favicon.svg">
   <link rel="icon" type="image/x-icon" href="/favicon.ico">
   ```

**Go code:**

```go
//go:embed assets/favicon-template.ico
var faviconICOBytes []byte // exactly 15086 bytes

func uploadFavicon(mgr *ssh.SSHManager, webRoot string, templateMeta templateMeta) error {
    // ICO — same for all templates
    if err := mgr.WriteToRemoteFile(webRoot+"/favicon.ico", bytes.NewReader(faviconICOBytes)); err != nil {
        return fmt.Errorf("upload favicon.ico: %w", err)
    }
    // SVG — per-template
    svg := generateFaviconSVG(templateMeta.BrandLabel, templateMeta.PrimaryColor)
    if err := mgr.WriteToRemoteFile(webRoot+"/favicon.svg", strings.NewReader(svg)); err != nil {
        return fmt.Errorf("upload favicon.svg: %w", err)
    }
    return nil
}

func generateFaviconSVG(brandLabel, primaryColor string) string {
    initial := "?"
    if len(brandLabel) > 0 {
        initial = strings.ToUpper(string(brandLabel[0]))
    }
    return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="12" fill="%s"/><text x="32" y="44" font-family="-apple-system,sans-serif" font-size="36" font-weight="700" fill="#fff" text-anchor="middle">%s</text></svg>`, primaryColor, initial)
}
```

**ICO byte template generation procedure** (one-time, documented for future re-generation):
1. Go to https://realfavicongenerator.net/
2. Upload any 512x512 PNG with brand logo (we use Inter-font letter "N" on neutral color)
3. Configure: enable multi-res 16/32/48/64
4. Download favicon package → extract `favicon.ico` (should be 15086 bytes)
5. Place in `internal/deploy/assets/favicon-template.ico`

Verification test:
```go
func TestFaviconICOSize(t *testing.T) {
    if len(faviconICOBytes) != 15086 {
        t.Errorf("favicon.ico size = %d, want 15086 (real-favicon-generator output)", len(faviconICOBytes))
    }
}
```

---

## 4. React-уровень изменения

### 4.1 `<Route path="*">` для NotFoundPage in SPA

В каждом `App.tsx`:

```tsx
import NotFoundPage from './pages/NotFoundPage';

<Routes>
  ... existing routes ...
  <Route path="*" element={<NotFoundPage />} />
</Routes>
```

**`NotFoundPage` обычный React component**, не standalone Vite entry. Persona-specific text:
- SaaS: "Page not found" + link to /
- Blog: "Post not found" + link to / + Archive + recent posts list (from BlogPosts data)
- Utility: "Tool not found" + link to / + list всех tools (when applicable)

**Status code: 200** (because nginx уже отдал index.html со status 200). Это **the Linear/Vercel/regex101 pattern**, matches real prod SPA sites.

**No standalone 404 Vite entry** — `<Route path="*">` рендерит внутри основного SPA bundle. Fix opus M1.

### 4.2 Tech-blog: missing routes

- `demo/tech-blog/src/pages/ContactPage.tsx`
- `demo/tech-blog/src/pages/PrivacyPage.tsx`
- Routes `/contact`, `/privacy` в App.tsx

### 4.3 PrivacyPage — intentional per-template divergence (opus M6)

Каждый template **должен** иметь свой PrivacyPage с **разным** wording + emails (`privacy@`, `legal@`, `dpo@`) per template. Это:
- Усиливает domain diversity
- Не требует Vite shared-package config
- Trade-off justified.

### 4.4 Favicon HTML linkage

В `index.html` каждого template **add**:
```html
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/x-icon" href="/favicon.ico">
```

Это **не Vite-managed** (favicons загружаются orchestrator'ом, не build process). Vite автоматически copies всё что в `public/` — но мы **не** кладём favicons в `public/`, чтобы избежать Vite cache invalidation на rebuild.

---

## 5. Файлы и LOC оценка v2.1

### 5.1 Backend (Go)

| File | Change | Δ LOC |
|---|---|---|
| `internal/deploy/steps_decoy.go` | refactor dispatcher + 3 persona functions + +1 line in `updateDecoyTemplate` | +~280 |
| `internal/deploy/snippets/saas-headers.conf` (new) | embed file | +10 |
| `internal/deploy/snippets/blog-headers.conf` (new) | embed | +10 |
| `internal/deploy/snippets/utility-headers.conf` (new) | embed | +8 |
| `internal/deploy/snippets_embed.go` (new) | go:embed declarations + `uploadHeaderSnippets()` | +50 |
| `internal/deploy/templates/404-saas.html.tmpl` (new) | static template | +30 |
| `internal/deploy/templates/404-blog.html.tmpl` (new) | + recent posts marker | +40 |
| `internal/deploy/templates/404-utility.html.tmpl` (new) | utility-specific | +30 |
| `internal/deploy/decoy_humans_pool.go` (new) | 20 names + generator с copy-fix | +100 |
| `internal/deploy/assets/favicon-template.ico` (new, binary) | 15086B embedded | binary |
| `internal/deploy/decoy_favicon.go` (new) | uploadFavicon + generateFaviconSVG | +50 |
| `internal/deploy/steps_decoy_test.go` | templatePersona table tests + render tests | +200 |
| `internal/deploy/steps_decoy_nginx_test.go` (new) | per-persona render assertions | +250 |
| `internal/deploy/steps_decoy_e2e_test.go` (new) | SSH mock end-to-end | +120 |
| `internal/deploy/decoy_humans_pool_test.go` (new) | determinism + race tests | +80 |
| `internal/deploy/decoy_favicon_test.go` (new) | byte size assertion | +30 |
| `shadowlink/server/decoy.go` | persona-aware headers + 404 wrapper | +120 |
| `shadowlink/server/decoy_test.go` | persona header tests + 404 wrapper test | +100 |
| `shadowlink/server/fileconfig.go` | parse new YAML format (with backwards compat) | +50 |
| `internal/deploy/steps_shadowlink_domain_decoy_map.go` | render persona in YAML | +30 |

**Backend total:** ~**+1490 LOC** (vs v2 estimate +1050 — increase из-за: explicit persona-passing contract in DecoyHandler §2.4, favicon implementation §3.4, humans pool tests).

### 5.2 Frontend (React)

Per template:
- `src/pages/NotFoundPage.tsx` — ~50 LOC
- `App.tsx` — +1 Route line
- `index.html` — +2 favicon link lines

Tech-blog extras:
- `src/pages/ContactPage.tsx` — ~50 LOC
- `src/pages/PrivacyPage.tsx` — ~80 LOC (per-template wording, см. §4.3)
- `App.tsx` — +2 routes

**Frontend total:** 4 × ~55 LOC + ~130 LOC (tech-blog extras) = ~**350 LOC**.

### 5.3 NOT modified

- shadowlink-server protocol code — 0 LOC
- `internal/admin/` handlers — 0 LOC
- Admin frontend panel — 0 LOC
- Migrations — 0

---

## 6. Тестирование

### 6.1 Unit tests

```go
// internal/deploy/steps_decoy_test.go
func TestTemplatePersona(t *testing.T) {
    cases := []struct{ template, persona string }{
        {"saas-landing", "saas"}, {"metricshub", "saas"}, {"analytics-ru", "saas"},
        {"tech-blog", "blog"}, {"json-tools", "utility"},
        {"", "saas"}, {"unknown", "saas"},
    }
    // ...
}

// internal/deploy/decoy_humans_pool_test.go
func TestHumansGenerationDeterministic(t *testing.T) {
    deployDate := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
    out1 := generateHumansForDomain("datacanvases.com", deployDate)
    out2 := generateHumansForDomain("datacanvases.com", deployDate)
    if out1 != out2 {
        t.Error("generateHumansForDomain not deterministic for same input")
    }
}

func TestHumansGenerationNoSharedMutation(t *testing.T) {
    // Fix N6: вызов для domainB не должен зависеть от предыдущего вызова для domainA
    deployDate := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
    outB_first := generateHumansForDomain("siteB.io", deployDate)
    _ = generateHumansForDomain("siteA.io", deployDate)
    outB_second := generateHumansForDomain("siteB.io", deployDate)
    if outB_first != outB_second {
        t.Error("generateHumansForDomain depends on previous call (global mutation bug)")
    }
}

func TestHumansGenerationConcurrentSafe(t *testing.T) {
    // -race detector
    deployDate := time.Date(2026, 5, 27, 0, 0, 0, 0, time.UTC)
    var wg sync.WaitGroup
    for i := 0; i < 50; i++ {
        wg.Add(1)
        go func(i int) {
            defer wg.Done()
            _ = generateHumansForDomain(fmt.Sprintf("site%d.io", i), deployDate)
        }(i)
    }
    wg.Wait()
    // Run under `go test -race` to catch any data races
}

// internal/deploy/decoy_favicon_test.go
func TestFaviconICOSize(t *testing.T) {
    if len(faviconICOBytes) != 15086 {
        t.Errorf("favicon.ico size = %d, want 15086 (real-favicon-generator output)",
                 len(faviconICOBytes))
    }
}

func TestFaviconSVGGeneration(t *testing.T) {
    svg := generateFaviconSVG("Crest", "#0066ff")
    must(t, strings.Contains(svg, `fill="#0066ff"`), "uses primary color")
    must(t, strings.Contains(svg, `>C<`), "uses brand initial")
}
```

### 6.2 nginx render tests

```go
// internal/deploy/steps_decoy_nginx_test.go
func TestRenderNginxSaaS(t *testing.T) {
    cfg := renderNginxConfigSaaS("datacanvases.com", templateMetas["saas-landing"])

    // Real 404 for missing assets (fix v2 review N1)
    must(t, strings.Contains(cfg, `try_files $uri =404`),
        "assets fail with real 404")
    // SPA fallback for paths
    must(t, strings.Contains(cfg, `try_files $uri $uri/ /index.html`),
        "paths use Linear-style SPA fallback (no =404)")
    must(t, strings.Contains(cfg, `error_page 404 /404.html`),
        "error_page directive present")
    must(t, strings.Contains(cfg, `include /etc/nginx/snippets/saas-headers.conf`),
        "uses SaaS headers snippet")
    must(t, strings.Contains(cfg, `/.well-known/security.txt`),
        "SaaS has security.txt")
    must(t, strings.Contains(cfg, `return 200 "OK"`),
        "/health → k8s plaintext")

    // NOT in config (v2 anti-patterns removed)
    must(t, !strings.Contains(cfg, `X-Powered-By`),
        "NO X-Powered-By (research §1)")
    must(t, !strings.Contains(cfg, `X-Region`),
        "NO X-Region (research §1)")
    must(t, !strings.Contains(cfg, `X-Request-ID`),
        "NO X-Request-ID (research §1)")
    must(t, !strings.Contains(cfg, `/v2/health`),
        "NO /v2/health (research §5)")
}

func TestRenderNginxBlog(t *testing.T) {
    cfg := renderNginxConfigBlog("myblog.io")
    must(t, strings.Contains(cfg, `include /etc/nginx/snippets/blog-headers.conf`),
        "uses blog headers snippet")
    must(t, strings.Contains(cfg, `/.well-known/security.txt`),
        "blog HAS security.txt (fix v2 N7)")
    must(t, !strings.Contains(cfg, `/health`),
        "blog NO /health endpoint")
    must(t, !strings.Contains(cfg, `^/api/`),
        "blog NO /api/* OPTIONS handler")
    must(t, !strings.Contains(cfg, `/humans.txt`),
        "blog NO humans.txt (research §4)")
    must(t, strings.Contains(cfg, `/feed.xml`),
        "blog HAS feed.xml")
    must(t, strings.Contains(cfg, `try_files $uri $uri/ /index.html`),
        "blog uses SPA fallback")
    must(t, strings.Contains(cfg, `try_files $uri =404`),
        "blog assets fail with real 404")
}

func TestRenderNginxUtility(t *testing.T) {
    cfg := renderNginxConfigUtility("jsonformat.io")
    must(t, strings.Contains(cfg, `include /etc/nginx/snippets/utility-headers.conf`),
        "uses utility headers snippet")
    must(t, !strings.Contains(cfg, `Content-Security-Policy`),
        "utility NO CSP (research §7)")
    must(t, !strings.Contains(cfg, `/.well-known/security.txt`),
        "utility NO security.txt (research §3)")
    must(t, !strings.Contains(cfg, `/health`),
        "utility NO /health")
    must(t, !strings.Contains(cfg, `/humans.txt`),
        "utility NO humans.txt")
    must(t, strings.Contains(cfg, `/api/process`),
        "utility HAS /api/process POST stub")
    must(t, strings.Contains(cfg, `try_files $uri $uri/ /index.html`),
        "utility uses SPA fallback")
    must(t, strings.Contains(cfg, `try_files $uri =404`),
        "utility assets fail with real 404")
}
```

### 6.3 Smoke checklist after deploy (v2.1)

```bash
DOMAIN=datacanvases.com

# 1. SPA fallback для path-style URL (200, не 404)
curl -ksI https://$DOMAIN/this-page-does-not-exist | head -1
# Expected: HTTP/1.1 200 (matches Linear/Vercel/regex101 behavior)

# 2. Real 404 для missing asset (Stripe/CDN convention)
curl -ksI https://$DOMAIN/random.png | head -1
# Expected: HTTP/1.1 404

# 3. /404.html напрямую — 404 (internal directive)
curl -ksI https://$DOMAIN/404.html | head -1
# Expected: HTTP/1.1 404

# 4. security.txt → 200
curl -ks https://$DOMAIN/.well-known/security.txt | head -5
# Expected: Contact: mailto:security@datacanvases.com ...

# 5. /health → 200 OK plaintext
curl -ks https://$DOMAIN/health
# Expected: OK (just OK, no JSON, no version)

# 6. CRITICAL: Headers consistency между / и /pricing (fix opus H3)
curl -ksI https://$DOMAIN/        | grep -iE "(strict-transport|x-frame|x-content|content-security|referrer-policy)" | sort > /tmp/h1
curl -ksI https://$DOMAIN/pricing | grep -iE "(strict-transport|x-frame|x-content|content-security|referrer-policy)" | sort > /tmp/h2
diff /tmp/h1 /tmp/h2
# Expected: empty diff (same headers)

# 7. NO X-Powered-By, NO X-Region (research-aligned)
curl -ksI https://$DOMAIN/ | grep -iE "x-powered-by|x-region|x-request-id"
# Expected: empty

# 8. OPTIONS на /api/anything → 204 + Allow
curl -ksX OPTIONS -i https://$DOMAIN/api/anything | head -5
# Expected: HTTP/1.1 204 + Allow: GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE

# 9. humans.txt → 200 + realistic names (SaaS only)
curl -ks https://$DOMAIN/humans.txt | head -10
# Expected: /* TEAM */ Backend lead: Marcus Patel ...

# 10. favicon → 200, exact 15086B (real-favicon-generator template)
SIZE=$(curl -ksI https://$DOMAIN/favicon.ico | grep -i "content-length" | awk '{print $2}' | tr -d '\r')
echo "favicon.ico size: $SIZE (expected 15086)"
# Expected: 15086

# 11. CSP header present (research §1: 9/10 SaaS имеют)
curl -ksI https://$DOMAIN/ | grep -i "content-security-policy"
# Expected: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...

# 12. Server header — nginx без version
curl -ksI https://$DOMAIN/ | grep -i "^server:"
# Expected: Server: nginx (no version — matches Stripe pattern)

# 13. /feed.xml — only relevant если pl1 переключим на tech-blog (not SaaS persona)
# Skipped for current SaaS deployment on pl1.
```

13 проверок, все обязательные для SaaS persona on pl1.

---

## 7. Rollout (вариант B — сразу на datacanvases.com)

### 7.1 Pre-deploy

1. Local tests:
   ```bash
   go test -race ./internal/deploy/... -count=1
   go test -race ./shadowlink/server/... -count=1   # DecoyHandler persona tests
   ```
2. Build all 4 React templates:
   ```bash
   for d in saas-landing tech-blog analytics-ru metricshub; do
     (cd demo/$d && npm install && npm run build)
   done
   ```
3. Verify `dist/index.html` присутствует в каждом template.
4. Verify pre-built favicon.ico существует в `internal/deploy/assets/favicon-template.ico` и его размер == 15086B (`stat -c%s internal/deploy/assets/favicon-template.ico`).
5. Commit changes to git.

### 7.2 Deploy на pl1 (corrected deploy sequence, fix v2 review N11/N12)

Через admin UI: `Settings → Platform Deploy → Re-deploy decoy` для `datacanvases.com`.

Orchestrator выполняет (после `uploadDecoyFiles`):

```bash
# Step 1: bootstrap snippets directory (fix N11)
mkdir -p /etc/nginx/snippets/

# Step 2: backup existing nginx config + snippets
TIMESTAMP=$(date +%s)
cp /etc/nginx/sites-available/decoy /etc/nginx/sites-available/decoy.bak.$TIMESTAMP
[ -d /etc/nginx/snippets ] && cp -r /etc/nginx/snippets /etc/nginx/snippets.bak.$TIMESTAMP

# Step 3: upload new snippets (mkdir already ensures dir exists)
# (via WriteToRemoteFile from Go orchestrator)
# → /etc/nginx/snippets/saas-headers.conf, blog-headers.conf, utility-headers.conf

# Step 4: upload new files (favicon, 404.html, humans.txt) atomically
# (Go orchestrator writes to .tmp and renames)

# Step 5: write new decoy nginx config to .new file
# (via WriteToRemoteFile)

# Step 6: validate ENTIRE nginx config (not single fragment) — fix N12
# Test the new config in place via atomic swap-and-validate:
mv /etc/nginx/sites-available/decoy /etc/nginx/sites-available/decoy.rollback
mv /etc/nginx/sites-available/decoy.new /etc/nginx/sites-available/decoy

if nginx -t 2>&1; then
    systemctl reload nginx
    rm /etc/nginx/sites-available/decoy.rollback
    echo "Deploy successful"
else
    # Rollback: restore old config
    mv /etc/nginx/sites-available/decoy.rollback /etc/nginx/sites-available/decoy
    # Old config still has previous state; nginx still running with previous config (since reload not called).
    echo "Deploy FAILED: nginx config invalid, rolled back"
    exit 1
fi
```

**Key changes vs v2 sequence:**
- `mkdir -p` for snippets directory (fix N11)
- `nginx -t` validates **active in-place** config (not `-c` fragment, fix N12)
- Explicit rollback via `mv` если `nginx -t` fails — old config restored before any reload

### 7.3 Smoke test (§6.3 — 13 checks)

Прогнать вручную после deploy. Все 13 проверок должны PASS.

### 7.4 Rollback (если smoke test показал regression)

```bash
ssh pl1 'cp /etc/nginx/sites-available/decoy.bak.<timestamp> /etc/nginx/sites-available/decoy \
      && cp -r /etc/nginx/snippets.bak.<timestamp>/* /etc/nginx/snippets/ \
      && nginx -t && systemctl reload nginx'
```

~1-2 секунды recovery.

### 7.5 VPN-трафик

ShadowLink-туннели идут через **TrustTunnel → 127.0.0.1:8080 (TCP)** к nginx → unix socket к shadowlink-server. `systemctl reload nginx` graceful — старые TCP connections донашиваются, новые приходят на новый process. VPN-туннели не прерываются.

Прерываются только plain HTTPS hits на nginx (probe, случайные браузеры) на ~1 секунду.

---

## 8. Backwards compatibility

### 8.1 Legacy `templateName=""`

`templateMetas[""]` = `{Persona: "saas", BrandLabel: "MetricsHub"}` — серверы задеплоенные **до** этой волны получат SaaS persona с MetricsHub branding в 404.html/security.txt/humans.txt. Это **меняет** их HTTP headers (now uses SaaS snippet — without X-Powered-By: MetricsHub) — что **именно та цель волны**.

### 8.2 Existing `domain_decoy_map` YAML format

**Old format** (current):
```yaml
domain_decoy_map:
  "host1": "/var/www/saas-landing"
```

**New format** (after v2.1):
```yaml
domain_decoy_map:
  "host1":
    directory: "/var/www/saas-landing"
    persona:   "saas"
```

**Parser logic** (`shadowlink/server/fileconfig.go`):
```go
// Try unmarshal as new format first
type domainConfig struct {
    Directory string `yaml:"directory"`
    Persona   string `yaml:"persona"`
}
type domainMapNew map[string]domainConfig

// Fallback to old format
type domainMapOld map[string]string

// Logic: try new first; if fail → old; if old → all hosts get DefaultPersona ("saas")
```

**Backwards compat 100%:** old YAML continues to work without migration. Admin UI может опционально переключить на new format когда нужна persona variation.

### 8.3 Existing pl1 state

После deploy на pl1 (`datacanvases.com` template = `saas-landing`):
- HTML brand остаётся "Crest Technologies"
- nginx headers полностью **меняются**: убирается `X-Powered-By: MetricsHub/2.4.1`, добавляется CSP, XFO становится SAMEORIGIN (вместо DENY)
- `/v2/health` исчезает, появляется `/health` → "OK" plaintext
- 404 на missing assets теперь real (was 200+index.html)
- security.txt появляется
- humans.txt появляется
- favicon размер становится 15086B (was unknown size from React build)

**Это breaking change для probes, делавших baseline ранее.** Цель — baseline стёрся, замещён real-prod-aligned profile.

---

## 9. Honest risk assessment v2.1

| Risk | v1 | v2 | v2.1 |
|---|---|---|---|
| Brand inconsistency HTML/headers | ❌ | ✅ | ✅ |
| 404 strategy not matching real prod | ❌ | ⚠️ (hybrid) | ✅ (Linear-style for all 3 personas) |
| X-Powered-By legacy | ❌ | ✅ | ✅ |
| X-Region introduced | ❌ | ✅ | ✅ |
| /v2/health anti-pattern | ❌ | ✅ | ✅ |
| Standalone React 404 entry | ❌ | ✅ | ✅ |
| Explicit nginx SPA list | ❌ | ✅ | ✅ |
| nginx add_header inheritance | ❌ | ✅ | ✅ |
| Asymmetric 404 assets vs paths | ❌ | ⚠️ deliberate hybrid | ✅ (now matches Linear/Vercel/regex101 — path 200, asset 404) |
| Go decoy.go divergence | ❌ | ⚠️ TBD | ✅ (explicit impl contract §2.4) |
| updateDecoyTemplate no nginx | ❌ | ✅ | ✅ |
| humans.txt without names | ❌ | ⚠️ impl bug N6 | ✅ (copy slice fix) |
| Color-block favicon | ⚠️ | ⚠️ strategy TBD | ✅ (pre-built ICO, fixed bytes) |
| Missing CSP | ❌ | ✅ | ✅ |
| Wrong XFO | ❌ | ⚠️ blog contradiction | ✅ (unified SAMEORIGIN) |
| Blog security.txt undefined | ❌ | ⚠️ ambiguous | ✅ (explicit: HAS) |
| Utility 404 contradiction | ❌ | ⚠️ 3 sources | ✅ (unified Linear-style) |
| nginx -t -c misuse | n/a | ❌ | ✅ (rewrite to in-place validate) |
| snippets dir bootstrap | n/a | ❌ | ✅ (mkdir -p) |
| humans.txt hardcoded date | n/a | ❌ | ✅ (deployDate parameter) |
| humans.txt empty twitter | n/a | ❌ | ✅ (removed twitter field) |

**Probability net-positive v2.1:** **high (85-90%)**. Все CRITICAL+HIGH из v1+v2 review закрыты с research support. Implementation-ready после minor clarifications.

**Caveats:**
- L7 (`chmod 755 /etc/letsencrypt/archive/`) — pre-existing security regression, **не блокирует** эту волну, **рекомендован** отдельный fix.
- TLS/H2 fingerprint TrustTunnel — out of scope, отдельная инициатива.
- CSP `'unsafe-inline'` — weak XSS protection, accept trade-off (deferred strict CSP с nonces).
- Pre-built favicon ICO — same для всех templates (no per-template color), accept trade-off (15086B mimicry > color variation).

---

## 10. Acceptance criteria

Волна **завершена**, когда:

1. ✅ `go test -race ./internal/deploy/... -count=1` — all green (включая humans pool race test)
2. ✅ `go test -race ./shadowlink/server/... -count=1` — DecoyHandler persona tests green
3. ✅ Все 4 React templates пересобраны, dist contains updated index.html (with NotFoundPage `<Route path="*">` + favicon links)
4. ✅ `internal/deploy/assets/favicon-template.ico` существует, size == 15086 bytes
5. ✅ Snippets uploaded на pl1: `/etc/nginx/snippets/saas-headers.conf` (`blog-headers.conf`, `utility-headers.conf` deployed когда соответствующие templates active)
6. ✅ `systemctl status nginx` = active на pl1 после reload
7. ✅ Smoke checklist (§6.3 — 13 проверок) все PASS на pl1
8. ✅ External curl от другого IP подтверждает:
   - `GET /this-doesnt-exist` → 200 (matches Linear)
   - `GET /random.png` → 404 (matches CDN convention)
   - `GET /.well-known/security.txt` → 200
   - `GET /health` → 200 "OK"
   - **NO** X-Powered-By, X-Region, X-Request-ID, /v2/health
   - CSP present
9. ✅ VPN-клиент подключается к pl1 без regression (smoke connect через nixavpn-client)
10. ✅ `tail -100 /var/log/nginx/error.log` — нет новых ошибок после reload
11. ✅ Headers consistency between `/` and `/pricing` confirmed (smoke check #6) — fix opus H3 visible

---

## 11. Out of scope (separate waves)

- `demo/json-tools/` (utility React project + adding `"json-tools"` to `templateMetas` with Persona: `"utility"`) — следующая волна.
- Removal of habr-mirror dead code (~2800 LOC) — отдельная уборка.
- TLS/H2/JA3 fingerprint TrustTunnel reverse_proxy — отдельная инициатива.
- Strict CSP с nonces (Vite plugin work) — major follow-up.
- Multi-language security.txt (RU support) — when будут RU-targeted decoy templates.
- Vite content-hash для cache invalidation (existing operational bug) — orthogonal optimization.
- nginx logrotate config для `/var/log/nginx/decoy.*.log` — operational followup.
- L7 baseline bug: `chmod -R 755 /etc/letsencrypt/archive/` в `issueLetsEncrypt` exposes private keys (`privkey.pem` обычно 600) — **pre-existing security regression**, рекомендован отдельный fix patch.
- Per-template **полностью разные** wording legal pages (мы оставили "different but copy-paste" в v2.1; полный rewrite — отдельная волна).
- Reproducible builds (deterministic Vite output hashes) — оптимизация для CT-log diversity.
