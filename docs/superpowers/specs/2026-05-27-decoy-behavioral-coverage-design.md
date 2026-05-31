# Decoy Behavioral Coverage — Design Spec

**Дата:** 2026-05-27
**Тип:** Architecture + implementation spec для closing behavioral gaps в декой-сайтах ShadowLink.
**Scope:** `internal/deploy/steps_decoy.go` (nginx config split на 3 persona) + `demo/<template>/` (NotFoundPage, новые routes, RSS feed) + статика (`/.well-known/security.txt`, `/humans.txt`, `/favicon.ico` нормализация).
**НЕ scope:** shadowlink-server protocol code, новый `demo/json-tools/` template (отдельная волна), удаление habr-mirror кода (отдельная уборка), admin UI изменения.

---

## 1. Цели и мотивация

### 1.1 Зафиксированные gaps

Research-аудит `2026-05-26-decoy-blog-state-audit.md` зафиксировал, что текущие декой-шаблоны (4 React SPA в `demo/`) деплоятся через единый `deployNginxConfig()`, который:

- Возвращает **200 + index.html** на **любой** unknown URL (`try_files $uri $uri/ /index.html` без `=404`). Real 404 не существует. **Это первая fingerprint-сигнатура** — peer tools (regex101, jsonformatter) возвращают real 404.
- Хардкодит `X-Powered-By: MetricsHub/2.4.1` для **всех** templates, включая `saas-landing` (HTML brand = "Crest Technologies") и `tech-blog`. Это **brand inconsistency** между HTML и HTTP-headers — instant fingerprint.
- Хардкодит `/v2/health` JSON с `region: eu-west` + `service: MetricsHub` для **всех** templates, включая `tech-blog` (где SaaS API на блоге = противоречие легенде).
- Отсутствует `/.well-known/security.txt` — real US-hosted продакшен сайты в 2025-2026 имеют его (RFC 9116).
- Отсутствует `/feed.xml` / `/rss.xml` — blog без RSS feed выглядит abandoned.
- Отсутствует `/contact` route в tech-blog (есть только Home/Archive/About/Post).
- Отсутствует `/privacy` route в tech-blog (есть в остальных 3 templates).
- `OPTIONS` запрос возвращает default 405 без `Allow` header — real web servers возвращают `Allow: GET, HEAD, OPTIONS`.
- `/favicon.ico` "depends on React build" — implicit, не контролируемо. Real sites имеют explicit favicon.

### 1.2 Цель этой волны

Закрыть **все** перечисленные gaps **разом** через рефакторинг `deployNginxConfig` на 3 persona-ветки + добавление per-template React-страниц + статических ресурсов.

После этой волны декои **passing** следующий probe-checklist:

```
curl -ksI <domain>/nonexistent           → 404 (не 200)
curl -ks  <domain>/.well-known/security.txt → 200 + RFC 9116 текст
curl -ksX OPTIONS <domain>/api/anything  → 204 + Allow header
curl -ksI <domain>/                      → 200, X-Powered-By matches HTML brand
curl -ks  <domain>/v2/health             → JSON product matches HTML brand (saas) | 404 (blog/utility)
curl -ksI <domain>/favicon.ico           → 200
curl -ks  <domain>/feed.xml              → real RSS XML (только blog)
curl -ks  <domain>/humans.txt            → 200 + plain-text
```

### 1.3 Что НЕ в этой волне

- Создание нового `demo/json-tools/` (utility) template. Persona `"utility"` будет **прописана в коде**, но без template'а — следующая волна.
- Удаление habr-mirror кода (`live_blog.go` и связанные ~2800 LOC). Отдельная уборка, не блокирует behavioral coverage.
- Изменения в shadowlink-server (handler.go, decoy.go, protocol code). НЕ ТРОГАЕМ.
- Изменения в admin UI (handlers/frontend). Все изменения внутри `internal/deploy/` + `demo/`.

---

## 2. Архитектура

### 2.1 3-persona split

`deployNginxConfig(domain, templateName)` рефакторится из **одной функции** в **dispatcher + 3 specialized функции**:

```
deployNginxConfig(domain, templateName) — dispatcher [~30 LOC]
  │
  └── на основе templatePersona(templateName) вызывает:
      ├── deployNginxConfigSaaS(domain, meta templateMeta)    [~150 LOC]
      ├── deployNginxConfigBlog(domain)                         [~120 LOC]
      └── deployNginxConfigUtility(domain)                      [~100 LOC]
```

### 2.2 Template → persona mapping

Новые pure-функции:

```go
// templatePersona returns "saas", "blog", or "utility" based on templateName.
// Unknown templates → "saas" (legacy default with warn-log).
func templatePersona(templateName string) string

// templateMetas — per-template branding metadata.
type templateMeta struct {
    Persona     string   // "saas" | "blog" | "utility"
    BrandName   string   // e.g. "Crest" — for X-Powered-By
    BrandVer    string   // e.g. "3.2.1"
    Region      string   // e.g. "us-east-1"
    // SPARoutes — список known SPA routes для template. Используется nginx-генератором
    // для рендеринга explicit `location =` блоков. Если URL не в этом списке →
    // real 404, НЕ silent fallback в index.html.
    //
    // Включает:
    //   - exact routes: "/", "/pricing", "/about", "/privacy", ...
    //   - regex routes: prefix "~^" → renders as `location ~ ^...` (e.g. "~^/blog(/.*)?$")
    SPARoutes []string
}

var templateMetas = map[string]templateMeta{
    "saas-landing": {
        Persona: "saas", BrandName: "Crest", BrandVer: "3.2.1", Region: "us-east-1",
        SPARoutes: []string{"/", "/pricing", "/about", "/careers", "/login", "/signup",
                            "/privacy", "/terms", "/security", "/docs", "~^/blog(/.*)?$"},
    },
    "metricshub": {
        Persona: "saas", BrandName: "MetricsHub", BrandVer: "2.4.1", Region: "eu-west",
        SPARoutes: []string{"/", "/docs", "/changelog", "/status", "/login", "/signup",
                            "/privacy", "/terms", "/security"},
    },
    "analytics-ru": {
        Persona: "saas", BrandName: "Analytica", BrandVer: "1.8.5", Region: "eu-central-1",
        SPARoutes: []string{"/", "/features", "/pricing", "/integrations", "/docs",
                            "/status", "/about", "/login", "/signup", "/privacy", "/terms",
                            "~^/blog(/.*)?$", "~^/cases(/.*)?$", "~^/webinars(/.*)?$"},
    },
    "tech-blog": {
        Persona: "blog", BrandName: "", BrandVer: "", Region: "",
        SPARoutes: []string{"/", "/archive", "/about", "/contact", "/privacy",
                            "~^/blog(/.*)?$"},
    },
    "": { // backwards compat — legacy templateName=""
        Persona: "saas", BrandName: "MetricsHub", BrandVer: "2.4.1", Region: "eu-west",
        SPARoutes: []string{"/"},  // unknown legacy — minimal safe set
    },
    // "json-tools" будет добавлен в следующей волне
}
```

### 2.3 Что НЕ меняется

- `uploadDecoyFiles`, `uploadReactDecoyFiles`, `uploadGeneratedDecoyFiles` — остаются. Добавляется только upload новых артефактов (`404.html`, `humans.txt`, `feed.xml`).
- `decoy_content_gen.go` (547 LOC) — остаётся. Расширяется в `uploadGeneratedDecoyFiles` для render новых template файлов.
- `domain_decoy_map` система — остаётся.
- `shadowlink/server/` — **не трогается**.
- `internal/admin/` — **не трогается**.
- Frontend admin panel — **не трогается**.

---

## 3. Per-persona nginx config

### 3.1 SaaS persona

```nginx
server {
    listen 127.0.0.1:8080;
    server_name {{domain}};
    server_tokens off;
    root {{webRoot}};
    index index.html;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "DENY" always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    add_header X-Request-ID              $request_id always;
    # Per-product branding (из templateMeta)
    add_header X-Powered-By              "{{brandName}}/{{brandVer}}" always;
    add_header X-Region                  "{{region}}" always;

    # Real 404 page — отдельный entry в React build (dist/404.html)
    error_page 404 /404.html;
    location = /404.html {
        internal;
        add_header Cache-Control "public, max-age=300";
    }

    # SPA routing — known React routes served from index.html, unknown → real 404.
    # Подход: explicit list of SPA routes (per templateMeta.SPARoutes), не catch-all.
    # Каждый known route mapped в один location-block, рендерится at deploy-time.
    # Пример для saas-landing (routes: /, /pricing, /blog, /docs, /about, /careers, /login, /signup, /privacy, /terms, /security):
    location = /          { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /pricing   { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /about     { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /careers   { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /login     { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /signup    { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /privacy   { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /terms     { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /security  { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    location = /docs      { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }
    # Dynamic routes like /blog/:slug — нужен regex location
    location ~ ^/blog(/.*)?$ { try_files /index.html =404; add_header Cache-Control "no-cache, must-revalidate"; }

    # Default fallback (любой URL не пойманный выше) — real 404 via error_page
    location / {
        # static files (например /favicon.ico, /robots.txt — пойманы выше через файловые extensions ниже)
        # если ничего не нашлось — error_page 404 → /404.html
        try_files $uri =404;
    }

    # /v2/health — domain-specific JSON
    location = /v2/health {
        default_type application/json;
        return 200 '{"status":"ok","version":"{{brandVer}}","region":"{{region}}","service":"{{brandName|lowercase}}"}';
        add_header Cache-Control "no-store";
        add_header X-Request-ID $request_id;
    }

    # /v2/* — 401 (API exists but requires auth)
    location /v2/ {
        default_type application/json;
        return 401 '{"error":"unauthorized","code":401,"message":"API key required. See https://{{domain}}/docs"}';
        add_header WWW-Authenticate 'Bearer realm="{{brandName}} API", charset="UTF-8"';
    }

    # /.well-known/security.txt — RFC 9116
    location = /.well-known/security.txt {
        default_type "text/plain; charset=utf-8";
        return 200 "Contact: mailto:security@{{domain}}\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en\nCanonical: https://{{domain}}/.well-known/security.txt\n";
        add_header Cache-Control "public, max-age=3600";
    }

    # /humans.txt — RFC tradition
    location = /humans.txt {
        default_type "text/plain; charset=utf-8";
        return 200 "/* TEAM */\n  Engineering: hello@{{domain}}\n  Support: support@{{domain}}\n\n/* SITE */\n  Last update: 2026-04-10\n  Standards: HTML5, CSS3, ES2024\n  Components: React 19, Vite 6\n";
        add_header Cache-Control "public, max-age=86400";
    }

    # OPTIONS handler — корректный Allow header
    location ~ ^/api/ {
        if ($request_method = OPTIONS) {
            add_header Allow "GET, POST, OPTIONS";
            add_header Access-Control-Allow-Origin "*";
            return 204;
        }
        return 404;
    }

    # Static assets caching
    location ~* \.(css|js|png|jpg|svg|ico|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
        access_log off;
    }

    # Scanner-block
    location ~* \.(php|asp|aspx|jsp)$ { return 404; }

    gzip on;
    gzip_vary on;
    gzip_types text/plain text/css application/json application/javascript text/javascript application/xml;
    gzip_min_length 1024;

    access_log /var/log/nginx/decoy.access.log combined;
    error_log  /var/log/nginx/decoy.error.log warn;
}
```

### 3.2 Blog persona

Differences from SaaS:
- **NO `X-Powered-By`** (real blogs Hugo/Jekyll/Ghost его не ставят на static export).
- **NO `/v2/health`** или `/v2/*` API — блог не имеет API.
- **`/feed.xml` real RSS** — generated на deploy-time из `BlogPosts`.
- **`/rss.xml` → 301 redirect** to `/feed.xml` (canonical).
- **OPTIONS handler** для `/`: `Allow: GET, HEAD, OPTIONS`.

```nginx
server {
    listen 127.0.0.1:8080;
    server_name {{domain}};
    server_tokens off;
    root {{webRoot}};
    index index.html;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "SAMEORIGIN" always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    # NO X-Powered-By, NO X-Region — real blogs его не ставят

    error_page 404 /404.html;
    location = /404.html { internal; add_header Cache-Control "public, max-age=300"; }

    location / { try_files $uri $uri/ /index.html =404; }

    # RSS feed — real file (rendered at deploy from BlogPosts)
    location = /feed.xml {
        default_type "application/rss+xml; charset=utf-8";
        add_header Cache-Control "public, max-age=3600";
    }
    location = /rss.xml { return 301 /feed.xml; }
    location = /atom.xml { return 301 /feed.xml; }

    # /v2/* НЕ существует — блог не имеет API
    location /v2/ { return 404; }

    location = /.well-known/security.txt { ... как в SaaS ... }
    location = /humans.txt { ... }

    # OPTIONS на root и blog routes
    location ~ ^/(blog|archive|about|contact|privacy) {
        if ($request_method = OPTIONS) {
            add_header Allow "GET, HEAD, OPTIONS";
            return 204;
        }
    }

    location ~* \.(css|js|png|jpg|svg|ico|woff2?)$ { ... }
    location ~* \.(php|asp|aspx|jsp)$ { return 404; }

    gzip on; gzip_vary on; ... application/xml ... ;
    access_log ... ;
}
```

### 3.3 Utility persona

(Пишется сейчас, template `demo/json-tools/` создаётся **следующей волной**.)

```nginx
server {
    listen 127.0.0.1:8080;
    server_name {{domain}};
    server_tokens off;
    root {{webRoot}};
    index index.html;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "DENY" always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    # NO X-Powered-By (utility = small dev tool, real tools обычно не ставят)

    error_page 404 /404.html;
    location = /404.html { internal; }

    location / { try_files $uri $uri/ /index.html =404; }

    # Utility's own API endpoint — обычно одна функция (e.g. /api/format)
    location = /api/process {
        if ($request_method = OPTIONS) {
            add_header Allow "POST, OPTIONS";
            add_header Access-Control-Allow-Origin "*";
            return 204;
        }
        if ($request_method != POST) { return 405; }
        default_type application/json;
        return 400 '{"error":"missing input","code":"E_NO_BODY"}';
    }

    # /v2/* НЕ существует
    location /v2/ { return 404; }

    location = /.well-known/security.txt { ... }
    location = /humans.txt { ... }

    location ~* \.(css|js|png|jpg|svg|ico|woff2?)$ { ... }
    location ~* \.(php|asp|aspx|jsp)$ { return 404; }

    gzip on; ... ;
    access_log ... ;
}
```

---

## 4. React-уровень изменения

### 4.1 NotFoundPage per template

Каждый template получает `src/pages/NotFoundPage.tsx`:

| Template | Persona | Сообщение | CTA links |
|---|---|---|---|
| `saas-landing` | saas | "Page not found" | Home, Pricing, Docs, Contact |
| `metricshub` | saas | "Page not found" | Home, Docs, Status, Login |
| `analytics-ru` | saas | "Страница не найдена" | Главная, Тарифы, Документация |
| `tech-blog` | blog | "Post not found" | Home, Archive, About, Latest posts list |
| (future) `json-tools` | utility | "Tool not found" | Home, All Tools, About |

В `App.tsx` каждого template:
```tsx
<Routes>
  ... existing routes ...
  <Route path="*" element={<NotFoundPage />} />
</Routes>
```

### 4.2 Standalone `404.html` for nginx error_page

`nginx error_page 404 /404.html` требует **реальный файл** `404.html` в webroot. SPA-react не может его обслужить (router не работает без JS на entry-point).

**Решение:** генерируем `404.html` как отдельный HTML файл из шаблона. Vite multi-entry config:

```ts
// vite.config.ts
build: {
  rollupOptions: {
    input: {
      main:     resolve(__dirname, 'index.html'),
      notFound: resolve(__dirname, '404.html'),
    }
  }
}
```

И добавляется `demo/<template>/404.html`:
```html
<!DOCTYPE html>
<html lang="{{LANG}}">
<head>
  <meta charset="UTF-8" />
  <title>404 — Page not found | __COMPANY_PLACEHOLDER__</title>
  <link rel="stylesheet" href="/assets/main.css" />
</head>
<body>
  <div id="root"></div>
  <script type="module" src="/src/404-entry.tsx"></script>
</body>
</html>
```

И отдельный entry-point `src/404-entry.tsx`:
```tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import NotFoundPage from './pages/NotFoundPage';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <NotFoundPage />
  </React.StrictMode>,
);
```

Это даёт нам **standalone 404.html**, который ведёт себя как React-app (для human reader) но не требует SPA router.

**Альтернатива (отброшена):** сгенерировать `404.html` как pure-HTML (без React) — не выбрана, потому что **stack divergence**: остальные страницы React, а 404 — vanilla HTML, это **mini-fingerprint** через DOM diff.

### 4.3 Tech-blog: missing routes

Добавляются 2 новых page:

- `demo/tech-blog/src/pages/ContactPage.tsx` — minimal contact page (email + about, real text)
- `demo/tech-blog/src/pages/PrivacyPage.tsx` — privacy policy (статичный текст, копируется из saas-landing с заменой brand)

И routes в `App.tsx`:
```tsx
<Route path="/contact" element={<ContactPage />} />
<Route path="/privacy" element={<PrivacyPage />} />
```

### 4.4 Tech-blog: feed.xml.tmpl

Новый файл `demo/tech-blog/feed.xml.tmpl`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>{{.CompanyName}}</title>
    <link>https://{{.Domain}}/</link>
    <description>{{.Tagline}}</description>
    <atom:link href="https://{{.Domain}}/feed.xml" rel="self" type="application/rss+xml" />
    <language>en-us</language>
    <lastBuildDate>{{.BuildDate}}</lastBuildDate>
    {{range .BlogPosts}}
    <item>
      <title>{{.Title}}</title>
      <link>https://{{$.Domain}}/blog/{{.Slug}}</link>
      <guid isPermaLink="true">https://{{$.Domain}}/blog/{{.Slug}}</guid>
      <pubDate>{{.Date}}</pubDate>
      <description><![CDATA[{{.Excerpt}}]]></description>
    </item>
    {{end}}
  </channel>
</rss>
```

`internal/deploy/steps_decoy.go::uploadGeneratedDecoyFiles` расширяется для render этого template'а.

### 4.5 Favicon normalization

Каждый template в `public/`:
- `favicon.svg` — vector
- `favicon.ico` — fallback (32×32 multi-resolution ICO)

В `index.html` (и `404.html`):
```html
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="icon" type="image/x-icon" href="/favicon.ico" />
<link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
```

Favicon-файлы генерируем простыми color-blocks с brand-инициалом (per template) — это **deterministic** и lightweight.

---

## 5. Файлы и LOC оценка

### 5.1 Меняется (Go)

| Файл | Изменение | Δ LOC |
|---|---|---|
| `internal/deploy/steps_decoy.go` | Refactor `deployNginxConfig` на 3 ветки + `templateMetas` map + `templatePersona()` helper | +~280 |
| `internal/deploy/steps_decoy_test.go` (existing?) | New table tests | +~120 |
| `internal/deploy/steps_decoy_nginx_test.go` (новый) | Render asserts per persona | +~150 |
| `internal/deploy/steps_decoy_e2e_test.go` (новый) | SSH mock end-to-end | +~100 |
| `internal/deploy/decoy_content_gen.go` | (нет изменений — генератор контента остаётся) | 0 |
| `internal/deploy/decoy_template_render_test.go` | Add tests for feed.xml.tmpl render | +~40 |

**Backend total:** ~+690 LOC.

### 5.2 Меняется (React per template)

**Для каждого из 4 templates** (`saas-landing`, `metricshub`, `analytics-ru`, `tech-blog`):

| Артефакт | Δ LOC |
|---|---|
| `src/pages/NotFoundPage.tsx` | ~50 |
| `src/404-entry.tsx` | ~12 |
| `404.html` | ~25 |
| `App.tsx` (добавить `<Route path="*">`) | +1 |
| `vite.config.ts` (multi-entry) | +5 |
| `public/favicon.svg` + `favicon.ico` | static |

**Дополнительно для tech-blog:**
- `src/pages/ContactPage.tsx` (+50 LOC)
- `src/pages/PrivacyPage.tsx` (+80 LOC скопировано из saas-landing с заменой brand)
- `App.tsx` (+2 routes)
- `feed.xml.tmpl` (+30 LOC)

**Frontend total:** 4 × ~95 LOC + 165 LOC (tech-blog бонус) = ~**545 LOC**.

### 5.3 Не меняется

- `shadowlink/server/` — 0 LOC.
- `internal/admin/` — 0 LOC.
- `frontend/src/` (admin panel) — 0 LOC.
- Migrations — нет.
- shadowlink CLI/server flags — нет.

---

## 6. Тестирование

### 6.1 Unit тесты

```go
// steps_decoy_test.go
func TestTemplatePersona(t *testing.T) {
    cases := []struct{ template, persona string }{
        {"saas-landing", "saas"},
        {"metricshub",   "saas"},
        {"analytics-ru", "saas"},
        {"tech-blog",    "blog"},
        {"json-tools",   "utility"},   // pre-registered for next wave
        {"",             "saas"},        // legacy default
        {"unknown",      "saas"},        // unknown → saas with warn
    }
    for _, c := range cases {
        if got := templatePersona(c.template); got != c.persona {
            t.Errorf("templatePersona(%q) = %q, want %q", c.template, got, c.persona)
        }
    }
}

func TestTemplateMetasComplete(t *testing.T) {
    // assert каждый registered template имеет non-empty Persona
    for name, meta := range templateMetas {
        if meta.Persona == "" {
            t.Errorf("templateMetas[%q] has empty Persona", name)
        }
    }
}
```

### 6.2 nginx config render tests

```go
// steps_decoy_nginx_test.go
func TestRenderNginxSaaS(t *testing.T) {
    cfg := renderNginxConfigSaaS("datacanvases.com", templateMetas["saas-landing"])

    must(t, strings.Contains(cfg, `X-Powered-By              "Crest/3.2.1"`), "X-Powered-By branded")
    must(t, strings.Contains(cfg, `location = /pricing`), "explicit SPA route /pricing")
    must(t, strings.Contains(cfg, `try_files /index.html =404`), "SPA route uses real 404")
    must(t, strings.Contains(cfg, `location ~ ^/blog(/.*)?$`), "regex SPA route /blog/:slug")
    must(t, strings.Contains(cfg, `error_page 404 /404.html`), "error_page directive")
    must(t, strings.Contains(cfg, `/v2/health`), "SaaS has /v2/health")
    must(t, strings.Contains(cfg, `/.well-known/security.txt`), "security.txt")
    must(t, strings.Contains(cfg, `/humans.txt`), "humans.txt")
    must(t, strings.Contains(cfg, `Allow "GET, POST, OPTIONS"`), "OPTIONS handler")
}

func TestRenderNginxBlog(t *testing.T) {
    cfg := renderNginxConfigBlog("myblog.io")
    must(t, !strings.Contains(cfg, `X-Powered-By`),  "blog has NO X-Powered-By")
    must(t, !strings.Contains(cfg, `/v2/health`),    "blog has NO /v2/health")
    must(t, strings.Contains(cfg, `/feed.xml`),      "blog has feed.xml")
    must(t, strings.Contains(cfg, `location = /archive`), "blog SPA route /archive")
    must(t, strings.Contains(cfg, `try_files /index.html =404`), "real 404 on SPA routes")
    must(t, strings.Contains(cfg, `error_page 404 /404.html`), "error_page")
    must(t, strings.Contains(cfg, `/.well-known/security.txt`), "security.txt")
}

func TestRenderNginxUtility(t *testing.T) {
    cfg := renderNginxConfigUtility("jsonformat.io")
    must(t, !strings.Contains(cfg, `X-Powered-By`),  "utility has NO X-Powered-By")
    must(t, !strings.Contains(cfg, `/v2/health`),    "utility has NO /v2/health")
    must(t, strings.Contains(cfg, `/api/process`),   "utility has /api/process stub")
    must(t, strings.Contains(cfg, `error_page 404 /404.html`), "real 404 via error_page")
    must(t, strings.Contains(cfg, `/.well-known/security.txt`), "security.txt")
}
```

### 6.3 E2E тест (SSH mock)

```go
// steps_decoy_e2e_test.go
func TestDeployDecoy_SaaSPersona(t *testing.T) {
    mgr := newMockSSHManager()
    o := &Orchestrator{}
    err := o.deployDecoy(mgr, 0, "datacanvases.com", "saas-landing", nil)
    must(t, err == nil, "deploy succeeds")

    nginxConf := mgr.lastWrittenFile("/etc/nginx/sites-available/decoy")
    must(t, strings.Contains(nginxConf, `Crest/3.2.1`), "SaaS persona deployed")
}

func TestDeployDecoy_BlogPersona(t *testing.T) { ... }
func TestDeployDecoy_UtilityPersona(t *testing.T) { ... }
```

### 6.4 Manual smoke test checklist (после deploy)

Юзер прогоняет после deploy на pl1:

```bash
DOMAIN=datacanvases.com

# Real 404 — ДОЛЖНО быть 404, не 200
curl -ksI https://$DOMAIN/this-page-does-not-exist | head -1
# Expected: HTTP/1.1 404 Not Found

# security.txt
curl -ks https://$DOMAIN/.well-known/security.txt
# Expected: Contact: mailto:security@datacanvases.com ...

# humans.txt
curl -ks https://$DOMAIN/humans.txt
# Expected: /* TEAM */ ...

# OPTIONS — должен возвращать 204 + Allow
curl -ksX OPTIONS -i https://$DOMAIN/api/anything | head -10
# Expected: HTTP/1.1 204, Allow: ..., Access-Control-Allow-Origin: *

# X-Powered-By matches HTML brand
curl -ksI https://$DOMAIN/ | grep -i x-powered-by
# Expected: X-Powered-By: Crest/3.2.1 (НЕ MetricsHub!)

# /v2/health JSON matches brand
curl -ks https://$DOMAIN/v2/health
# Expected: {"status":"ok","version":"3.2.1","region":"us-east-1","service":"crest"}

# favicon
curl -ksI https://$DOMAIN/favicon.ico | head -1
# Expected: HTTP/1.1 200 OK

# (если переключим pl1 на tech-blog в будущем)
# curl -ks https://blog.example/feed.xml | head -5
# Expected: <?xml version="1.0" encoding="UTF-8"?> <rss version="2.0" ...
```

---

## 7. Rollout (вариант B — сразу на datacanvases.com)

### 7.1 Pre-deploy checklist

1. На локальной машине:
   ```bash
   cd D:/NIXAVPN
   go test ./internal/deploy/... -count=1
   # All tests must pass
   ```
2. Билд всех 4 dist'ов:
   ```bash
   for d in saas-landing tech-blog analytics-ru metricshub; do
     cd demo/$d && npm install && npm run build && cd ../..
   done
   ```
3. Verify `dist/404.html` exists for каждого template.
4. Verify `dist/favicon.svg` и `dist/favicon.ico` existst.
5. Commit changes to git (НЕ push — pl1 manual deploy).

### 7.2 Deploy на pl1

1. Через admin UI: `Settings → Platform deploy → Re-deploy decoy` для `datacanvases.com`.
2. Orchestrator вызывает `deployDecoy(serverID, "datacanvases.com", "saas-landing")`.
3. Orchestrator:
   - Backs up current nginx config: `cp /etc/nginx/sites-available/decoy /etc/nginx/sites-available/decoy.bak.$(date +%s)`
   - Uploads new files (`404.html`, `favicon.*`, etc) atomically via `.tmp` + `mv`
   - Writes new nginx config to `/etc/nginx/sites-available/decoy.new`
   - `nginx -t -c /etc/nginx/sites-available/decoy.new` — **if fail, abort, keep old config**
   - `mv decoy.new decoy && systemctl reload nginx`
4. Smoke test (см. 6.4) — все checks PASS.

### 7.3 Rollback plan

**Если smoke test показал что что-то сломалось:**

1. `ssh pl1 'cp /etc/nginx/sites-available/decoy.bak.<timestamp> /etc/nginx/sites-available/decoy && nginx -t && systemctl reload nginx'`
2. nginx возвращается в pre-deploy состояние **за ~1 секунду**.
3. React-уровень: если изменился dist, `git revert <commit>` локально, rebuild, redeploy. Это **5-10 минут** medianно.

**Если abort на стадии `nginx -t`** (config invalid) — мы не дошли до `mv decoy.new decoy`, никакого rollback не требуется, старый config продолжает работать.

### 7.4 VPN-трафик

ShadowLink-туннели идут через **TrustTunnel → unix socket → shadowlink-server**, не через nginx-decoy. `systemctl reload nginx` **graceful** — VPN не прерывается. Прерываются только plain HTTPS hits на nginx (probe, случайные браузеры) на ~1 секунду.

---

## 8. Backwards compatibility

### 8.1 Legacy `templateName = ""`

Поддерживается в `templateMetas[""]` = `{"saas", "MetricsHub", "2.4.1", "eu-west"}`. Это означает: серверы которые были задеплоены **до** этой волны (с пустым templateName) при следующем re-deploy получат SaaS persona с MetricsHub branding (как было).

### 8.2 Existing domain_decoy_map

Не меняется. Если в YAML есть `domain_decoy_map: { "host1": "/var/www/saas-landing" }`, новый nginx config будет применяться по такому же mapping'у.

### 8.3 Existing pl1 state

После deploy на pl1 (`datacanvases.com` template = `saas-landing`):
- HTML brand остаётся "Crest Technologies" (не меняем `decoy_content_gen.go`)
- nginx headers меняются с "MetricsHub/2.4.1" → "Crest/3.2.1" (consistency)
- `/v2/health` JSON меняется на `{"service":"crest","version":"3.2.1","region":"us-east-1"}`

Это **breaking change для probes которые делали baseline ранее** (запомнили что X-Powered-By = MetricsHub) — но мы как раз и хотим, чтобы baseline стёрся. Real sites обновляют major versions, X-Powered-By меняется — это **нормально**.

---

## 9. Open questions / decisions made

### 9.1 Почему 404.html — React entry, не pure HTML

**Decision:** standalone React entry с одним компонентом NotFoundPage.

**Reasoning:** если 404.html — pure vanilla HTML, а остальные страницы React, это **stack divergence** в DOM. Probe сравнивает HTML-структуру 404 и 200, видит "404 не React, остальное React" — фингерпринт.

Standalone React entry даёт нам **same stack** для 404 и 200, цена — отдельный entry в Vite + ~12 LOC `404-entry.tsx`.

### 9.2 Почему `Allow: GET, POST, OPTIONS` для SaaS

**Reasoning:** real SaaS APIs accept GET/POST/PUT/DELETE/PATCH (REST). Но для **декоя** мы только эмулируем surface — реального backend нет. Используем minimal credible set `GET, POST, OPTIONS` для `/api/*` потому что:
- Если probe пошлёт `PUT /api/foo` и получит 405 без `Allow: PUT` — это OK, real APIs часто не accept PUT.
- Если probe пошлёт `OPTIONS /api/foo` и получит 204 + Allow — это credible.

Blog получает `Allow: GET, HEAD, OPTIONS` (real blogs read-only). Utility — `Allow: POST, OPTIONS` для `/api/process` (utility принимает только POST с payload).

### 9.3 Почему `humans.txt` в scope

**Reasoning:** real US dev sites часто имеют /humans.txt (RFC tradition с 2011). Probe который тестирует "is this a real dev site" может проверить `/humans.txt` — наличие = positive signal. Low cost (~10 LOC nginx return).

### 9.4 Почему НЕ trogаем `X-Frame-Options: DENY → SAMEORIGIN` для blog

Real blogs обычно `SAMEORIGIN` или ничего. SaaS — часто `DENY`. Tech-blog меняем на `SAMEORIGIN` (он blog), остальные оставляем `DENY`.

---

## 10. Acceptance criteria

Эта волна считается **завершённой**, когда:

1. ✅ `go test ./internal/deploy/... -count=1` — all green
2. ✅ Все 4 templates пересобраны (`npm run build`), `dist/404.html` присутствует
3. ✅ Deploy на pl1 выполнен, `systemctl status nginx` = active
4. ✅ Manual smoke checklist (см. 6.4) — все 8 checks PASS
5. ✅ Внешний probe (curl с другого IP) подтверждает 404 на random URL, security.txt 200, X-Powered-By matches brand
6. ✅ VPN-клиент подключается к pl1 без regression (smoke connect через nixavpn-client)
7. ✅ В nginx error log нет new errors после reload (`tail -100 /var/log/nginx/error.log`)

---

## 11. Out of scope (отдельные волны)

- **`demo/json-tools/` template** — React project для utility (JSON formatter). После завершения behavioral coverage.
- **Removal of habr-mirror code** — `live_blog.go` + ~2800 LOC уборка. Отдельный spec.
- **Persona expansion** — добавить `"docs"` (Docusaurus-style) и `"portfolio"` (personal site) personas — отдельная волна, **только если** будут реальные templates.
- **Probe-resistance metrics** — automated nightly smoke checklist (curl tests) as canary — отдельный spec.
- **Multi-language security.txt** — пока только `en`. Если будут RU templates, добавим `ru` в `Preferred-Languages`.
