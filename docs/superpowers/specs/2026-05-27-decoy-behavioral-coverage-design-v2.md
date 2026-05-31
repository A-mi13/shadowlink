# Decoy Behavioral Coverage — Design Spec v2

**Дата:** 2026-05-27 (afternoon, после opus-review v1 + curl-probing research)
**Замещает:** `2026-05-27-decoy-behavioral-coverage-design.md` (v1)
**Источники:**
- `docs/superpowers/specs/2026-05-27-decoy-behavioral-coverage-design-review.md` (opus review v1)
- `docs/superpowers/research/2026-05-27-real-world-decoy-patterns.md` (фактические curl-probes 20+ prod sites)

**Verdict v1:** v1 закрывал старые gaps но вводил ~7 новых fingerprint surfaces (X-Powered-By "Crest/3.2.1", public /v2/health JSON с region+version, standalone React 404 entry, explicit nginx SPA route list, etc). Все они **противоречили реальным prod patterns** 2026 (см. research).

**Verdict v2:** опирается на 30+ curl HEAD probes реальных prod sites (Stripe/Linear/Vercel/Notion/Figma/Slack/Cloudflare/GitHub/Cursor/Anthropic + peer utility tools regex101/jsonformatter/jsonlint/freeformatter/sqlformat). Каждое решение в headers/endpoints/404 имеет **evidence trail** в research.

---

## 1. Цели и обновлённый scope

### 1.1 Что закрываем (gaps из v1, актуально и сейчас)

1. **Real 404 на unknown paths** — текущий decoy возвращает 200+index.html на любой URL (SPA fallback). Probe сравнивает с peer set → fingerprint.
2. **Brand inconsistency между HTML и headers** — текущий nginx хардкодит `X-Powered-By: MetricsHub/2.4.1` для всех templates, включая saas-landing (HTML brand = "Crest Technologies") и tech-blog (где Saas API anti-pattern).
3. **Отсутствие security.txt** — universal у 9/9 tier-1 SaaS (research §3), наше отсутствие = anomaly.
4. **OPTIONS без Allow header** — minor probe vector.
5. **Brand inconsistency между HTML на главной и nginx-генерируемыми response'ами** (`/v2/health` показывает "MetricsHub" даже когда HTML brand другой).
6. **Отсутствует `/contact`, `/privacy` в tech-blog**.
7. **`/favicon.ico` implicit, depend on React build** — лучше explicit.

### 1.2 Что v2 НЕ делает (vs v1)

- ❌ **НЕ ставит `X-Powered-By: <Brand>/<version>`.** Research §1: 8/10 prod sites без. 2/10 ставят `Next.js` (имя framework, не имя продукта). Решение v2: для SaaS persona опционально ставим `Next.js`. Для blog/utility — не ставим.
- ❌ **НЕ ставит `X-Region` или `X-Request-ID` в response headers.** Research §1: 0/10 prod sites так делают. Полностью убираем.
- ❌ **НЕ создаёт public /v2/health JSON endpoint** с region+version. Research §5: anti-pattern, никто из prod sites так не делает. Заменяем на `/health → 200 "OK"` plaintext (k8s-style) или убираем совсем.
- ❌ **НЕ создаёт standalone React 404 entry в Vite multi-build.** Research §6 + opus M1: pure static HTML 404.html — стандартный pattern (Vercel/Cloudflare/Stripe). React 404 entry = новый JS chunk = новый fingerprint.
- ❌ **НЕ хардкодит explicit list known SPA routes в nginx.** Opus C2 + research §2: real sites используют либо `try_files $uri $uri/ /index.html` (для SPA 200-pattern), либо real 404 через server-side rendering — не explicit list.
- ❌ **НЕ генерирует humans.txt с шаблонным "/* TEAM */ Engineering: hello@..."** без имён людей. Research §4: 44% prod sites имеют humans.txt, но **обязательно с realistic names**.

### 1.3 Что v2 ДОБАВЛЯЕТ (новое vs v1)

- ✅ **CSP header.** Research §1: 9/10 SaaS имеют CSP. v1 его не включал — gap.
- ✅ **Per-persona 404 strategy:**
  - SaaS landing → **real 404** (Stripe-style: `error_page 404 → static 404.html`)
  - Blog → **real 404** (тоже static, со ссылками на recent posts)
  - Utility → **200 + SPA fallback** (regex101/jsonlint-style)
- ✅ **CSP build-time validation:** в spec включается ограниченный CSP который не сломает React inline scripts (`script-src 'self' 'unsafe-inline'`).
- ✅ **Realistic humans.txt с pool имён** (опционально per-template). Pool: 20-30 имён (Sarah Chen, Marcus Patel, Liam Rodriguez и т.д.), deterministic seed per-domain. Для tech-blog/utility — пропускаем humans.txt.

### 1.4 Out of scope (отдельные waves)

- Создание `demo/json-tools/` template (utility React-проект) — следующая волна.
- Удаление habr-mirror dead code (~2800 LOC) — отдельная уборка.
- TLS/H2 fingerprint TrustTunnel reverse_proxy — отдельная инициатива (opus H4). Эта волна закрывает только HTTP-уровень.
- `shadowlink/server/decoy.go::DecoyHandler` (Go-уровневый second decoy path) — **частично в scope**, см. §2.4.

---

## 2. Архитектура

### 2.1 3-persona split

`deployNginxConfig(domain, templateName)` → dispatcher → 3 persona-specific renderers.

```go
// internal/deploy/steps_decoy.go

type templateMeta struct {
    Persona   string  // "saas" | "blog" | "utility"
    BrandLabel string  // human-readable name для security.txt (e.g. "Crest")
                       // — НЕ для HTTP headers (research §1).
}

var templateMetas = map[string]templateMeta{
    "saas-landing": {Persona: "saas", BrandLabel: "Crest"},
    "metricshub":   {Persona: "saas", BrandLabel: "MetricsHub"},
    "analytics-ru": {Persona: "saas", BrandLabel: "Analytica"},
    "tech-blog":    {Persona: "blog", BrandLabel: ""},
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

### 2.2 Server-level vs location-level headers — fix nginx inheritance bug (opus H3)

**Проблема v1:** `add_header` в location-блоке затирает ВСЕ server-level `add_header`. Это **сломало** бы security headers.

**Решение v2:** использовать `include /etc/nginx/snippets/<persona>-headers.conf;` в **каждом** location которому нужны headers. Snippet содержит весь security-headers set:

```nginx
# /etc/nginx/snippets/saas-headers.conf
add_header Strict-Transport-Security  "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options     "nosniff" always;
add_header X-Frame-Options            "SAMEORIGIN" always;  # was DENY in v1, research §1
add_header Referrer-Policy            "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'self'" always;
# NO X-Powered-By (research §1: 8/10 prod sites без)
# NO X-Region (research §1: 0/10)
# NO X-Request-ID (research §1: 0/10)
```

Snippets для **blog** и **utility** — аналогично, но с разными значениями (blog: больше permissive CSP для embeds; utility: минимальный без CSP).

**Snippet файлы упаковываются в Go binary через `go:embed`** (или генерятся на orchestrator side и загружаются на сервер при deploy). НЕ ставим их вручную на сервер.

### 2.3 Per-persona nginx structure

#### SaaS persona

```nginx
server {
    listen 127.0.0.1:8080;
    server_name {{Domain}};
    server_tokens off;
    root {{WebRoot}};
    index index.html;

    # Security headers via include (избегает inheritance bug)
    include /etc/nginx/snippets/saas-headers.conf;

    # Real 404 — статический HTML файл (БЕЗ React)
    error_page 404 /404.html;
    location = /404.html {
        internal;
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "public, max-age=300" always;
    }

    # SPA routing — standard pattern (no explicit list)
    # try_files: file → directory → index.html → 404
    # КЛЮЧЕВОЕ изменение: explicit fallback на error_page 404,
    # НЕ silent 200+index.html
    location / {
        try_files $uri $uri/ @react_or_404;
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "no-cache, must-revalidate" always;
    }

    # @react_or_404: если URL похож на React-route (без extension) — index.html;
    # если выглядит как asset (.png, .css) — real 404.
    location @react_or_404 {
        # nginx if-evil: только safe usage (add_header + return)
        # path с extension = unknown asset → real 404
        if ($request_uri ~* "\.(css|js|png|jpg|svg|ico|woff2?|html|xml|json|map)$") {
            return 404;
        }
        # path без extension = SPA route → index.html (status 200)
        try_files /index.html =404;
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "no-cache, must-revalidate" always;
    }

    # Static assets caching + real 404 для missing assets
    location ~* \.(css|js|png|jpg|svg|ico|woff2?)$ {
        try_files $uri =404;   # FIX opus C1: real 404 на missing assets
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

    # /.well-known/security.txt — RFC 9116
    location = /.well-known/security.txt {
        default_type "text/plain; charset=utf-8";
        return 200 "Contact: mailto:security@{{Domain}}\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en\nCanonical: https://{{Domain}}/.well-known/security.txt\n";
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "public, max-age=3600" always;
    }

    # /humans.txt — realistic team list (deterministic per-domain from pool)
    # Content rendered at deploy-time через text/template + names pool
    location = /humans.txt {
        # alias to file generated at deploy: /var/www/<template>/humans.txt
        # generated content example:
        #   /* TEAM */
        #     Backend lead: Marcus Patel — @marcuspatel
        #     Frontend: Sarah Chen — @sarahchen_dev
        #     DevOps: Liam Rodriguez
        #
        #   /* THANKS */
        #     Open-source community
        #
        #   /* SITE */
        #     Last update: 2026-05-15
        #     Standards: HTML5, CSS3, ES2024
        include /etc/nginx/snippets/saas-headers.conf;
        add_header Cache-Control "public, max-age=86400" always;
    }

    # OPTIONS handler для /api/* (минимально валидный REST set)
    location ~ ^/api/ {
        if ($request_method = OPTIONS) {
            add_header Allow "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE" always;
            add_header Access-Control-Allow-Methods "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE" always;
            add_header Access-Control-Allow-Origin "*" always;
            return 204;
        }
        return 404;
    }

    # JSON 404 для /api/* requests с Accept: application/json (opus M9)
    location = /api/_404json {
        internal;
        default_type application/json;
        return 404 '{"error":"not_found","message":"Endpoint not found","code":404}';
    }

    # Scanner-block (existing pattern)
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

#### Blog persona

Аналогично SaaS, но:
- `include /etc/nginx/snippets/blog-headers.conf` (XFO: SAMEORIGIN, без X-Powered-By, CSP без `frame-ancestors 'self'` для allow embeds)
- **NO `/health`** (blog не имеет health endpoint)
- **NO `/api/*`** OPTIONS handler (blog не имеет API)
- **NO /humans.txt** (research §4: tech blogs реже имеют humans.txt чем SaaS)
- **HAS `/feed.xml`** — generated at deploy from BlogPosts (см. §3.3)
- **HAS `/rss.xml → 301 /feed.xml`** (canonical)
- OPTIONS на `/blog/...`, `/archive`, `/about` → `Allow: GET, HEAD, OPTIONS`

#### Utility persona

Аналогично SaaS, но:
- `include /etc/nginx/snippets/utility-headers.conf` (минимальный set: HSTS, XCTO, XFO, без CSP — research §7: 3/5 utility tools без CSP)
- **NO security.txt** (research §3: 0/2 peer utility tools имеют)
- **NO humans.txt** (utility = solo dev tool, usually нет team page)
- **`try_files $uri $uri/ /index.html` БЕЗ `=404`** — utility делает 200+SPA fallback на любой unknown URL (regex101/jsonlint так делают, research §2)
- React router в самой утилите содержит `<Route path="*" element={<NotFoundPage />}>` который рендерит 200-status NotFoundPage внутри SPA
- **NO `error_page 404 /404.html`** — utility вообще не возвращает 404 на путях, status всегда 200 (SPA app)
- 404 только на missing assets (`\.(css|js|png)$ → try_files $uri =404`)
- **HAS `/api/process` stub** — POST endpoint stub возвращает 400 без body

### 2.4 Unifying Go-уровневый DecoyHandler (opus H1)

В `shadowlink/server/decoy.go::DecoyHandler::ServeHTTP` (строки 88-104) есть второй decoy path. Текущее поведение:
- Ставит `X-Frame-Options: SAMEORIGIN` (не DENY!)
- НЕ ставит HSTS, CSP, Referrer-Policy
- Стандартный Go `http.FileServer` 404 (без custom 404.html)

**Когда он работает:** когда трафик идёт через ShadowLink сервер напрямую (не через TrustTunnel + nginx), или когда nginx-decoy выключен.

**Решение v2:** **унифицировать headers** между Go-handler и nginx. В Go-handler добавить тот же header set (через `w.Header().Set(...)`) для всех 3 personas. Для этого:

1. Передать `templateName` или persona в `DecoyHandler` через config (extension к domainMap).
2. `DecoyHandler.ServeHTTP` ставит persona-specific headers перед вызовом `http.FileServer`.
3. Для 404 — `DecoyHandler` перехватывает 404 через `http.ResponseWriter` wrapper и подставляет custom 404.html (как nginx делает).

**Это меняет scope spec'а:** теперь мы трогаем `shadowlink/server/decoy.go`. Spec честно отражает это в §1.4 ("частично в scope"). Альтернатива (отложить) — оставить divergence headers между Go и nginx путями, **что probe сразу заметит** через CF и direct-IP probing.

### 2.5 Что НЕ меняется

- `uploadDecoyFiles`, `uploadReactDecoyFiles`, `uploadGeneratedDecoyFiles` — остаются.
- `decoy_content_gen.go` (547 LOC) — расширяется для render новых templates (humans.txt, 404.html, feed.xml).
- `domain_decoy_map` система — остаётся.
- ShadowLink protocol code — не трогается.
- Frontend admin panel — не трогается.

### 2.6 Issue H2: `updateDecoyTemplate` path

**Проблема:** `internal/deploy/steps_decoy.go::updateDecoyTemplate(mgr, templateName, domain)` (строки 947-961) — деплоит **только файлы**, не вызывает `deployNginxConfig`. Если admin меняет template через UI (saas-landing → tech-blog), HTML обновится но nginx config останется со старой persona → brand inconsistency.

**Fix v2:** в `updateDecoyTemplate` добавить вызов `deployNginxConfig(mgr, domain, templateName)` после `uploadDecoyFiles`. Это **+1 строка** в существующей функции. Spec честно отражает это: §1.4 — мы теперь трогаем `updateDecoyTemplate` (но это не admin/handlers/, это orchestrator-уровень в `internal/deploy/`).

---

## 3. Контентные артефакты (deploy-time generated)

### 3.1 `404.html` — pure static HTML per template

Не Vite multi-entry, не React. Просто `text/template`-генерируемый HTML файл, упакован в `internal/deploy/templates/404-<persona>.html.tmpl`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404 — Page not found | {{.CompanyName}}</title>
<link rel="icon" type="image/x-icon" href="/favicon.ico">
<style>
  /* Inline CSS — matches React app design via shared color palette + font */
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

**Per-persona variations:**
- SaaS: links to /, /pricing, /docs, /contact
- Blog: links to /, /archive, /about, latest posts list (rendered at deploy)
- Utility (если применимо к ним): обычно НЕ генерируется (utility persona use SPA fallback 200)

**Stack divergence заключение (opus M1 reconsidered):** Pure HTML 404 != JS-bundled main page **не** signature, потому что **real prod sites именно так и делают** (Vercel 404, Cloudflare error pages, Stripe 404 — все static HTML, **не** React-rendered). 5/12 sites из research возвращают text/plain или text/html-without-JS 404. **Standalone React 404 entry — это новый pattern, не стандартный.**

### 3.2 `humans.txt` — realistic names pool (для SaaS persona)

**Pool of realistic names** (deterministic seed from domain hash):

```go
// internal/deploy/decoy_humans_pool.go (новый файл)

var humansNamePool = []humanProfile{
    {FirstName: "Sarah",   LastName: "Chen",      Twitter: "sarahchen_dev"},
    {FirstName: "Marcus",  LastName: "Patel",     Twitter: "marcuspatel"},
    {FirstName: "Liam",    LastName: "Rodriguez", Twitter: ""},
    {FirstName: "Emma",    LastName: "Watson",    Twitter: "emma_w_eng"},
    {FirstName: "Noah",    LastName: "Kim",       Twitter: "noahkim_co"},
    {FirstName: "Olivia",  LastName: "Brown",     Twitter: ""},
    {FirstName: "Ava",     LastName: "Singh",     Twitter: "avas_codes"},
    {FirstName: "Ethan",   LastName: "Lee",       Twitter: ""},
    {FirstName: "Isabella",LastName: "Taylor",    Twitter: "bellataylor"},
    {FirstName: "Lucas",   LastName: "Garcia",    Twitter: ""},
    {FirstName: "Mia",     LastName: "Wilson",    Twitter: "miawilson_eng"},
    {FirstName: "Mason",   LastName: "Anderson",  Twitter: ""},
    {FirstName: "Zoe",     LastName: "Park",      Twitter: "zoe_park"},
    {FirstName: "Logan",   LastName: "Davis",     Twitter: ""},
    {FirstName: "Aria",    LastName: "Hayes",     Twitter: "aria_h"},
    {FirstName: "James",   LastName: "Murphy",    Twitter: ""},
    {FirstName: "Charlotte",LastName: "O'Brien",  Twitter: "charlotte_ob"},
    {FirstName: "Benjamin",LastName: "Cohen",     Twitter: ""},
    {FirstName: "Amelia",  LastName: "Foster",    Twitter: ""},
    {FirstName: "Henry",   LastName: "Zhang",     Twitter: "henryz_dev"},
    // 20 names total — picks 3-5 per domain deterministically
}

func generateHumansForDomain(domain string) string {
    seed := fnv32(domain)
    rng := rand.New(rand.NewSource(int64(seed)))
    rng.Shuffle(len(humansNamePool), func(i, j int) {
        humansNamePool[i], humansNamePool[j] = humansNamePool[j], humansNamePool[i]
    })
    // pick first 3-5 (also seeded)
    teamSize := 3 + rng.Intn(3) // 3-5
    ...
}
```

Generated content example:
```
/* TEAM */
  Backend lead: Marcus Patel — @marcuspatel
  Frontend: Sarah Chen — @sarahchen_dev
  DevOps: Liam Rodriguez
  Design: Aria Hayes — @aria_h

/* THANKS */
  Open-source community
  Our beta testers

/* SITE */
  Last update: 2026-05-15
  Standards: HTML5, CSS3, ES2024
  Built with: React, Vite, TypeScript
```

**Применяется только для SaaS persona.** Blog/utility — humans.txt пропускается.

### 3.3 `feed.xml` (только для tech-blog)

Не меняется vs v1 — нормальный RSS 2.0 feed rendered из BlogPosts при deploy. См. v1 §4.4.

### 3.4 Favicon — multi-res ICO + SVG

Research §6: 5/10 prod sites используют **multi-res ICO 15086B** — это template от **real-favicon-generator.net** или аналогичных tools. Mimic его — наш favicon тоже **15086B multi-res ICO** plus `favicon.svg` для современных браузеров.

Generated при deploy:
- `<webroot>/favicon.ico` — multi-resolution (16×16, 32×32, 48×48, 64×64) ICO, 15086B fixed
- `<webroot>/favicon.svg` — SVG vector, per-template brand letter + color

```html
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/x-icon" href="/favicon.ico">
```

**Per-template SVG generation в Go:** простой `<svg><circle><text>` с deterministic color из templateMeta + первая буква BrandLabel. Это **не** color-block-with-initial AI fingerprint (opus M2) — потому что multi-res ICO size **точно совпадает** с real-favicon-generator output (= mimicry под legitimate tool).

---

## 4. React-уровень изменения

### 4.1 `<Route path="*">` для SPA fallback

В каждом `App.tsx`:

```tsx
import NotFoundPage from './pages/NotFoundPage';

<Routes>
  ... existing routes ...
  <Route path="*" element={<NotFoundPage />} />
</Routes>
```

`NotFoundPage` — обычный React-компонент (НЕ standalone entry). Persona-specific:
- SaaS: redirects to `/` через `<meta http-equiv="refresh" content="3;/">` + content "page not found"
- Blog: рендерит "Post not found" + список recent posts
- Utility: "Tool not found" + список всех tools

**Унифицированный подход для всех 3 persona:**

| URL pattern | Server-side response | Client-side rendering |
|---|---|---|
| `/foo.png`, `/bar.css`, любой path с asset extension, не existing | nginx **real 404** (через `try_files $uri =404` в asset location + `error_page 404 /404.html`) | Browser показывает 404.html (static HTML) |
| `/anything-without-extension`, unknown SPA route | nginx **200 + index.html** (`try_files` через `@react_or_404`) | React Router `<Route path="*">` рендерит NotFoundPage внутри SPA |
| Known SPA route (existing in React Router config) | nginx **200 + index.html** | React Router рендерит соответствующую страницу |

**Почему гибрид (не pure real 404 like Stripe, не pure 200 like Linear):**
- 5/10 real prod sites returns 404 на asset-style URLs (Stripe, Figma, Slack, GitHub, Anthropic). **Это распространённый pattern.**
- 4/12 prod sites (включая Linear, Vercel, regex101, jsonlint) returns 200 на path-style URLs. **Это тоже распространённый pattern.**
- Гибрид (404 для assets + 200 для paths) — **никем не противоречит**, потому что probe тестирует **либо** asset либо path, не оба, и **получит ответ matching одному из known patterns**.

**Это превосходит v1** (где было 200 на любой URL — palette только path-style, asset-style попадал в SPA fallback что unusual) и **не делает explicit list SPA routes** (opus C2).

**Single difference для utility persona:** assets всё равно 404 (то же поведение), а path-style URLs → 200 + SPA-rendered NotFoundPage (matches regex101/jsonlint).

### 4.2 Tech-blog: missing routes (без изменений vs v1)

- `demo/tech-blog/src/pages/ContactPage.tsx`
- `demo/tech-blog/src/pages/PrivacyPage.tsx`
- Routes `/contact`, `/privacy` в App.tsx

### 4.3 PrivacyPage shared (opus M6)

**Решение:** оставляем per-template копии, **с **намеренно разным** wording + emails (`privacy@`, `legal@`, `dpo@`) per template.** Это:
- усиливает domain diversity (probe сравнит wording — увидит разный)
- НЕ требует Vite shared-package config
- проигрывает в DRY, но выигрывает в anti-cluster signal

В spec явно: "PrivacyPage **должна** отличаться wording'ом между templates. См. examples в spec implementation guide."

---

## 5. Файлы и LOC оценка v2 (обновлённая)

### 5.1 Backend (Go)

| Файл | Изменение | Δ LOC |
|---|---|---|
| `internal/deploy/steps_decoy.go` | Refactor `deployNginxConfig` на 3 ветки + dispatcher + templateMetas + добавить вызов в `updateDecoyTemplate` | +~280 |
| `internal/deploy/snippets/saas-headers.conf` (новый) | embed Go file | +~10 |
| `internal/deploy/snippets/blog-headers.conf` (новый) | embed | +~10 |
| `internal/deploy/snippets/utility-headers.conf` (новый) | embed | +~10 |
| `internal/deploy/templates/404-saas.html.tmpl` (новый) | static template | +~30 |
| `internal/deploy/templates/404-blog.html.tmpl` (новый) | + recent posts list | +~40 |
| `internal/deploy/decoy_humans_pool.go` (новый) | names pool + generator | +~80 |
| `internal/deploy/steps_decoy_test.go` | tests for templatePersona + render | +~150 |
| `internal/deploy/steps_decoy_nginx_test.go` (новый) | render assertions per persona | +~200 |
| `internal/deploy/steps_decoy_e2e_test.go` (новый) | SSH mock | +~100 |
| `shadowlink/server/decoy.go` | unify headers с nginx persona | +~80 |
| `shadowlink/server/decoy_test.go` | persona header tests | +~60 |

**Backend total:** ~**+1050 LOC** (vs v1 +690 LOC — больше потому что добавили unify Go-handler).

### 5.2 React (per template)

Тот же scope что v1 — каждый template получает NotFoundPage + tech-blog получает Contact/Privacy + favicon.svg.

**Frontend total:** ~**+450 LOC** (минус standalone 404 entry — мы убрали Vite multi-entry).

### 5.3 Что НЕ меняется

- shadowlink-server protocol code (handler.go, websocket.go и т.д.) — 0 LOC.
- `internal/admin/` handlers — **0 LOC** (НЕ трогаем).
- Frontend admin panel — 0 LOC.
- Migrations — нет.

---

## 6. Тестирование

### 6.1 Unit tests

- `templatePersona()` table tests (как в v1)
- `templateMetas` completeness check
- `generateHumansForDomain()` deterministic test (same domain → same names)
- nginx snippets validation: snippets must have `;` line endings, valid nginx syntax (через `nginx -t` в test container — optional)

### 6.2 nginx render tests

Per persona — assert наличие/отсутствие ключевых директив:

```go
func TestRenderNginxSaaS(t *testing.T) {
    cfg := renderNginxConfigSaaS("datacanvases.com")
    must(t, strings.Contains(cfg, `include /etc/nginx/snippets/saas-headers.conf`), "uses headers snippet")
    must(t, strings.Contains(cfg, `error_page 404 /404.html`), "real 404")
    must(t, strings.Contains(cfg, `try_files $uri =404`),     "assets fail real 404 (opus C1)")
    must(t, strings.Contains(cfg, `/.well-known/security.txt`), "security.txt")
    must(t, strings.Contains(cfg, `return 200 "OK"`),         "k8s-style /health")
    must(t, !strings.Contains(cfg, `X-Powered-By`),           "NO X-Powered-By (research §1)")
    must(t, !strings.Contains(cfg, `X-Region`),               "NO X-Region (research §1)")
    must(t, !strings.Contains(cfg, `X-Request-ID`),           "NO X-Request-ID (research §1)")
    must(t, !strings.Contains(cfg, `/v2/health`),             "NO /v2/health (research §5)")
}

func TestRenderNginxBlog(t *testing.T) {
    cfg := renderNginxConfigBlog("myblog.io")
    must(t, !strings.Contains(cfg, `/v2/health`),  "blog no /v2/health")
    must(t, !strings.Contains(cfg, `/health`),     "blog no /health")
    must(t, !strings.Contains(cfg, `/api/`),       "blog no /api/* OPTIONS")
    must(t, strings.Contains(cfg, `/feed.xml`),    "blog has feed")
    must(t, !strings.Contains(cfg, `/humans.txt`), "blog no humans.txt (per §1.3)")
}

func TestRenderNginxUtility(t *testing.T) {
    cfg := renderNginxConfigUtility("jsonformat.io")
    must(t, !strings.Contains(cfg, `error_page 404 /404.html`), "utility uses SPA 200, no real 404 server-side")
    must(t, !strings.Contains(cfg, `/.well-known/security.txt`), "utility no security.txt (research §3)")
    must(t, !strings.Contains(cfg, `/humans.txt`),               "utility no humans.txt")
    must(t, strings.Contains(cfg, `try_files $uri $uri/ /index.html`), "utility uses SPA fallback")
}
```

### 6.3 Smoke checklist after deploy (v2)

```bash
DOMAIN=datacanvases.com

# 1. SPA route → 200 + index.html (унаследовано, как было)
curl -ksI https://$DOMAIN/ | head -1
# Expected: HTTP/1.1 200

# 2. Real 404 для несуществующего asset
curl -ksI https://$DOMAIN/random.png | head -1
# Expected: HTTP/1.1 404

# 3. Soft 404 для несуществующего path (SPA routing)
curl -ksI https://$DOMAIN/this-page-does-not-exist | head -1
# Expected: HTTP/1.1 200 (но React render NotFoundPage)
# (это OK — matches linear.app behavior)

# 4. /404.html напрямую → 404 (потому что internal)
curl -ksI https://$DOMAIN/404.html | head -1
# Expected: HTTP/1.1 404 (nginx returns 404 на attempt access internal)

# 5. security.txt → 200
curl -ks https://$DOMAIN/.well-known/security.txt | head -5
# Expected: Contact: mailto:security@... + Expires...

# 6. /health → 200 OK plaintext
curl -ks https://$DOMAIN/health
# Expected: OK (just OK, no JSON)

# 7. Headers consistency между / и /pricing (opus H3 fix)
curl -ksI https://$DOMAIN/ | grep -iE "(strict|x-frame|x-content|csp|content-security)"
curl -ksI https://$DOMAIN/pricing | grep -iE "(strict|x-frame|x-content|csp|content-security)"
# Expected: same headers in both responses

# 8. NO X-Powered-By, NO X-Region (research-aligned)
curl -ksI https://$DOMAIN/ | grep -iE "x-powered-by|x-region"
# Expected: empty (no output)

# 9. OPTIONS на /api/anything → 204 + Allow
curl -ksX OPTIONS -i https://$DOMAIN/api/anything | head -5
# Expected: HTTP/1.1 204 Allow: GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE

# 10. JSON 404 для /api/* (если Accept: application/json) — это nice-to-have
# (если не реализовано — пропустить)
curl -ksI -H "Accept: application/json" https://$DOMAIN/api/random | head -5
# Expected: HTTP/1.1 404 Content-Type: application/json

# 11. /humans.txt → 200 + realistic names (SaaS only)
curl -ks https://$DOMAIN/humans.txt | head -5
# Expected: /* TEAM */ ... Patel ... @marcuspatel ...

# 12. favicon → 200 + multi-res ICO
curl -ksI https://$DOMAIN/favicon.ico | head -3
# Expected: HTTP/1.1 200 Content-Type: image/x-icon Content-Length: 15086

# 13. CSP header present
curl -ksI https://$DOMAIN/ | grep -i "content-security-policy"
# Expected: Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; ...
```

13 проверок, все обязательные.

---

## 7. Rollout (вариант B — сразу на datacanvases.com)

Не меняется vs v1 §7 — кроме того что:
- Pre-deploy local check: `nginx -t` через docker container на сгенерированном config'е (catches snippet path errors)
- Backup nginx config + snippets перед mv (existing v1 pattern)
- Rollback restores **both** sites-available/decoy AND snippets/

### 7.1 Pre-deploy

1. `go test ./internal/deploy/... -count=1`
2. `npm run build` per template (4 шт)
3. Verify `dist/index.html` + `dist/favicon.{ico,svg}` + (SaaS templates) `humans.txt`
4. Commit

### 7.2 Deploy on pl1

1. Через admin UI → `Re-deploy decoy` для datacanvases.com
2. Orchestrator:
   - `cp /etc/nginx/sites-available/decoy decoy.bak.$(date +%s)`
   - `cp -r /etc/nginx/snippets/ /etc/nginx/snippets.bak.$(date +%s)/`
   - Upload new snippets to `/etc/nginx/snippets/`
   - Upload new files (`404.html`, `humans.txt`, `favicon.ico`, `favicon.svg`) atomically
   - Write new `decoy.new` config
   - `nginx -t -c /etc/nginx/decoy.new` — abort on fail
   - `mv decoy.new decoy && systemctl reload nginx`
3. Smoke checklist (§6.3 — 13 checks)

### 7.3 Rollback

```bash
ssh pl1 'cp /etc/nginx/sites-available/decoy.bak.<ts> /etc/nginx/sites-available/decoy \
      && cp -r /etc/nginx/snippets.bak.<ts>/* /etc/nginx/snippets/ \
      && nginx -t && systemctl reload nginx'
```

~1 секунда recovery.

---

## 8. Backwards compatibility

- Legacy `templateName=""` → SaaS persona с `BrandLabel: "MetricsHub"` (как v1).
- Existing `domain_decoy_map` — нет изменений.
- `updateDecoyTemplate` теперь вызывает `deployNginxConfig` (новое поведение):
  - Если admin меняет template через UI → headers пересоберутся под новый persona.
  - Если admin **не** меняет template — никаких изменений (re-deploy only).

---

## 9. Honest risk assessment v2

| Risk | v1 | v2 |
|---|---|---|
| Brand inconsistency между HTML/headers | ❌ Кардинально | ✅ Решено (per-persona snippets) |
| Real 404 vs SPA 200 mismatch с peer set | ❌ Хардкод real 404 везде (50% сайтов так не делают) | ✅ Per-persona (SaaS+Blog real 404, Utility soft 404 200) |
| `X-Powered-By` legacy signal | ❌ Ввели Crest/3.2.1 | ✅ Убрали |
| `X-Region`, `X-Request-ID` ввели как new signal | ❌ Да | ✅ Убрали |
| Public /v2/health JSON anti-pattern | ❌ Да | ✅ Заменено на /health → "OK" |
| Standalone React 404 entry — новый chunk | ❌ Да | ✅ Pure HTML 404 (matches Vercel/Stripe) |
| Explicit nginx list SPA routes — необычно | ❌ Да | ✅ Standard try_files |
| nginx add_header inheritance bug | ❌ Да | ✅ include snippets |
| Asymmetric 404 для assets vs paths | ❌ Да | ✅ try_files $uri =404 для assets |
| Go-уровневый decoy.go divergence | ❌ Игнор | ✅ Unify headers (scope expanded) |
| `updateDecoyTemplate` не пересобирает nginx | ❌ Bug | ✅ +1 line fix |
| Auto-generated humans.txt без имён | ❌ Да | ✅ Pool realistic names ИЛИ пропускаем |
| Color-block favicon AI signature | ⚠️ Да | ⚠️ Уменьшили (15086B multi-res = mimicry под real-favicon-generator) |
| Missing CSP | ❌ Да | ✅ Добавили per-persona |
| Wrong XFO (DENY везде) | ❌ Hard DENY | ✅ SAMEORIGIN для SaaS (matches 5/10 prod), DENY only для blog |

**Probability v2 net-positive:** **high** (все CRITICAL+HIGH из opus + все §8 findings из research **закрыты**). Не **гарантированно** на 100% — могут быть unknown signals (TLS layer, H2 SETTINGS) которые мы не контролируем (opus H4 — отдельная инициатива).

---

## 10. Acceptance criteria

Эта волна **завершена**, когда:

1. ✅ `go test ./internal/deploy/... -count=1` — all green
2. ✅ Все 4 templates пересобраны, dist contains `favicon.ico`/`favicon.svg`, NotFoundPage компонент включён в App.tsx
3. ✅ Snippets `/etc/nginx/snippets/saas-headers.conf` + `blog-headers.conf` deployed на pl1
4. ✅ Deploy на pl1 выполнен, `systemctl status nginx` = active
5. ✅ Smoke checklist (§6.3) — все 13 проверок PASS
6. ✅ External curl от другого IP подтверждает:
   - `curl -ksI https://datacanvases.com/random.png` → 404 (НЕ дефолтный nginx 404, а наш static 404.html)
   - `curl -ksI https://datacanvases.com/anything` → 200 (SPA fallback — React render NotFoundPage)
   - НЕТ `X-Powered-By`, НЕТ `X-Region`, НЕТ `X-Request-ID` в headers
   - CSP present
7. ✅ VPN-клиент подключается к pl1 без regression
8. ✅ `internal/admin/` test suite (если есть) — PASS (мы не трогали admin, но `updateDecoyTemplate` изменилось)

---

## 11. Out of scope (separate waves)

- `demo/json-tools/` (utility React project) — следующая волна
- Удаление habr-mirror dead code (~2800 LOC) — отдельная уборка
- TLS/H2/JA3 fingerprint TrustTunnel — отдельная инициатива
- Multi-language security.txt (RU support) — when будут RU-targeted decoy templates
- Per-template **полностью разные** wording legal pages (мы оставили "different but copy-paste" в v2; полный rewrite в отдельную волну)
- nginx logrotate config — operational followup
- Reproducible builds (deterministic Vite output hashes) — оптимизация
