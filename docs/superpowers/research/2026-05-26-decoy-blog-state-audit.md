# Decoy Blog Framework — State Audit (Phase 1 prep)

**Date:** 2026-05-26
**Goal:** ground truth перед Phase 1 spec — что есть, что удалить, что отполировать.
**Conclusion (TL;DR):** habr-mirror полностью feature-flagged `live_blog.enabled` (DEFAULT FALSE), unused в проде. Static decoy (4 React-шаблона + tech-blog генератор) — рабочий but with gaps по headers/edge-pages. См. Top-3 risks внизу.

---

## Section 1 — Habr-mirror files (для удаления)

### 1.1 Серверный код (shadowlink/server/)

| Path | LOC | Action | Notes |
|---|---|---|---|
| `shadowlink/server/live_blog.go` | 649 | **DELETE** | Core LiveBlogHandler — reverse proxy + LRU cache + rate limiter + canary metrics |
| `shadowlink/server/live_blog_test.go` | 675 | **DELETE** | Unit tests for handler |
| `shadowlink/server/live_blog_canary.go` | 171 | **DELETE** | Watchdog loop running canary fetches к habr article |
| `shadowlink/server/live_blog_canary_test.go` | 90 | **DELETE** | Invariant tests (I1-I5: size/brand/leak/href/cdn) |
| `shadowlink/server/live_blog_timing.go` | 33 | **DELETE** | Fallback latency jitter (используется ТОЛЬКО в live_blog) |
| `shadowlink/server/live_blog_timing_test.go` | 122 | **DELETE** | Timing tests |
| `shadowlink/server/html_rewriter.go` | 481 | **DELETE** | DOM rewriter (habr brand → DataCanvases, href fixups, CDN strip) |
| `shadowlink/server/html_rewriter_test.go` | 499 | **DELETE** | Rewriter unit tests |
| `shadowlink/server/handler_live_blog_test.go` | 106 | **DELETE** | Integration test: GET /blog/* routes к liveBlog |
| `shadowlink/server/nginx_404.html` | 7 | **DELETE** | Used by LiveBlogHandler as 404 fallback when upstream fails |

**Total habr-mirror Go LOC к удалению:** **2833** (10 файлов).

### 1.2 Server config & wiring

| File | Lines | Action |
|---|---|---|
| `shadowlink/server/config.go` | 98-100, 172-276 | **DELETE** — `LiveBlogConfig` struct, `DefaultLiveBlogConfig()`, `applyLiveBlogDefaults()` (~110 lines) |
| `shadowlink/server/fileconfig.go` | 29, 67-88, 311-368 | **DELETE** — `FileLiveBlogConfig`, ApplyTo branch (~80 lines) |
| `shadowlink/server/fileconfig_test.go` | grep matches | **partial** — delete LiveBlog-specific tests |
| `shadowlink/server/handler.go` | 54-58 (field), 245-254 (init), 247 cfg.LiveBlog.Enabled gate, 365-366 (comment), 382-387 (dispatch), 1935-1943 (canary loop start) | **DELETE** wiring; keep file (handler.go = 2000+ LOC) |
| `shadowlink/server/metrics.go` | 202-221 (atomic counters), 412-427 (snapshot struct), 488-503 (load), 707-769 (Prom exporter) | **DELETE** ~100 lines, all 18 `DecoyLiveBlog*` fields/exporters |
| `shadowlink/server/metrics_test.go` | grep matches | **partial** — delete tests referencing live_blog counters |

### 1.3 Деплой / админка (внешний tree)

| File | Lines | Action |
|---|---|---|
| `internal/admin/shadowlink_handlers.go` (2242 LOC total) | 84-87, 609-627, 1062-1067, 1293-2104 | **DELETE huge block** — `LiveBlogConfigJSON`, `DefaultLiveBlogConfigJSON`, `validateLiveBlogConfigJSON`, `GetLiveBlogConfig`, `PutLiveBlogConfig`, `ApplyLiveBlog`, `DisableLiveBlog`, `runApplyLiveBlog`, `runDisableLiveBlog`, `renderShadowLinkConfigYAML` live_blog branch — **~900 LOC**; markDeploying mentions `ApplyLiveBlog/DisableLiveBlog` (lines 34-36) — comments to update |
| `internal/admin/shadowlink_handlers_test.go` | grep matches | **partial** — delete LiveBlog-tagged tests |
| `internal/admin/shadowlink_handlers_idempotent_test.go` | grep matches | **partial** |
| `internal/admin/shadowlink_handlers_concurrency_test.go` | grep matches | **partial** |
| `internal/admin/audit.go` | 232-234 | **DELETE** 3 audit constants `AuditShadowLink{PutLiveBlog,ApplyLiveBlog,DisableLiveBlog}` |
| `cmd/api/main.go` | 946-967 | **DELETE** 4 route registrations: `disable-live-blog`, `live-blog-config GET/PUT`, `apply-live-blog`; **KEEP** `GET /metrics/:id` route but rewrite its impl (currently reads `decoy_live_blog_metrics`) |
| `internal/shadowlink/metrics_scraper.go` | 359 LOC | **DELETE entire file** or rewrite — exclusively scrapes `decoy_live_blog_*` Prom counters |
| `internal/shadowlink/metrics_scraper_test.go` | grep matches | **DELETE** |
| `internal/deploy/steps_shadowlink.go` | 76-85 | **DELETE** comments about `live_blog` section in YAML rendering |
| `internal/deploy/steps_shadowlink_test.go` | grep matches | **partial** — delete LiveBlog assertions |
| `internal/deploy/steps_shadowlink_domain_decoy_map_test.go` | grep matches | **partial** |
| `migrations/071_decoy_live_blog_metrics.sql` | 38 lines | **KEEP as-is** (history) + new `119_drop_decoy_live_blog_metrics.sql` for `DROP TABLE decoy_live_blog_metrics`. Кажется the `protocol_configs.applied_at` column добавленный там же — НЕ удалять (используется UI's pending-apply indicator вне live_blog scope). |

### 1.4 Frontend (admin panel)

| File | LOC | Action |
|---|---|---|
| `frontend/src/components/shadowlink/LiveDecoyConfigTab.tsx` | 279 | **DELETE** |
| `frontend/src/components/shadowlink/LiveDecoyMetricsTab.tsx` | 249 | **DELETE** |
| `frontend/src/components/shadowlink/CanaryHealthCard.tsx` | 61 | **DELETE** |
| `frontend/src/api/shadowlink.ts` | grep matches | **partial** — drop `getLiveDecoyConfig/putLiveDecoyConfig/applyLiveDecoy/disableLiveDecoy/getLiveDecoyMetrics` API wrappers |
| `frontend/src/types/shadowlink.ts` | grep matches | **partial** — drop `LiveBlog*` types |
| `frontend/src/pages/ShadowLinkPage.tsx` | line 8-9 import, 16-26 Tab type/labels (`live_decoy`, `metrics`) | **partial** — remove tabs `live_decoy` и `metrics` (or keep `metrics` if we add static-decoy metrics в Phase 1+); imports |

**Total frontend LOC к удалению:** **~589 (3 файла полностью) + partial in 3 более**.

### 1.5 Документация (информативно, удаление опционально)

- `shadowlink/docs/protocols/live-decoy.md` — ops manual для T1.3
- `docs/superpowers/specs/2026-04-23-t13-live-decoy-design.md`
- `docs/superpowers/plans/2026-04-23-t13-flipon-admin-integration.md`
- `docs/superpowers/specs/2026-04-23-t13-flipon-admin-integration-design.md`
- В `CLAUDE.md` секция "Live Decoy (T1.3)" (lines ~227-241) — **MUST UPDATE/REMOVE**

**Grand totals:**
- Backend (Go) deletion: ~**2833 LOC live_blog files** + ~**1300 LOC partial** in config/fileconfig/handler/metrics/admin = **~4100 LOC**
- Frontend deletion: ~**589 full + partial**
- DB: 1 table drop (migration 119)

---

## Section 2 — Production usage live_blog

### 2.1 YAML configs где `live_blog: enabled: true`

**Поиск:** Grep "live_blog" / "LiveBlog" в `**/*.yaml`, `**/*.yml` (включая `shadowlink/**`, `internal/**`, `migrations/**`, `pl1*`, `deploy/**`).

**Результат:** **ZERO matches** в репо. Никакого checked-in YAML с `live_blog.enabled: true`.

### 2.2 Default value

В `shadowlink/server/config.go:200`:
```go
func DefaultLiveBlogConfig() LiveBlogConfig {
    return LiveBlogConfig{
        Enabled:           false,   // ← DEFAULT OFF
        Upstream:          "https://habr.com",
        ...
    }
}
```

В `internal/admin/shadowlink_handlers.go:1322`:
```go
func DefaultLiveBlogConfigJSON() *LiveBlogConfigJSON {
    return &LiveBlogConfigJSON{
        Enabled:            false,   // ← DEFAULT OFF
        ...
    }
}
```

И в `internal/deploy/steps_shadowlink.go:79-85` comment:
> `live_blog section is optional; absent = disabled (pre-T1.3 behavior).`
> `live_blog секция намеренно отсутствует — её добавит /apply-live-blog endpoint позже.`

### 2.3 Deploy YAML renderer

`WriteShadowLinkConfigYAML` (initial deploy) — НЕ записывает `live_blog:` секцию вообще.
`renderShadowLinkConfigYAML` (apply update) — пишет `live_blog:` секцию **только если** `cfg.LiveBlog != nil` (admin UI явно saved one).

### 2.4 Memory check (MEMORY.md preferences)

`feedback_pl1_manual_deploy.md` — pl1 deploy выполняется юзером вручную; no automated re-apply trigger.

### 2.5 Probable runtime state

На pl1 (`104.222.177.67` / `datacanvases.com`) `live_blog` **скорее всего НИКОГДА не enabled** в проде:
- Дефолт OFF
- Нет checked-in YAML с enabled
- Apply requires admin UI clicking "Save → Apply" + super_admin role + SSH password
- Канареечные метрики `decoy_live_blog_canary_ok_total` должны были тикать раз/15min, если бы было ON — но в архивных канарейках МЕМ нет упоминаний этих counters

**Вывод:** habr-mirror — **dead code in production**. Удаление безопасно.

---

## Section 3 — Static decoy state

### 3.1 Templates (under `demo/`)

| Template | Type | Entry HTML | Sources | Dist (prebuilt) |
|---|---|---|---|---|
| `demo/tech-blog/` | React SPA + Go templates | `index.html` (with `__*__PLACEHOLDER__`) | `src/App.tsx`, `src/pages/{HomePage,ArchivePage,PostPage,AboutPage}.tsx`, `src/components/{Nav,Footer,BackToTop}.tsx` | `dist/index.html`, `dist/assets/main.{js,css}` |
| `demo/saas-landing/` | React SPA | `index.html` + 11 pages (`HomePage`, `PricingPage`, `BlogPage`, `PostPage`, `DocsPage`, `AboutPage`, `CareersPage`, `LoginPage`, `SignupPage`, `PrivacyPage`, `TermsPage`, `SecurityPage`) | `src/pages/*.tsx` | `dist/index.html`, `dist/assets/main.{js,css}` |
| `demo/analytics-ru/` | React SPA (RU localized) | `index.html` + 13 pages (HomePage, FeaturesPage, PricingPage, IntegrationsPage, DocsPage, StatusPage, BlogPage, PostPage, CasesPage, WebinarsPage, AboutPage, LoginPage, SignupPage, PrivacyPage, TermsPage), i18n provider | `src/i18n/` + `src/pages/*.tsx` | `dist/...` |
| `demo/metricshub/` | React SPA | `index.html` + 9 pages (HomePage, DocsPage, ChangelogPage, StatusPage, LoginPage, SignupPage, PrivacyPage, TermsPage, SecurityPage) | `src/pages/*.tsx` | `dist/...` |
| `demo/` (root flat HTML) | legacy static | `index.html`, `changelog.html`, `privacy.html`, `security.html`, `signup.html`, `status.html`, `terms.html`, `deploy.sh`, `nginx.conf` | — | n/a |

### 3.2 Routes покрытые existing decoy

`tech-blog` (React Router): `/` HomePage, `/archive` ArchivePage, `/about` AboutPage, `/blog/:slug` PostPage — **4 routes**.
`saas-landing` (React Router): `/`, `/pricing`, `/blog`, `/blog/:slug`, `/docs`, `/about`, `/careers`, `/login`, `/signup`, `/privacy`, `/terms`, `/security` — **12 routes**.
`analytics-ru`: 13+ routes (i18n).
`metricshub`: 9 routes.

### 3.3 Static generation pipeline (`internal/deploy/`)

`internal/deploy/decoy_content_gen.go` (547 LOC) — `GenerateContent(domain, templateName) DecoyContent`:
- FNV-hash domain → seed → math/rand
- Pools: `companyNames`, `taglines`, `metaDescs`, `companyNamesRu`, `taglinesRu`, `primaryColors`, `blogTitlesTech`, `blogTitlesSaas`, …
- Returns struct with `Domain, CompanyName, Tagline, MetaDesc, MetaKeywords, PrimaryColor, UnsplashSeed, BlogPosts[N], NavLinks, Year`
- **DETERMINISTIC** by domain — same domain = same content

`internal/deploy/steps_decoy.go` (1011 LOC) — основной orchestrator:
- `deployDecoy()` — install nginx+certbot → upload files → nginx config → LE cert → renewal hook → TrustTunnel integration
- `uploadDecoyFiles(mgr, templateName, domain)` switch:
  - `"tech-blog"` → `uploadGeneratedDecoyFiles` (Go-template render: post.html, sitemap.xml.tmpl, robots.txt.tmpl)
  - `"saas-landing" | "metricshub" | "analytics-ru" | ""` → `uploadReactDecoyFiles` (pre-built React dist + inject `__*__PLACEHOLDER__` → JSON config in index.html + Go-template sitemap/robots)
- `deployNginxConfig(mgr, domain, templateName)` — generates nginx config inline (lines 326-423)

**Wire to handler:** `internal/deploy/steps_shadowlink_domain_decoy_map.go` (240 LOC) emits the `domain_decoy_map:` YAML block which `shadowlink/server/decoy.go::DecoyHandler` reads to map `Host → /var/www/<template>` directory.

### 3.4 Endpoints serving — currently

| Endpoint | Source | Reality |
|---|---|---|
| `GET /` | React SPA via `try_files $uri $uri/ /index.html;` | OK |
| `GET /blog` | React route (saas-landing, analytics-ru only) | OK if template has it |
| `GET /blog/<slug>` | React route + tech-blog Go-rendered `.html` | OK (tech-blog produces real .html files) |
| `GET /about` | React route (all templates) | OK |
| `GET /contact` | **MISSING** — no route in any template | ❌ falls to `/index.html` via SPA fallback |
| `GET /privacy` | React route (saas-landing, analytics-ru, metricshub) | OK; missing in tech-blog |
| `GET /404` | **NO real 404 page** — nginx default + SPA fallback overrides everything | ❌ all 404s return index.html with 200 |
| `GET /robots.txt` | Generated (`saasRobotsTmpl` / `tech-blog/robots.txt.tmpl`) | OK |
| `GET /sitemap.xml` | Generated | OK |
| `GET /rss.xml`, `/feed.xml` | **MISSING** | ❌ |
| `GET /search` | **MISSING** | ❌ |
| `GET /.well-known/security.txt` | **MISSING** | ❌ |
| `GET /favicon.ico` | Not explicitly generated | depends on React build |
| `GET /v2/health` | nginx hard-coded (`return 200 '{"status":"ok",…}'`) | ✅ realistic |
| `GET /v2/*` | nginx hard-coded `return 401 '{"error":"unauthorized",…}'` | ✅ realistic |
| `GET /*.php|.asp|.aspx|.jsp` | nginx `return 404` | ✅ scanner-block |
| `HEAD <anything>` | Default nginx behaviour | partial — works but no custom |
| `OPTIONS <anything>` | Default nginx (405) | ⚠️ no CORS preflight handling |

### 3.5 nginx config (rendered in `deployNginxConfig`)

Currently sets:
- `listen 127.0.0.1:8080` (HTTP, behind TrustTunnel). **Note:** this is the TrustTunnel architecture — shadowlink path uses different nginx (port 443 TLS → unix socket). The decoy file-tree in `/var/www/<template>` is served by either path.
- Security headers: `HSTS max-age=63072000`, `X-Content-Type-Options nosniff`, `X-Frame-Options DENY`, `Referrer-Policy strict-origin-when-cross-origin`, `X-Request-ID`, `X-Powered-By "MetricsHub/2.4.1"`, `X-Region "eu-west"` — **stylistic mismatch:** `X-Powered-By` says "MetricsHub" regardless of `templateName`. Fix needed.
- `try_files $uri $uri/ /index.html` SPA fallback — **breaks any chance of real 404**.
- `location ~* \.(css|js|png|jpg|svg|ico|woff2?)$ { expires 30d; immutable }` — good caching.
- `gzip on; gzip_types text/plain text/css application/json application/javascript text/javascript;` — gzip ON.
- **brotli OFF** (debian nginx default).

---

## Section 4 — Gaps vs real blog (полировка target)

### 4.1 HTTP method handling

| Surface | Issue |
|---|---|
| **HEAD** | nginx auto-handles HEAD same as GET (Content-Length, no body) — OK |
| **OPTIONS** | Returns 405 Method Not Allowed by default — real WordPress/static blogs typically return Allow header. Low risk, but probe vectors do test OPTIONS. |
| **PUT/DELETE/PATCH** | Default 405. ✅ matches reality. |
| **TRACE** | Default 405 from nginx ≥1.10. Good. |

### 4.2 Caching headers

| Header | Status | Recommendation |
|---|---|---|
| `ETag` | Auto-generated by nginx for static files (mtime+size hex) | ✅ already present |
| `Last-Modified` | Auto-generated | ✅ |
| `Cache-Control` | Set inline (`no-cache, must-revalidate` for `/`, `public, immutable` for hashed assets, `no-store` for /v2/health) | ✅ mostly correct, но static SPA `/blog/<slug>.html` тоже `no-cache` — реальный блог cached дольше |
| `Vary` | `gzip_vary on` → added on compressed responses | partial — нет `Accept-Encoding` для не-gzip |
| `Age` | Not present | low-risk (only set by intermediaries; CF synthesizes) |
| `Expires` | Not set | low-risk |
| If-None-Match / 304 flow | nginx auto-handles | ✅ |

### 4.3 Compression

- **gzip:** ON, types narrow (text/plain, text/css, application/json, application/javascript, text/javascript) — **MISSING:** `text/html`, `text/xml`, `application/xml`, `application/rss+xml`, `application/atom+xml`, `image/svg+xml`, `application/wasm`.
- **brotli:** OFF (default Debian nginx — Brotli requires `libnginx-mod-brotli` or compile). Real CF-fronted sites all support brotli. **Probe vector:** CF intermediate adds br, origin doesn't. **Medium risk.**
- `gzip_min_length 1024` — OK (very small responses uncompressed).
- `gzip_comp_level` — not set → default 1 (real sites use 5-6).

### 4.4 robots.txt / sitemap

- **robots.txt:** `User-agent: *  Allow: /  Sitemap: https://<domain>/sitemap.xml` — **too minimal**. Real blogs declare `Disallow: /wp-admin/`, `Disallow: /search?`, `Crawl-delay`, sometimes specific bots. Adding 5-10 realistic disallow lines would help.
- **sitemap.xml:** OK structure, but `<lastmod>` only on blog posts; root `/`, `/about`, `/blog` missing `<lastmod>`.
- **sitemap index** (`/sitemap-index.xml`): missing — real sites with >50K URLs use index. Optional.

### 4.5 404 / error pages

**Critical gap.** SPA fallback `try_files $uri $uri/ /index.html` means **every non-matching path returns 200 + index.html**. Real blogs:
- Return 404 status with branded HTML page
- WordPress: `<title>Page not found - <site name></title>` + same nav/footer
- Static blogs (Hugo/Jekyll): generate `/404.html` and nginx serves it via `error_page 404 /404.html;`

**Fix:** Add `error_page 404 /404.html;` + generate `/404.html` in `decoy_content_gen.go`. Disable SPA fallback for `/blog/*` and `/api/*` paths.

### 4.6 HTTPS / HSTS

- HSTS header: `max-age=63072000; includeSubDomains; preload` — ✅ aggressive but valid.
- HTTP→HTTPS redirect: handled at TrustTunnel/CF, not at nginx :8080.
- `Strict-Transport-Security` only on decoy nginx response — **lost** when shadowlink path serves decoy via its own `decoy.go::ServeHTTP` (only sets X-Content-Type-Options/X-Frame-Options/Referrer-Policy).

### 4.7 Other "real-site" signals

| Signal | Status | Recommendation |
|---|---|---|
| `Server: nginx/1.x.x` | `server_tokens off` → just `nginx` | acceptable |
| `X-Powered-By: PHP/8.x` или `Express/4.x` | Currently fakes `MetricsHub/2.4.1` | mismatch with template name; should be `WordPress 6.4` or `Ghost 5.x` for a blog persona, or absent |
| `<link rel="alternate" type="application/rss+xml">` в HTML head | **MISSING** in tech-blog index.html | ❌ — real blogs declare RSS |
| Open Graph + Twitter meta | ✅ present in tech-blog/index.html |  |
| JSON-LD structured data | ✅ present (uses `@type: Blog`) — but contains weird `propertyID: "rl-state"` field that looks like a debugging leak. **AUDIT:** lines 32-37 of tech-blog/index.html have `"identifier": {"propertyID": "rl-state", "value": "v1;bucket=none;refill_in=0;burst_left=100;exempt=0;…"}` — this is a **REAL leak** of rate-limit state from server side! Has to be removed/replaced with realistic identifier (e.g. ISSN). |
| favicon.ico | depends on React build's public/ — may be missing | check all 4 templates |
| `/apple-touch-icon.png`, `/manifest.json` | depends on each React template | check |
| Static assets immutable cache | ✅ via React's hashed filenames + `expires 30d` |  |
| Comment system / RSS feed | none | optional polish |
| Analytics snippet (GA / Plausible) | none | could add fake Plausible script for realism |
| Cookie banner | none | RU/EU sites typically have it — adding would help analytics-ru |
| `<noscript>` fallback | none in React SPAs — **harmful**: TSPU may detect "JS-only sites have nothing in noscript" pattern. Real blogs render server-side and have text content in noscript |

### 4.8 Per-template polish gaps

- **tech-blog**: Goлоgy lang="en" but content can be RU (companyNamesRu pool unused for this template). Mix risk if domain looks Russian. Check whether `analytics-ru` is the only ru template or if all four can switch via param.
- **All React SPAs**: Initial HTML payload is **near-empty** (`<div id="root"></div>` + script tag). Curl/JS-disabled view → blank page. SSR/SSG (Vite SSG) would make it more convincing but is large work.
- **`/blog`** на metricshub — отсутствует (template doesn't have BlogPage). If we want consistent "blog" persona across all decoys, add it.

### 4.9 Existing `nginx_404.html` leak (from habr-mirror)

`shadowlink/server/nginx_404.html` (`<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>`) — was used by LiveBlogHandler. **Will be deleted along with live_blog. But:** идея реально использовать "стандартный nginx 404" хорошая — это менее уникальный fingerprint чем custom branded 404 на shadowlink path (`decoyWithTimingParity → decoy.go::ServeHTTP`). Recommend porting it (or equivalent) as the **default 404 body** для shadowlink decoy path.

---

## TOP-3 Risks для Phase 1

### Risk 1 — JSON-LD `rl-state` leak in `demo/tech-blog/index.html` (HIGH)

**Что:** Lines 32-37 в `demo/tech-blog/index.html` содержат JSON-LD blob с `"propertyID": "rl-state", "value": "v1;bucket=none;refill_in=0;burst_left=100;exempt=0;…"`. Это **прямой output rate-limit sentinel'а** из `shadowlink/server/ratelimit_sentinel_test.go` (RLSentinel v1 format) — попал в blog template как debug artifact. **Не относится к habr-mirror**, present and deployed today.

**Воздействие:** Любой scraper / probe / DPI крупного игрока (TSPU, Censys, internet-wide scans) видит `rl-state` literal на every tech-blog domain → unique fingerprint → ShadowLink installations легко clusterizable.

**Mitigation в Phase 1:** Must fix as P0 before any polish work. Replace JSON-LD identifier with realistic value (ISSN/ISBN/DOI), or drop the `identifier` field entirely.

### Risk 2 — Удаление LiveBlog ломает `cmd/api/main.go` route registrations + admin frontend bundle (HIGH)

**Что:** `cmd/api/main.go` lines 964-967 регистрируют 4 роута для LiveBlog (`/disable-live-blog/:id`, `/live-blog-config/:id` GET/PUT, `/apply-live-blog/:id`). Frontend `LiveDecoyConfigTab.tsx` (279 LOC) и `LiveDecoyMetricsTab.tsx` (249 LOC) дергают эти endpoints через `getLiveDecoyConfig/putLiveDecoyConfig/applyLiveDecoy` из `frontend/src/api/shadowlink.ts`. `ShadowLinkPage.tsx` mounts эти tabs (lines 8-9, 16-26 — `Tab` type has `'live_decoy' | 'metrics'`).

**Воздействие:** Atomic-удаление невозможно — нужно одной PR удалить backend handlers + routes + frontend components + types + tab. Иначе CI build TS-fail или 404 в browser при клике на удалённый таб.

**Mitigation:** Order in Phase 1 plan:
1. Frontend: delete LiveDecoy*.tsx + remove from ShadowLinkPage tabs + drop from api/shadowlink.ts/types/shadowlink.ts
2. Backend: delete routes in main.go → delete handler funcs → delete LiveBlogConfigJSON → delete YAML rendering → delete server/live_blog*.go + html_rewriter*.go + config struct/file parsing
3. DB: migration 119 (DROP TABLE decoy_live_blog_metrics) + delete `internal/shadowlink/metrics_scraper.go`
4. Tests: re-run всю shadowlink/internal/admin/internal/deploy test suite — есть chance что фронтенд `metrics` tab всё ещё нужен (renamed to "decoy metrics" or removed entirely).

**Also note:** `protocol_configs.applied_at` column was added by migration 071 alongside `decoy_live_blog_metrics` — **must preserve** (used by UI's pending-apply UX в admin flow вне LiveBlog scope).

### Risk 3 — Existing SPA fallback `try_files … /index.html` makes any 404 impossible (MEDIUM)

**Что:** `deployNginxConfig` (`steps_decoy.go:355`) hardcodes `try_files $uri $uri/ /index.html;` для root location. Это значит:
- `GET /random-page-that-does-not-exist` → 200 + index.html (с правильным title для домашней)
- Real blogs return 404 on unknown paths
- DPI/probe vectors that send `GET /admin.php`, `GET /wp-login.php`, `GET /robots.txt.bak` get 200 instead of 404 → **definitive fingerprint** что это SPA-fallback (not a real CMS).

Currently only `/v2/*` and `*.php|asp|aspx|jsp` return non-200. Everything else 200.

**Воздействие:** Phase 1 "fully convincing real blog" goal — **этот gap самый weighty**. Все остальные polish items (HEAD/OPTIONS/ETag/compression) маленькие по сравнению.

**Mitigation:**
- Generate `/404.html` template в `decoy_content_gen.go` (branded "Page not found"; nav + footer; suggested links to homepage/archive).
- nginx config: `error_page 404 /404.html;` + remove SPA fallback for paths matching `/wp-admin|wp-login|admin\.php|phpmyadmin|.env|\.git|robots\.txt\.|sitemap\.xml\.` → respond 404 explicitly.
- Restrict SPA fallback ONLY to known React routes (per template — `/blog/*`, `/about`, `/archive`, `/pricing`, …). Else 404.
- This requires per-template route knowledge — make `deployNginxConfig` accept a list of "valid SPA routes" from `decoy_content_gen.go`.

---

## Appendix — Inventory totals (one-line)

- **Habr-mirror files for full deletion:** 10 server/, 3 frontend/ — **~3 500 LOC**.
- **Partial deletions:** 1 large handlers file (`shadowlink_handlers.go`: 900 LOC), config.go (~110), fileconfig.go (~80), handler.go (~15), metrics.go (~100), main.go (~5), audit.go (3 constants).
- **DB:** 1 table to drop (`decoy_live_blog_metrics`), 1 column to KEEP (`protocol_configs.applied_at`).
- **Existing decoy:** 4 React templates × ~10 routes each + tech-blog Go-rendered blog posts; 1011-LOC orchestrator deploys via SSH.
- **Top 3 risks:** rl-state leak (P0); coordinated removal across stack (HIGH); SPA fallback eliminates 404 (MEDIUM).
