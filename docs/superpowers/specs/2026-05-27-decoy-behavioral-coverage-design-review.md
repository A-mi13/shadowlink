# Code Review — Decoy Behavioral Coverage Design Spec

**Дата ревью:** 2026-05-27
**Reviewer:** Opus 4.7 (1M context), senior code reviewer mode
**Object:** `D:/NIXAVPN/shadowlink/docs/superpowers/specs/2026-05-27-decoy-behavioral-coverage-design.md`
**Verdict (one-liner):** Spec в целом разумен, но содержит **несколько CRITICAL архитектурных ошибок в nginx-конфиге** (логически не возвращает 404 в задуманных случаях; конфликт `location ~* ext` с `error_page`), **HIGH рассогласование с реальностью кода** (decoy serving ходит через TrustTunnel reverse_proxy + nginx, но в коде `shadowlink/server/decoy.go` есть и второй decoy-путь), **серьёзный pitfall с per-template дубликатами** при росте до 4 templates × N страниц. До implementation нужно: пересмотреть nginx pattern (см. C1), решить вопрос про PoolReadiness/2-х путей decoy (H1), и явно зафиксировать что делает TrustTunnel reverse_proxy (H4).

---

## Общее резюме

1. **Направление верное.** 3-persona split — нормальная декомпозиция (но см. C5 — она недо- или избыточна в зависимости от того, что станет с `metricshub`).
2. **Real-404 nginx pattern в § 3.1 содержит логическую ошибку.** Конструкция `try_files /index.html =404` для known SPA route возвращает 404, если `index.html` отсутствует в webroot — это **никогда не должно произойти**, но семантически "try_files на единственный файл, всегда существующий, fallback в 404" — это просто `return 200`. Реальный 404 на unknown URL обеспечивает только `location /` с `try_files $uri =404` ниже — и здесь логика правильная. Однако комбинация `location ~* \.(css|js|png|...)` ниже **перехватывает** все запросы с этими extensions, включая `/foobar.png` который не существует — и `try_files` там нет, nginx вернёт **403 или дефолтный 404 (без error_page!)** в зависимости от config. Это новая fingerprint-поверхность.
3. **`X-Powered-By` мы оставляем — а реальные SaaS landings в 2026 чаще НЕ ставят X-Powered-By.** Stripe, Linear, Vercel, Notion — не ставят. Это противоречит твоей же цели "real US-hosted sites". См. M3.
4. **`/v2/health` без auth у SaaS = anti-pattern.** Real SaaS public health endpoints либо `/health` (root, не versioned) либо `/status`, либо за auth. `/v2/health` + публичный JSON с region/version = signal "test fixture, not prod".
5. **404.html как React entry — over-engineering и сам по себе НОВАЯ fingerprint поверхность.** См. C3. Pure HTML 404 c встроенным <style> = более типично для prod sites (Cloudflare error, Vercel 404, GitHub 404 — все статичные).
6. **Backwards-compat для `templateName=""` сохранён, но не покрывает кейс смены template через UI** — нужна явная migration story (H2).
7. **Smoke checklist 6.4 — хороший старт, но не проверяет ничего из того что зондированию РКН важно** (TLS fingerprint, h2 settings, response timing). Это вне scope этого spec'а, но **стоит явно указать "не проверяет"**, чтобы юзер не думал что чек-лист exhaustive.
8. **Per-template дубликаты NotFoundPage/ContactPage/PrivacyPage — реальная проблема.** 4 шаблона × ~50 LOC дубликат — это окей, но как только дойдём до 6 templates с 5 страницами каждый = 1500 LOC copy-paste. См. M6.
9. **Risk overall:** spec ПРОДВИГАЕТ нас вперёд по behavioral coverage, но **вводит несколько новых signature surfaces** одновременно с закрытием старых. Net-positive — да. Гарантированно — нет.

---

## Top-5 Issues (sorted by severity)

| # | Severity | Section | Title |
|---|---|---|---|
| 1 | **CRITICAL** | § 3.1 (SaaS nginx) | `location ~* \.(css\|js\|...)$` создаёт несимметричный 404 path для несуществующих ассетов с этими extensions |
| 2 | **CRITICAL** | § 3.1, § 3.2 (SaaS+Blog nginx) | `try_files /index.html =404` для known SPA routes семантически бессмысленен и не повторяет real-world nginx pattern |
| 3 | **HIGH** | § 4.2 (404.html React entry) | Standalone Vite entry для 404 = новый fingerprint (split bundle, отдельный JS chunk, разный init time) |
| 4 | **HIGH** | § 8 + общий контекст | Spec игнорирует второй decoy-путь в `shadowlink/server/decoy.go::DecoyHandler` — там тоже X-Frame-Options и тоже static serve. Что с ним? |
| 5 | **HIGH** | § 2.3 + § 3.1 | Mixing `add_header` уровня server с `add_header` уровня location — nginx **затирает** server-уровневые headers если в location есть хоть один `add_header` |

---

## Полный список findings

### CRITICAL

#### C1. `location ~* \.(css|js|png|jpg|svg|ico|woff2?)$` — несимметричный 404 path
**Section:** § 3.1, lines 226-230 (и аналогично § 3.2, § 3.3)

```nginx
location ~* \.(css|js|png|jpg|svg|ico|woff2?)$ {
    expires 30d;
    add_header Cache-Control "public, immutable";
    access_log off;
}
```

Этот блок **перехватывает все запросы** с указанными extensions, ПЕРЕД `location /`. Внутри нет `try_files`. Что будет на `GET /nonexistent.png`?
- nginx ищет файл `{webRoot}/nonexistent.png`
- Не находит → возвращает **404, но БЕЗ обработки через `error_page`** (потому что error_page работает на уровне server, но `try_files` в этом блоке отсутствует и nginx генерит дефолтный 404 page).

**Эффект:** probe делает `curl /random.png` → получает default nginx 404 (HTML с `<center>nginx</center>`), а на `curl /random` (без extension) — кастомный 404.html. **Это fingerprint** — разные 404 responses для разных URL classes.

**Кроме того**, `add_header Cache-Control` в этом блоке **затрёт всё** из server-level (см. C5).

**Fix:** добавить `try_files $uri =404;` явно, и убедиться что `error_page 404 /404.html` срабатывает в этом контексте (потребует тестирования: `error_page` на уровне server работает, но `internal` location нужен).

```nginx
location ~* \.(css|js|png|jpg|svg|ico|woff2?)$ {
    try_files $uri =404;
    expires 30d;
    add_header Cache-Control "public, immutable";
    access_log off;
}
```

И нужен **manual e2e test** на pl1: `curl -sI https://datacanvases.com/random.png` → должен возвращать `/404.html` body, не дефолтный nginx 404.

---

#### C2. `try_files /index.html =404` для known SPA routes — семантически бессмысленен
**Section:** § 3.1, lines 166-177

```nginx
location = /          { try_files /index.html =404; ... }
location = /pricing   { try_files /index.html =404; ... }
```

`try_files /index.html =404` означает: «попробуй файл `/index.html` относительно root. Если не существует — верни 404». В webroot **всегда** есть `index.html` (без него ни одна страница SPA не работает). Поэтому `=404` тут **никогда не сработает**. Это эквивалентно `return 200` с serving `/index.html`.

Это не bug per se, но:
1. Spec даёт читателю **ложное впечатление** что эти блоки делают "real 404". Они не делают — 404 на этих URLs **физически не возможен**.
2. Real-world nginx pattern для SPA с настоящим 404 выглядит иначе. Стандартный pattern:
   ```nginx
   location / {
       try_files $uri $uri/ /index.html;
   }
   ```
   плюс **внутри React** компонент `<Route path="*">` рендерит NotFoundPage. nginx всегда отдаёт 200 + index.html, а React rendere ставит correct HTTP semantics через meta или другой механизм. Это **универсальный** approach реальных сайтов (Vercel, Netlify, Cloudflare Pages — все так).

Spec вместо этого делает hybrid: для known routes — 200 от nginx с index.html, для unknown — real 404 от nginx. **Реальные сайты так не делают.** Это сама по себе fingerprint-сигнатура: probe сравнивает behavior с известными CDN/hosting platforms — никто не делает explicit list of known SPA routes на nginx-уровне.

**Fix variant A (simpler, more realistic):** оставить `try_files $uri $uri/ /index.html =404` и добавить корректный 404 ответ через **React Router catch-all** + кастомный 404.html для случаев когда index.html не загружается. Real 404 не нужен на каждый URL — нужен на классы (scanner paths `/wp-admin`, etc).

**Fix variant B (если действительно хотим real-404):** generate SPA route list at build-time через Vite plugin, но **не на nginx-уровне** — это not how real-world deployments do it. Лучше всего: nginx даёт 200+index.html на любой not-found-file URL, и React app сам выставляет `<meta name="robots" content="noindex">` + рендерит 404 page. Реальные сайты делают именно так.

**Действие:** я бы **переписал § 3.1 целиком** с pattern variant A. Real-world fingerprint для SPA — 200 на любой path, и это норма.

---

### HIGH

#### H1. Второй decoy-путь не упомянут в spec'е
**Section:** § 2.3 "Что НЕ меняется", § 1.3 "Что НЕ в этой волне"

В `shadowlink/server/decoy.go::DecoyHandler::ServeHTTP` (lines 88-104) есть **второй static-decoy serving path** — Go-уровневый, через `http.FileServer`. Он также:
- Ставит `X-Frame-Options: SAMEORIGIN` (не `DENY`!)
- НЕ ставит `X-Powered-By` вообще
- НЕ ставит `Strict-Transport-Security`
- НЕ имеет real 404 (стандартный `http.FileServer` возвращает дефолтный Go 404)

**Когда он работает?** Когда трафик идёт **не через nginx**, например через embedded http path в shadowlink-server (handler.go routing). А когда трафик идёт через nginx? Когда `reconfigureTrustTunnelForDecoy` добавил reverse_proxy → nginx на 127.0.0.1:8080.

**Проблема:** на разных code paths decoy headers **разные**. Probe может попасть **на оба пути** (через CF + через прямой IP). Spec улучшает **только** nginx-путь и оставляет Go-путь нетронутым → instant fingerprint divergence "headers зависят от того, как ты туда попал".

**Действие:** в spec **явно объявить scope:**
- Если этот волне Go-decoy-путь действительно не трогаем — добавить раздел "Known divergence: Go-уровневый DecoyHandler в shadowlink/server/decoy.go обслуживает другие code paths (например, прямой IP без CF). Его behaviour отличается от nginx-decoy. Закрытие этой divergence — отдельная волна T-XYZ."
- Альтернатива (preferred): **унифицировать** — Go-decoy перенаправляет на nginx через internal reverse_proxy, тогда все запросы идут через один config. Это требует pre-work.

Без этого решения **новые real-404, security.txt, humans.txt — будут доступны только через nginx-путь**, и probe через прямой IP это сразу заметит.

---

#### H2. Что происходит с серверами при изменении template через UI?
**Section:** § 8.1 "Legacy `templateName = ''`"

Spec говорит: "при следующем re-deploy получат SaaS persona с MetricsHub branding". Что если **до** re-deploy admin меняет template через UI (saas-landing → tech-blog)? Что произойдёт:

1. Admin UI вызывает `updateDecoyTemplate(mgr, "tech-blog", domain)` — заливает новые файлы.
2. Но **`deployNginxConfig` не вызывается в этом code path** (см. `updateDecoyTemplate` lines 947-961).
3. → nginx config остаётся **со старой persona** (saas → MetricsHub headers), а файлы — tech-blog.
4. → Probe видит: HTML brand = "tech-blog" (новый), HTTP headers = "MetricsHub/2.4.1" (старый). **Brand inconsistency — то самое от чего мы пытаемся уйти!**

**Fix:** в `updateDecoyTemplate` добавить вызов `deployNginxConfig(mgr, domain, templateName)`. **Это нужно прописать в spec'е** как required change. Сейчас spec говорит "internal/admin не трогается", а тут как раз надо тронуть orchestrator-уровень.

---

#### H3. `add_header` на уровне location **затирает** server-level headers
**Section:** § 3.1, lines 146-152 (server-level) vs lines 166-177 (location-level)

nginx **семантика наследования add_header**: если в `location {}` есть **хоть один** `add_header`, **ВСЕ** server-level `add_header` исчезают для этого location.

В § 3.1:
- server-level: `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `X-Request-ID`, `X-Powered-By`, `X-Region`
- location = /pricing: `add_header Cache-Control "no-cache, must-revalidate"`

→ Запрос на `/pricing` **не получает** STS, XCTO, XFO, Referrer-Policy, X-Request-ID, X-Powered-By, X-Region. Только `Cache-Control`.

Это **подтверждённое поведение nginx** и **известный pitfall**. Probe делает `curl -I /` (видит все security headers) и `curl -I /pricing` (видит только Cache-Control) → **детект**.

**Fix:** либо повторять весь блок `add_header` в каждом location, либо использовать `include /etc/nginx/snippets/security-headers.conf;` в каждом location. Это удваивает размер конфига, но обязательно. Альтернатива — модуль `ngx_http_headers_more_module`, но он не дефолтный.

**Действие:** spec нужно **полностью переделать** в части `add_header` композиции, или использовать `more_set_headers` (но это extra dependency).

---

#### H4. Spec оставляет TrustTunnel reverse_proxy конфигурацию без изменений, но **именно она** определяет TLS-level headers (включая HTTP/2 SETTINGS frame)
**Section:** § 1.3, § 2.3

TrustTunnel `[reverse_proxy]` секция терминирует TLS и форвардит на 127.0.0.1:8080. nginx-headers — это **уровень после** TLS. С точки зрения внешнего probe, **первое впечатление** определяется TrustTunnel's TLS handshake и его HTTP/2 настройками. Spec ничего не говорит про:
- Какой TLS profile у TrustTunnel? Matches ли он Chrome `Chrome_133` который вы lock'нули в shadowlink? Если нет — JA3 mismatch между WS (через CF) и plain HTTPS (через TT).
- Какие H2 SETTINGS frames у TrustTunnel? Real nginx 1.24 имеет конкретный fingerprint.
- ALPN: `h2,http/1.1` или только `http/1.1`?

Это **не в scope** этого spec'а — но если оно не контролируемо, то **закрытие nginx-headers gaps только частично закроет behavior fingerprint**, потому что TLS-уровневые fingerprints всё ещё расходятся с real US-hosted SaaS.

**Действие:** добавить в § 1.3 "Что НЕ в этой волне" пункт:
> TLS handshake fingerprint TrustTunnel (JA3, ALPN, H2 SETTINGS) — отдельная инициатива. Эта волна закрывает HTTP-уровень, но если TLS-fingerprint расходится с real nginx — probe всё равно заметит "странный сервер". Не блокирует, но **не гарантирует full coverage**.

---

#### H5. `/v2/health` JSON public — anti-pattern для real SaaS
**Section:** § 3.1, lines 187-192

Real SaaS health endpoints либо:
- За auth (`401` без token)
- На отдельном поддомене (`status.example.com` через Statuspage.io / Better Uptime)
- На `/health` без version prefix (k8s liveness style)

Public `/v2/health` который **возвращает** `region: us-east-1` + `version: 3.2.1` — **раскрывает infrastructure** без причины. Real SaaS этого не делают. Это **сам по себе** signal "test/staging fixture, not prod" в 2026.

**Fix:** либо
- A) Сделать `/v2/health` за auth (401), сам JSON `/health` либо отсутствует либо 401.
- B) Минимальный health: `{"status":"ok"}` БЕЗ region/version. Probe всё равно подумает что у нас прод.
- C) Перенести на `status.<domain>` поддомен — но это deploy infra change.

**Рекомендация:** B (минимальный JSON) — самый дешёвый fix.

---

### MEDIUM

#### M1. Standalone `404.html` Vite entry создаёт **новый JS chunk** = новый fingerprint
**Section:** § 4.2

Vite multi-entry build с `main` + `notFound`:
- Создаёт `assets/main.js` (entry для index.html)
- Создаёт **отдельный** `assets/notFound.js` (entry для 404.html)
- Создаёт **shared chunks** (React, ReactDOM)

Probe сравнивает `<script src>` на `/` и `/random-404` — разные entry → fingerprint "это site с custom 404 entry, что нетипично". Real sites обычно:
- A) Static 404.html (pure HTML + inline CSS) — Vercel/Cloudflare/GitHub style
- B) SPA с `<Route path="*">` который возвращает Same HTML (status 200, не 404)

**Решение spec'а** даёт **gorst of both worlds** — extra JS chunk + extra HTTP request на 404 + standalone React app.

**Fix:** перейти на **pure HTML 404 с inline стилями**. Аргумент spec'а "stack divergence через DOM diff" — слабый. Real prod 404 pages — это **static HTML+CSS**, и probe это **ожидает**. Заявление "React vs vanilla = fingerprint" неверно — это **typical pattern**.

```html
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>404 — Not Found</title>
<style>body{font-family:system-ui;...}</style>
</head>
<body>
<h1>404</h1>
<p>This page could not be found. <a href="/">Go home</a></p>
</body>
</html>
```

Один файл, один шаблон с brand-подстановкой, генерится в `internal/deploy/decoy_content_gen.go` рядом с robots.txt. Никаких Vite multi-entry, никакого нового JS chunk. **Net-positive по fingerprint coverage**.

---

#### M2. Favicon "generate простыми color-blocks с brand-инициалом" — это сам по себе fingerprint
**Section:** § 4.5

Real sites используют **профессиональный** дизайн favicon (logo на gradient, etc.) или **дефолтный** Vite favicon (тот самый purple `vite.svg`). Auto-generated color-block с инициалом — **известный pattern для AI/quick projects** (GitHub Codespaces, Stackblitz starters). Это **отдельная категория** в восприятии.

**Fix:** взять **бесплатные SVG favicons** с готовых icon-наборов (Heroicons, Lucide, Feather) per template. 4 favicon × 1 раз — это 4 файла в репо, не auto-generated.

Альтернатива: использовать **emoji favicon** (Twemoji rendered SVG) — это **очень типично** для blogs/utilities (https://emojify.io style). Это нормально.

---

#### M3. `X-Powered-By` для SaaS — устаревший signal
**Section:** § 2.2, § 3.1

В 2026 real prod SaaS (Stripe, Linear, Vercel, Notion, Figma, Slack web app) **не ставят** `X-Powered-By`. Это **легаси-конвенция** из PHP-эпохи (`X-Powered-By: PHP/5.4`). Современные frameworks (Next.js, Remix, SvelteKit) **отключают** этот header by default.

Spec вводит `X-Powered-By: Crest/3.2.1` как **positive signal** — но в действительности это **negative signal** для probe который сравнивает с real US SaaS sample. Probe видит "X-Powered-By присутствует → это либо legacy app, либо fake".

**Fix:** **вообще не ставить** X-Powered-By для SaaS persona. `X-Region` тоже снять (не типично). Brand consistency обеспечивается через **HTML content**, не через HTTP headers.

Это упрощает spec и убирает целый класс bugs (M11 ниже про consistency).

---

#### M4. `humans.txt` text слишком "AI-generated"
**Section:** § 3.1, lines 209-213

```
/* TEAM */
  Engineering: hello@{{domain}}
  Support: support@{{domain}}

/* SITE */
  Last update: 2026-04-10
  Standards: HTML5, CSS3, ES2024
  Components: React 19, Vite 6
```

Real `humans.txt` имеют:
- Имена людей (с никами)
- Городские координаты
- Twitter handles
- "Thanks to..." секцию

Шаблонный `humans.txt` без имён — **сам по себе fingerprint**. Probe который соберёт 100 humans.txt с разных US sites увидит наш как outlier.

**Fix:** либо генерить из templated set имён (5-10 рандомных human names from common-name corpus, deterministic per domain), либо **не делать humans.txt вообще**. Лучше "файл отсутствует (404)" чем "очевидно auto-generated".

`humans.txt` далеко не universal — отсутствие НЕ выглядит подозрительно. Это NOT must-have, в отличие от security.txt (которая теперь почти везде).

**Рекомендация:** убрать humans.txt из scope, оставить только security.txt.

---

#### M5. `Allow: GET, POST, OPTIONS` для SaaS API — не соответствует real REST
**Section:** § 3.1, lines 216-223; § 9.2

Real REST APIs возвращают `Allow: GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE` для `/api/*` endpoints. Минимальный `GET, POST, OPTIONS` — **подозрительно слабый** Allow для SaaS. Probe который тестирует `OPTIONS /api/users` ожидает увидеть стандартный REST verb set.

**Fix:** `Allow: GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE`. Цена — нулевая, credibility — выше.

Также добавить `Access-Control-Allow-Methods` (real APIs ставят его в дополнение к `Allow`).

---

#### M6. Per-template дубликаты `PrivacyPage` копируются с заменой brand — typo-prone и не масштабируется
**Section:** § 4.3

Spec говорит "скопировано из saas-landing с заменой brand". Это **manual copy-paste** который при обновлении одного template **забудется** в других. Через 3 месяца у нас:
- saas-landing PrivacyPage: ~80 LOC (свежий)
- tech-blog PrivacyPage: ~80 LOC (копия 3-месячной давности)
- analytics-ru PrivacyPage: ~80 LOC (копия 6-месячной давности с поломанным `mailto:`)

Probe сравнит `<title>` / wording / footer на трёх decoy и заметит **разные версии одного текста с одного origin** — fingerprint "это всё один продукт под разными масками".

**Trade-off solution:**
- Создать **lightweight shared package** `demo/_shared/legal/` с одним PrivacyPage компонентом, который **импортируется** во все 4 templates через relative path `../../_shared/legal/PrivacyPage.tsx`. Каждый template передаёт свой brand через props.
- Vite не возражает против import за пределы package root если разрешено в config.
- Решает **изоляцию** (шаблоны всё ещё технически отдельные projects) **и** **DRY**.

Альтернатива (если не хотим shared): **make legal pages per-template intentionally different** — разное wording, разный layout, разные emails (`legal@`, `privacy@`, `dpo@`). Это **усиливает** разнообразие, **разрушает** correlation between sites.

**Spec должен выбрать один из двух path, не оставлять "копируется с заменой brand".**

---

#### M7. `X-Request-ID $request_id always` — анализ leak'ает request_id внутри
**Section:** § 3.1, line 150

nginx `$request_id` — random 16-byte hex per request. Useful для логов. Но **возврат его в response header** — это:
- Real prod sites: иногда делают (Heroku, Cloudflare X-CF-Request-ID), часто **нет**.
- Probe заметит формат `$request_id` — 32-hex char no dashes. Heroku формат — UUID with dashes. AWS — другой формат. → "это nginx default $request_id formatter" = signal.

**Fix:** либо убрать, либо переформатировать в UUID-like (`return 200 ... X-Request-ID "${request_id...}"`) с custom формат. Или просто убрать — отсутствие безопаснее чем nginx-default format.

---

#### M8. `WWW-Authenticate: Bearer realm="..."` без `error="invalid_token"`
**Section:** § 3.1, line 198

Real APIs возвращают:
```
WWW-Authenticate: Bearer realm="API", error="invalid_token", error_description="Missing or invalid token"
```

Spec возвращает только `realm` и `charset`. **`charset="UTF-8"`** в WWW-Authenticate — это редкий extension RFC 7617 для Basic, **не Bearer** (Bearer не использует charset). Probe заметит → "fake".

**Fix:** `WWW-Authenticate: Bearer realm="{{brand}}", error="invalid_token", error_description="Authentication required"`. Убрать `charset`.

---

#### M9. Spec не специфицирует **MIME type negotiation** для 404 page
**Section:** § 3.1

`error_page 404 /404.html` отдаёт `Content-Type: text/html`. Что если запрос пришёл с `Accept: application/json` (probe тестирует API-style 404)? Real APIs возвращают:
```json
{"error":"not_found","message":"..."}
```
с `Content-Type: application/json`.

nginx **не делает** content negotiation автоматически. Spec даёт ОДИН 404 (HTML), на любой Accept. Probe-тест:
```
curl -H 'Accept: application/json' /api/nonexistent
```
→ HTML 404 → fingerprint "this site doesn't do API 404 correctly".

**Fix:** добавить отдельный 404 для `/api/*`:
```nginx
location ~ ^/api/ {
    error_page 404 = @api_404;
    try_files $uri @api_404;
}
location @api_404 {
    default_type application/json;
    return 404 '{"error":"not_found","message":"Endpoint not found","code":404}';
}
```

Для blog/utility — JSON 404 не нужен (нет API).

---

#### M10. `internal` directive для `/404.html` location обязательна, но spec ставит её **только в одном месте**
**Section:** § 3.1 line 157, § 3.2 line 269, § 3.3 line 322

`location = /404.html { internal; ... }` — `internal` означает что URL `/404.html` **не доступен** напрямую через external request. Это правильно — иначе probe может **запросить** `/404.html` напрямую и получить кастомный 404 page с `200 OK` (suspicious).

Spec расставляет `internal` в трёх местах верно. Но **сам файл `404.html` всё ещё в webroot и может быть запрошен через static file pattern** `location ~* \.(css|js|html)$` если бы html был в extensions list. Сейчас не входит — но если кто-то добавит `.html` в `webFileExts` (existing line 211-220 у деплой-кода), станет проблемой.

**Fix:** в spec явно: "**не добавлять `.html` в `webFileExts`**" + добавить comment в коде. Или: переместить `/404.html` за пределы webroot (например, в `/etc/nginx/snippets/404.html`) и ссылаться через `root`. Тогда **физически не доступен** через FileServer.

---

#### M11. Brand inconsistency между `/v2/health` JSON и HTML
**Section:** § 3.1 line 189 + § 8.3

```
return 200 '{"status":"ok","version":"{{brandVer}}","region":"{{region}}","service":"{{brandName|lowercase}}"}';
```

Spec говорит "{{brandName|lowercase}}" — это **template syntax**. Go's `text/template` не имеет `lowercase` filter by default, нужен `funcMap`. Если забыть funcMap → `{{.BrandName | lowercase}}` падает с runtime error "function lowercase not defined".

**Fix:** либо хранить lowercase BrandName в `templateMeta` отдельным полем (`ServiceName string`), либо явно зарегистрировать funcMap в Go-уровне рендеринга nginx config.

В spec'е это **не описано**. Если implementation просто скопирует строку → nginx config будет содержать literal `{{brandName|lowercase}}` (template не отрабатывает, потому что это **nginx-config string**, а не Go template — путаница между двумя уровнями шаблонизации). Spec **не указывает** где именно substitution происходит: на стороне Go при генерации nginx-config? Через `sed`? Через `envsubst`?

Это **ambiguity** которая приведёт к багу.

**Действие:** spec должен явно содержать пример Go-кода рендеринга, например:
```go
type nginxSaaSData struct {
    Domain, WebRoot, BrandName, BrandLowercase, BrandVer, Region string
}
data := nginxSaaSData{
    Domain: domain, WebRoot: webRoot,
    BrandName: meta.BrandName,
    BrandLowercase: strings.ToLower(meta.BrandName),
    ...
}
tmpl.Execute(&buf, data)
```

---

### LOW

#### L1. `Content-Security-Policy` действительно отсутствует
**Section:** общий, user noted в вопросе

Real prod sites в 2026 **обычно** ставят CSP (хотя бы `default-src 'self'`). Отсутствие CSP **не подозрительно** (много legacy сайтов её не имеют), но **наличие** делает persona более credible. Cost — low. **Рекомендация:** добавить per-persona базовый CSP, **но** аккуратно — слишком строгий CSP сломает React inline scripts.

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'" always;
```

Это **не блокер** этой волны, но добавьте в follow-up wave.

---

#### L2. `Set-Cookie` действительно отсутствует — но это OK
**Section:** user noted в вопросе

Real SaaS landings **до login** обычно ставят:
- `_ga` (Google Analytics)
- `_csrf_token` (для form'ы signup)
- A/B test cookies

Но это требует **реальную** аналитику или session storage. Эмулировать через `add_header Set-Cookie` можно, но cookies без backend (которые reset на каждом запросе) → fingerprint "fake cookies, no session continuity".

**Рекомендация:** **не эмулировать cookies**. Probe который тестирует cookies ожидает session continuity (set on first request, sent back on next). Без real backend это невозможно. Отсутствие cookies → "static landing page, no tracking" — это **сама по себе** legitimate persona (privacy-focused sites, или просто sites без login). Real personas покрывают это.

---

#### L3. `Server: nginx` (without version)
**Section:** user noted

`server_tokens off` → header `Server: nginx` (без версии). Real prod sites:
- AWS CloudFront: `Server: CloudFront`
- Cloudflare: `Server: cloudflare`
- Stripe: `Server: nginx` (без версии, точно как у нас)
- Vercel: `Server: Vercel`
- nginx-direct (no CDN): `Server: nginx/1.24.0` или `Server: nginx` если server_tokens off

`Server: nginx` (без версии) — **типично для production**. NOT a signal. **Действие:** ничего не менять.

---

#### L4. HTTP/2 SETTINGS frame fingerprint — out of scope
**Section:** user noted

H2 SETTINGS — это **TLS+H2 уровень** (JA3S / Akamai H2 fingerprint). nginx config **не контролирует** SETTINGS — они захардкожены в `ngx_http_v2_module`. Real nginx 1.24 / 1.26 имеет конкретный fingerprint, и если TrustTunnel реализует свой H2 stack (не nginx), это будет diverge.

**Это вне scope этого spec'а.** Но связано с H4. **Действие:** добавить в `Out of scope` (§ 11):
> H2 SETTINGS frame fingerprint (Akamai H2 hash) — определяется TrustTunnel's HTTP/2 stack. Если TT не использует stock nginx h2 → divergence. Отдельная инициатива.

---

#### L5. `gzip_types` не включает SVG
**Section:** § 3.1 line 237, § 3.2 line 298

SVG = XML text, очень хорошо сжимается. Real nginx configs включают `image/svg+xml` в gzip_types. Spec не включает.

**Fix:** добавить `image/svg+xml` в gzip_types.

---

#### L6. `expires 30d` для `.js` и `.css` без content-hash в filename
**Section:** § 3.1 line 226

В spec'е cache-control `expires 30d; immutable` для все css/js. Но Vite output (см. `vite.config.ts` для saas-landing) хардкодит `entryFileNames: 'assets/main.js'` — **без content hash**. Если задеплоить новую версию dist, browser клиента **закэширует старый main.js на 30 дней**. Это **operational bug**, не security/fingerprint.

**Fix:** либо включить content-hash в Vite output (стандарт), либо снизить cache до `1d` для unhashed assets.

Это **существующий bug в текущем коде**, не введённый spec'ом — но spec **сохраняет** его.

---

#### L7. `chmod -R 755 /etc/letsencrypt/archive/` — security regression
**Section:** vне spec'а, обнаружено при чтении `issueLetsEncrypt`

`steps_decoy.go:461`: `chmod -R 755 /etc/letsencrypt/archive/`. Это **меняет права на private keys** (`privkey.pem`) — обычно 600. **Security issue**, но **существующий** (не вводится этим spec'ом). Упоминаю для отчётности.

---

#### L8. `if ($request_method = OPTIONS)` — known nginx anti-pattern
**Section:** § 3.1 lines 217-222

nginx official **"If Is Evil"** doc: `if` inside `location` имеет известные issues с rewrite phases. Современный pattern:
```nginx
location ~ ^/api/ {
    limit_except GET POST OPTIONS {
        deny all;
    }
    error_page 405 = @options;
    ...
}
location @options {
    if ($request_method = OPTIONS) {
        add_header Allow "GET, POST, OPTIONS";
        return 204;
    }
}
```

Это перебор для нашего use case. **`if ($request_method = OPTIONS)` работает корректно для `add_header` + `return`** (одна из safe usages). **Fix:** ничего не менять, но добавить comment в код "safe `if` usage per nginx docs".

---

### Open questions / TBD в spec'е

1. **§ 2.2 `templateMetas` — где конкретно определена?** Package-level var? Через init()? Spec не уточняет. **Действие:** явно сказать "package-level `var` в `internal/deploy/steps_decoy.go`".

2. **§ 3.1 "{{brandName|lowercase}}" — какой шаблонизатор?** См. M11. **TBD.**

3. **§ 4.4 `feed.xml.tmpl` — где он рендерится?** В deploy-time через `text/template` (как sitemap)? Spec неявно говорит "уровень `uploadGeneratedDecoyFiles`", но `tech-blog` ходит через `uploadGeneratedDecoyFiles`, а saas/metricshub/analytics — через `uploadReactDecoyFiles`. Blog **уже** проходит через templating path. ОК, но **явно** добавить в spec: "feed.xml.tmpl rendered только в blog persona path, потому что только tech-blog template ходит через uploadGeneratedDecoyFiles".

4. **§ 5.1 LOC оценка `+~690 LOC` backend.** Это включает или нет: tests + templateMetas map + 3 функции? Если каждая из 3 функций по 100-150 LOC + 150 LOC tests + 30 LOC dispatcher = 530. ОК, оценка примерно верна.

5. **§ 6.4 smoke checklist** не проверяет:
   - `add_header` inheritance (security headers visible на `/pricing`, см. H3)
   - `Accept: application/json` 404 (см. M9)
   - non-existent asset (`.png` not found, см. C1)
   - **Действие:** добавить эти 3 кейса в чек-лист.

6. **§ 7.2 deploy step "Backs up current nginx config"** — кто это делает? Текущий код `deployNginxConfig` в `steps_decoy.go:407` просто **перезаписывает** `/etc/nginx/sites-available/decoy` через base64 echo. **Не делает backup.** Spec говорит "backs up" — но это **новая** logic которую надо добавить в `deployNginxConfig`. **TBD:** уточнить в spec'е что это требует кода (с примером).

7. **§ 7.4 "ShadowLink-туннели идут через TrustTunnel → unix socket".** Сейчас фактически через `127.0.0.1:8080` (TCP), не unix socket — см. `reconfigureTrustTunnelForDecoy`. Уточнение нужно.

---

### Что НЕ упомянуто в спеке но стоит обсудить

#### N1. **Reproducibility builds**

Vite build генерит content-hashed assets (если включить). Они **отличаются** между билдами с разными версиями `node_modules`. Probe который scrape'ит несколько decoy в разное время увидит **меняющиеся hashes** — но **тот же** код. Это OK для real sites (они тоже релизятся). Но **в нашем случае** все 4 templates деплоятся **синхронно** при изменении spec'а — probe заметит "все 4 сайта обновили JS в один и тот же день" → correlation signal.

**Mitigation:** deploy templates на разные дни (не одной волной). Это противоречит твоей "rollout сразу на pl1" — но safer.

**Это не критично сейчас** (у нас всего 1 production decoy на pl1). Стоит запомнить когда будет несколько серверов.

---

#### N2. **`/robots.txt` уже генерится — но `Sitemap:` ссылка только в `saasRobotsTmpl`**

В `steps_decoy.go:744`:
```go
var saasRobotsTmpl = `User-agent: *
Allow: /
Sitemap: https://{{.Domain}}/sitemap.xml`
```

Это используется в `uploadReactDecoyFiles` (saas/metricshub/analytics). Для `tech-blog` (uploadGeneratedDecoyFiles) есть **отдельный** `robots.txt.tmpl` файл — посмотри что там. Если разные robots.txt formats — fingerprint.

**Действие:** проверить consistency robots.txt между всеми 4 templates. Spec этого не покрывает.

---

#### N3. **`access_log /var/log/nginx/decoy.access.log combined`**

Лог-файл per-decoy. С 4 templates × 1 access.log → один большой log file. Real sites обычно используют **stdout** (для systemd/journald). nginx default — `combined` формат — это OK. Но размер логов растёт неограниченно — **operational issue** (logrotate настроен?).

**TBD:** spec не касается logrotate. Стоит добавить в acceptance criteria "logrotate настроен на /var/log/nginx/decoy.*.log".

---

### Honest risk assessment

> **Если эта волна готова — это гарантированно улучшит наш cover-quality? Или может ввести new fingerprint surface?**

**Краткий ответ:** net-positive, но **не гарантировано** и **точно** введёт **новые** fingerprint surfaces.

**Что улучшится:**
- ✅ Real 404 для unknown paths (закрывает первую сигнатуру из § 1.1)
- ✅ Brand consistency между HTML и headers (закрывает second сигнатуру) **— только если H2 (inheritance bug) исправлен и H3 (template update path) исправлен**
- ✅ security.txt — реальный positive signal (его наличие = signal "это professional dev shop")
- ✅ OPTIONS handler — закрывает minor probe vector

**Что станет ХУЖЕ или risk-of-new-signature:**
- ⚠️ **Standalone React 404 entry** — новый JS chunk, **необычный pattern** (см. M1)
- ⚠️ **`X-Powered-By: Crest/3.2.1`** — устаревший signal, real SaaS его не ставят (см. M3)
- ⚠️ **`/v2/health` public с раскрытым region+version** — anti-pattern для SaaS (см. H5)
- ⚠️ **Auto-generated humans.txt** — looks AI-generated, real ones содержат имена людей (см. M4)
- ⚠️ **Auto-generated color-block favicon с инициалом** — looks AI-generated (см. M2)
- ⚠️ **Explicit list of SPA routes на nginx-уровне** — никто из real sites так не делает (см. C2)
- ⚠️ **Asymmetric 404 для assets с extension vs без** (см. C1)
- ⚠️ **Inheritance bug** ломает security headers для `/pricing`, `/blog`, etc. (см. H3) — **это сам по себе baseline сломает**, потому что real sites имеют consistent security headers

**Probability assessment:**
- Если все CRITICAL+HIGH issues fixed before merge → **net-positive**, **probably** улучшит cover-quality.
- Если merge as-is → **net-neutral до net-negative**, потому что новые fingerprints (M1, M3, H3 особенно) перевешивают closed ones.

**Recommendation:** **не мерджить spec в текущем виде.** Минимально требуется:
1. **C1, C2, H3 — fix obligatory.** Это технические корректности nginx.
2. **H1, H2 — clarify scope/process** (можно решить документацией, не кодом).
3. **H5, M3 — pересмотреть** `/v2/health` и `X-Powered-By` (low cost decision).
4. **M1 — pure HTML 404** вместо React entry (упрощение + удаляет signature).
5. **M2, M4 — favicons + humans.txt approach** (либо real-looking content, либо вообще убрать).

**После этих 5 fixes** — спек готов к implementation. Сейчас спек **корректный по структуре**, **но technical details содержат несколько archi anti-patterns** что нивелирует часть value.

---

## Приоритизация по effort vs impact

| Issue | Effort | Impact | Recommend |
|---|---|---|---|
| C1 (несимметричный 404 для assets) | S (5 min nginx) | High | **fix now** |
| C2 (SPA routes pattern) | M (rewrite § 3.1) | High | **fix now** |
| H1 (Go decoy.go путь) | S (документация) | Medium | **clarify scope** |
| H2 (updateDecoyTemplate path) | S (add 1 line) | High | **fix now** |
| H3 (header inheritance) | M (include snippets) | **High — это сейчас сломает headers** | **fix now** |
| H4 (TLS fingerprint TrustTunnel) | S (document out-of-scope) | Medium | **clarify** |
| H5 (/v2/health anti-pattern) | S (trim JSON fields) | Medium | **fix now** |
| M1 (404.html pure HTML) | S (simpler than React) | High | **fix now** |
| M2 (favicon professional) | S (download SVGs) | Medium | **fix now** |
| M3 (drop X-Powered-By) | S (delete lines) | High | **fix now** |
| M4 (humans.txt drop or real) | S (delete blocks) | Medium | **fix now** |
| M5 (Allow header full REST verbs) | S | Low-Medium | nice to have |
| M6 (shared legal components) | L (Vite config + new dir) | Medium | deferred wave |
| M7-M11 | S каждый | Low-Medium | batch fix |
| L1-L8 | varies | Low | deferred |

---

**Конец отчёта.**
