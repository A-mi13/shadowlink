# Code Review v2 — Decoy Behavioral Coverage Design Spec

**Date:** 2026-05-27 (afternoon, после empirical research + v2 rewrite)
**Reviewer:** Opus 4.7 (1M context), senior code reviewer mode
**Object:** `D:/NIXAVPN/shadowlink/docs/superpowers/specs/2026-05-27-decoy-behavioral-coverage-design-v2.md`
**Cross-references:**
- `2026-05-27-decoy-behavioral-coverage-design-review.md` (opus review v1)
- `2026-05-27-real-world-decoy-patterns.md` (curl-probing research)

**Verdict (one-liner):** v2 закрывает **большинство** CRITICAL+HIGH из v1 review (опираясь на research), но **вводит как минимум 1 новый CRITICAL bug** (`humansNamePool` global mutation), **2 новых HIGH** (internal contradiction XFO blog SAMEORIGIN vs DENY, и нерешённое security.txt-for-blog ambiguity), и оставляет **2 unresolved issue** из v1 (внутренний `try_files /index.html =404` pattern в named location voscriptively-логически тождественен критикованной v1 структуре; `chmod 755 /etc/letsencrypt/archive/` L7 baseline bug не упомянут). **Spec НЕ готов к implementation.** Минимум 4 fixes требуются.

---

## Executive summary

| Категория | v1 → v2 | Comments |
|---|---|---|
| CRITICAL closed | 2/2 (C1, C2) | C1: real, асимметрия для assets через `try_files $uri =404` fixed. C2: explicit list SPA routes действительно убран в server-level (но reintroduce в @react_or_404 в скрытой форме — см. R3). |
| HIGH closed | 4/5 (H1, H2, H3, H5) | H4 (TLS fingerprint) honestly OOS-flagged. |
| MEDIUM closed | 9/11 | M1, M2, M3, M4, M5, M9, M11 — да. M6 (PrivacyPage shared) honestly defered. M7-M8 (X-Request-ID, WWW-Authenticate) — moot because spec убрал эти headers/endpoints. |
| LOW unaddressed | 4/8 | L1 (CSP) → ✅ added. L5 (svg gzip), L6 (Vite content-hash), L7 (`chmod 755` security regression), L8 (`if` evil) — не упомянуты в v2. |
| **NEW issues v2** | — | См. секции N1-N6 ниже |

**Decision:** **DO NOT MERGE.** Probability net-positive **medium-high** *после* следующих fixes:
1. (CRITICAL) `humansNamePool` Shuffle mutates global → race + non-determinism
2. (HIGH) внутреннее противоречие XFO в blog persona (SAMEORIGIN vs DENY)
3. (HIGH) `security.txt` for blog persona — ambiguous in §2.3 (inheritance vs override)
4. (HIGH) `humans.txt` "Last update: 2026-05-15" hardcoded date в template — palится через год

---

## §1. Issue-by-issue verification: v1 → v2

### CRITICAL from v1

#### C1 — Asymmetric 404 for assets vs paths
**v1:** `location ~* \.(css|js|...)$` ловит `/random.png`, нет `try_files`, дефолтный nginx 404.
**v2 §2.3 SaaS:** `location ~* \.(css|js|png|...)$ { try_files $uri =404; ... }` + server-level `error_page 404 /404.html;` + `location = /404.html { internal; ... }`.
**Verdict:** ✅ **closed.** Логически correct. Smoke test #2 (`/random.png → 404`) проверяет это.
**Caveat:** spec не доказывает что `error_page 404` действительно отработает в `try_files $uri =404` контексте — это behavior зависит от nginx version. **Должен быть e2e test на pl1** (упомянут в §10 acceptance criterion #6, ok).

#### C2 — Explicit list of SPA routes
**v1:** `location = / { ... } location = /pricing { ... } location = /docs { ... }` — explicit list, no real prod site so does.
**v2 §2.3 SaaS:** только `location / { try_files $uri $uri/ @react_or_404; }` + named location `@react_or_404` который делает if-extension → 404, else index.html.
**Verdict:** ✅ **structurally closed**, но смотри R3 ниже — named location всё ещё содержит `try_files /index.html =404` pattern (cosmetic).
**Real-world check:** `try_files $uri $uri/ /index.html` (без named location) — стандартный pattern. v2 использует `@react_or_404` intermediate именно потому что хочет различать extension vs no-extension. **Это сам по себе non-standard pattern** (real SPA sites просто отдают index.html на любой not-found, см. research §2: Linear/Vercel/regex101 — 200 на ANY URL). См. **R1 (NEW HIGH).**

### HIGH from v1

#### H1 — Go-уровневый decoy.go путь игнорируется
**v1:** spec не упоминает second decoy path в `shadowlink/server/decoy.go::DecoyHandler`.
**v2 §2.4:** spec **раскрыл scope** — добавляет unification с nginx persona, +80 LOC в `decoy.go`, +60 LOC tests.
**Verdict:** ✅ **closed**, но scope expand честно описан (§1.4 + §5.1).
**Caveat:** §2.4 говорит "передать `templateName` или persona в `DecoyHandler` через config (extension к domainMap)" — но **не описывает как именно** передать. `domainMap` — это что-то существующее? Без чёткого design это **TBD**. См. **N4 (NEW MEDIUM).**

#### H2 — `updateDecoyTemplate` не вызывает `deployNginxConfig`
**v1:** identified as bug.
**v2 §2.6:** "Fix v2: в `updateDecoyTemplate` добавить вызов `deployNginxConfig(mgr, domain, templateName)` после `uploadDecoyFiles`. Это +1 строка."
**Verdict:** ✅ **closed.** Документировано как +1 line. Trivially correct.

#### H3 — `add_header` inheritance bug
**v1:** server-level add_header затирается location-level add_header.
**v2 §2.2:** "use `include /etc/nginx/snippets/<persona>-headers.conf;` в **каждом** location." Снippets делают full security set.
**Verdict:** ✅ **closed**, conceptually. Но смотри **N2 (NEW MEDIUM):** snippets path `/etc/nginx/snippets/` существует не на всех distros (это Debian convention) — нужно `mkdir -p` в deploy шагах, что в §7.2 не описано explicit.
**Caveat 2:** snippet `saas-headers.conf` в §2.2 включает CSP **с `'unsafe-inline'`** — это даёт XSS-protection ≈ 0 (любой XSS bypassable). Real prod SaaS используют `nonce`/`hash`-based CSP. Probe который проверяет CSP strictness отнесёт это в "junior dev" category. Но это **acceptable** trade-off потому что без `'unsafe-inline'` React не будет работать без переделки Vite (это major task). См. **N3 (NEW LOW).**

#### H4 — TrustTunnel TLS fingerprint
**v1:** spec ничего не говорил про TLS-уровень.
**v2 §1.4:** "TLS/H2 fingerprint TrustTunnel reverse_proxy — отдельная инициатива. Эта волна закрывает только HTTP-уровень."
**Verdict:** ✅ **honestly OOS-flagged**, acceptable.

#### H5 — Public /v2/health JSON anti-pattern
**v1:** `/v2/health` с region+version exposed.
**v2 §2.3:** `location = /health { default_type text/plain; return 200 "OK"; }` (k8s-style).
**Verdict:** ✅ **closed.** Соответствует research §5 (GitHub `/health → 200`).
**Minor:** SaaS persona имеет `/health`, blog **не имеет** (§2.3 blog: "NO /health"). Это OK — research §5 показал что blog/utility часто без health endpoint.

### MEDIUM from v1

#### M1 — Standalone React 404 entry
**v1:** Vite multi-entry создаёт new JS chunk.
**v2 §3.1 + §4.1:** pure HTML 404 (text/template), внутри React добавляется `<Route path="*">` с NotFoundPage component, **не** standalone entry.
**Verdict:** ✅ **closed.**
**Caveat:** 404.html в §3.1 inline CSS дублирует часть стилей React app (color, font). Probe видит **два места** где определён цвет (HTML body + main app bundle). Если эти цвета **identical** — OK (consistent brand). Если **drift** через несколько deploys (someone обновит React palette не обновив 404.html) — fingerprint. **Operational risk, not bug.** Лучше: вытащить colors в shared Go const, используется и при render 404.html и можно генерить small CSS file который React app тоже импортирует. **Defer to followup.**

#### M2 — Color-block favicon = AI fingerprint
**v1:** auto-generated initial.
**v2 §3.4:** "multi-resolution ICO 15086B + favicon.svg... mimics real-favicon-generator output."
**Verdict:** ⚠️ **partial.** Research §6 confirms 15086B template. Но v2 не дает **how exactly** генерить 15086B-byte ICO в Go. Простой Go encoder может дать другой byte count в зависимости от encoder settings. Нужен либо: (a) pre-built ICO template который Go копирует + меняет цвет в палитре (rare in Go libs), либо (b) hard-coded byte template с substituted color bytes. **Implementation detail TBD**, может оказаться нетривиально. См. **N5 (NEW MEDIUM).**

#### M3 — X-Powered-By устаревший signal
**v1:** `X-Powered-By: Crest/3.2.1` (product version).
**v2 §1.2:** "❌ НЕ ставит X-Powered-By... Опционально ставим Next.js для SaaS persona."
**v2 §2.2 snippet:** "# NO X-Powered-By (research §1: 8/10 prod sites без)."
**Verdict:** ✅ **closed.** v2 не ставит X-Powered-By вообще. Опция "Next.js" упомянута в §1.2 но не реализована в snippets — это **correct, conservative choice**.

#### M4 — humans.txt без имён людей
**v1:** auto-generated шаблон.
**v2 §3.2:** pool 20 realistic names, deterministic seed from domain hash.
**Verdict:** ⚠️ **conceptually closed**, но **implementation contains critical bug.** См. **N6 (NEW CRITICAL).**

#### M5 — Allow header full REST verbs
**v1:** `GET, POST, OPTIONS` only.
**v2 §2.3 SaaS:** `Allow "GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE"`.
**Verdict:** ✅ **closed.**

#### M6 — PrivacyPage shared
**v2 §4.3:** "оставляем per-template копии, с **намеренно разным** wording + emails."
**Verdict:** ✅ **honestly addressed** (chose path of intentional divergence vs DRY shared package). Trade-off justified.

#### M7 — X-Request-ID
**v2:** убран entirely (research §1: 0/10 prod sites).
**Verdict:** ✅ **closed.**

#### M8 — WWW-Authenticate
**v2:** moot — `/api/*` returns 404 (not 401), so WWW-Authenticate header не нужен.
**Verdict:** ✅ **closed by removal.**

#### M9 — Accept: application/json 404
**v2 §2.3 SaaS:** `location = /api/_404json { internal; default_type application/json; return 404 '{...}'; }`.
**Verdict:** ⚠️ **partially closed.** Code defines internal location, **но** spec **не показывает** как `/api/*` запрос с `Accept: application/json` маршрутится в `/api/_404json`. Нужно либо:
- `error_page 404 = @api_404;` внутри `location ~ ^/api/` (как было в v1 review M9), либо
- `if ($http_accept ~ application/json)` (evil)

Smoke test #10 говорит "if не реализовано — пропустить". Это значит spec **сам не уверен** что implement-able. **Implementation TBD.** См. **N4 (NEW MEDIUM).**

#### M10 — `internal` directive
**v2 §2.3:** `location = /404.html { internal; ... }` — корректно.
**Verdict:** ✅ **closed.**

#### M11 — `{{brandName|lowercase}}` template syntax ambiguity
**v2:** `templateMetas` использует `BrandLabel`-as-string, нет `|lowercase` filter в snippet templates (security.txt использует `mailto:security@{{Domain}}` без brand interpolation).
**Verdict:** ✅ **closed by simplification.**

### LOW from v1

#### L1 — CSP
**v2 §1.3:** "CSP header. Research §1: 9/10 SaaS имеют CSP."
**Verdict:** ✅ **added.**

#### L5 — svg gzip
**v2 §2.3:** `gzip_types text/plain text/css application/json application/javascript text/javascript application/xml image/svg+xml;` — **includes** svg.
**Verdict:** ✅ **closed.**

#### L6 — Vite content-hash for cache invalidation
**v2:** не упомянут. Vite output `assets/main.js` (no hash) останется legacy bug.
**Verdict:** ❌ **unaddressed.** Operational bug, not security/fingerprint. **Низкий приоритет, ОК deferred but should be noted in §11.**

#### L7 — `chmod 755 /etc/letsencrypt/archive/` security regression
**v2:** не упомянут.
**Verdict:** ❌ **unaddressed baseline bug.** Не введён этой spec'ой но **сохраняется**. Spec **должен** включить cleanup как part of "пока трогаем decoy deploy" hygiene. **NEW HIGH if security-sensitive deploy contexts exist.** Поскольку это existing bug — приоритизация решается отдельно. **Минимум — задокументировать.**

#### L8 — `if` is evil
**v2 §2.3:** **TWO uses of `if`** — `@react_or_404` (`if request_uri ~* \.(...)$ return 404`) и `/api/*` OPTIONS handler (`if request_method = OPTIONS`). Оба — safe usages (`add_header` + `return` ONLY). Это **известно safe per nginx docs.**
**Verdict:** ✅ **acceptable.** Но spec не комментирует это явно — добавить comment в snippet would be hygiene.

---

## §2. NEW issues introduced in v2

### N6 — **CRITICAL** — `humansNamePool` global mutation race + non-determinism
**Section:** §3.2 lines 363-372

```go
var humansNamePool = []humanProfile{ ... }  // package-level GLOBAL

func generateHumansForDomain(domain string) string {
    seed := fnv32(domain)
    rng := rand.New(rand.NewSource(int64(seed)))
    rng.Shuffle(len(humansNamePool), func(i, j int) {
        humansNamePool[i], humansNamePool[j] = humansNamePool[j], humansNamePool[i]  // !!!
    })
    teamSize := 3 + rng.Intn(3)
    // ... presumably uses humansNamePool[:teamSize]
}
```

**Проблема 1 — non-determinism между разными доменами:**
- Deploy `domain=A.com` → shuffles pool. После: pool reordered.
- Deploy `domain=B.com` → shuffles **already-reordered** pool. Seed для B применяется к **non-initial state**.
- Результат: humans.txt для B.com **зависит от того, был ли до этого deploy A.com**.
- Probe scrapes humans.txt у нескольких доменов в разные моменты → видит **inconsistency между deploys**.

**Проблема 2 — concurrent deploys race condition:**
- `domain_decoy_map` system supports multi-domain. Если admin одновременно re-deploys domain X и domain Y, **два goroutines пишут в один и тот же глобальный slice** → data race, может быть corruption.
- `go test -race` это поймает.

**Проблема 3 — failed deploy leaves pool в "broken" state** для future deploys.

**Fix:**
```go
func generateHumansForDomain(domain string) string {
    seed := fnv32(domain)
    rng := rand.New(rand.NewSource(int64(seed)))
    // make a COPY before shuffling
    pool := make([]humanProfile, len(humansNamePool))
    copy(pool, humansNamePool)
    rng.Shuffle(len(pool), func(i, j int) {
        pool[i], pool[j] = pool[j], pool[i]
    })
    teamSize := 3 + rng.Intn(3)
    // use pool[:teamSize]
}
```

**Action required before implementation.**

### R3 / N1 — **HIGH** — Hybrid 404 (§4.1) — нет в research как pattern
**Section:** §4.1 "Унифицированный подход для всех 3 persona"

v2 спецификация:
- `/foo.png` (asset extension, not exists) → nginx **real 404**
- `/anything-without-extension` (path) → nginx **200 + index.html** (SPA fallback)

Research §2: 12 sites probed, нет ни одного который **mixes** эти два поведения с явным extension-based branching. Реальные сайты делятся **по архитектуре**:
- Server-rendered apps (Stripe, GitHub, Slack) — **real 404 для всего**, включая `/random` (без extension).
- SPA apps (Linear, Vercel, regex101) — **200+SPA для всего**, включая `/random.png` (хотя я не пробил `.png` к Linear специфически).

Spec претендует: "Гибрид (404 для assets + 200 для paths) — никем не противоречит, потому что probe тестирует либо asset либо path, не оба."

**Это слабое заявление.** Если probe **сделает оба** запроса (что **дёшево** — это два curls), он увидит:
- `GET /random.png → 404` (text/html 404.html, ваш кастомный)
- `GET /random → 200` (text/html index.html)

Никакой пары "Linear-style" + "Stripe-style" prod site **не показывает оба** behavior одновременно. **Это уникальный fingerprint** именно нашей системы.

**Possible fix:** выбрать **один** pattern per persona, **не гибрид**:
- SaaS → real 404 для всего (как Stripe). `try_files $uri =404` для всех путей.
- Utility → 200+SPA для всего (как Linear/regex101).
- Blog → split: `/blog/<slug>` if not in known list → real 404, иначе SPA. Это **может** быть валидно потому что blogs обычно server-rendered.

Хотя research §2 показывает что SPA-heavy sites (Linear, Vercel, regex101) **возвращают 200 на random URL включая** что-то вроде `/random.css`. Так что pure-SPA-fallback тоже валидный alternative.

**Verdict:** v2 §4.1 — **risky innovation**, не подкреплён research. Либо ужесточить research (specific test что peer SPA-utility tools возвращают на `.png` requests), либо выбрать non-hybrid.

### N2 — **HIGH** — Internal contradiction: XFO blog SAMEORIGIN vs DENY
**Section:** §2.3 blog vs §9 risk table

§2.3 Blog persona: "include `/etc/nginx/snippets/blog-headers.conf` (XFO: **SAMEORIGIN**, без X-Powered-By, CSP без `frame-ancestors 'self'` для allow embeds)"

§9 risk table row "Wrong XFO": "SAMEORIGIN для SaaS (matches 5/10 prod), **DENY only для blog**"

**Это прямое противоречие** между двумя секциями одного spec'а.

Что правильно? Research §1 не имеет blog samples (все 10 — SaaS). Логически:
- Blog часто хочет **embedding** (e.g. Medium embed) → SAMEORIGIN или ALLOW
- DENY для blog = странно

**§2.3 SAMEORIGIN правильно**, §9 risk table содержит ошибку формулировки.

**Fix:** обновить §9 risk table: "SAMEORIGIN для SaaS+Blog (research §1 + blog convention)".

### N7 — **HIGH** — security.txt для blog persona — undefined behavior
**Section:** §1.3 vs §2.3 vs research §3

- §1.3: "✅ Per-persona 404 strategy: SaaS landing → real 404, Blog → real 404, Utility → 200 + SPA fallback" — implies blog ≈ SaaS treatment.
- §2.3 Blog persona delta list: говорит **NO** для `/health`, `/api/*`, `/humans.txt`. **Молчит про `/.well-known/security.txt`.**
- §6.2 `TestRenderNginxBlog` test list: не проверяет наличие/отсутствие security.txt.
- Research §3: 9/9 tier-1 SaaS имеют security.txt. Tech blogs не sampled — но research §3 ставит "blog → depends, скорее **да**".

**Implication:** реализатор spec'а будет гадать. Либо включит security.txt в blog (по аналогии с SaaS template structure), либо забудет.

**Fix:** §2.3 Blog persona delta list должна **явно** указать "HAS security.txt" или "NO security.txt".

### N4 — **MEDIUM** — §2.4 DecoyHandler unification — implementation TBD
**Section:** §2.4

> "Передать `templateName` или persona в `DecoyHandler` через config (extension к domainMap)."

`domainMap` упомянут как something existing. Не описано:
1. Какая структура `domainMap` сейчас?
2. Как persona прокидывается через config YAML?
3. Каскад reload — что произойдет когда admin меняет template для одного domain, а server держит persona в memory?
4. Backwards compat для существующих deploys без persona в config?

Без этих ответов **§2.4 — high-level intent**, не implementable spec.

**Fix:** добавить §2.4.1 "Implementation contract" с pseudo-code load + change-detection logic.

### N5 — **MEDIUM** — §3.4 favicon — "15086B fixed" без implementation strategy
**Section:** §3.4

> "Generated при deploy: `<webroot>/favicon.ico` — multi-resolution (16×16, 32×32, 48×48, 64×64) ICO, **15086B fixed**, ..."

Go standard lib не имеет ICO encoder. Generating ICO с **exact byte size 15086** через `image/png` + manual ICO header — нетривиально. Доступные approaches:
1. Pre-built byte template ICO в Go binary, swap color bytes — **fragile**, любой encoder mismatch в template даст другой size.
2. Внешний CLI tool (`png2ico`, `imagemagick`) — **adds dependency** на host server.
3. Использовать **тот же** ICO для всех templates — теряет per-template variation (color).
4. Просто отбросить "fixed 15086B" requirement, принять что наш ICO может быть любой size — **снижает mimicry value** (research §6 hint о signal-via-15086B).

Spec **не выбирает** ни один из этих путей. **TBD.**

**Fix:** §3.4.1 "Implementation strategy" с outcomes-based outcome ("если 15086B недостижим — выбираем option 4").

### N3 — **LOW** — CSP `'unsafe-inline'` — weak protection
**Section:** §2.2 snippet

CSP `script-src 'self' 'unsafe-inline'` — Vue/React friendly, но XSS-protection ≈ 0. Real prod SaaS используют nonce-based CSP. Probe смотрящий **strict** CSP отнесёт нас в "junior" category.

**Trade-off:** strict CSP требует Vite plugin для injection nonce'ов в каждый inline script. Major dev work. **Accept this trade-off explicitly**, добавить в §11 как "follow-up: strict CSP с nonces".

### N8 — **LOW** — humans.txt "Last update: 2026-05-15" hardcoded date
**Section:** §3.2 generated content example

```
/* SITE */
  Last update: 2026-05-15
```

Если эта дата **literal** в spec (как пример) — OK. Но если **literal в template** — то через 6 месяцев `Last update` будет показывать `2026-05-15` для каждого свежего deploy → суверенный "stale" signal.

**Fix (если template):** генерить дату на момент deploy: `Last update: {{deployDate}}` через text/template. Spec **не уточняет** какой подход — implementation ambiguity.

### N9 — **LOW** — `humans.txt` `Twitter: ""` empty handles
**Section:** §3.2 pool

7 из 20 имён имеют `Twitter: ""`. Если template render просто emits `— @<twitter>` строку для всех — empty twitter будет рендериться как `— @` (broken). Если template skips empty — то half of team page будет without handles. Real humans.txt — usually все или **никто** в команде.

**Fix:** либо все имена с twitter, либо все без (или mixed только если очень few without — like 1-2 out of 5).

---

## §3. Issues unresolved from v1 baseline

Из original baseline (`internal/deploy/steps_decoy.go` existing code, не related to spec):
- **L7 — `chmod -R 755 /etc/letsencrypt/archive/`** — exposes private keys (`privkey.pem` обычно 600). v2 не упомянуто. **Security regression** в existing code, сохраняется after v2 implementation.

**Recommendation:** добавить в §11 "Out of scope" с note "Pre-existing security bug в `issueLetsEncrypt` — должен быть закрыт отдельным fix, не блокирует эту волну."

---

## §4. LOC оценка assessment

**v2 §5.1 claims +1050 backend LOC, v1 was +690.**

Sanity check:
- `steps_decoy.go` refactor +280 — vs v1 ~200. Believable.
- `decoy.go` unification +80 + tests +60 = +140. **Believable but undercounts headers transmission code** (passing persona через config, handling pre-existing domainMap structure). Realistic: **+150-200**.
- Templates 30+40 = +70. **Believable for static template files.**
- humans pool +80. **Believable** for 20 names + 1 generator function + tests.
- 3 snippet files +30. **Acceptable** (each ~10 lines of headers).
- 3 test files +450 (150+200+100). **Believable**.

**Realistic total: +1100-1200 LOC backend**, slightly higher than claimed +1050 но в пределах ±20%. **Acceptable estimate.**

Frontend +450 — similar order to v1 (-standalone 404 = ~-30 LOC). **Believable.**

---

## §5. Логические противоречия в §4.1 SPA routing

User спросил specifically про §4.1. Подробный анализ:

§4.1 table:
| URL pattern | Server-side | Client-side |
|---|---|---|
| `/foo.png`, asset extension, not existing | nginx **real 404** | Browser shows 404.html |
| `/anything-without-extension` | nginx **200 + index.html** | React Router `<Route path="*">` рендерит NotFoundPage |
| Known SPA route | nginx **200 + index.html** | React Router rendering |

**Logical issue 1:** Row 2 и Row 3 — **server-side identical** (`200 + index.html`). Это значит **nginx не различает** known route от unknown path. **Корректно** — nginx просто отдаёт index.html через `try_files` или `@react_or_404`, React решает что показать. **Good.**

**Logical issue 2:** Row 1 + Row 2 — **разные server-side responses**. Probe сделав `GET /xyz.png` (404) и `GET /xyz` (200) видит **deliberate branching by extension**. Research §2 не имеет подтверждения что real sites так branche. См. **R3 (N1) HIGH** выше.

**Logical issue 3:** "Single difference для utility persona: assets всё равно 404 (то же поведение), а path-style URLs → 200 + SPA-rendered NotFoundPage."
- Wait — это **то же самое что SaaS persona** (gymnast row 1 + row 2)?
- §1.3 говорит: "Utility → 200 + SPA fallback (regex101/jsonlint-style)" — implying ANY URL → 200.
- §4.1 utility row: "assets всё равно 404" — implying asset URLs → 404.
- **Contradiction:** §1.3 говорит utility = full 200, §4.1 говорит utility = asset 404.

Это **внутренняя несогласованность** прямо в §4.1 и противоречит §2.3 utility delta ("`try_files $uri $uri/ /index.html` БЕЗ `=404`" — нет real 404 для assets).

**Fix:** выбрать один подход для utility. Если "pure 200+SPA" (matches regex101/jsonlint) — то §4.1 row "assets всё равно 404" wrong. Если "asset 404 like SaaS" — то §2.3 utility delta и §1.3 utility description wrong.

**Severity: HIGH** (см. **N10 NEW HIGH** ниже).

### N10 — **HIGH** — Utility persona: asset-404 vs pure-200 internal inconsistency
**Sections:** §1.3, §2.3 utility, §4.1 table last paragraph

Three sources, three different stories:
- §1.3: "Utility → 200 + SPA fallback" (suggests ANY URL → 200)
- §2.3 utility: "404 только на missing assets (`\.(css|js|png)$ → try_files $uri =404`)" (asset 404 yes)
- §4.1 table last paragraph: "Single difference для utility persona: assets всё равно 404" (asset 404 yes)

Заявление в §1.3 несовместимо с §2.3 + §4.1. Likely §1.3 — это implementation summary который потерял nuance "assets отдельно". **Reword §1.3.**

Но если §2.3 правильно (asset 404 + path 200) — это **тот же гибрид как SaaS**, что делает utility persona **не различимой** от SaaS на nginx-уровне. Тогда **зачем три персоны?** Persona splits хочется потому что utility **should** возвращать 200 даже на assets (matches regex101 behavior). Иначе разница только в content templates.

**Two possible fixes:**
1. Utility делает **pure 200+SPA** (matches regex101). Тогда `nginx`: `try_files $uri $uri/ /index.html;` for **everything**, **no separate asset location**. Это требует чтобы assets находились в `dist/` (Vite output) — иначе bare URL `/styles.css` (не существует) returns 200+index.html (что **really weird** для CSS but matches regex101 behavior).
2. Utility = SaaS (asset 404). Тогда **отдельная persona не нужна**, можно reuse SaaS code path.

Spec **должен** выбрать. Сейчас ambiguity → implementation drift.

---

## §6. Risks not covered in v2

### N11 — **MEDIUM** — Snippets directory bootstrap
**Section:** §7.2

> "Upload new snippets to `/etc/nginx/snippets/`"

На некоторых nginx installations `/etc/nginx/snippets/` НЕ существует by default (особенно `nginx` package vs `nginx-extras`, vs custom builds). `cp` в non-existent directory → error → deploy fail.

**Fix:** §7.2 шаг "Upload new snippets" должен начинаться с `mkdir -p /etc/nginx/snippets/`. Add to spec.

### N12 — **MEDIUM** — `nginx -t -c /etc/nginx/decoy.new` неверный syntax
**Section:** §7.2

> "`nginx -t -c /etc/nginx/decoy.new` — abort on fail"

`nginx -t -c` ожидает **полный** config file (main `nginx.conf`), не site fragment. Это **не сработает** как single-file validation.

**Correct approach:**
- `nginx -t` (validates entire active config, **after** copying new file in place but **before** reload). Risk: invalid syntax leaves nginx с broken config; reload fails; previous running config продолжает работать (nginx default behavior).
- Better: `cp decoy.new decoy && nginx -t && systemctl reload nginx || mv decoy.bak decoy && systemctl reload nginx` — explicit rollback.

**Fix:** §7.2 deploy steps — переписать командную последовательность.

---

## §7. Risk assessment v2

| Risk | v1 | v2 | After fixes (N1-N12) |
|---|---|---|---|
| Brand inconsistency HTML/headers | ❌ | ✅ | ✅ |
| Real 404 vs SPA 200 mismatch | ❌ | ⚠️ (гибрид нелegit pattern — N1) | ✅ (если N1 fix: choose one) |
| X-Powered-By legacy | ❌ | ✅ | ✅ |
| X-Region introduced | ❌ | ✅ | ✅ |
| /v2/health anti-pattern | ❌ | ✅ | ✅ |
| Standalone React 404 entry | ❌ | ✅ | ✅ |
| Explicit nginx SPA list | ❌ | ✅ (no longer explicit) | ✅ |
| nginx add_header inheritance | ❌ | ✅ | ✅ |
| Asymmetric 404 assets vs paths | ❌ | ⚠️ (теперь deliberate, N1) | ⚠️ |
| Go decoy.go divergence | ❌ | ⚠️ (high-level intent, no impl spec — N4) | ⚠️ |
| updateDecoyTemplate no nginx | ❌ | ✅ | ✅ |
| humans.txt without names | ❌ | ⚠️ (impl bug N6) | ✅ |
| Color-block favicon | ⚠️ | ⚠️ (impl strategy TBD N5) | ⚠️ |
| Missing CSP | ❌ | ✅ | ✅ |
| Wrong XFO | ❌ | ✅ SaaS, ⚠️ blog contradiction N2 | ✅ after N2 fix |
| **NEW: humansNamePool race (N6)** | — | ❌ | ✅ after copy fix |
| **NEW: XFO blog contradiction (N2)** | — | ❌ | ✅ |
| **NEW: blog security.txt undefined (N7)** | — | ❌ | ✅ |
| **NEW: utility hybrid contradiction (N10)** | — | ❌ | ✅ |
| **NEW: snippets dir bootstrap (N11)** | — | ❌ | ✅ |
| **NEW: nginx -t -c misuse (N12)** | — | ❌ | ✅ |

---

## §8. Готовность к implementation

**NOT READY.** Минимум 4 must-fix перед merge:

| # | Severity | Section | Fix |
|---|---|---|---|
| 1 | **CRITICAL** | §3.2 N6 | `humansNamePool` Shuffle — copy slice first |
| 2 | **HIGH** | §2.3 + §9 N2 | Resolve XFO blog SAMEORIGIN vs DENY contradiction |
| 3 | **HIGH** | §2.3 blog + §1.3 N7 | Explicit say whether blog has security.txt |
| 4 | **HIGH** | §1.3 + §2.3 utility + §4.1 N10 | Pick ONE strategy for utility 404 (pure 200 or asset 404) |

Strongly recommended additional fixes:
- §4.1 N1 (R3): justify hybrid 404 with extra research **OR** simplify to non-hybrid per persona
- §2.4 N4: spell out DecoyHandler config-passing contract
- §3.4 N5: specify favicon implementation strategy (accept variable size if needed)
- §7.2 N11, N12: bootstrap snippets dir, correct nginx -t usage
- §3.2 N8/N9: humans.txt date generation strategy + twitter handle consistency

---

## §9. Probability net-positive

**As-is (before fixes):** **medium** (50-60%). Net-positive over v1, but introduces N6 race + 3 internal contradictions which a probe **can** detect (XFO inconsistency between blog templates — visible from outside, утилитная 404 behavior unclear what implementation does).

**After all CRITICAL+HIGH fixes:** **high (80-85%).** Solid foundation, real-world-aligned.

**Caveat:** даже после fixes остаются open questions per N4/N5 которые могут привести к implementation drift. Recommend: spec gets to "implementation-ready" state, then a **third-pass review** of pseudo-code или PR diff перед merge.

---

## §10. Top-3 issues (for summary)

1. **CRITICAL — N6:** `humansNamePool` global mutation = race condition + non-determinism между deploys. Probe scrape'ит humans.txt у 3 доменов — видит inconsistencies между независимыми scrape sessions. **Fix:** copy slice before Shuffle.

2. **HIGH — N10:** Utility persona имеет три несовместимых описания 404 behavior (§1.3 vs §2.3 vs §4.1). Реализатор не знает что код должен делать. **Fix:** выбрать один паттерн (предпочтительно pure 200+SPA matching regex101).

3. **HIGH — N1 (R3):** Гибридное 404 (extension-based branching) — innovation не подкреплённая research'ом. Probe с двумя curls (`/x.png` vs `/x`) видит unique fingerprint. **Fix:** либо найти research evidence гибридного pattern у real sites, либо переключиться на pure-persona approach.

---

## Conclusion

v2 — **significantly improved** vs v1. Большинство CRITICAL+HIGH из v1 review **реально закрыты** opираясь на research, не just promised. Empirical research-driven design = главный value-add.

**Однако** v2 содержит:
- 1 critical implementation bug (humansNamePool race)
- 3 internal contradictions (XFO blog, security.txt blog, utility 404)
- 2 TBDs masquerading as design (Go decoy.go unification, favicon implementation)
- 1 questionable innovation not backed by research (hybrid 404)

**Recommendation:** revise spec → v2.1 closing N1, N2, N6, N7, N10. Then implementation-ready.

**Estimated revision effort:** 1-2 hours of spec editing (no new research needed; all fixes are clarifications + 1 Go bugfix).
