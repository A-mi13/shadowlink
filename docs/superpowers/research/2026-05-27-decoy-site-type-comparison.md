# Decoy Site Type Comparison — Strategic Research (2026-05-27)

**Цель:** Выбрать тип "cover site", который ShadowLink-сервер будет показывать
неавторизованным запросам (active probing от РКН/DPI). Чисто стратегический
research — выбор направления, не имплементация.

**Контекст проекта (важные ограничения):**
- Origin = USA datacenter (`104.222.177.67`, ColoCrossing) на pl1
- Direct-primary архитектура (CF orange — fallback, не primary). См.
  `2026-05-26-honest-gap-analysis-direct-primary.md`
- Серверы маленькие, команда маленькая → low-maintenance contenta critically
- Cert на наш домен (`datacanvases.com`), не на borrowed target → cluster-risk
  через CT logs (`%datacanvases.com%`)
- ShadowLink — собственный HTTP-stego протокол (не REALITY-style borrowing).
  Decoy site = что увидит probe или браузер при заходе на `https://<domain>/`
  без правильных headers/payload
- Существует базис: `shadowlink/server/decoy.go` (Go FileServer
  per-domain map) + `internal/deploy/decoy_content_gen.go` (547 строк
  генератора, см. `2026-05-26-decoy-blog-state-audit.md`)

---

## 1. Threat Model — что мы защищаем

### 1.1 Что нас атакует

1. **Passive DPI classifier (TSPU)**: смотрит TLS fingerprint, H2 SETTINGS,
   timing, pattern. Не видит content. ShadowLink mimicry уже это закрывает.
2. **Active probing (РКН)**: открывает `https://datacanvases.com/` в headless
   Chrome или curl, смотрит что вернёт. Сравнивает с «персона» которую
   декларирует. Дальше — clicks по links, тестирует sub-paths, POSTs.
3. **Behavioral analyst (рукой человек)**: оператор смотрит на странный
   домен, идёт на сайт, читает контент, решает «реальный это блог или
   камуфляж».
4. **CT-log cluster analysis**: oblivious атакующий собирает все домены,
   выданные на наш IP/cert chain, шумит по contento similarity.

### 1.2 Что должно делать decoy

- **Reachability test pass**: probe видит правдоподобный HTTP/HTTPS site
  (не 404, не "Welcome to nginx", не "It works", не Apache default)
- **Geographic plausibility**: контент выглядит ожидаемым для US-hosted
  small-team site
- **Behavioral plausibility**: site должен пройти 3-5 минут human inspection
  без явных aномалий (битые links, lorem ipsum, AI artifacts)
- **Anti-cluster**: 10 ShadowLink доменов на одном IP не должны выглядеть
  как 10 copies of one template — нужна real diversity
- **Low-maintenance**: маленькая команда не будет писать 50 статей в месяц.
  Контент должен быть write-once или auto-generated с минимальным human
  touch.

---

## 2. Сравнение 8 типов decoy

Оценка по 5 критериям (0-5 баллов каждый):
- **PLAUS** — правдоподобие для одиночного независимого домена US-hosted
- **PROBE** — устойчивость к active probing (sub-paths, POSTs, missing endpoints)
- **MAINT** — низкое обслуживание контента (5 = вообще не трогать)
- **CLUSTER** — устойчивость к multi-domain CT-log/content cluster analysis
- **PRECEDENT** — есть ли успешные real-world кейсы в anti-censorship 2024-2026

### 2.1 Тип 1: Блог / News / CMS

**Описание:** Ghost / Hugo / Jekyll / Wordpress, статьи + (опционально)
комментарии + (опционально) admin.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 4 | "Personal tech blog" / "small-team newsroom" — самый частый паттерн в US small-domain world. CT-logs показывают тысячи таких. |
| PROBE | 3 | RSS feed, sitemap.xml, /tag/X, /author/X — много endpoint'ов которые DPI может тестировать. Если их нет → tell. Если все есть → много кода. |
| MAINT | 2 | Без обновления — выглядит мёртво (Last-Modified старее года = подозрительно). AI-generated content под Google penalty 2025 (Google Quality Rater Guidelines, December 2025 Core Update). |
| CLUSTER | 3 | Diversity достижима через variant templates + разные topics, но statictly похожие шаблоны cluster'ятся легко. |
| PRECEDENT | 4 | Самый частый выбор: NaiveProxy file_server гайды, Hysteria2 docs ("personal blog, landing page, documentation site"), Trojan-GFW fallback примеры. Tor blog deployments тоже используют. |
| **TOTAL** | **16/25** | |

**Плюсы:**
- Знакомый паттерн (low suspicion baseline)
- Можно реально публиковать контент когда хочется
- Внутренний admin/комментарии создают "alive" сигнал

**Минусы:**
- AI контент палится Google Quality Rater + риск SEO penalty означает
  что real bloggers избегают AI → нам сложно scale без палева
- Comments-with-bots = enterprise effort (модерация, anti-spam, реальные
  user-agent profiles)
- "Mёртвый" блог (нет постов 6 мес) сам по себе fishy

### 2.2 Тип 2: SaaS Landing (текущее: "Crest Technologies")

**Описание:** Single-page или multi-page маркетинг-сайт для несуществующего
SaaS продукта.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 3 | US-hosted SaaS startup landing — массовое явление. Но: ни одного pricing/login click не работает = probe видит что demo broken. |
| PROBE | 2 | Probe нажимает "Sign up" / "Login" / "Pricing" → все ведут в никуда или возвращают одинаковый 404. **HIGH detection risk.** |
| MAINT | 5 | Write once, ship forever. Нет blog feed, нет updates required. |
| CLUSTER | 2 | Marketing landings — самый homogeneous класс сайтов. Hero + Features + Testimonials + CTA. Cluster trivial. |
| PRECEDENT | 1 | Не нашёл ни одного успешного anti-censorship deployment основанного на SaaS landing. Community guidance (XTLS, Reality) явно предупреждает: landing pages с broken CTAs = tell. |
| **TOTAL** | **13/25** | |

**Плюсы:**
- Minimal maintenance
- Легко варьировать (smm tools, devops, AI assistants — много "vertical" tem)

**Минусы (критичные):**
- Любая active probe сразу ловит "broken product" — нет работающего
  signup, нет реальной БД, нет user accounts. Это **fundamental dead-end.**
- Если делать "working signup" — это уже не landing, а полноценный SaaS
  (огромный scope).
- v5 spec анализа `2026-05-26-decoy-blog-state-audit.md` явно
  деассемблирует SaaS-landing вариант как «slim cover».

### 2.3 Тип 3: Утилиты онлайн (JSON formatter, regex tester, image compressor)

**Описание:** Single-page tool типа regex101 / jsonformatter / freeformatter.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 5 | Single-page utility с одной function — **самый правдоподобный** standalone US site. Десятки тысяч таких реально существуют. Один developer, hosted on $5 VPS. |
| PROBE | 5 | Endpoint set минимален: `/`, `/api/format`, `/about`. Probe не может сильно копать. Сам tool работает (real JSON parse client-side). |
| MAINT | 5 | **Самый низкий**. Tool работает forever, контент = JS bundle + статичный HTML. Нет blog feed, нет articles, нет comments. |
| CLUSTER | 4 | Diversity лёгкая: JSON formatter / SQL formatter / regex tester / image compressor / password generator / hash calculator — 10 утилит = 10 разных templates с разной логикой. Каждая sub-niche имеет десятки real competitors. |
| PRECEDENT | 2 | Не нашёл явных кейсов "anti-censorship behind utility site", **но** Hysteria2 docs упоминают "small static site" generically. Отсутствие precedent — обоюдоострое: и не палево (нет signature), и не verified. |
| **TOTAL** | **21/25** | |

**Плюсы:**
- **Highest plausibility for low-maintenance solo-developer-on-US-VPS pattern**
- Cluster diversity естественная — 10 утилит легко делаются 10 разных
- AI generation НЕ involves (Google penalty не применяется — это не "content")
- Real working function (JSON parse) проходит human inspection без труда
- Минимальный endpoint surface = маленькая attack surface

**Минусы:**
- Меньше organic backlinks → если probe смотрит google indexing, может
  быть "new site, low authority" — но это нормально для small utilities
- Если SAME utility template на 10 доменах — обнаружится. Нужно 5-10
  разных tool ниш.

### 2.4 Тип 4: Файловый хостинг (gofile / anonfiles стиль)

**Описание:** Upload-and-share service, либо public, либо invitation-based.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 2 | File hosting US-hosted в 2026 — **высокий suspicion**. Используется для warez/illegal, многие провайдеры закрывают. RKN отдельно блокирует file hosters. |
| PROBE | 2 | Upload endpoint должен работать, storage real. Без работающего upload — палится. С работающим — open file hosting = abuse magnet. |
| MAINT | 1 | Storage management, abuse handling, copyright takedowns — full-time job. |
| CLUSTER | 3 | Templates известны (Bootstrap-based dropzone), но самих хостеров мало → каждый домен сразу "ещё один file host" подозрителен. |
| PRECEDENT | 0 | **Negative** precedent: file hosters активно блокируются в РФ (anonfiles, gofile уже в списках). Decoy file host = **anti-pattern**. |
| **TOTAL** | **8/25** | |

**Verdict: AVOID.**

### 2.5 Тип 5: Медиа-галерея (gif/meme/image host)

**Описание:** Imgur-style, browse-by-tag, infinite scroll.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 2 | Same problems as file host — image hosting в US blocked by RKN proactively (imgur is blocked since 2024). |
| PROBE | 3 | Real images load, real pagination — но scale (10k+ images) = real cost. |
| MAINT | 1 | Image curation + DMCA + storage. |
| CLUSTER | 3 | Templates fairly diverse, but image content stock cluster'ится. |
| PRECEDENT | 0 | Не нашёл anti-censorship проектов с image-host decoy. |
| **TOTAL** | **9/25** | |

**Verdict: AVOID.** Те же проблемы что file hosting + ещё больше storage cost.

### 2.6 Тип 6: Документация / docs site

**Описание:** Docusaurus / MkDocs / Sphinx — docs для (несуществующего) OSS
проекта или внутренней библиотеки.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 3 | "Docs for our open-source X" — типичный GitHub-сопровождающий паттерн. Но без real GitHub project → probe легко проверяет. |
| PROBE | 4 | Если "docs for company X" — endpoint set простой: `/`, `/getting-started`, `/api/`, `/changelog`. Низкая attack surface. |
| MAINT | 4 | Write once, occasional version bumps. Меньше maintenance чем blog, но больше чем utility. |
| CLUSTER | 3 | Docs themes ограничены (Docusaurus, MkDocs Material, GitBook) — easy cluster. |
| PRECEDENT | 2 | Видел в Reality discussions упоминания "docs site behind reverse proxy", но не строгая практика. |
| **TOTAL** | **16/25** | |

**Плюсы:**
- Low maintenance
- Clean endpoint surface
- Plausible for tech-team domain

**Минусы:**
- **Docs without real product** = легко проверяется (link на GitHub
  repo, который не существует или forked-empty). Нужно maintain fake
  repo с commits.
- Узкий audience-fit — domain like `mytool.dev` без download-able artifact
  выглядит abandoned.

### 2.7 Тип 7: Личный сайт / портфолио

**Описание:** "John Smith — Software Engineer", about/projects/contact.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 4 | Standalone personal sites — массовое явление. |
| PROBE | 4 | Static, minimal endpoints. Нечего пробировать. |
| MAINT | 5 | Write once, update rarely. Самый низкий. |
| CLUSTER | 1 | **Catastrophic** для multi-domain deployment: 10 personal sites = 10 разных personalities. Каждый требует AI-generated bio, project list, photos, real-looking commit history на GitHub. **Не scalable.** |
| PRECEDENT | 1 | Видел single-domain deployments, но не multi-domain anti-censorship. |
| **TOTAL** | **15/25** | |

**Verdict:** Хорош для **одного** домена, плох для нашего use-case
(множество ShadowLink endpoint'ов).

### 2.8 Тип 8: Сообщество / форум (mini-Reddit)

**Описание:** Discourse / Lemmy / Flarum / custom — board с posts +
комментариями.

| Criterion | Score | Notes |
|---|---|---|
| PLAUS | 2 | "Empty community" моментально палится. Real community = users, posts, моderation. |
| PROBE | 2 | Тонна endpoints (/u/X, /c/Y, /post/Z) — все должны работать realistic'но. |
| MAINT | 0 | **Самый высокий**. Real moderation, spam fighting, content seeding bots. |
| CLUSTER | 3 | Тематически различимо, но платформенно унифицировано (Discourse везде Discourse). |
| PRECEDENT | 0 | Не нашёл deployments. |
| **TOTAL** | **7/25** | |

**Verdict: AVOID.** Maintenance overhead disqualifies.

---

## 3. Финальный ранкинг

| Rank | Type | Score | Verdict |
|------|------|-------|---------|
| **1** | **Утилиты онлайн** (JSON formatter, regex, image compressor) | **21/25** | **WINNER** — best plausibility/maintenance ratio |
| 2 | Блог / News / CMS | 16/25 | Strong, но AI penalty + maintenance overhead |
| 2 | Документация / docs | 16/25 | Good, но без real product fishy |
| 4 | Личный сайт | 15/25 | Single-domain only |
| 5 | SaaS landing | 13/25 | Broken CTAs = active probing tell |
| 6 | Медиа-галерея | 9/25 | RKN proactive blocking |
| 7 | Файловый хостинг | 8/25 | RKN proactive blocking, abuse magnet |
| 8 | Форум / community | 7/25 | Maintenance impossible |

---

## 4. Главное направление: **Утилиты онлайн (Type 3)**

### 4.1 Почему утилиты выигрывают

1. **Geographic+role plausibility:** "solo developer's free tool on a small
   US VPS" — самый распространённый паттерн для standalone-домена с
   foreign datacenter IP. Десятки тысяч таких реально существуют (regex101,
   jsonformatter.curiousconcept.com, freeformatter.com, regexr.com,
   jsonlint.com, sqlformat.org, и т.д.). Probe видит site, сравнивает с
   peer set — попадает в massive non-suspicious cluster.

2. **Minimal endpoint surface:** real utility = `/` + `/api/process` +
   `/about`. Active probing не имеет много направлений. Сравнение с
   real `regex101.com` показывает: даже у "топового" sole-page tool
   нет 50 endpoint'ов.

3. **Real working function** проходит human inspection. Probe (или
   живой analyst) загружает JSON, видит как он форматируется, заключает
   "real tool". В отличие от SaaS landing где "Sign up" не работает.

4. **No content treadmill:** JSON formatter работает forever без
   обновлений. Нет AI-content penalty (Google December 2025 update
   targets blog-style content, не utility tools). Нет comments to
   moderate. Нет blog feed to update.

5. **Cluster diversity естественная:** 10 разных tool ниш = 10
   принципиально разных templates с разной логикой. Намного легче
   делать unique 10 утилит чем 10 unique blogs.

6. **No precedent — but no negative precedent either.** Отсутствие
   formal recommendations означает, что у DPI **нет signature** для
   "VPN-behind-utility-site". Blog cover уже отрабатывался многократно
   — у TSPU есть pattern recognition. Utilities — uncharted territory.

### 4.2 Конкретный план (если выбираем Type 3)

Рекомендуемый pool из 5-10 разных утилит-ниш:
1. **JSON formatter/validator** — base, large peer set
2. **Regex tester** — большой peer set (regex101, regexr)
3. **URL encoder/decoder + base64** — простая, real-world tool
4. **JWT decoder** — niche, но real (jwt.io как референс)
5. **Hash calculator** (MD5/SHA256/bcrypt) — простая, real
6. **Color picker / palette generator** — visual variety
7. **SQL beautifier / minifier**
8. **CSS/HTML minifier**
9. **Markdown preview / converter**
10. **UUID generator + timestamp converter**

Каждый = standalone domain (`jsonformat.io`, `regextest.dev`, etc.) с
СВОЕЙ visual identity (разные frameworks, разные colors, разный
copywriting tone). Все 10 = 10 разных GitHub-style personas.

### 4.3 Почему блог занял только 2 место (vs идея пользователя)

User предложил полноценный блог с админкой, статьями + бот-комменты.

**Проблемы этого подхода:**

1. **AI-generated content под Google penalty 2025+** (December 2025
   Core Update, Quality Rater Guidelines targeting "scaled content
   abuse"). Любой бот-генерированный контент рискует:
   - Google manual action (June 2025 wave hit многих)
   - Quality raters mark as "Lowest" quality
   - Domain reputation падает → "abandoned/dead blog" signal
   - Если real human visit нашёл AI artifacts → cluster intelligence

2. **Comments-with-bots = enterprise effort.** Real comments требуют:
   - Realistic user-agent rotation для bot accounts
   - Anti-spam moderation (irony: бороться со своими ботами)
   - Plausible comment timing (sleep schedules, weekend patterns)
   - Avatar pool с unique image fingerprints
   - Email verification mock + persistent user DB

3. **Blog endpoint surface = большой.** RSS, sitemap, /tag/X, /author/X,
   /archive/YYYY/MM, /search?q=, /page/N — все должны работать
   plausibly. Утилита имеет 3 endpoint'а; blog — 30+.

4. **"Stale blog" = active red flag.** Если нет новых постов 3+ месяца —
   real blogs обычно имеют это как explicit "we're not updating", но
   "abandoned" сразу подозрительно для probing.

5. **Existing decoy code (`internal/deploy/decoy_content_gen.go`, 547
   строк) уже реализует blog persona.** Идея не нова — она УЖЕ
   деплоится. Если она работает — оставить. Если нет — пора менять
   парадигму, и Type 3 (utility) дешевле и устойчивее.

**Когда блог всё-таки имеет смысл:**
- Если есть real человек который реально пишет 1 пост в месяц
- Если он на personal-domain (Type 7) с одной авторской identity
- Single-domain deployment, не multi-cluster

### 4.4 Можно ли комбинировать?

**Да, и это рекомендуется.** Гибридная стратегия:
- **70% доменов** = utility tools (Type 3) — workhorse
- **20% доменов** = blog (Type 1) — для доменов с real human author
- **10% доменов** = docs site (Type 6) — для tech-team domains

Это даёт cluster diversity на уровне domain-type-mix, не только
content-variance. Probing видит heterogeneous infrastructure
(developer's tool, hobbyist blog, OSS project docs) — это soundlier
чем "10 одинаковых blogs".

---

## 5. Что говорят peer projects о выборе decoy (2024-2026)

### 5.1 REALITY (XTLS/Xray)

Reality НЕ использует locally-hosted decoy — она **borrowing** TLS
handshake от реального target site (Microsoft, Apple, Bing, etc.).
Best practice 2025:
- Geographic proximity к VPS (server в Германии → German dest)
- Reachable из censored region (Bing OK в Iran)
- Whitelisted/unthrottled SNI preferred (но риск abuse pattern)
- Rotation / diversification across users
- IP-as-dest hidden play (1.1.1.1:443) для Iran speed restrictions

**Применимо к нам:** Мы НЕ можем borrowed-cert path делать —
архитектурный ceiling. Reality lesson для нас: "если у тебя свой cert,
сделай decoy максимально неотличимым от real small site".

Источник: [XTLS Fallbacks docs](https://xtls.github.io/en/document/level-1/fallbacks-with-sni.html),
[XTLS/Xray-core Discussion #3318](https://github.com/XTLS/Xray-core/discussions/3318),
[XTLS/Xray-core Discussion #2431](https://github.com/XTLS/Xray-core/discussions/2431)

### 5.2 NaiveProxy (Caddy + forwardproxy@naive)

NaiveProxy explicit'но рекомендует **real static site** на `/var/www/html`:
> "Serve real static content from /var/www/html (not a default 'It
> works!' page). Use a domain that looks legitimately registered with
> normal DNS records."

Canonical Caddyfile pattern:
```
:443, example.com {
    tls me@example.com
    forward_proxy { basic_auth user pass; hide_ip; hide_via; probe_resistance }
    file_server { root /var/www/html }
}
```

Documentation НЕ указывает тип сайта — "real static site" суффициентно,
implying что utility/blog/docs все OK если они **реально работают как
сайт** (links, pages, не lorem ipsum).

Источник: [NaiveProxy ArchWiki](https://wiki.archlinux.org/title/Na%C3%AFveProxy),
[klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy),
[Oil and Fish: NaiveProxy + Caddy 2](https://oilandfish.net/posts/naiveproxy-caddy-2.html)

### 5.3 Hysteria2 (apernet/hysteria)

Hysteria2 supports 3 masquerade modes — `file` / `proxy` / `string`.
Documentation explicit:
> "Populate the directory with a real, plausible-looking static site (a
> personal blog, landing page, documentation site). An empty directory
> or default placeholder undermines the cover."

Acceptable types по official docs: blog, landing, docs. **Не упоминаются**:
file hosting, image gallery, forum, SaaS. Это implicit guidance что
maintenance-heavy options не рекомендуются.

Источник: [Hysteria 2 official docs](https://v2.hysteria.network/docs/advanced/Full-Server-Config/),
[Hysteria2 Setup Guide](https://www.samnet.dev/learn/guides/hysteria2-setup/),
[ambientnode.uk Hysteria 2 stealth tunnel](https://ambientnode.uk/bypassing-censorship-in-the-age-of-dpi-a-stealth-tunnel-with-hysteria-2)

### 5.4 TrustTunnel (AdGuard)

TrustTunnel НЕ имеет explicit decoy site feature — relies on TLS
identity + HTTP/2/HTTP/3 framing. У нас architecture больше похожа на
старые protocols (Trojan/NaiveProxy/Hysteria), где decoy critical.

Источник: [TrustTunnel](https://trusttunnel.org/),
[TrustTunnel GitHub](https://github.com/TrustTunnel/TrustTunnel),
[Tom's Guide TrustTunnel coverage](https://www.tomsguide.com/computing/vpns/adguard-vpns-obfuscated-trusttunnel-protocol-goes-open-source-heres-what-you-need-to-know)

### 5.5 Community guidance (XTLS discussions, net4people/bbs)

Recurring themes:
- **Avoid personal blogs as decoys для popular VPN domains** — low-traffic
  niche сайты attract suspicion (sudden burst of connections to obscure
  blog)
- **Avoid popular utility CDN sites только если они не plausibly
  reachable** from server region
- **Prefer medium-traffic, plausible destinations matching server geography**

Для нас: US datacenter + small utility = matches the "small US dev
hosting a tool" profile perfectly. US datacenter + small Russian-language
blog = mismatch. Это **сильно поддерживает Type 3 (utilities) над Type 1
(blog)** для нашей конкретной geographic context.

Источники: net4people/bbs discussions, XTLS community recommendations
(synthesized from search results above).

---

## 6. Релевантный академический research 2024-2026

### 6.1 SNITCH (NDSS MADWeb '25) — IP geolocation для VPN detection

**Schwartz et al.**, "SNITCH: Leveraging IP Geolocation for Active VPN
Detection" (NDSS MADWeb 2025).

Key findings:
- Active probing tool, **не зависит** от прежних known VPN-to-IP mappings
- Detects "any kind of proxy" — HTTPS proxy, VPN, SSH forwarding, Tor
- Limitations: regions with "outdated network infrastructure" (Africa,
  parts of Asia) — high deviation in network delay degrades accuracy.
  РФ/Иран не в списке degraded regions → SNITCH применим к нам.

**Применимо к выбору decoy:** SNITCH работает на TIMING-уровне, не на
content. **Тип декой не имеет значения для SNITCH detection** —
важна geographic plausibility IP и timing characteristic. Это
**усиливает** аргумент за "Type 3 utility" — geographic plausibility
US-utility + US-IP = clean.

Source: [SNITCH paper PDF](https://www.ndss-symposium.org/wp-content/uploads/madweb25-8.pdf),
[NDSS listing](https://www.ndss-symposium.org/ndss-paper/auto-draft-576/)

### 6.2 Cross-layer RTT fingerprinting (NDSS '25)

**Xue et al.**, "The Discriminative Power of Cross-layer RTTs in
Fingerprinting Proxy Traffic" (NDSS 2025).

Key findings:
- 80% of top 5000 websites generate detectable proxy fingerprint via
  cross-layer RTT discrepancy
- Protocol-agnostic detection — работает против ВСЕХ обfuscated
  proxies, включая Reality/Hysteria/Trojan/VLESS

**Применимо к выбору decoy:** Это **transport-layer** attack — opять
независит от типа decoy. Однако усугубляет приоритет того, чтобы
decoy выглядел "in-place" — если probe видит decoy с RTT-сигнатурой
"forwarded proxy", и decoy выглядит как simple US utility (которое
обычно direct-hosted, не proxied), это incoherence сильно усиливает
detection confidence.

**Implication:** для Type 3 utility deployment, важно minimal proxy
chains между origin и client. Direct nginx → shadowlink-server (как в
текущей architecture) лучше чем nginx → another-proxy → shadowlink.

Source: [Cross-layer RTT paper](https://censoredplanet.org/papers/rtt-fingerprinting.pdf),
[U-Michigan coverage](https://cse.engin.umich.edu/stories/countering-a-flaw-in-anti-censorship-tools-to-improve-global-internet-freedom)

### 6.3 USENIX Security '24: Encapsulated TLS handshakes

**Xue et al.**, "Fingerprinting Obfuscated Proxy Traffic with Encapsulated
TLS Handshakes" (USENIX Security 2024).

Detection mechanism: nested TLS handshakes — proxy-tunneled TLS over
proxy-frontend TLS creates "TLS within TLS" pattern. Universal.

**Применимо:** Не наша архитектура напрямую — ShadowLink не делает
nested TLS. Но showcase того, что academic detection moved beyond
content-level to **transport patterns**. Это уменьшает важность outright
content type выбора и подчёркивает важность transport mimicry (что
ShadowLink уже делает: mimicry engine, sec-ch-ua lockstep, padding
distributions).

Source: [USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting)

### 6.4 GFW active probing — 404 content uniqueness

Frolov et al.'s research (referenced in net4people/bbs) показал что
"infinite timeout" responses у many circumvention tools = fingerprint.
Same principle для 404 HTML uniqueness — если proxy server возвращает
generic 404 page, uniqueness of HTML = fingerprint.

**Применимо к нам:**
- Hysteria2 explicit: "A bare 404 response is a fingerprint censors can
  probe for"
- Type 3 utility decoy: real working tool → no 404 on `/` → strong
- Type 1 blog decoy: real blog → no 404 → strong тоже
- Type 2 SaaS landing: 404 on /pricing, /signup → **fingerprint risk**

Sources: [net4people/bbs Issue #58](https://github.com/net4people/bbs/issues/58),
[arxiv.org/html/2503.02018v1](https://arxiv.org/html/2503.02018v1),
[ensa.fi/active-probing/](https://ensa.fi/active-probing/),
[Tor blog GFW probing](https://blog.torproject.org/learning-more-about-gfws-active-probing-system/)

### 6.5 Russia-specific 2024-2026 detection landscape

Recent reports (net4people/bbs #546, Habr article, InstaTunnel Medium):
- OpenVPN: 100% detection within 30s
- WireGuard: 100% detection by mid-2024
- Shadowsocks: 95% detection post-September 2024
- VLESS+Reality: 99.5% bypass success in late 2025 (но новые TLS-policing
  методы тестируются ноябрь 2025+)
- Trojan: 90% detection post-August 2025
- VMess: 80% detection post-September 2025

**Implication:** Russia DPI moved beyond protocol detection к
behavioral classification. Decoy content matters all the more — если
протокол confined to plausible decoy site, detection drops sharply.
Reality 99.5% success подчёркивает что **proper TLS+decoy combination
still wins**. Decoy type — vehicle для plausibility.

Sources: [net4people/bbs Issue #546](https://github.com/net4people/bbs/issues/546),
[Habr VLESS Russia](https://habr.com/en/articles/990144/),
[InstaTunnel Medium GFW steganographic](https://medium.com/@instatunnel/bypassing-the-great-firewall-the-rise-of-steganographic-tunneling-53780017657f)

---

## 7. Применение к ShadowLink стратегии

### 7.1 Конкретные рекомендации

1. **Перейти от blog persona (current 547-line generator) к utility-tools
   pool persona.** Каждый ShadowLink domain = одна (различная) utility.
   Postal multi-decoy = разные nimentitities, не варианты одного blog.

2. **Существующий `decoy_content_gen.go` (547 строк)** — оценить
   `2026-05-26-decoy-blog-state-audit.md` для understanding текущего
   state. Possibly: refactor generator для multi-niche utility templates
   вместо blog-only.

3. **Hybrid:** keep blog generator для 20% доменов (где есть AI-curated
   content разумного качества), добавить utility generator для 70%
   доменов, docs generator для 10%.

4. **TLS server-side fingerprint (Go default crypto/tls) = critical
   gap** (см. `2026-05-26-honest-gap-analysis-direct-primary.md` §1.3
   и §1.4). Decoy content matters less if JA3S кричит "Go server".
   **Mandatory nginx-front** должно быть invariant, не optional.

5. **Multi-domain CT-log diversity** — domain naming не должен иметь
   visible cluster (`tool1.dev`, `tool2.dev`, `tool3.dev` = cluster
   immediate). Use **разные TLDs и совершенно разные wordings**
   (`jsonformat.io`, `regex-test.dev`, `quick-base64.app`).

6. **Каждая utility должна ДЕЙСТВИТЕЛЬНО работать.** Это easier чем
   real blog (никаких articles), но requires real JS bundle с real
   logic. Probe должен мочь paste JSON и видеть formatted output.

### 7.2 Open questions для пользователя

- Принимает ли утилитный направление? Если да — план migration с
  blog generator на utility generator pool.
- Сколько ShadowLink доменов планируется в pool? Если <5 — Type 7
  (личный сайт) viable as supplement. Если >10 — strictly Type 3
  utility-pool.
- Готов ли вложиться в 10 разных utility tools? Это ~200-300 LOC
  каждый (HTML/CSS/JS), один раз write, low-maintenance forever.

---

## 8. Top-3 находки (для cross-reference)

### Finding 1: SaaS landing — confirmed dead-end для active probing
SaaS landing с "Sign up" / "Login" / "Pricing" buttons которые ведут в
никуда — first thing active probing tests. Это уже presence в нашем
v5 spec analysis (`2026-05-26-decoy-blog-state-audit.md`). Все peer
projects (NaiveProxy, Hysteria2, REALITY community) implicit'но
исключают SaaS landings.
Sources: [Hysteria2 docs](https://v2.hysteria.network/docs/advanced/Full-Server-Config/),
[NaiveProxy ArchWiki](https://wiki.archlinux.org/title/Na%C3%AFveProxy)

### Finding 2: AI-generated blog content under Google penalty (2025+)
Google December 2025 Core Update + Quality Rater Guidelines target
"scaled content abuse". Manual actions initiated June 2025. AI-generated
blog cover risks domain reputation collapse — turning decoy into LIABILITY
not asset. Blog с AI articles требует human editing → not low-maintenance.
Sources: [Google December 2025 Core Update](https://almcorp.com/blog/google-december-2025-core-update-complete-guide/),
[AI content penalty 2025](https://www.mindbees.com/blog/google-ai-content-penalty-strategies-2025/),
[Real risk of AI content](https://peec.ai/blog/the-real-risk-of-ai-generated-content)

### Finding 3: Utility tool decoy = uncharted territory с positive risk profile
Сильнейший plausibility score (5/5), zero negative precedent в
anti-censorship research, ideal geographic match для US-VPS small-dev
profile. Отсутствие explicit recommendation = absence of known DPI
signature. Type 3 (utility) wins comparison по 21/25 vs blog 16/25.
Сравнение с peer projects: NaiveProxy/Hysteria2 docs implicitly allow
("real static site"), не требуют конкретного типа. Real working JS
function (JSON parse client-side) проходит human inspection без
backend cost.
Sources: [regex101](https://regex101.com/),
[JSON Formatter](https://jsonformatter.curiousconcept.com/),
[Hysteria2 masquerade docs](https://v2.hysteria.network/docs/advanced/Full-Server-Config/),
[NaiveProxy](https://github.com/klzgrad/naiveproxy)

---

## 9. Limitations of this research

1. Не нашёл академический paper, который БЫ напрямую сравнивал типы
   decoy sites по detection rate. Все papers фокусируются на transport
   level. Это значит, что content-level decoy выбор — empirical
   community wisdom, не formally validated.
2. Не нашёл "Aparecium" paper (упомянутый в memory) — возможно
   memory ссылается на pre-print или informal name. Closest matches:
   USENIX 2024 encapsulated TLS handshakes, NDSS 2025 cross-layer RTT.
3. Российский RKN-специфичный active probing методы — наименее
   документированы. Большинство research = GFW (China) или Iran. RKN
   методы во многом скопированы с GFW, но specifics differ.
4. Все recommendations basis on 2024-2026 data — landscape evolves
   ежеквартально. Recheck before major deployment commitment.

---

## Conclusion

**Утилиты онлайн (Type 3) — рекомендуемое направление**, особенно
для multi-domain ShadowLink deployments. Blog persona (current 547-line
generator) сохраняется как 20% mix component для доменов с real human
author. SaaS landing, file/image hosting, и community forum **исключены**
из cover-site pool.

Этот выбор orthogonal к более фундаментальным gaps описанным в
`2026-05-26-honest-gap-analysis-direct-primary.md`:
- Server-side TLS fingerprint (mandatory nginx-front)
- Single-IP failure mode at scale
- CT-log cluster через `%datacanvases.com%`

Decoy type = plausibility layer. Эти gaps = infrastructure layer.
Решать оба, не один из.
