# Third-pass verification review — Decoy Behavioral Coverage Design Spec v2.1

**Date:** 2026-05-27 (evening, после v2.1 rewrite)
**Reviewer:** Opus 4.7 (1M context), focused verification mode
**Object:** `D:/NIXAVPN/shadowlink/docs/superpowers/specs/2026-05-27-decoy-behavioral-coverage-design-v2.1.md`
**Previous reviews:**
- `2026-05-27-decoy-behavioral-coverage-design-review.md` (v1 review)
- `2026-05-27-decoy-behavioral-coverage-design-v2-review.md` (v2 review)

**Verdict (one-liner):** Все 4 CRITICAL+HIGH и все 5 рекомендуемых fixes из v2 review **реально закрыты в v2.1** с матчингом research-evidence. Архитектурный switch (hybrid 404 → unified Linear-style) логически согласован между всеми разделами. Новых contradictions/TBDs не введено. **READY TO IMPLEMENT.**

---

## §1. Verification table: v2 review issues → v2.1 fix status

| # | v2 Issue | Severity | v2.1 Section | Fix verification | Status |
|---|---|---|---|---|---|
| 1 | N6 — `humansNamePool` global mutation | CRITICAL | §3.2 lines 527-533 | `pool := make([]humanProfile, len(humansNamePool)); copy(pool, humansNamePool); rng.Shuffle(len(pool), ...)` — copy слайса ДО Shuffle, mutate `pool` not `humansNamePool`. Test `TestHumansGenerationNoSharedMutation` + `TestHumansGenerationConcurrentSafe` (race-aware). | ✅ CLOSED |
| 2 | N2 — XFO blog SAMEORIGIN vs DENY contradiction | HIGH | §2.2 blog snippet (line 132) + §9 risk row "Wrong XFO" | Snippet: `X-Frame-Options "SAMEORIGIN"`. §9 row: "✅ (unified SAMEORIGIN)". Risk table no longer claims "DENY only для blog". | ✅ CLOSED |
| 3 | N7 — blog security.txt undefined | HIGH | §2.3 Blog persona delta + §6.2 test | §2.3: "**HAS `/.well-known/security.txt`** (fix v2 review N7 — explicit: blog имеет security.txt по аналогии с SaaS)". Test `TestRenderNginxBlog` asserts `strings.Contains(cfg, "/.well-known/security.txt")`. | ✅ CLOSED |
| 4 | N10 — utility 404 three contradicting descriptions | HIGH | §1.3, §2.3 utility, §4.1 — unified | §1.3 теперь явно говорит: "все 3 persona → Linear-style". §2.3 utility: `try_files $uri $uri/ /index.html` (paths) + `try_files $uri =404` (assets) — same as SaaS. §4.1 NotFoundPage 200 inside SPA, "no standalone 404 Vite entry". Все 3 раздела consistent. | ✅ CLOSED |
| 5 | N1 (R3) — hybrid 404 not in research | HIGH | §1.3 архитектурное решение | Hybrid removed. Решение: "все 3 persona → Linear-style (200+SPA fallback на любой URL)". Justification matches research §2 (Linear/Vercel/regex101/jsonlint все used 200+SPA). Single asymmetry (asset 404) justified through CDN convention. | ✅ CLOSED |
| 6 | N4 — DecoyHandler unification TBD | MEDIUM | §2.4 lines 323-422 | Spelled out: DecoyHandlerConfig struct extension (DomainPersona map, DefaultPersona), `NewDecoyHandlerV2`, persona-aware ServeHTTP с `setSaaSHeaders/setBlogHeaders/setUtilityHeaders`, `fourOhFourWrapper` для 404.html interception, YAML format extension с backwards compat. +50-100 LOC noted. Implementation-ready. | ✅ CLOSED |
| 7 | N5 — favicon 15086B TBD | MEDIUM | §3.4 lines 570-632 | Pre-built ICO byte template (`assets/favicon-template.ico`, 15086B, `//go:embed`) + per-template SVG generated at deploy. Trade-off explicit: "Не имеет per-template color variation — ICO byte-size mimicry > color diff". Test `TestFaviconICOSize` enforces 15086 byte invariant. One-time regeneration procedure documented. | ✅ CLOSED |
| 8 | N11 — snippets dir bootstrap | MEDIUM | §2.2 `uploadHeaderSnippets` line 166 + §7.2 step 1 | `mgr.ExecuteCommandWithTimeout("mkdir -p /etc/nginx/snippets/", 10*time.Second)` в Go code. Plus shell step 1: `mkdir -p /etc/nginx/snippets/`. Two-layer защита. | ✅ CLOSED |
| 9 | N12 — nginx -t -c misuse | MEDIUM | §7.2 lines 985-1000 | Переписано: atomic swap-and-validate. `mv decoy decoy.rollback && mv decoy.new decoy && nginx -t && systemctl reload nginx`. Explicit rollback path. No more `nginx -t -c <fragment>`. | ✅ CLOSED |
| 10 | N8 — humans.txt hardcoded date | LOW | §3.2 line 547 | `fmt.Fprintf(&sb, "  Last update: %s\n", deployDate.Format("2006-01-02"))` — receives `deployDate time.Time` as parameter. | ✅ CLOSED |
| 11 | N9 — humans.txt empty twitter handles | LOW | §3.2 line 488-495 | `humanProfile` struct dropped Twitter field entirely. Comment: "All entries WITHOUT twitter handles (fix v2 review N9: uniform style ... we choose all-skip)". | ✅ CLOSED |

**Total: 11/11 issues closed.** Zero regressions, zero "partially closed".

---

## §2. New architectural consistency check

v2.1 главное архитектурное решение: **unified Linear-style 404 для всех 3 persona** (§1.3). Проверка cross-section согласованности:

### §1.3 (decision statement)
> "все 3 persona → Linear-style (200+SPA fallback на любой URL)"
> "Single asymmetry: assets ... → real 404"

### §2.3 SaaS (lines 212-225)
- `location / { try_files $uri $uri/ /index.html; ... }` ← path → 200
- `location ~* \.(css|js|png|...)$ { try_files $uri =404; ... }` ← asset → 404
- **Match §1.3** ✅

### §2.3 Blog (delta list line 277-294)
- "Real 404 для missing assets — same as SaaS"
- "`<Route path="*">` в App.tsx" → path → 200
- **Match §1.3** ✅

### §2.3 Utility (delta list line 296-321)
- "Real 404 для missing assets — same as SaaS"
- "`<Route path="*">` в App.tsx" → path → 200
- **Match §1.3** ✅

### §4.1 (React)
- "Status code: 200 (because nginx уже отдал index.html со status 200)"
- "the Linear/Vercel/regex101 pattern, matches real prod SPA sites"
- **Match §1.3** ✅

### §6.3 smoke checks
- Check #1: `/this-page-does-not-exist → HTTP/1.1 200` (path → 200)
- Check #2: `/random.png → HTTP/1.1 404` (asset → 404)
- **Match §1.3** ✅

### §6.2 nginx render tests
- `TestRenderNginxSaaS`: `try_files $uri =404` (asset) **AND** `try_files $uri $uri/ /index.html` (path)
- `TestRenderNginxBlog`: both assertions
- `TestRenderNginxUtility`: both assertions
- **All match §1.3** ✅

**Conclusion:** Архитектурное решение последовательно применено через 6 разделов. Нет contradicting statements.

---

## §3. New TBDs / contradictions introduced

Прошёл по всему v2.1 spec в поисках новых проблем.

### Найдено: 0 новых TBDs.
Все ранее TBD-помеченные элементы (DecoyHandler unification, favicon strategy) теперь имеют explicit implementation contract.

### Найдено: 0 новых internal contradictions.
Cross-checked: §1.3 vs §2.3 vs §4.1 vs §6.2 vs §6.3 — все 4 раздела согласованы относительно 404 strategy.

### Найдено: 0 новых implementation bugs.
- `generateHumansForDomain` copy-fix корректен (`pool := make([]humanProfile, len(humansNamePool)); copy(...)` — Go idiomatic copy of slice).
- `fourOhFourWrapper.WriteHeader` логика корректна (intercepted flag, fallback to default 404 if ReadFile fails).
- `uploadHeaderSnippets` mkdir-first pattern корректен.
- `nginx -t` swap-and-validate sequence корректен.

### Minor observations (не блокирующие):

#### O1 — Inline CSS color drift risk (carried over from v2 M1 caveat)
§3.1 404.html template использует `{{.PrimaryColor}}` template variable. Если React app's primary color меняется через theme file без update template, через несколько deploys 404.html и React app начнут расходиться. **Not a bug** — единая variable feed может быть централизована. **Operational risk, defer to operational hygiene.**

#### O2 — `templateMeta.PrimaryColor` field referenced but not declared
§3.1 template uses `{{.PrimaryColor}}`. §3.4 `generateFaviconSVG(brandLabel, primaryColor)` принимает primaryColor parameter. Но §2.1 `templateMeta` struct (lines 84-90) объявляет только `Persona` и `BrandLabel` — **нет `PrimaryColor` field**.

**Implication:** при реализации поле нужно добавить в struct + populate в `templateMetas` map. Это **обнаружится сразу** в compile time, не runtime ambiguity. **Minor spec omission, не блокирующее** — implementer закроет в первые минуты работы.

#### O3 — `decoy_humans_pool_test.go` race test не runs Shuffle race scenario explicitly
§6.1 `TestHumansGenerationConcurrentSafe` запускает 50 goroutines с **разными доменами**. После v2.1 fix (copy slice) это всё ещё валидный тест (race detector поймает любой shared state mutation). Но для прямого regression-доказательства того что N6 fix работает, более precise test — спам один и тот же `domain` параллельно. Не критично — current test всё равно triggers race detector если copy fix забыт.

#### O4 — Backwards compat tests для YAML format не упомянуты explicitly
§8.2 описывает parser logic для old vs new YAML format. §6 (testing) не упоминает test для backwards compat parsing. **Mild gap** — implementer может пропустить test для legacy YAML deploys. Recommendation для §6.1: добавить `TestFileConfigBackwardsCompat_OldYAMLFormat` test entry.

**Severity of O1-O4: all SUGGESTION, none blocking.**

---

## §4. LOC estimate sanity check (+1490 backend)

§5.1 заявляет ~**+1490 LOC backend** (vs v2's +1050).

Breakdown:
- `steps_decoy.go` +280 — refactor + 3 persona funcs + 1-line update. **Realistic.**
- 3 snippet files +28 — trivial. **Realistic.**
- `snippets_embed.go` +50 — embed decls + upload function. **Realistic.**
- 3 template files +100 — 404 templates per persona. **Realistic.**
- `decoy_humans_pool.go` +100 — 20 names + generator + helper. **Realistic.**
- `decoy_favicon.go` +50 — upload + SVG generation. **Realistic.**
- Tests (steps_decoy_test +200, nginx_test +250, e2e +120, humans +80, favicon +30) = +680. **Realistic for 3 persona × multiple assertions.**
- `shadowlink/server/decoy.go` +120 — persona headers + 404 wrapper. **Realistic.**
- `shadowlink/server/decoy_test.go` +100 — persona + wrapper tests. **Realistic.**
- `fileconfig.go` +50 — YAML format extension с backwards compat. **Realistic.**
- `steps_shadowlink_domain_decoy_map.go` +30 — render persona. **Realistic.**

**Sum check:** 280+28+50+100+100+50+200+250+120+80+30+120+100+50+30 = **1588**. Estimate +1490 в пределах ±10% от breakdown sum. **Reasonable estimate** with normal padding for unforeseen.

**Note:** §5.1 caveat "+50-100 LOC" для YAML parsing — embedded в total (`fileconfig.go +50` + `steps_shadowlink_domain_decoy_map.go +30`). **Accounted.**

---

## §5. Smoke checklist completeness check

§6.3 содержит 13 checks. Coverage analysis:

| Verification target | Smoke check # |
|---|---|
| SPA fallback (path → 200) | #1 |
| Real 404 (asset → 404) | #2 |
| Internal directive (/404.html → 404) | #3 |
| security.txt rendering | #4 |
| /health k8s plaintext | #5 |
| Header consistency / vs /pricing (fix H3) | #6 |
| Removed anti-pattern headers | #7 |
| OPTIONS REST verbs | #8 |
| humans.txt content | #9 |
| favicon 15086B size | #10 |
| CSP present | #11 |
| Server header no version | #12 |
| feed.xml (blog only — skip on SaaS pl1) | #13 |

**Gaps:**
- Не проверяется persona consistency через Go decoy.go path (TrustTunnel reverse_proxy bypass). Это **direct-IP path**, не nginx path. Если admin запустит external curl с direct IP к shadowlink-server (bypassing CF + nginx), should он увидеть persona headers? §2.4 говорит да, но §6.3 smoke не тестирует this code path. **Acceptable gap** для current wave (admin не разворачивает direct-IP deployments routinely на pl1).
- Не проверяется YAML backwards compat (loading old format). **See O4 above.**

**13 checks достаточно для acceptance** на pl1 SaaS deployment.

---

## §6. Final verdict

### CRITICAL: 0
### HIGH: 0
### MEDIUM: 0
### SUGGESTION (non-blocking): 4 (O1-O4)

**Recommendation:** **READY TO IMPLEMENT.**

v2.1 — solid foundation:
- 11/11 v2 review issues addressed with research-aligned solutions
- Architectural pivot (hybrid → Linear-style unified) is internally consistent across §1.3, §2.3, §4.1, §6.2, §6.3
- Implementation contracts spelled out for previously-TBD items (DecoyHandler unification, favicon)
- Deploy sequence corrected (snippets bootstrap, atomic swap-and-validate)
- LOC estimate realistic (+1490)
- Smoke checklist sufficient for acceptance

The 4 suggestions (O1-O4) are documentation/test-quality improvements that can be addressed during implementation, not preconditions to start.

**Probability net-positive after implementation:** **high (85-90%)** — consistent with v2.1 §9 self-assessment.

**Implementer recommendations:**
1. Add `PrimaryColor` field to `templateMeta` struct (O2) — first 5 minutes of work.
2. Add `TestFileConfigBackwardsCompat_OldYAMLFormat` to test suite (O4).
3. Consider centralizing color palette across React + 404.html generation (O1) for future maintenance.
4. (Optional) Add explicit same-domain concurrent race test in addition to multi-domain (O3).

---

## §7. Top observations summary

1. **N6 fix is correct Go idiomatic copy** — `make([]T, len(src)); copy(dst, src)` — race-detector test backs it up. CRITICAL bug from v2 is fully neutralized.
2. **Architectural pivot from hybrid 404 → unified Linear-style is research-backed** (matches Linear/Vercel/regex101 — peer SPA-heavy sites). Eliminates N1, N10 simultaneously. Single code path = less surface for future drift.
3. **Implementation contracts (§2.4 DecoyHandler, §3.4 favicon)** convert previously-TBD items into actionable Go code. Implementer can start without further design clarification.
