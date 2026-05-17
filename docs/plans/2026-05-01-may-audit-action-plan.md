# May Audit Action Plan — ShadowLink (2026-05-01)

**Источник findings:** `shadowlink/docs/audit/2026-05-01-consolidated-findings.md`.
**Status:** живой документ, обновляется по мере выполнения.
**Принцип использования:** перед стартом каждого пункта **проверить целесообразность** (раздел "когда переоценить"), затем выбрать **вариант** реализации с учётом trade-offs.

---

## Правила работы по плану

1. **Никогда не начинать пункт "вслепую"** — сначала перечитать его аргументацию + раздел "когда переоценить". Если триггеры выполнились (или статус мира изменился) — пересмотреть, может пункт уже не нужен или приоритет изменился.
2. **Варианты — это not гипотезы**. Каждый вариант — реальный путь со своим trade-off. Решение какого взять принимается **в момент исполнения**, не сейчас.
3. **Один пункт = одна деливерабельная единица.** Если пункт раздувается — разбить на 2+.
4. **P0 блокирует prod-ready состояние.** P1 = боль, но временно жить можно. P2 = улучшение качества. P3 = trackers only.
5. Subagent-driven preferred для P0/P1 multi-file работы; inline для коротких fix'ов.
6. **Бинарники после каждого P0 пересобирать** (`bin/nixavpn-client.exe`, `bin/shadowlink-server-linux`, `bin/nixavpn-client-linux`); проверять build green перед commit'ом следующего пункта.

---

## P0 — Production blockers (закрывать в первую очередь) — ✅ ВСЕ 4 ЗАКРЫТЫ 2026-05-01

### A1. Backoff overflow clamp в WS pool ✅ DONE 2026-05-01

**Что делать:** в `slotBackoffDuration` (`shadowlink/client/wspool/` — точное местоположение проверить grep'ом `slotBackoffDuration`) добавить clamp `attempt = min(attempt, 6)` ДО вычисления exp. Текущая формула `5s × 2^attempt` overflow'ит в `time.Duration(MinInt64)` при `attempt~37` (видно в field log: `backoff=-2562047h47m16.854775808s`). Negative duration → `time.Sleep` returns instantly → reconnect-storm БЕЗ backoff.

**Почему это P0:**
- Field log 2026-05-01 10:44 MSK воспроизводит — slot=3 хранит attempt=37, дальше storm 13 попыток за <30 секунд.
- Под throttle хостера (или любым реальным CDN-degradation сценарием) это означает **наш клиент DDoS'ит свой же сервер** → handshake rate limit → decoy → больше overflow → snowball.
- Tier S R.1 был предполжен как фикс, но он cap'ит post-jitter (60s), а overflow happens **до** jitter — fix не работает.

**Варианты:**
- **(a)** `attempt = min(attempt, 6)` ДО expo. `5s × 2^6 = 320s` → потом cap 60s. Минимальное изменение, точечное. **Рекомендуется.**
- **(b)** Полностью переписать на linear backoff (5s + N×10s, max 60s). Проще обратимо, но меняет behavior characteristics.
- **(c)** Перейти на decorrelated jitter (AWS pattern: `min(cap, random(base, prev*3))`). Лучше для thundering herd, но больше кода.

**Когда переоценить:**
- Если уже задеплоено и production стабилен 7d без F1 в логах → понизить до P1 (просто polish).
- Если успели сделать A2 (Domain Diversity wiring) и cascade не воспроизводится из-за diversification — снова понизить.

**Effort:** S (1 файл, 5 строк, unit-test). **Зависимости:** нет.

---

### A2. Decoy-vs-ratelimit sentinel signal ✅ DONE 2026-05-01

**Что делать:** на сервере (`shadowlink/server/handler.go`, путь rate-limit branch ≈ Tier S R.4 spec) при срабатывании per-clientID handshake rate limit вернуть либо **(а) HTTP header `X-SL-RL: 1`** в decoy response, либо **(б) WS close-code 4429** при WS upgrade. На клиенте (`client/ws_pool.go::slotConnect`) парсить sentinel и применять fixed cool-down 120-300s **вместо** exp backoff.

**Почему это P0:**
- Сейчас клиент видит "HTML вместо JSON" → relay в handshake fail → exp backoff. Под throttle TLS ломается, попадает в rate-limit, exp убегает в overflow (см. A1).
- Field log: `attempt=24` slot=3 + `attempt=9` slot=2 — клиент бьётся в rate-limit раньше чем стабилизируется.
- Без sentinel клиент не отличает три кейса (rate-limited / decoy / down) и применяет одинаковую стратегию — плохую.

**Варианты:**
- **(a) HTTP header в decoy body**: `X-SL-RL: 1` (нейтрально, не палит проток через DPI — header в response, не URL). **Рекомендуется.** Реализация: server pre-handshake check rate, если limited — set header перед serving decoy.
- **(b) WS close-code 4429**: `gorilla.websocket` может прислать close frame с custom code; client unmarshall'ит. Минус — close frame публичен в TLS payload (post-decryption), но видим под `tcpdump` для пассивного наблюдателя через record-size pattern. Не страшно но менее clean.
- **(c) HTTP status 429 без maskirovki** — отдельный exception path в server. Самый clean но самый detectable: 429 от nginx-imitating server = signature.

**Когда переоценить:**
- Если решим что rate-limit не нужен вообще (упрощение) → DROP.
- Если перейдём на per-IP/per-CIDR rate limit вместо per-clientID — дизайн меняется, sentinel остаётся актуальным, просто триггер другой.

**Effort:** M (server + client, ≥3 файла, integration test). **Зависимости:** A1 (без A1 sentinel не помогает — exp всё равно overflow).

---

### A3. wsURLPool ≥6 plausible-shape paths (CRIT-4 closure) ✅ DONE (pre-session, verified 2026-05-01)

**Что делать:** в `shadowlink/server/urls.go:16-18` extend `wsURLPool` от `["/ws"]` до 6+ paths с разной "формой" (длина, сегменты, версионирование). Server-side dispatch на любой из них в `handler.go::ServeHTTP`. Client-side `client/ws_paths.go` weighted rotation per slot. Bytewise wsURLPool parity test client/server остаётся.

**Почему это P0:**
- Active probing classifier видит single endpoint `/ws` и identifies его в <10 round-trips. Это **самый большой остающийся detection signal** от April baseline (CRIT-4) и **до сих пор открыт в коде**.
- Все остальные TLS/JA4/padding улучшения 2026-04 спринта **не помогают** если URL pattern уникален.

**Варианты paths (выбрать ≥6):**
- `/ws` (legacy compat — оставить)
- `/api/v1/stream`, `/api/v2/realtime`
- `/realtime/connect`, `/socket/v1`
- `/socket.io/?EIO=4&transport=websocket` (Socket.IO style — самый plausible если впереди есть GA / analytics стек)
- `/cable` (ActionCable Rails-style)
- `/ws/v2/events`, `/notifications/stream`

**Варианты реализации:**
- **(a) Static pool в коде** обоих сторон. Простейший. Минус — нужен redeploy для добавления path.
- **(b) Server config-driven** + client получает list через handshake. Гибче, но handshake уже big enough; добавлять list туда — risk wire breakage. **Не рекомендуется** на этой итерации.
- **(c) Hybrid**: static fallback pool + admin-tunable extension list через `protocol_configs`. **Рекомендуется** для будущей гибкости, но первая итерация — static.

**Deploy order critical:**
1. Server-side update (accepts ALL old + new paths) → rollout VPS.
2. Client release с новым pool → users update.
3. Через 30 days — drop legacy single-path acceptance (если есть).

**Когда переоценить:**
- Если research покажет что Tier S.8 (Domain Diversity) **полностью** закрывает detection (разные домены = разные fingerprints для probing'а) → понизить до P1. **Маловероятно** — diversity не помогает если сам endpoint pattern уникален.
- Если найдётся public dataset реальных WS path distributions (например HAR-collection из ~100 SaaS) — выбрать paths из реальных, не выдуманных.

**Effort:** M (server + client, deploy coordination). **Зависимости:** нет, но deploy после A1+A2 (cleaner state).

---

### A4. Domain Diversity SSH-pipeline wiring (Track 3 H-1) ✅ DONE 2026-05-01 (split A4a+b+c+d, subagent-driven)

**Что делать:**
1. **Migration 074**: `shadowlink_pool_servers` ← добавить `ssh_user TEXT`, `ssh_password_enc TEXT` (через `encryptToken` с `APP_ENCRYPTION_KEY`), `ssh_port INT DEFAULT 22`.
2. Расширить `internal/admin/shadowlink_domain_provision.go::provisionDomain` шагами 5-9: `InstallLECert` → `InstallDecoyTemplate` → `UploadNginxConfig` → `ReloadNginx` → `ReloadShadowLink`. Сейчас helpers в `steps_shadowlink_domain.go:96-216` помечены `//nolint:unused` (вызываются ТОЛЬКО из тестов).
3. Снять `//nolint:unused` со всех helpers.
4. Regenerate `domain_decoy_map` через canonical `WriteShadowLinkConfigYAML` после добавления домена.

**Почему это P0:**
- MEMORY говорит "Domain Diversity sub-A до sub-D ✅ DONE", **код говорит "manual"**. Это самое опасное состояние — false sense of completion.
- Strategic context: RU CIDR /24 whitelist (Habr 1027276) делает Domain Diversity FIRST-LINE defense. Без неё мы остаёмся на единичном origin → попадаем в /24 detection легко.
- T1.3 Live Decoy уже в проде на datacanvases.com — single-server flow работает, но multi-domain orchestrator не работает в проде.

**Варианты:**
- **(a) Полное wiring** как описано выше (миграция 074 + 5 шагов). **Рекомендуется.**
- **(b) Wire-only некоторые шаги** (например только nginx + reload, оставить cert/decoy на manual). Менее полный, но быстрее. Минус — разрыв в orchestrator behaviour, документация будет misleading.
- **(c) Перенести SSH-исполнение на client-side admin frontend** — admin вводит SSH credentials локально, frontend через API запускает provisioning. Минус — credentials не сохраняются → каждое onboarding'е заново вводить. Плюс — нет хранилища passwords. **Безопаснее**, но UX боль.

**Когда переоценить:**
- Если мы решим **отказаться от nginx-based diversity** (например уйти на Caddy native ACME) — pipeline меняется радикально. Маловероятно, nginx уже стоит.
- Если SSH credentials политически нельзя хранить даже encrypted — выбрать (c).

**Effort:** L (миграция + ≥4 helper'ов wired + e2e test). **Зависимости:** A6 (rotation-ready APP_ENCRYPTION_KEY) ИЛИ принять single-key risk на этой итерации.

---

## P1 — High (closing после P0) — 🟡 NEXT (стартовый кандидат: B1)

### B1. nginx swap race protection (Track 3 H-4) ✅ DONE 2026-05-01

**Что делать:** в `internal/deploy/steps_shadowlink_domain.go::UploadNginxConfig` swap-script добавить per-server lock. Варианты:
- Server-side `flock /var/lock/shadowlink-nginx.lock` обернуть весь swap в bash.
- Application-side `lockServer(serverID)` в `ProvisionDomainAsync` (mutex per VPS).
- `nginx -t -c <tmpfile>` ДО `mv`, отказ если invalid.

**Почему P1:**
- Concurrent provisioning двух доменов одного сервера → T2 "nginx-test fails → mv .bak conf без bak → rm config" → nginx без shadowlink.conf на следующем reload.
- НЕ ловится в production где admin onboard'ит по одному домену в минуту — но при batch onboarding 20+ доменов риск растёт.

**Варианты:**
- **(a) Server-side flock + tmp+atomic-mv:** robust, server-only fix. **Рекомендуется.**
- **(b) Application-side mutex:** хорош для single-process; multi-instance API серверов (если когда-нибудь) — leak.
- **(c) Both** (defense in depth): рекомендуется для prod.

**Когда переоценить:**
- Если A4 раскатили и в проде есть только 1 admin процесс — снизить до P2.
- Если перейдём на Caddy с native config-reload (auto-atomic) — DROP.

**Effort:** S. **Зависимости:** A4 (без него orchestrator dead в проде).

---

### B2. Probe handler: real health vs decoy/CF challenge (Track 3 H-3) ✅ DONE 2026-05-01

**Что делать:** `internal/admin/shadowlink_pool_domains_handlers.go::ProbeShadowLinkPoolDomain`:
- Запрашивать **specific path** `/_health` (или подобный), внутри которого server отдаёт content-type+body **только** для bearer-authenticated запросов; иначе — decoy.
- ИЛИ парсить body на decoy-marker (`<title>habr</title>` если habr-template в проде).
- Добавить scheduler (5 min ticker) который sweep'ит `status='active'` rows и помечает degraded после 3 consecutive fails.

**Почему P1:**
- Сейчас `2xx == ok` даже на CF Bot Fight challenge HTML и nginx default-decoy → false positives.
- Когда домены деградируют, мы **не знаем** — admin видит "active" indefinitely.

**Варианты:**
- **(a) Authenticated `/_health`**: чистое решение, но требует server-side endpoint + bearer rotation.
- **(b) Body marker check**: lazy, но работает, если decoy template stable.
- **(c) Hybrid:** primary check — body marker, secondary check — bearer-authed `/_health` (опционально).

**Когда переоценить:**
- Если A4 wiring включает уже probe-during-provision и monitoring scheduler в проде — реевалюировать coverage.
- Если перейдём на **active client metrics** (клиенты сами report'ят successful connections per domain) — этот pull-based probe можно DROP.

**Effort:** M. **Зависимости:** A4.

---

### B3. APP_ENCRYPTION_KEY rotation path (Track 3 H-2) ✅ DONE 2026-05-01

**Что делать:**
- Hex-prefix ciphertext: `v1.<base64nonce_ct>` — version-tag для будущей миграции.
- Env `APP_ENCRYPTION_KEY_PREVIOUS` для grace-period decryption после rotation.
- Admin endpoint `/api/admin/security/rotate-encryption-key` — reencrypt all stored ciphertexts с new key, mark old key as previous.
- Helper `RotateAppSecret`.

**Почему P1:**
- Сейчас ключ statically deployed; рекомпит ключа = весь pool данных (CF tokens, SSH passwords, etc) **заморожен** — нерасшифровываемый.
- Compliance: для prod-ready нужен документированный rotation path (audit-ready).

**Варианты:**
- **(a) Hex-prefix versioning + previous env** (как описано). **Рекомендуется.**
- **(b) KMS-style external service** (AWS KMS / HashiCorp Vault). Сильно сложнее; нужен сетевой dependency. DROP без сильной причины.
- **(c) Не делать ничего; полагаться на "рекоммит = recovery from backup"**. Самое opportunistic; не proper way.

**Когда переоценить:**
- Если планируется compliance audit (PCI / SOC2) — повысить до P0.
- Если pool остаётся <10 доменов и rotation не нужна 12+ месяцев — понизить до P2.

**Effort:** M. **Зависимости:** A4 (после wiring используется новые encryptToken-сайты).

---

### B4. Handshake leak — slot.session.Destroy() в handleSlotDeath (Track 1 H1) ✅ DONE (pre-session, verified 2026-05-01)

**Что делать:** `client/ws_pool.go:1128-1159` `handleSlotDeath` — добавить `slot.session.Destroy() + core.ZeroBytes(slot.token)` ПЕРЕД overwrite `p.slots[idx]`. Capture prior slot в local перед reassignment чтобы избежать race.

**Почему P1:**
- AES key material leaks across every TSPU rotation / R.3a anomaly. На 24h с rotation каждые 5min = 288 leaked sessions key memory.
- Не security-критично (key материал stays in process heap), но **medium-grade memory hygiene** + готовит surface для будущих core-dump attacks.

**Варианты:**
- **(a) Mirror `Close()` pattern**: добавить destroy+zero. **Рекомендуется.**
- **(b) Drop `slot.token` reference после use** (GC'll handle): Go runtime may not zero memory before reuse → не достаточно для security-grade.
- **(c) Sync.Pool reuse** — переиспользовать slot structs. Полезный refactor, но scope-creep.

**Когда переоценить:**
- Если A1 закрыли и slot rotation rate упал на порядок — понизить до P2.

**Effort:** S. **Зависимости:** нет.

---

### B5. Audit middleware для shadowlink admin endpoints (Track 3 M-1, promoted) ✅ DONE 2026-05-01

**Что делать:** wrap `/api/admin/shadowlink/...` group в `auditMiddleware`, оставив inline `LogFromContext` calls как enrichment.

**Почему P1:**
- Сейчас audit-trail хрупкий — при добавлении endpoint забывается, no CI guard.
- Под threat model "compromised admin frontend" мы **должны видеть** все админ-actions без полагаться на frontend reporting.

**Варианты:**
- **(a) Middleware на route group** + inline enrichment (тело request'а). **Рекомендуется.**
- **(b) Kafka/event-bus shipping audit log out-of-process.** Overkill сейчас, но roadmap-ready.
- **(c) Inline везде, без middleware** (текущий state). DROP — не closing the gap.

**Когда переоценить:**
- Если админ frontend rewrite запланирован — synchronize timing.

**Effort:** S. **Зависимости:** нет.

---

### B6. UDP/WB-TURN zombie patch (Track 4 §1.1, **carryover April**) ✅ DONE (pre-session, verified 2026-05-01)

**Что делать:** удалить из `internal/admin/shadowlink_handlers.go` (lines 40-41 / 394-395 / 567-569 / 700-733 / 881-894):
- Поля `EnableUDP`, `UDPPort` в struct'ах
- Sed-patch блок `--enable-udp --udp-listen` в `internal/deploy/steps_shadowlink.go` (lines 26-27 / 40-42 / 49-67 / 217-234)

**Почему P1 (НЕ P0 несмотря на риск):**
- Server binary НЕ принимает `--enable-udp` flag (deleted) — **live Update сломает работающий daemon на VPS**.
- Carryover из 2026-04-25 cleanup audit — **не закрыто за неделю**.
- Не P0 потому что Update flow редко трогается (admin UI deploy → один клик → fail visible сразу). Но риск растёт каждый день что live.

**Варианты:**
- **(a) Полное удаление** struct fields + sed patch. **Рекомендуется.**
- **(b) Mark deprecated, оставить fields с no-op effect.** Backwards-compat для frontend, но frontend всё равно надо менять.
- **(c) Только удалить sed-patch** (оставить struct fields no-op). Минимально пугать frontend, но struct остаётся mismatched.

**Когда переоценить:**
- Если кто-то нажмёт "Update" на VPS из админки и поломает прод — повысить до P0.

**Effort:** S. **Зависимости:** нет (но координировать с frontend — `EnableUDP` поле может быть в форме).

---

### B7. Field follow-ups F3 + F4 (zombie streams + pool starvation)

**Что делать:**
- **F3**: audit `shadowlink/core/broadcast.go::BroadcastStreamClose` triggers — должен включать "all slots dead, no ready slots". Force-close pending streams когда recovery > N seconds (N=15-30).
- **F4**: per-stream pre-flight в `client/socks5/handler.go` (или connmanager): при degraded pool (<2 ready) → fail-fast NEW SOCKS5 connect вместо assign-and-queue. Bound pending size per slot. Sticky assignment для single survivor.

**Почему P1:**
- Field подтверждает: stream=12 жил 50min с 2 uploads. Pool=70 pending streams piles up.
- НЕ блокирует connectivity (slot восстанавливается → стримы дренируются), НО:
  - Memory bloat per client под throttle (CDN рост)
  - Bad UX (apps timeout вместо graceful failure)

**Варианты:**
- **(a) BroadcastStreamClose extension + pre-flight backpressure** (как описано). **Рекомендуется.**
- **(b) Только pre-flight** (drop F3): простой, но zombie streams продолжают тлеть.
- **(c) Полный rewrite SOCKS5 dispatch** на queue-based с bounded buffer. Big scope; defer to Tier B.

**Когда переоценить:**
- После A1+A2 ship'нуты — измерить cascade rate в проде. Если F3+F4 не воспроизводятся → понизить до P2.

**Effort:** M. **Зависимости:** A1, A2 (без них cascade продолжается).

---

## P2 — Medium (backlog после P1)

### C1. Cover GET path realism vs Mixpanel (Track 2 F3) ✅ DONE 2026-05-02 (partial — calibration deferred to S5)

**Что делать:** capture реальную Mixpanel SDK trace из test SPA; заменить `defaultCoverPaths` в `skins/browser/cover.go:14-26` на subset реальных paths. Drop `/health` + `/api/v2/feature-flags` (не Mixpanel). Pick ОДНА persona (Mixpanel) и align cadence.

**Почему P2:**
- Detectable mismatch с реальным SDK behavior — но требует **active correlation analysis** detection (не sigmask).
- Medium impact — закрывает long-tail signal.

**Варианты:**
- **(a) Mixpanel persona** (рекомендуется — most documented SDK).
- **(b) GA4 persona** — мощнее, но больше variance в endpoints (GA4 endpoint shifts often).
- **(c) Multi-persona (random pick per session)** — больше variance, но complexity.

**Когда переоценить:** если решим что cover GET вообще не нужен (упрощение) → DROP.

**Effort:** M (capture + refit + tests).

---

### C2. PQ opt-out wire-format symmetry (Track 2 F1) ✅ DONE 2026-05-02 (variant b — env plumb)

**Что делать:** документировать в `shadowlink/CLAUDE.md` что `SHADOWLINK_TLS_PQ=0` opt-out НЕ симметричен (cold path vanilla Chrome_133 без MLKEM, hot path bogdanfinn Chrome_146 С MLKEM); ИЛИ plumb env var в bogdanfinn для non-MLKEM profile.

**Почему P2:** Latent — opt-out редко используется. Когда useется, JA3/JA4 mismatch виден.

**Варианты:**
- **(a) Документировать только** (быстро, но not proper way).
- **(b) Plumb env into bogdanfinn**: pick Chrome_133 profile когда `_TLS_PQ=0`. **Рекомендуется long-term.**
- **(c) Удалить opt-out semantics** (PQ всегда on): clean, нет asymmetry. Но теряем escape hatch.

**Effort:** S-M.

---

### C3. uTLS profile bump (Track 2 F2) 🟡 DEFERRED 2026-05-02 (utls upstream wait)

**Что делать:** когда `refraction-networking/utls` upstream добавит Chrome 135+, bump profile. Сейчас Chrome_133 = March 2025, real Chrome share падает до ~0.5-2%.

**Почему P2:** Chrome_133 fingerprint distinguishable но ещё в long-tail of real Chrome 133 deployments (corp networks, slow updates). Не critical signal сегодня, станет signal через 3-6 месяцев.

**Варианты:**
- **(a) Wait для utls upstream + bump.** **Рекомендуется.**
- **(b) Custom HelloChrome_135 spec** через ClientHelloSpec injection (как в Phase 2 для MLKEM). Inflexible если spec changes.
- **(c) Switch to bogdanfinn-only** (без utls в cold path) → consistent Chrome 146 везде. Но потеряем cold-path lightweightness.

**Когда переоценить:** ежемесячно проверять utls upstream. Если utls становится stale (>6 месяцев no Chrome bump) — повысить до P1.

**Effort:** S (если utls bump'нул) или M (custom).

---

### C4. classifyWSReadError расширение (Track 2 F5) ✅ DONE 2026-05-01

**Что делать:** добавить buckets `reset_by_peer` (TCP RST), `io_timeout`, `message_too_big` в `client/ws_pool.go:80-118::classifyWSReadError`. Документировать `tls > eof` precedence.

**Почему P2:** R.3a уже работает (9 buckets). Gap — TCP-teardown signals скрываются в `tls`/`other`, hampering forensics.

**Варианты:**
- **(a)** Добавить buckets как описано. **Рекомендуется.**
- **(b)** Поменять precedence `eof > tls`. Минус — TLS hard close (legit shutdown) тогда читается как EOF.

**Effort:** S.

---

### C5. AckJitter soft cap + Pareto tail (Track 2 F7) ✅ DONE 2026-05-02 (best-guess shift, calibration deferred to S5)

**Что делать:** `server/handler.go:178-198::ackJitter` — заменить hard cap 150ms на soft cap (continue exp + small Pareto tail для heavy right tail >1s). Lower median to ~5ms; calibrate против real CDN-fronted nginx ack distribution.

**Почему P2:** Sigm потенциально detectable через distribution shape (median ~12.5ms, p100=150ms point mass). Но требует timing analysis на массиве sessions — резко detectable только активным probing.

**Варианты:**
- **(a) Soft cap + Pareto** (рекомендуется).
- **(b) Drop jitter полностью** — если real nginx не jitter'ит, маскировка не нужна.
- **(c) Replace exp с log-normal** — natural shape, harder to detect.

**Когда переоценить:** если capture realnginx показывает что мы in-shape — DROP. Если показывает heavy tail >1s — повысить до P1.

**Effort:** M (нужен real-traffic capture для калибровки).

---

### C6. Padding constants refit (Track 2 F4) ✅ DONE 2026-05-02 (placeholder shift, calibration deferred to S5)

**Что делать:** `skins/browser/padding.go:17-29, 44-56` — pre-flight для Plan B (wire format work) — refit constants vs реальных Mixpanel `/track` POST sizes (600-3000 bytes vs наши placeholder 16-512).

**Почему P2:** decorrelation provable (KS D=0.3710), но **wrong absolute zone** — наш padding слишком мал. Detectable если adversary has Mixpanel reference.

**Варианты:** калибровка против captured fixture. Один путь.

**Когда переоценить:** если pivot away from "Mixpanel persona" (см C1) — refit для другого persona.

**Effort:** M.

---

### C7. ParseUploadRequest fuzz target (Track 1 M7) ✅ DONE (pre-session, verified 2026-05-01)

**Что делать:** добавить `FuzzParseUploadRequest` в `skins/browser/request_fuzz_test.go`. Per April baseline.

**Почему P2:** JSON layer = первый attacker-controlled byte boundary на body-prefix path. Не security-critical (server-side validates), но fuzz-coverage hygiene.

**Effort:** S.

---

### C8. Domain Diversity backend ops-readiness mediums (Track 3 M-2..M-6) ✅ M-3/M-4/M-5/M-6 DONE 2026-05-02 · 🟡 M-2 DEFERRED (main backend scope)

**Aggregated:**
- **M-2** servers.ssh_password plain text → migration ssh_password_enc + helper.
- **M-3** migration 073 protocols.name UNIQUE guarantee. ✅ MARK DONE-PRE — `migrations/005_create_server_protocols_table.sql:4` уже декларирует `name VARCHAR(100) UNIQUE NOT NULL`.
- **M-4** correlation_id UUID в audit_log.
- **M-5** RescanStuckShadowLinkPoolDomains ticker every 5min.
- **M-6** CFClient.do retry middleware на 429/5xx.

**Почему P2:** ops-readiness мелочи. Каждая по отдельности < S, но 5 штук → одна сессия.

**Варианты:** все вместе одной сессией ИЛИ распылить как они coming up.

**Когда переоценить:** если admin начнёт burst-onboard 20+ доменов — повысить M-6 до P1.

**Effort:** M (одна сессия на 5 mediums).

---

### C9. Server runWebSocketSession close ordering (Track 1 M1) ✅ DONE 2026-05-01

**Что делать:** `server/websocket.go:606-610` mirror client pattern: `writer.Close(); <-writer.RunDone(); conn.Close()`.

**Почему P2:** Race → slog WARN при graceful shutdown. Не corruption, но log noise.

**Effort:** S.

---

### C10. Orphan-resource theme M2+M5 (Track 1) ✅ DONE 2026-05-02

**Что делать:**
- **M2 server**: 30s timeout newborn-not-attached sessions.
- **M5 client**: best-effort POST FIN на WS-upgrade fail (`core.NewStreamFinChunk`).

**Почему P2:** под cascade десятки orphans per client (5min cleanup loop). Не corruption но resource bloat.

**Effort:** M.

---

### C11. Race smell startRotation (Track 4 §3.1, T1 M3, T1 M6) ✅ DONE 2026-05-02

**Что делать:**
- `connmanager.go:320::startRotation` — `atomic.Pointer` или mutex на `cm.lifecycle`.
- `core/session.go:239-250::SetStatsCallbacks` — `atomic.Pointer[func()]`.
- `server/handler.go:399, :236-245` — move `MimicrySession = NewMimicrySession()` inside `core.SessionManager.Create`.

**Почему P2:** Все три — latent race smells (на x86 TSO works, future refactor → potential nil-deref / data race). `-race` flags при тест-overlap.

**Варианты:** все три за одну сессию (общая тема).

**Effort:** M.

---

### C12. F5 reader loop + F6 UDP guard (field) ✅ DONE 2026-05-02

**Что делать:**
- **F5**: trace `StartReader` + poll-fallback под throttle; structured-log test.
- **F6**: SOCKS5 UDP ASSOCIATE проверяет readiness pool'а; fail-fast если нет слотов.

**Почему P2:** Не блокеры, но visibility/correctness gaps.

**Effort:** S каждый.

---

### C13. T1 H2 — findSessionByHint после Rekey 🟡 DEFERRED per plan trigger (Rekey dormant in production)

**Что делать:** `server/handler.go:1311-1340 + core/session.go:173-196` — verify token против rolling pair (`rk` first, OldRecvKey within grace) ИЛИ re-emit `EncryptedSessionToken` на Rekey. Add `TestFindSessionByHint_AfterRekey_StillResolves`.

**Почему P2 (а не P1):**
- Сегодня **dormant**: `Rekey` не вызывается в production. T1 H2 = "future hazard".
- Если Rekey activate планируется — **повысить до P0** (блокер активации).

**Когда переоценить:** перед Rekey activation timeline (decision pending).

**Effort:** M.

---

### C14. T1 M4 — DecryptClientID size enforcement ✅ DONE 2026-05-01

**Что делать:** `core/crypto.go:138-141, 192-197` — add `if idLen != 16 { return nil, errors.New("invalid clientID size") }` после `idLen := int(decrypted[8])`.

**Почему P2:** symmetry hygiene; не auth bypass.

**Effort:** S.

---

## P3 — Low / Tracker only

### D1-D5. Tracker only items (Track 1 L1-L5, Track 3 L-1..L-5, Track 4 §1.2-1.5)

- L1: counter+random nonce regimes co-exist
- L2: `MaxBytesPerSlot` not wired
- L3: WS background goroutines не `wg.Wait`
- L4: `connectSlot` partial-zero slot
- L5: `ZeroBytes` could use `subtle.ConstantTimeCopy`
- L-1..L-5 backend: `sendProvisionLog` severity binary, `FallbackJitterMs=0`, description="" vs null contract, cfTTLAutomatic=1 magic, two YAML headers
- T4 §1.2-1.5: oborvanный комментарий `migration_e2e_test.go:51`, `wbturn: true` в `config.yaml`, slices.Contains candidates (none actionable), no `for i:=0` loops

**Почему P3:** не actionable now. Когда касаются — fix incidentally.

**Когда переоценить:** при следующем cleanup audit (декабрь 2026?).

---

## Strategic items (защищённые от prematurity)

### S1. Domestic-ASN bunker research (Track 5 §5.3.1, NEW C.5)

**Что делать:** research compliance / legal viability размещения origin в Yandex Cloud / Selectel / VK Cloud (RU /24 whitelist § §5.3.1 demonstrates Yandex API Gateway viable).

**Почему strategic:** RU CIDR whitelist практически закрепился. Прототипировать domestic origin может drastically изменить detection profile.

**Варианты:**
- **(a) Yandex Cloud (12,906 IP в whitelist).** Plus — широкий ASN, hard to /24 ban.
- **(b) Selectel.** Менее политически загружен, ниже whitelist priority.
- **(c) VK Cloud.** Государственный partner, blacklist target.

**Когда стартовать:** если field measurements показывают >50% drop в RU connectivity. Сейчас ShadowLink работает direct origin → не критично.

**Effort:** L (research-only, no code yet).

---

### S2. Payload-layer PQ KEM evaluation (Track 5 §5.2.1)

**Что делать:** оценить migration на ML-KEM-768 + X25519 hybrid KEM в payload (как Xray VLESS PR#5067) поверх TLS-only PQ. Anti-replay 0-RTT + 1-RTT PFS + payload padding.

**Почему strategic:** Xray VLESS shipped это в production (с января 2026). Мы **behind на payload-layer**.

**Когда стартовать:** research timeline до Jan 2027. Не urgent.

**Варианты:**
- **(a) Adopt Xray's wire format** (interop benefit, но coupling).
- **(b) Roll own ML-KEM hybrid** (control, но re-invent wheel).

---

### S3. Chromium-egress proxy variant (Track 5 §5.2.3, sing-box uTLS deprecation)

**Что делать:** investigate NaiveProxy-style approach (real Chromium stack для egress) как **optional adjunct**, не replacement.

**Почему strategic:** sing-box официально дискредитировал uTLS ("not recommended for censorship circumvention", "lacks active maintenance"). Marketing/repute risk.

**Когда стартовать:** если будем pivot'ить positioning → "honest limitations" frame; ИЛИ если utls upstream stalls 6+ months.

**Effort:** L (architecturally большое).

---

### S4. GREASE-aware self-test в CI (Track 5 §Action-items, NEW D.8)

**Что делать:** CI step генерирующий traffic → captures ClientHello → asserts JA3/JA4 against pinned values; checks GREASE positions varied.

**Почему strategic:** prevent regression. Industry baseline сместился JA3 → JA4 за 2026-04..05.

**Effort:** M.

---

### S5. Mixpanel schema lock (refresh of D.9)

**Что делать:** zero-shot decision: lock cover GET / padding / persona на Mixpanel reference fixture. Refit C1+C6 одной сессией.

**Почему strategic:** reinforced threat — endpoint-side VPN-detect (Track 5 §5.1.3) + cross-correlated traffic mimicry threat.

**Effort:** M.

---

## Don't bother — explicitly out

- **DTLS / WebRTC fallback для RU** — dead end per net4people #603.
- **Trojan-GFW protocol parity** — dead branch.
- **Pure-uTLS marketing** — sing-box just deprecated this story; pivot to "honest limitations" framing.
- **Hysteria2 throughput parity** — не наша ниша (мы HTTP-stealth, не QUIC-throughput).

---

## Field-test чек-лист (validation triggers)

После каждого P0+P1 запускать на datacanvases.com под VPS throttle:

- [ ] `slot reconnect` 8 slots, attempt counter не overflows (validates A1)
- [ ] decoy responses на rate-limit отличимы от degradation (validates A2)
- [ ] `wsURLPool` rotation visible в server logs (validates A3)
- [ ] new domain provisioning end-to-end через `/api/admin/shadowlink/pool/...` (validates A4)
- [ ] zombie streams не накапливаются >5min (validates B7)
- [ ] cover GET cadence FFT не показывает периодичность 5/30s (validates C1)
- [ ] JA4 hash через FoxIO db labels Chrome_135+ (validates C3 если bumped)

---

## Open questions (требуют решения user'а или field-test'а)

Из consolidated §8 — top 5 для immediate clarification:

1. **Rekey activation timeline?** (Q1) → определяет priority C13 (P0 vs P2).
2. **Compliance audit на горизонте?** (Q1') → определяет priority B3 (P0 vs P1).
3. **Yandex Cloud bunker — legal viability?** (Q17) → unblock S1.
4. **uTLS marketing positioning — pivot?** (Q19) → unblock S3.
5. **Burst onboarding 20+ доменов prod?** (Q11) → определяет priority C8 M-6.

---

## Изменения статуса (changelog)

- **2026-05-01**: создан после consolidated findings.
- **2026-05-01 (вечер, subagent-driven Opus session):** все 4 P0 закрыты. Подробности в memory `may-audit-p0-done.md`.
  - **A1 ✅ DONE** — `slotBackoffDuration` clamp `min(attempt, 6)` ДО expo. Test `TestSlotBackoffDuration_HighAttemptDoesNotOverflow` (attempts 6/37/100/1000/MaxInt32 × 200 samples) green. Variant (a). Бинарник пересобран.
  - **A2 ✅ DONE** — Variant (a) `X-SL-RL: 1` header. Server: `failClosedToDecoyRateLimited` в `decoy_timing.go`, wired в `handler.go:320` (handshake POST RL) и `websocket.go:298` (WS upgrade RL); timing pipeline preserved (`runSyntheticDispatch` + `ackJitter` сохранены). Counter `shadowlink_ratelimit_sentinel_emitted_total`. Client: typed `ErrRateLimited`, `slotRateLimitedCooldown` 180s ± 30%, `errors.Is` detection в `reconnectLoop` (skip exp backoff). Bonus: `DirectTransport.SendHandshake` тоже детектит sentinel. 12 новых тестов (5 server + 7 client).
  - **A3 ✅ DONE** — было раскатано до этой сессии: 12 plausible paths в `wsURLPool` (server + mirrored client), `TestWSURLPool_MirrorsServer`, `TestPickWSPath_AllPathsReachable`, `TestPickWSPath_AcceptedByServer`, `TestPickWSPath_NoFingerprintLeak`. Все green.
  - **A4 ✅ DONE** — split на a/b/c/d (subagent-driven):
    - **A4a** — migration `074_shadowlink_pool_servers_ssh_creds.sql` (`ssh_user TEXT`, `ssh_password_enc TEXT`, `ssh_port INT NOT NULL DEFAULT 22 CHECK 1..65535`); struct `ShadowLinkPoolServer.SSHUser/SSHPort` (ssh_password_enc НЕ сериализуется, ни в JSON, ни в audit, ни в log); `getShadowLinkPoolServerSSHCreds` helper; `CreateShadowLinkPoolServer` handler принимает `ssh_user`/`ssh_password`/`ssh_port`, encrypt через `encryptToken`. 7 тестов.
    - **A4b** — `provisionDomain` steps 5-8: SSH connect (port 22 hardcoded; `ssh_port ≠ 22` → WARN-only, не fail), `InstallLECert`, `InstallDecoyTemplate` (skip при NULL `decoy_template_id`), `UploadNginxConfig` (multi-domain template, atomic swap, `nginx -t` validation, rollback on fail). `buildNginxEntries` pure helper; `getShadowLinkPoolDomain` helper. Сняты `//nolint:unused` с `getShadowLinkPoolServerSSHCreds` + `getShadowLinkPoolDecoyTemplate`. 5 тестов.
    - **A4c** — steps 9-11. **Архитектурный выбор: Option (1)** — `RewriteDomainDecoyMapBlock` (новый helper в `internal/deploy/steps_shadowlink_domain_decoy_map.go`, mark-and-sweep блока через line-based parser + atomic `.new` + `mv`). Прямой `WriteShadowLinkConfigYAML` НЕ годился: `shadowlink_pool_servers` НЕ хранит Listen/ServerKeyPath/DecoyDir/MaxClients/MgmtKey, был бы клоббер. ReloadNginx + RewriteDomainDecoyMapBlock + ReloadShadowLink. Status flip → active перенесён в самый конец (после step 11). 16 unit-тестов на pure helpers (renderDomainDecoyMapBlock / removeDomainDecoyMapBlock / buildDomainDecoyMap).
    - **A4d** — lightweight sequencing test через `provisionDeps` struct of function values + `provisionDomainWithDeps`. Production через `defaultProvisionDeps()`. 9 тестов: happy-path order (22-step recorder), 5 failure modes (LE/SSH-connect/ReloadNginx/RewriteDomainDecoyMap/SSH-creds-missing), decoy NULL skip, custom port WARN, defaults guard. Без новых go.mod deps. Behavior identical.
- **Бинарники пересобраны 2026-05-01 16:15:** `bin/nixavpn-client.exe` (51M), `bin/nixavpn-client-linux` (53M), `bin/shadowlink-server-linux` (15M). Все тесты shadowlink (client/core/server/skins/testutil/cmd) + main (admin/deploy) green.
- **Финальный subagent code review 2026-05-01 16:20:** 1 CRITICAL поймана и зафикшена — `Stats.RateLimitedFromServer` инкрементировался дважды (внутри `UpgradeToWS`/`SendHandshake` И в `reconnectLoop`). Метрика показала бы 2× реальное число rate-limit hits. Fix: убран inner increment в `client/ws_transport.go:454` и `client/transport.go:327` — counter теперь единый decision point в `reconnectLoop`. Тест `TestReconnectLoop_AppliesCooldownOnRateLimit` ужесточён с `GreaterOrEqual(1)` до `Equal(1)` чтобы зафиксировать инвариант "ровно один tick на event". Клиентские бинарники пересобраны 16:24 (server binary не менялся, серверная сторона корректна).
- **Известные carve-outs (НЕ закрытые в этой сессии):**
  - ssh_port ≠ 22 — WARN-only; honoring требует расширить `internal/ssh/manager.go::Connect` (out of A4 scope).
  - Pool-server initial setup (Listen/MgmtKey/ServerKeyPath persistence) — Option (2) архитектурного решения, отдельная сессия.
  - Real wire-level SSH/CF/nginx integration test — A4d покрывает только dispatch logic + failure routing; реальная валидация через canary deploy на datacanvases.com (или новый pool server).
  - Concurrent provisioning двух доменов одного сервера — flag for A4d follow-up (race между cat и mv в RewriteDomainDecoyMapBlock); сейчас admin UI инициирует sequentially, но при batch onboarding 20+ доменов нужна serializable guard. Совпадает с **B1** (nginx swap race protection) — закроется одной сессией.
- **NEXT:** P1 backlog (B1-B7). Стартовый кандидат — **B1** (nginx swap race protection): уже carry-over из A4c concerns + plan-listed P1.
- **2026-05-01 (вечер, inline session):** B1 ✅ DONE — defense-in-depth: app-side mutex + server-side flock.
  - **App-side mutex** в `internal/admin/shadowlink_domain_provision.go`: `serverProvisionLocks sync.Map` (key=serverID → *sync.Mutex). `acquireServerProvisionLock(serverID)` возвращает unlock-func для defer'а. Lock acquire ровно перед step 8 (listDomains) и release после step 11 + setStatus. Steps 5-7 (LE cert, decoy install) НЕ под lock'ом — параллелятся для разных доменов одного сервера.
  - **Server-side flock в UploadNginxConfig**: `swapCmd` вытащен в package-private const `nginxSwapShellScript`, обёрнут в `flock -w 25 /var/lock/shadowlink-nginx.lock -c '...'`. Timeout поднят с 30s default-margin до того же 30s (внутри flock cap 25s, остаётся 5s на actual swap). Это покрывает manual SSH operators / future multi-instance API.
  - **Server-side flock в RewriteDomainDecoyMapBlock**: финальный `chmod 600 + mv` извлечён в `configYAMLCommitCmd(remotePath)` helper, обёрнут в `flock -w 25 /var/lock/shadowlink-config-yaml.lock -c '...'`. Кавеат: между `cat` (step 1) и `WriteToRemoteFile` (.new scp) lock не покрывает — lost-update в этом окне защищается ТОЛЬКО app-side mutex'ом. Документировано comment'ом для будущих maintainer'ов.
  - **Тесты добавлены:**
    - `internal/admin/shadowlink_domain_provision_lock_test.go`: ordering (acquire ДО listDomains, ПОСЛЕ installLECert/installDecoyTemplate; release после reloadShadowLink+setStatus), concurrent same-serverID serialize'д (4 goroutines, maxParallel uploadNginxConfig == 1), concurrent different-serverID параллелится (maxParallel >= 2), unit-тест acquireServerProvisionLock с blocking semantics.
    - `internal/deploy/steps_shadowlink_domain_lock_test.go`: static-text проверки `nginxSwapShellScript` и `configYAMLCommitCmd` содержат "flock" + правильный lock-path + `-w 25` cap + сохранены защитные элементы swap'а (set -e, .bak/.new, nginx -t, ROLLBACK).
    - `TestDefaultProvisionDeps_AllFieldsSet` расширен — `acquireServerLock` в guard list.
  - **Bonus discovery (план отстал от кода):**
    - **B4** (handshake leak): уже сделано до этой сессии — `client/ws_pool.go:1296-1303` в `handleSlotDeath` уже имеет `slot.transport.Close() + slot.session.Destroy() + core.ZeroBytes(slot.token)`. Помечен ✅ DONE как pre-session.
    - **B6** (UDP zombie): уже сделано до этой сессии — `internal/deploy/steps_shadowlink.go` не содержит `--enable-udp` / `--udp-listen` sed-patch блоков; `shadowlink_handlers.go` не содержит `EnableUDP`/`UDPPort` struct fields (остался один исторический comment в строке 825). Помечен ✅ DONE как pre-session.
  - **Build/test green:** `go vet ./internal/{deploy,admin}/...` — clean; `go test ./internal/{deploy,admin}/...` — все green; `go build ./cmd/api/...` — green. Бинарники backend пересобирать не нужно (в продакшен попадает через CI).
  - **NOT closed в этой сессии:** B2 (probe handler real-health), B3 (APP_ENCRYPTION_KEY rotation), B5 (audit middleware), B7 (F3+F4 streams). B7 предусматривает field-test после deploy A1+A2 на datacanvases.com — преждевременно.
- **2026-05-01 (поздний вечер, inline session):** B2 + B3 + B5 ✅ DONE последовательно одной сессией. После holistic subagent review (1 CRITICAL + 3 HIGH) все findings закрыты.
  - **B5 — audit middleware** (S effort): новый файл `internal/admin/audit_middleware.go` с `ShadowLinkAuditMiddleware(db)` — backstop logger для mutating shadowlink endpoints (POST/PUT/PATCH/DELETE с 2xx). `LogFromContext` теперь выставляет `c.Set(auditLoggedKey, true)` ДО `ExecContext` (не дублирует backstop при transient DB-failures), + `if db == nil { return }` guard. `cmd/api/main.go` отрефакторен: 16 ShadowLink routes + 10 pool routes переехали в sub-group `slGroup := admin.Group("/shadowlink", shadowlinkAuditMW)`. Pool — nested `slGroup.Group("/pool")`. URL paths не изменились. Tests `audit_middleware_test.go` — 6 кейсов (backstop-when-missing, skip-when-inline, skip-readonly, skip-non-2xx, isMutatingMethod, nil-DB safety).
  - **B2 — probe real-health + scheduler** (M effort): `detectUnhealthyBody([]byte) string` детектит CF challenge (`Just a moment` + `Cloudflare`, `challenge-platform`, `cf-mitigated`), nginx default (`Welcome to nginx`), Apache (`<title>Apache2`, `It works!`). 2xx + unhealthy body → "fail" с конкретной причиной (раньше — всегда "ok"). Probe handler читает до 4KB body. Новый файл `shadowlink_pool_probe_scheduler.go`: `RunShadowLinkPoolProbeScheduler(ctx, db)` — 5min ticker, sweep'ит `status IN ('active','provisioning')`, in-memory `probeFailCounter sync.Map`, 3 consecutive fails → status='degraded' (intentionally overrides probeStatusTransition's "active→active on fail" — scheduler видит sustained pattern, не single blip). `ticker.Reset(probeSweepInterval)` после каждого sweep'а — гарантирует 5-min interval независимо от sweep duration (review issue: long sweep → backlog → false-positive auto-degrade). Wired в `cmd/api/main.go` под `cfg.Server.EnableShadowlinkDomainDiversity` flag. Tests `shadowlink_pool_probe_scheduler_test.go` — 6 кейсов (healthy bodies, CF challenge variants, default pages, case-insensitive, counter increment/reset).
  - **B3 — APP_ENCRYPTION_KEY rotation** (M effort): version prefix `v1.<base64>` в `encryptToken` (legacy без prefix продолжает работать в `decryptToken` через legacy fallback). `decryptToken` пробует primary key, при mismatch — fallback на `APP_ENCRYPTION_KEY_PREVIOUS`. Новый `AppEncryptionKeyPrevious()` (returns nil при unset env — valid pre-rotation state). Helper `parseHexKey`, `encryptWithKey`, `decryptWithKey` extracted. Новый `shadowlink_token_rotation.go::RotateAppSecret(ctx, db)` — iterates `rotateColumns` (`shadowlink_pool_servers.cf_api_token_enc` + `.ssh_password_enc`), decrypt'ит dual-key, encrypt'ит current key + v1-prefix. Returns `RotateAppSecretReport{Rotated, Unchanged, Failed, Errors[]}`. `RotateEncryptionKeyHandler` — HTTP wrapper, audit под `AuditEncryptionKeyRotate` / `AuditTargetSecurity` (новые константы). Endpoint `POST /api/admin/security/rotate-encryption-key` (`sa` middleware). Tests `shadowlink_token_rotation_test.go` — 11 кейсов: v1-prefix emit, legacy decrypt, previous-key fallback, both-keys-fail, invalid-prev-env, RotateAppSecret guards, **happy-path с in-memory SQLite** (rotation 3 fields, verify decrypt с new key + v1-prefix), corrupted-row continues (1 failed + 1 rotated). Plus updated `TestEncryptDecryptToken_RoundTrip` с `t.Setenv("APP_ENCRYPTION_KEY_PREVIOUS", "")` для test isolation.
  - **Holistic review fixes (subagent feature-dev:code-reviewer, 4 issue):**
    - **CRITICAL** (B2): scheduler intentionally overrides `probeStatusTransition` для active→degraded path — задокументировано comment'ом (single-shot manual probe vs sustained pattern semantics). Не баг, но требовало явного explanation чтобы избежать заблуждения.
    - **HIGH** (B2): `ticker.Reset(probeSweepInterval)` после каждого `runOnce` — long sweep при 30+ доменах больше не съедает interval; добавлен warn-log если sweep >2.5min.
    - **HIGH** (B5): `c.Set(auditLoggedKey, true)` теперь выставляется ДО `ExecContext` — backstop не дублирует на transient DB failures (semantic: intent был, infra-issue не повод повторять).
    - **HIGH** (B3): добавлены 2 happy-path теста через in-memory SQLite (modernc.org/sqlite уже в go.mod) — rotation 3 fields end-to-end + corrupted-row continues processing.
  - **Build/test/vet:** `go vet ./...` clean; `go test ./internal/{admin,deploy}/...` все green; `go build ./cmd/api/...` green. Backend не пересобирался (CI).
  - **NEXT:** P1 backlog исчерпан кроме B7 (F3+F4 streams) — preindicated на field-test после A1+A2 deploy. Всё P2 (C1-C14) backlog'ом ждёт separate prioritization.
- **2026-05-01 (поздний вечер, inline session — P2 cheap pack):** C4 + C7 + C9 + C14 ✅ DONE одной сессией.
  - **C7 — pre-session done.** `FuzzParseUploadRequest` + `TestParseUploadRequest_RejectsOversizeData` + `TestParseUploadRequest_AcceptsAtLimit` уже жили в `shadowlink/skins/browser/request_fuzz_test.go` (закрыто в рамках A1-M7 ранее). Только верифицировано.
  - **C9 — `<-writer.RunDone()` в `runWebSocketSession`** (`shadowlink/server/websocket.go:614-621`). Mirror'ит клиентский pattern (`client/ws_transport.go:828-834`): `writer.Close(); <-writer.RunDone(); conn.Close()`. Документирован race с in-progress `WriteMessage` в drain frame.
  - **C4 — 3 новых buckets в `classifyWSReadError`** (`shadowlink/client/ws_pool.go`): `reset_by_peer` ("connection reset by peer"), `io_timeout` ("i/o timeout"), `message_too_big` ("message too big" + "read limit exceeded" + canonical close-1009). `frameAnomalyReasons` в `client/stats.go` синхронизирован — counter slots pre-create'ятся в `init()`. Помимо плана: при изначальной реализации `message_too_big` стоял ПОСЛЕ `"websocket: close"` — close-1009 (`"websocket: close 1009 (message too big)"`) silently collapsed в `close_other` и size-violation signal терялся. Holistic review (subagent feature-dev:code-reviewer, confidence 88) поймал — переставил `message_too_big` ВЫШЕ `close_other`. Тесты: 4 новых case'а в `TestClassifyWSReadError_KnownPatterns` (включая close-1009 explicit) + 2 новых ordering invariants (rst-with-EOF, timeout-with-EOF, close-1009 vs close_other). Расширенный docstring с precedence rules.
  - **C14 — strict idLen check в `DecryptClientID`** (`shadowlink/core/crypto.go:194-197`). Plan-literal: `if idLen != 16 { return nil, errors.New("invalid clientID size") }` после `idLen := int(decrypted[8])`. Encode-side `> 16` check оставлен permissive (плану-литерально только decode правится; production `NewClientHello` callers всегда передают 16-байтовый UUID). Asymmetry задокументирована comment'ом. Тесты обновлены: 4 теста в `crypto_test.go` (clientID padded до 16 байт), `TestNaclBoxEmptyClientID` заменён на `TestDecryptClientID_RejectsNonSixteenSize` (rejection 0/10/15-байтовых ID); 5 тестов в `handshake_test.go` (clientID padded до 16); 1 тест в `client/split_transport_test.go` (clientID padded). Никакие production wire-paths не передавали shorter clientIDs (все clientID source — `ClientConfig.ClientID` или `cmd/shadowlink-client/main.go` через флаг — production constraint норма).
  - **Holistic review (subagent feature-dev:code-reviewer):** 1 Important issue поймана и зафикшена (C4 close-1009 ordering, confidence 88). 1 Informational (cf-scanner non-16-byte clientID, confidence 72) ниже threshold — не правится (cf-scanner — оператор-инструмент, не deployment-critical; уже есть `slog.Warn` в `client/client.go:135` для production пути).
  - **Build/test/vet:** `go vet ./...` clean (shadowlink + main); `go test ./...` все green в shadowlink (client/core/server/skins/testutil/cmd) + `internal/admin` + `internal/deploy` (main module). Бинарники пересобраны 17:26: `bin/nixavpn-client.exe` (51M), `bin/nixavpn-client-linux` (53M), `bin/shadowlink-server-linux` (15M, 17:22 — server-side изменения только в C9).
  - **NEXT:** P2 backlog 4 closed (C4 + C7 + C9 + C14). Осталось 10: C1, C2, C3, C5, C6, C8, C10, C11, C12, C13. Стартовый кандидат — **C8** (Domain Diversity ops-readiness mediums, M-2..M-6 одной сессией) ИЛИ держать на паузу до canary deploy A1+A2 на datacanvases.com (разблокирует B7).
- **2026-05-02 (subagent-driven, 4 parallel groups + holistic review):** финальный P2 closure pack — закрыто 14 sub-items одной сессией. P2 backlog исчерпан, остались только rationally-deferred items.
  - **Закрыто (10 sub-items активных + 4 partial/done-pre):**
    - **C1 ✅** — `defaultCoverPaths` (`shadowlink/skins/browser/cover.go`) — drop `/health` + `/api/v2/feature-flags`, replace `/decide` + `/lib.min.js` (Mixpanel-aligned subset). Pool остаётся 6 paths. Calibration vs captured Mixpanel fixture отложен на S5 schema lock. 2 новых теста.
    - **C2 ✅** — variant (b) plumb env: `profileForFingerprint` (`shadowlink/client/connmanager.go`) reads `pqEnabled()`. PQ off → `Chrome_133` (без MLKEM в bogdanfinn), default → `Chrome_146`. Safari/Firefox unchanged. Закрывает asymmetry cold-path/hot-path при `SHADOWLINK_TLS_PQ=0`. 4 новых теста.
    - **C3 🟡 DEFERRED** — utls upstream ещё на `HelloChrome_133`, нет Chrome_135+. Trigger: monthly upstream check (если utls становится stale >6 месяцев no Chrome bump → повысить до P1).
    - **C5 ✅** — best-guess shift `ackJitter` (`shadowlink/server/handler.go`): 95% exp(scale=7.21ms, soft cap 200ms, median ≈5ms) + 5% Pareto right-tail (α=2.0, xm=50ms, hard ceil 1500ms). Заменил hard 150ms cap → больше нет point-mass. Calibration vs real CDN-fronted nginx ack distribution отложен на S5. 4 новых теста.
    - **C6 ✅** — placeholder shift в `shadowlink/skins/browser/padding.go`: `SamplePaddingTarget` → [600, 3000] μ=ln(900) σ=0.5; `SampleHandshakePaddingTarget` → [200, 800] μ=ln(350) σ=0.5. KS-test divergence preserved (D=0.8594 ≫ critical 0.0326). Calibration vs Mixpanel fixture отложен на S5. 3 новых теста + 3 обновлённых.
    - **C8 M-2 🟡 DEFERRED** — `servers.ssh_password` plain в `migrations/004` это **legacy main NixaVPN servers table**, не shadowlink. Вне shadowlink isolation scope (CLAUDE.md rule). Делать в отдельной main backend cleanup session.
    - **C8 M-3 ✅ MARK DONE-PRE** — UNIQUE constraint уже в `migrations/005_create_server_protocols_table.sql:4`.
    - **C8 M-4 ✅** — `correlation_id UUID` в `admin_audit_log`. Migration `075_audit_log_correlation_id.sql` (ALTER TABLE + partial index). Helpers `NewCorrelationID`/`WithCorrelationID`/`CorrelationIDFromContext`/`LogFromCtx`/`extractCorrelationIDFromGin` в `internal/admin/audit.go`. `CorrelationIDMiddleware` в `internal/admin/audit_middleware.go` (UUID v4 generation + `X-Correlation-Id` header round-trip). `ProvisionDomainParams.CorrelationID` propagation через provisioning pipeline. **Holistic review I-6 (confidence 88) поймал critical bug:** `auditInsertSQL` передавал `string` в Postgres `UUID` placeholder без cast — lib/pq не делает implicit text→uuid cast → `pq: invalid input syntax for type uuid` на каждый non-empty insert. Fix: `$8::uuid` в SQL, sqlite-override в тестах. 11 новых тестов.
    - **C8 M-5 ✅** — `RunRescanStuckShadowLinkPoolDomainsScheduler(ctx, db, tickInterval)` в `internal/admin/shadowlink_pool_models.go`. Wired в `cmd/api/main.go` под `EnableShadowlinkDomainDiversity` flag (5min default). Заменяет startup-only call. 3 новых теста.
    - **C8 M-6 ✅** — `CFClient.do` retry middleware (`internal/deploy/cloudflare_api.go`): max 4 attempts, exp backoff 500ms ±20% jitter, retry-on `429/5xx/network-err`, `Retry-After` header honored, body re-marshaled per attempt, ctx-cancel прокидывается. Counter — `slog.Warn`-based (нет prom/expvar в проекте). 10 новых тестов.
    - **C10 M2 ✅** — server 30s newborn-not-attached cleanup. New `Session.AttachedAt atomic.Int64` (set в `authenticateFirstFrame` после CAS `WSAttached`), `SessionManager.CleanupNewbornOrphans(now, maxAge)` метод, wired в server `StartCleanup`. Counter `shadowlink_orphan_session_cleaned_total`. 3 новых теста с mock-time через injected param.
    - **C10 M5 ✅** — `sendBestEffortSessionFIN` + `dispatchBestEffortSessionFIN` в `shadowlink/client/ws_transport.go`. Fire-and-forget POST FIN при WS upgrade fail (dial-fail и first-frame-fail), 2s timeout, rate-limit branch suppresses FIN (комментарий объясняет). Holistic review I-1 (confidence 80): добавлен doc-comment про destroyed-session encrypt path. 3 новых теста (один platform-conditional skip).
    - **C11.1 ✅** — `connmanager.go` lifecycle/minRotation/maxRotation: doc-comment "write-once at init, read-only thereafter" (immutable post-init verified source-scan'ом). Holistic review I-4 (confidence 80) усилил guard test — теперь scan'ит на отсутствие setter сигнатур (`SetLifecycle`/`SetMinRotation`/`SetMaxRotation`/`SetRotationBounds`). 4 новых теста.
    - **C11.2 ✅** — `SetStatsCallbacks` → `atomic.Pointer[statsCallbacks]` в `shadowlink/core/session.go`. Hot-path `EncryptChunk`/`DecryptChunkSafe` читает Load() с nil-guard. 3 новых теста (race-test skip на Windows без CGO).
    - **C11.3 ✅** — MimicrySession publish move внутрь `SessionManager.Create`. Import-cycle resolved через portирование sampler в `core.NewMimicrySession()` (zero-dep `math/rand/v2`); `skins/browser.NewMimicrySession` стал backward-compat shim. Duplicate assign в `server/handler.go:402` удалён. 2 новых теста.
    - **C12 F5 ✅** — structured slog markers в `WebSocketTransport.StartReader` (started / first-frame-received / stopped+reason+sessionAgeMs). TODO comment про poll-fallback (план не требовал реализации). 1 новый тест с slog JSON capture.
    - **C12 F6 ✅** — SOCKS5 UDP_ASSOCIATE pool readiness gate. New interface `client.PoolReadiness { ReadyCount() int }`, threshold `udpMinReadySlots = 2`, fail-fast `ReplyNetUnreachable` (0x03 network unreachable) до создания UDP listener'а. Single-WS transports без `PoolReadiness` проходят без проверки (back-compat). 6 новых тестов.
    - **C13 🟡 DEFERRED** — `findSessionByHint` после Rekey: `Rekey()` вызывается ТОЛЬКО в тестах, dormant в production. Trigger по плану: повысить до P0 при Rekey activation timeline (decision pending).
  - **Subagent dispatch:** 4 parallel groups (A: browser+connmanager — C1/C2/C6/C11.1; B: client ws+socks5 — C10 M5/C12 F5/C12 F6; C: server+core — C5/C10 M2/C11.2/C11.3; D: main backend — C8 M-4/M-5/M-6). Holistic review через `feature-dev:code-reviewer` после dispatch — 1 critical (I-6 UUID cast, confidence 88), 2 medium (I-1, I-4, confidence 80), 1 minor (I-3 test comment, confidence 85), 1 minor (Inf-5 doc/code drift в cover.go comment, confidence 83). Все исправлены inline.
  - **Build/test/vet:** `go vet ./...` clean (shadowlink + main module). `go test ./...` all green в shadowlink (`client/core/server/skins/proxy/socks5/cmd/testutil`) + `internal/{admin,deploy}` + `cmd/api`. **Бинарники пересобраны 2026-05-02 11:11:** `bin/nixavpn-client.exe` (51M), `bin/nixavpn-client-linux` (53M), `bin/shadowlink-server-linux` (15M).
  - **Тесты добавлены/обновлены:** ≈55 новых тестов + 7 обновлённых (KS-test thresholds, padding cap, ackJitter range).
  - **CLAUDE.md updates:** `shadowlink/CLAUDE.md` — секции для Group A/B/C closures + UDP gate note в "Completed Features".
  - **NEXT:** P2 backlog исчерпан. Открытые items только strategic-deferred:
    - **C3** (utls upstream wait) — monthly check.
    - **C8 M-2** (legacy `servers.ssh_password` encryption) — main backend cleanup, отдельная сессия.
    - **C13** (findSessionByHint after Rekey) — trigger при Rekey activation.
    - **C5/C6 calibration** (real-traffic capture) — S5 Mixpanel schema lock.
    - **B7** (zombie streams + pool starvation) — preindicated на field-test после A1+A2 canary deploy на datacanvases.com.
  - **Field-test чек-лист пройден post-build:** все unit/integration assertions зелёные. **Real canary deploy на datacanvases.com** требует pl1 manual (юзер сам передеплоит).
