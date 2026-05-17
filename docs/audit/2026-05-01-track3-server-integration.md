# ShadowLink Track 3 — Server + Integration Audit

**Date**: 2026-05-01
**Scope**: Phase 0 cleanup verification, Domain Diversity backend (`internal/admin/shadowlink_pool*.go`, `internal/deploy/steps_shadowlink_domain.go`, `nginx_shadowlink_template.go`), AES-GCM token crypto (`shadowlink_token_crypto.go`), nginx multi-server template, migrations 071/072/073, `cmd/api/main.go` startup, Sub-phase B7 probe handler.
**Reviewer**: Track 3 (server + integration), audit-only.
**Compared baseline**: `shadowlink/docs/audit/2026-04-25-final-review-server-integration.md` (S/I-CRIT-1, S/I-HIGH-1..6 set).

## Executive Summary

Большая часть Critical/High апрельского аудита **закрыта** в текущем дереве: проверены fixes для I-HIGH-2 (`validateAPIIP`, `shadowlink_handlers.go:241-249`), I-HIGH-3 (`validateShadowLinkDomain`, `shadowlink_handlers.go:213-234`), I-HIGH-4 (per-server `applyMutex` через `lockServer`, `shadowlink_handlers.go:190-195`), I-HIGH-5 (`findShadowLinkBinary` теперь возвращает абсолютный путь, `shadowlink_handlers.go:1055-1088`), I-HIGH-6 (idempotent re-deploy через `mergeOrRegenerateKeys`, `shadowlink_handlers.go:521-558`), I-MED-6 (apply→DB транзакция, `shadowlink_handlers.go:1535-1685`), а также добавлен audit-trail (`LogFromContext` инлайн в каждом ShadowLink endpoint — см. комментарий в `cmd/api/main.go:627-642`, формально закрывает I-HIGH-1, хотя см. M-1 ниже).

Phase 0 cleanup в `internal/` чист — grep `handleLegacyPost|handleHandshake|handleDownloadStream|findSession|ExtractSessionToken` по `internal/...` не нашёл ни одной живой ссылки (только в shadowlink/ и docs).

Domain Diversity backend (Sub-phase A+B+C+D) **shipped с серьёзными gaps в operational-readiness**: encryption-at-rest без rotation, orchestrator только CF (SSH-bound шаги stub'нуты — все production-deploy ШАГИ всё ещё manual), nginx template не загружен ни в одном code path с `/etc/nginx/conf.d/shadowlink.conf` (есть только `RenderNginxConfig` + `UploadNginxConfig` без вызовов).

**Critical**: 0 (нет production-blocking багов).
**High**: 4 — orchestrator не вызывает SSH-шаги (B5/B6/B8 dead), `APP_ENCRYPTION_KEY` без rotation/versioning, probe-handler не различает CF challenge от живого decoy, nginx template `bak` swap может оставить broken `.bak` при concurrent UploadNginxConfig.
**Medium**: 6 — ssh_password в Plain DB, audit-events не имеют корреляции admin→pool→domain, миграция 073 без rollback DDL, нет unique-key constraint на `protocols.name='ShadowLink'`, `RescanStuckShadowLinkPoolDomains` ловит только `provisioning>10min`, нет наблюдения за CF rate limits.
**Low**: 5 — emoji в логах, пустая `description` template, etc.

Production-deploy с одним сервером и hand-managed multi-domain rollout — **OK**. Автоматизация Domain Diversity к выкату не готова: H-1 + H-2 блокируют real fleet onboarding.

---

## Findings

### CRITICAL

(none in this pass)

### HIGH

#### H-1 — Domain Diversity orchestrator не выполняет SSH-bound шаги; все nginx/LE/decoy-операции «deferred»

**File**: `internal/admin/shadowlink_domain_provision.go:43-146` + `internal/deploy/steps_shadowlink_domain.go:96-216`

`provisionDomain` останавливается после CF zone+DNS (`Step 4`) и пишет в логи:
```
[domain N] NOTE: SSH-bound steps (LE cert, decoy install, nginx config, reloads)
require manual operator action — see Sub-phase C/D plans
```

Однако в репо уже есть готовые helper-функции `InstallLECert`, `InstallDecoyTemplate`, `UploadNginxConfig`, `ReloadNginx`, `ReloadShadowLink` (steps_shadowlink_domain.go:96-216). Они вызываются ТОЛЬКО из тестов. В production code path они dead:

```bash
$ grep -rn "InstallLECert\|UploadNginxConfig\|ReloadShadowLink" internal/ --include='*.go' | grep -v _test.go
# (empty)
```

`getShadowLinkPoolDecoyTemplate` в `shadowlink_pool_models.go:333` помечен `//nolint:unused` с комментарием "wired in Sub-phase C/D once SSH credentials reach the pool table". MEMORY.md утверждает: «Sub-phase D ✅ DONE 2026-04-30… вся серия Domain Diversity (A+B+C+D) ЗАКРЫТА». **Несоответствие memory ↔ code**: SSH-pipeline остался `TODO`. До закрытия H-1 multi-domain pool — это admin-list-with-CF-DNS, не autodeploy.

**Impact**: Прод-onboarding нового домена требует ручного `certbot`, `rsync`, `nginx -t`, `systemctl reload` за каждый. Operator burden растёт линейно с количеством доменов. Frontend wizard (`AddDomainWizard`) запускает provisioning, видит «status=active» (CF DNS прописан), но клиенты получат 502 nginx если operator забыл вручную выполнить остальное.

**Recommendation**:
1. Добавить `ssh_user TEXT, ssh_password_encrypted TEXT, ssh_port INT` в `shadowlink_pool_servers` (миграция 074) и enc-at-rest через `encryptToken`/`decryptToken`.
2. Расширить `provisionDomain` шагами 5-9: `InstallLECert` → `InstallDecoyTemplate` (через `getShadowLinkPoolDecoyTemplate`) → перебрать активные домены сервера и вызвать `UploadNginxConfig` → `ReloadNginx` → `ReloadShadowLink`.
3. Добавить regenerate `domain_decoy_map` в `/etc/shadowlink/config.yaml` через `WriteShadowLinkConfigYAML` (params.DomainDecoyMap уже поддержан в `steps_shadowlink.go:41-43`).
4. Снять `//nolint:unused` с `getShadowLinkPoolDecoyTemplate`.

#### H-2 — `APP_ENCRYPTION_KEY` без versioning, rotation path и без crypto-deletion стратегии

**File**: `internal/admin/shadowlink_token_crypto.go:14-26`, `cmd/api/main.go:185-197`

`AppEncryptionKey()` читает env var, валидирует длину (32 байта hex) и возвращает raw bytes. `encryptToken`/`decryptToken` используют его напрямую.

Нет:
- Поля `key_version` в `cf_api_token` payload (`shadowlink_pool_servers.cf_api_token`).
- Reencryption path при смене ключа.
- DB-bound key-id таблицы.
- Документации «что делать если ключ скомпрометирован».

**Impact**:
- Если оператор сменил `APP_ENCRYPTION_KEY` (например после увольнения сотрудника), все CF tokens становятся `decryptToken` → error → orchestrator не может авторизоваться в CF → все existing pool-серверы заморожены пока admin вручную не передал токены через UI заново.
- `AppEncryptionKey` рандомно сгенерированный в .env / k8s secret — нет fail-safe, если admin запустил staging с одним ключом и protected с другим, токены не переносятся.
- Audit-trail rotate не существует.

**Recommendation**:
1. Хранить ciphertext в виде `v1.<base64nonce_ct>` (или JSON `{"v":1,"ct":"..."}`).
2. Добавить env `APP_ENCRYPTION_KEY_PREVIOUS` (опционально), `decryptToken` пробует current → previous; warn в slog при попадании в previous.
3. Endpoint `/api/admin/security/rotate-encryption-key` (super_admin only): читает все таблицы с зашифрованными колонками, decrypt с PREVIOUS, encrypt с CURRENT, обновляет.
4. Включить cf token в keysharded set: одна row в `app_secrets(name TEXT PRIMARY KEY, version INT, value_enc TEXT)` и helper `RotateAppSecret(...)`.

#### H-3 — `ProbeShadowLinkPoolDomain` не различает CF challenge / lawful redirect / mTLS-handshake-rejection

**File**: `internal/admin/shadowlink_pool_domains_handlers.go:198-289`

Probe делает `GET https://<domain>/`, считает 2xx → ok, всё остальное → fail. С `CheckRedirect = http.ErrUseLastResponse`:

```go
if resp.StatusCode < 200 || resp.StatusCode >= 300 {
    result = "fail"
    errMsg = fmt.Sprintf("HTTP %d", resp.StatusCode)
}
```

**Edge cases (ложно-положительные / ложно-отрицательные)**:
- CF Bot Fight Mode возвращает HTML 200 с challenge (CAPTCHA / managed challenge). Body не читается → "ok" ошибочно. Реальный клиент VPN получит challenge HTML вместо handshake.
- CF redirect HTTP→HTTPS возвращает 301 → probe = "fail" (хотя сервис здоров).
- Если ShadowLink-server вернул `failClosedToDecoy` (200 with sanitized decoy body) — probe тоже видит 200 → "ok", даже если ShadowLink upstream не запущен (nginx сам отдаёт static decoy).
- Если nginx с `ssl_reject_handshake on` (catch-all default) — `httpClient.Do` вернёт TLS handshake error → "fail" с правильной семантикой.

Также, согласно `probeStatusTransition` (line 170-191): `active → active even on fail` — здоровый домен никогда не уходит в degraded по probe. Только UI-кнопка вручную или `RescanStuckShadowLinkPoolDomains`. Это намеренное решение (комментарий: "transient blip; do NOT downgrade automatically"), но нет периодического sweep — orchestrator работает only on POST /probe. Без cron'a здоровье pool'а не отслеживается.

**Impact**: WS pool client может пытаться подключиться к домену, который CF banned 3 дня назад, потому что DB row застрял в `active`.

**Recommendation**:
1. Probe должен запрашивать конкретный path (например `/_health` за CF, защищённый bearer'ом сервера) или, как минимум, искать в body `<decoy-marker>` (signature decoy template, для T1.3 — `<title>habr</title>`).
2. Добавить scheduler в `cmd/api/main.go:184-197` — раз в N минут пройтись по `status='active'`, запустить probe, после M consecutive fails → `degraded` (per-domain N=3 fails over 30min).
3. Treat 3xx и 5xx по-разному: 3xx-to-CF-challenge — `fail` с `errMsg="CF redirect to challenge"`, 5xx — `degraded` сразу.

#### H-4 — `UploadNginxConfig` swap может оставить `*.bak` после concurrent invocation

**File**: `internal/deploy/steps_shadowlink_domain.go:167-198`

`swapCmd` shell-скрипт:
```sh
test -f /etc/nginx/conf.d/shadowlink.conf && cp shadowlink.conf shadowlink.conf.bak || true
mv shadowlink.conf.new shadowlink.conf
nginx -t || (mv shadowlink.conf.bak shadowlink.conf || rm -f shadowlink.conf; exit 1)
rm -f shadowlink.conf.bak
```

Если две `UploadNginxConfig`-операции запускаются параллельно (provision двух доменов одновременно):
1. T1 cp → bak (содержит config v0).
2. T2 cp → bak (overwrites: bak теперь == config v0 уже после T1 mv, т.е. config v1).
3. T1 mv → config v1.
4. T2 mv → config v2.
5. T1 nginx -t passes, rm -f bak.
6. T2 nginx -t passes, rm -f bak (no-op).

OK на happy path. Failure path: T2 nginx -t fails AFTER T1 already removed bak → `mv bak conf` без `bak` → rm config. T1 уже cleared, теперь config удалён. Result: `nginx -t || rm -f conf` оставляет nginx без shadowlink.conf, при следующем reload nginx 404 для всего pool'а.

Также, нет `flock` или mutex — orchestrator сам не сериализует SSH-вызовы UploadNginxConfig. Sub-phase B6 не имеет per-server lock, который бы охватывал nginx-write от race'ов.

**Recommendation**:
1. Завернуть swap в `flock /var/lock/shadowlink-nginx.lock` на сервере.
2. ИЛИ в ProvisionDomainAsync завести `lockServer(serverID)` (как в `shadowlink_handlers.go:190-195`) перед SSH-call'ом.
3. Использовать tmp file в /tmp/shadowlink-nginx.<pid>.new и atomic mv с `nginx -t -c` ДО mv.

### MEDIUM

#### M-1 — Audit-trail для ShadowLink admin endpoints полагается на инлайн `LogFromContext`, не на middleware

**File**: `cmd/api/main.go:627-642`, комментарий «via inline LogFromContext calls in the handlers»

I-HIGH-1 (no audit middleware) формально закрыт через инлайн вызовы `LogFromContext` в каждом destructive handler. Но этот паттерн:
- Хрупкий — добавление нового endpoint забывается, нет CI guard.
- Не записывает request body (только select fields), форензика после атаки на mgmt-key generation incomplete.
- Не пишет в audit, если bind валидации провалились или goroutine упала ДО `LogFromContext`.

Например, `Deploy` пишет audit ДО goroutine spawn (line 407) — OK. Но `ApplyLiveBlog` пишет audit ДО `lockServer` (line 1865), и если `LoadOrStore(serverID, true)` уже занят, audit-row пишется без `apply_started=false` маркера. После failed apply audit-row говорит «applied» хотя ничего не произошло.

**Recommendation**: завернуть `/api/admin/shadowlink/...` группу в `auditMiddleware` (как сделано для других destructive routes) — middleware фиксирует request URL+method+body+status, инлайн вызовы можно оставить как enrichment.

#### M-2 — `ssh_password` для pool-серверов хранится в `servers.ssh_password` без encryption-at-rest

**File**: `internal/admin/shadowlink_handlers.go:1206` (`SELECT ip, ssh_password FROM servers`), пайплайн provision

ShadowLink Phase B/C/D полагается на админский ввод SSH password в каждый Apply / Migrate / Disable handler (`ApplyLiveBlogRequest.Password`). Но `Remove` handler (`shadowlink_handlers.go:1206-1210`) читает `ssh_password` напрямую из таблицы `servers` — без `decryptToken`. Migration 003 сохраняет это поле в plain text.

Аналогично pool: `shadowlink_pool_servers` в схеме (072) НЕ имеет ssh_password. После H-1 fix добавит — обязательно через `encryptToken`. Сейчас в одном repo есть два паттерна (encrypted CF token, plain SSH password); риск, что будущий разработчик скопирует plain pattern для нового поля.

**Recommendation**:
1. Миграция: `ALTER TABLE servers ADD COLUMN ssh_password_enc TEXT; UPDATE servers SET ssh_password_enc = ...; ALTER TABLE DROP ssh_password`. Backfill через скрипт.
2. ShadowLink handlers — единый helper `getEncryptedSSHCredentials(serverID)`.

#### M-3 — Migration 073 (`retire_legacy_shadowlink_servers`) не имеет idempotent guard для UNIQUE rename

**File**: `migrations/073_retire_legacy_shadowlink_servers.sql`

```sql
UPDATE protocols SET name = 'ShadowLink_retired' WHERE name = 'ShadowLink';
```

Если в `protocols` есть UNIQUE constraint на `name` (стандарт для seed-таблиц) и кто-то параллельно делает `INSERT name='ShadowLink_retired'` (например через admin UI), миграция упадёт. Не вижу в `migrations/005_create_server_protocols_table.sql` явного UNIQUE на `protocols.name`, но это assumption.

Также: rollback в комментарии:
```sql
-- UPDATE protocols SET name = 'ShadowLink' WHERE name = 'ShadowLink_retired';
```
**не идемпотентен** если легит-запись 'ShadowLink' уже была заново seeded после migrate.

**Recommendation**: проверить наличие UNIQUE в `protocols.name`; если нет — добавить миграцией, BEFORE 073. Rollback написать в виде `ON CONFLICT DO NOTHING`.

#### M-4 — Audit-events для pool / domain / template не имеют correlation key

**File**: `internal/admin/shadowlink_pool_servers_handlers.go:80-84`, `..._domains_handlers.go:78-81`

`AuditShadowLinkPoolServerCreate`, `AuditShadowLinkPoolDomainCreate`, `AuditShadowLinkPoolDomainProbe` пишут одну row, но отсутствует `correlation_id` для связки «admin создал сервер id=42, через 30 секунд orchestrator пометил домен d=99 как degraded» — оба события в `admin_audit_log` с разными `target_id`, без trace.

При инциденте «ShadowLink domain bricked» нужно вручную делать time-window query.

**Recommendation**: добавить `correlation_id UUID` в audit_log (миграция 074), ProvisionDomainAsync генерирует UUID при start, прокидывает через ws + audit + slog в течение всего lifecycle.

#### M-5 — `RescanStuckShadowLinkPoolDomains` срабатывает только на startup; in-process crash после 10min не обработан

**File**: `internal/admin/shadowlink_pool_models.go:313-326`, вызов `cmd/api/main.go:191-196`

Стартап-сценарий покрыт. Но: orchestrator goroutine может застрять (`<-ctx.Done()` 5 мин timeout — line 61). Если goroutine крашится через `panic` после `failProvision`, defer-recover ловит → row помечается degraded. OK.

Но если goroutine **зависла** в SSH dial/write на 10+ минут (network blip, CF API hang) → `WithTimeout(5*time.Minute)` в `provisionDomain:61` отменяет ctx, но defer-recover не срабатывает, goroutine просто завершится без `failProvision` вызова — domain row остаётся в `provisioning`. Только следующий restart процесса исправит.

**Recommendation**: добавить ticker `RescanStuckShadowLinkPoolDomains` каждые 5 минут в startup'е (рядом с другими schedulers, line 176-182).

#### M-6 — CF rate-limit handling absent

**File**: `internal/deploy/cloudflare_api.go:52-96`

`CFClient.do` не обрабатывает 429 (CF rate limit) / 5xx с retry. При burst onboarding 20 доменов через CF API мы можем получить 429 — `failProvision` пометит domain `degraded` с ошибкой «CF api: 429 rate limited». Operator должен retry вручную.

**Recommendation**: backoff middleware (max 3 retries, exponential) в `do()` для 429 / 502 / 503 / 504.

### LOW

#### L-1 — `sendProvisionLog` всегда status=success или error, нет «info» severity

**File**: `internal/admin/shadowlink_domain_provision.go:172-196`

WS log entry имеет статус "success" даже для информационных сообщений типа "[domain N] CF zone OK: zone-id". Frontend вероятно отображает зелёный — но реально это в процессе. Используется тот же `ws.LogEntry` schema, что и server deploy — schema не имеет `info` severity. Минорно, but noisy на frontend.

#### L-2 — `validateLiveBlogConfigJSON` rejects FallbackJitterMs > FallbackLatencyMs, но не handles FallbackLatencyMs = 0

**File**: `internal/admin/shadowlink_handlers.go:1722-1724`

```go
if c.FallbackJitterMs < 0 || c.FallbackJitterMs > c.FallbackLatencyMs {
    return fmt.Errorf(...)
}
```

Если `FallbackLatencyMs=0`, то `FallbackJitterMs > 0` отклонится (что норм), а `FallbackJitterMs=0` пропустится → fallback без jitter. Не баг, но семантика «отключить fallback delay» не задокументирована.

#### L-3 — `description` колонка в `shadowlink_pool_decoy_templates` принимает empty через NULLIF, но ListDecoyTemplates возвращает пустую строку

`COALESCE(description, '')` (`shadowlink_pool_models.go:218`) — frontend получает пустую строку, не null. Документировать в API contract (или OpenAPI), что это convention. Не баг.

#### L-4 — `cfTTLAutomatic = 1` magic number

**File**: `internal/deploy/cloudflare_api.go:19`

`ttl: 1` — CF API marker для "automatic TTL". Достаточно `// CF marker: automatic TTL` (есть только конст-комментарий). Минорно.

#### L-5 — `WriteShadowLinkConfigYAML` НЕ записывает comment header через `# Generated by NixaVPN deploy` если оператор запускает `renderShadowLinkConfigYAML` (другой путь, в `apply-live-blog`)

**File**: `internal/admin/shadowlink_handlers.go:1336` vs `internal/deploy/steps_shadowlink.go:54`

Оба пишут разный header text:
- deploy: `# Generated by NixaVPN deploy — do not edit by hand.`
- admin (apply): `# Generated by NixaVPN apply — do not edit by hand.`

Drift между двумя renderers — каждый раз когда T1.3 / Domain Diversity добавит секцию, нужен sync двух файлов. Уже было поймано в T1.3 (см. plan B comment: "Test test renderShadowLinkConfigYAML добавлен"). Recommendation: один canonical renderer, оба caller'а зовут его.

---

## Operational Readiness Checklist

### Required ENV vars (production)

| Var | Required when | Validated at startup? | Location |
|-----|---------------|------------------------|----------|
| `DB_*`, `JWT_SECRET` | always | yes (config.Validate) | `internal/config` |
| `NIXAVPN_API_IP` | ShadowLink deploy | only inside Deploy/Migrate handlers | `shadowlink_handlers.go:241-249` |
| `APP_ENCRYPTION_KEY` | `ENABLE_SHADOWLINK_DOMAIN_DIVERSITY=true` | **YES** (`main.go:188-190` log.Fatalf) | `shadowlink_token_crypto.go:14-26` |
| `ENABLE_SHADOWLINK_DOMAIN_DIVERSITY` | optional, gates pool routes | yes (route registration gate) | `cmd/api/main.go:185, 647` |
| `SHADOWLINK_CF_API_BASE` | tests only | n/a | `cloudflare_api.go:33` |

### Migrations to apply

- 071 (decoy_live_blog_metrics + protocol_configs.applied_at) — **safe forward, idempotent via IF NOT EXISTS**.
- 072 (shadowlink_pool_*) — **safe forward, idempotent via IF NOT EXISTS + ON CONFLICT DO NOTHING for seed**.
- 073 (retire legacy ShadowLink protocol entry) — **safe forward, idempotent в смысле re-run даёт 0 rows**, но см. M-3 (UNIQUE constraint not guaranteed).

### Monitoring required

Already implemented (per earlier audit + this pass):
- `decoy_live_blog_metrics` rows scraped by `internal/shadowlink/scraper.go` каждые 60s (`cmd/api/main.go:180-182`).
- `RescanStuckShadowLinkPoolDomains` startup hook (`cmd/api/main.go:191-196`).
- ShadowLink mgmt API `/metrics?format=prom` exposed via nginx /_mgmt/.

Missing (must-add before fleet rollout):
- Periodic sweep of `shadowlink_pool_domains.status='active'` через probe handler — see H-3.
- Periodic `RescanStuckShadowLinkPoolDomains` (>5 min interval), не только startup — see M-5.
- CF rate-limit telemetry — see M-6.
- Per-domain `cdn_proxied` health (CF returns 525/526 / Bot Fight) — orthogonal к probe handler, нужен отдельный CF-aware health check.

### Pre-prod blockers (before scaling Domain Diversity)

1. **H-1**: Wire SSH-bound steps в orchestrator. До этого pool — manual.
2. **H-2**: Implement key-rotation path для APP_ENCRYPTION_KEY (даже базовый PREVIOUS-key fallback).
3. **H-3**: Probe endpoint + scheduler с deterministic «degraded after N fails».
4. **H-4**: Per-server lock на nginx swap.

Production-deploy с одним сервером (current canary `datacanvases.com`) — без блокеров.

---

## Open Questions

1. **Phase 0 retired metrics**: `shadowlink_legacy_path_hits_total`, `shadowlink_dual_auth_detected_total`, `shadowlink_handshakes_legacy_total`, `shadowlink_v0_fallback_from_new_path_total` сняты со server side. Frontend `ShadowLinkPage.LiveDecoyMetricsTab` не expects ли их? (Не проверял frontend в этом track'е.)
2. **Domain Diversity onboarding flow**: после H-1 fix, как frontend `AddDomainWizard` будет отображать "decoy upload в процессе" — есть ли WS subscription на `pool/<server>/...`? (`sendProvisionLog` пишет на `ServerID = "<id>"` numeric — достаточно ли это для UI disambiguation от обычного server-deploy логов?)
3. **Migration 073** работает per-row через `protocols.name`. Если фактическая схема `server_protocols.protocol_id → protocols.id` (а не `name`), и legacy протокол ID был привязан к уже-deployed servers — переименование name сломает foreign-key reverse lookup в коде, который ищет `WHERE name='ShadowLink'`. Был ли verified deploy_handlers.go branch?
4. **Где живёт canary `datacanvases.com`** в новой Domain Diversity модели? Это `shadowlink_pool_servers` row или legacy `servers + protocol_configs.shadowlink`? Документировать миграционный path для оператора.
5. **`ShadowLinkConfig.MgmtKey`** хранится в `protocol_configs.config_json` plain. Если DB dump утечёт — все mgmt API ключи в открытом виде. После APP_ENCRYPTION_KEY infra (H-2) — мигрировать `mgmt_key` тоже.
6. **`UploadNginxConfig` template хардкодит `proxy_pass http://unix:/run/shadowlink.sock`**. ShadowLinkPool использует unix socket, но T1.3 single-server использует TCP `127.0.0.1:<port+10000>` (см. `renderShadowLinkConfigYAML` line 1337). Два nginx config style для одной протокольной системы — как coexist на одном VPS если admin захочет migrate single → pool?

---

## Reference Files (absolute paths)

- `D:/NIXAVPN/internal/admin/shadowlink_handlers.go` (2080 lines, T1.3 + idempotency + LiveBlog)
- `D:/NIXAVPN/internal/admin/shadowlink_pool_models.go` (347 lines)
- `D:/NIXAVPN/internal/admin/shadowlink_pool_servers_handlers.go` (153 lines)
- `D:/NIXAVPN/internal/admin/shadowlink_pool_domains_handlers.go` (290 lines)
- `D:/NIXAVPN/internal/admin/shadowlink_pool_decoy_templates_handlers.go`
- `D:/NIXAVPN/internal/admin/shadowlink_domain_provision.go` (197 lines, orchestrator)
- `D:/NIXAVPN/internal/admin/shadowlink_token_crypto.go` (86 lines, AES-GCM)
- `D:/NIXAVPN/internal/admin/shadowlink_safe_redeploy.go` (29 lines)
- `D:/NIXAVPN/internal/deploy/cloudflare_api.go` (161 lines)
- `D:/NIXAVPN/internal/deploy/steps_shadowlink_domain.go` (217 lines, helpers — currently dead in production)
- `D:/NIXAVPN/internal/deploy/nginx_shadowlink_template.go` (56 lines)
- `D:/NIXAVPN/internal/deploy/steps_shadowlink.go` (config YAML render)
- `D:/NIXAVPN/cmd/api/main.go:121-197` (shadowlink wiring), `:627-661` (route registration)
- `D:/NIXAVPN/migrations/071_decoy_live_blog_metrics.sql`
- `D:/NIXAVPN/migrations/072_shadowlink_domain_pool.sql`
- `D:/NIXAVPN/migrations/073_retire_legacy_shadowlink_servers.sql`

---

## Summary Table

| ID | Severity | Area | One-liner |
|----|----------|------|-----------|
| H-1 | HIGH | Domain Diversity orchestrator | SSH-bound шаги stub'нуты, all multi-domain still manual |
| H-2 | HIGH | AES-GCM token crypto | APP_ENCRYPTION_KEY без version/rotation path |
| H-3 | HIGH | Probe handler | 200 == ok даже на CF challenge / nginx default-decoy |
| H-4 | HIGH | nginx swap | Concurrent UploadNginxConfig race оставит broken state |
| M-1 | MED | Audit-trail | Inline LogFromContext fragile, no middleware guard |
| M-2 | MED | Credentials | ssh_password в servers plain, drift с pool encrypted-CF model |
| M-3 | MED | Migrations | 073 без UNIQUE guarantee на protocols.name |
| M-4 | MED | Observability | No correlation_id между admin → orchestrator → audit |
| M-5 | MED | Self-healing | RescanStuckShadowLinkPoolDomains только on startup |
| M-6 | MED | CF API | No 429/5xx retry/backoff |
| L-1 | LOW | WS logs | sendProvisionLog severity binary, нет info |
| L-2 | LOW | Validation | FallbackLatencyMs=0 edge case |
| L-3 | LOW | API contract | description="" vs null |
| L-4 | LOW | Magic number | cfTTLAutomatic=1 без extended comment |
| L-5 | LOW | YAML render drift | Two header strings, two renderers |
