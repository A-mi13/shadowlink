# ShadowLink Final Review — Server & Integration

**Date**: 2026-04-25
**Scope**: `shadowlink/server/`, `shadowlink/cmd/shadowlink-server/`, integration в main NixaVPN tree (`internal/admin/shadowlink_handlers.go`, `internal/config/assembler.go`, `internal/config/assembler_shadowlink.go`, `internal/client/config_handlers.go`, `internal/deploy/steps_shadowlink.go`, `internal/deploy/steps_decoy.go`)
**Reviewer**: Opus subagent (server/integration final pass)
**State of the tree**: post-WB-TURN-cleanup (2026-04-25), Phase B/C/D bearer migration shipped, T1.3 Live Decoy shipped

## Executive Summary

Серверная сторона ShadowLink в целом крепкая: handler routing с явным fail-closed на decoy + timing match (`failClosedToDecoy` в `decoy_timing.go:34-70`), constant-time check management API, грамотный split rate limiter (`ratelimiters.go`), SSRF-защита через `safedial.go` + `isPrivateIP` для UDP, cleanup loop, graceful shutdown через `BroadcastStreamClose`, replay cache на новой Phase B path. Live Decoy реализован осторожно: SPA fallback, stale grace, canary watchdog, body-size cap, off-host redirect refusal, nginx-like 404 на CDN-fail. Большая часть аудитных правок (audit numbering F1/F2/H*/M*/W*/CRIT-*) явно прокомментирована в коде.

Основные риски сосредоточены не в серверном ядре, а в **integration layer**:

1. **CRITICAL — UDP YAML keys silently ignored.** `internal/deploy/steps_shadowlink.go:48-67` и `internal/admin/shadowlink_handlers.go:887-894` пишут `enable_udp:` / `udp_listen:` в `/etc/shadowlink/config.yaml`, но `shadowlink/server/fileconfig.go:16-31` (FileConfig) НЕ имеет таких полей. После migration-to-yaml UDP relay стартует на хардкоженном `NewUDPRelay(60*time.Second)` без слушающего сокета — `udp_listen :56000` нигде не открывается, файрвольное правило `ufw allow 56000/udp` повисает в пустоту. Для пользователей system VPN это потенциальный регресс UDP relay.
2. **HIGH — admin handlers НЕ под аудитом.** Все 9 endpoints `admin.GET/POST/PUT/DELETE("/shadowlink/...")` в `cmd/api/main.go:594-604` НЕ обернуты в `auditMiddleware`. Live Decoy enable/disable, mgmt-key replacement, binary upload — все эти destructive ops уходят в БД без записи в `audit_log`. Forensics после инцидента невозможна.
3. **HIGH — NIXAVPN_API_IP не валидируется.** `steps_shadowlink.go:86-89` и `shadowlink_handlers.go:213-217,991-995` берут `os.Getenv("NIXAVPN_API_IP")` и подставляют в nginx `allow %s;` без валидации формата. Опечатка → `allow ; deny all;` ломает /_mgmt/ scrape. SSRF-через-env невозможен (deploy запускает оператор), но **integrity** affected.

Помимо этого набор MEDIUM-замечаний по concurrency hot-spots в `handler.go` и LOW по logging hygiene.

Общая оценка: **прод-готовность подтверждаю** для текущей deploy конфигурации (1 сервер, ~100 клиентов), но перед наращиванием парка нужно закрыть Critical UDP YAML и High audit middleware.

---

## Server-side Findings

### CRITICAL

#### S-CRIT-1 — UDP relay не слушает входящих пакетов после migrate-to-yaml

**Files**: `shadowlink/server/handler.go:96-107` (NewHandler), `shadowlink/server/udp_relay.go:28-33` (NewUDPRelay), `shadowlink/server/fileconfig.go:16-31` (FileConfig)
**Severity**: CRITICAL (functional regression for system VPN UDP)

`Handler.NewHandler` создаёт `udpRelay = NewUDPRelay(60 * time.Second)` без какой-либо привязки к конфигу — это **client-mode** релэй, который dial-ит исходящие UDP сокеты на CONNECT (`udp_relay.go:39-91`), но НЕ имеет listening socket для inbound traffic.

Тем временем deploy code (`internal/deploy/steps_shadowlink.go:212-223`, `internal/admin/shadowlink_handlers.go:386-401`) пишет в YAML:
```yaml
enable_udp: true
udp_listen: ":56000"
```

`server/fileconfig.go:FileConfig` НЕ читает эти ключи (yaml-тегов нет), и `Config.UDPListen` поля не существует. Эти строки **silently ignored** парсером.

**Impact**:
- Файрвол открыт (`ufw allow 56000/udp`), но порт ничем не слушается.
- Если в будущем потребуется inbound UDP (QUIC-fallback, server-initiated) — нет слушателя.
- Operator confusion: deploy logs показывают «UDP-режим включён (порт 56000/udp)» (`shadowlink_handlers.go:732`), но фактически опция бесполезна.

В текущей архитектуре UDPRelay используется как client-side outbound — это работает (`handler.go:1441-1463` использует `udpRelay.Send` для CONNECT), и поэтому регресс не наблюдается на 1-сервере. Но статус «config.yaml корректно описывает UDP» — ложный.

**Fix options**:
1. Удалить `enable_udp` / `udp_listen` из templates в `WriteShadowLinkConfigYAML` и `renderShadowLinkConfigYAML`, plus убрать `EnableUDP/UDPPort` из `ShadowLinkYAMLParams`. Файрвольное правило тоже убрать.
2. ИЛИ добавить `EnableUDP *bool` + `UDPListen string` в `FileConfig` и фактически создавать listener (потребует server-feature design).

Рекомендую вариант 1 — UDP relay уже работает через outbound dial, listening socket не нужен.

### HIGH

#### S-HIGH-1 — `handleNewFormatPost` принимает `application/json` POST с произвольным телом до Content-Type discriminator

**Files**: `shadowlink/server/handler.go:212-225`
**Severity**: HIGH (DoS amplifier potential)

```go
ct := r.Header.Get("Content-Type")
if r.Method != "POST" || ct != "application/json" {
    h.decoy.ServeHTTP(w, r)
    return
}
```

Проблема: `Content-Type` сравнивается **строго** через `==`. Реальные клиенты часто шлют `application/json; charset=utf-8`, что попадёт в decoy. Это намеренное «нет boundary case-sensitivity» (`browser` skin тоже шлёт ровно `application/json`), и сейчас работает, но:

(a) Если кто-то добавит middleware/CDN, переписывающее Content-Type → весь legitimate трафик упадёт в decoy → крах сессий.

(b) Любой scanner может слать `Content-Type: application/json` с 12KB random body — это даёт ему доступ к `failClosedToDecoy` workflow, где `core.GenerateKeyPair()` (X25519 scalar mult ~50-100µs) выполняется на каждом запросе. На 2 vCPU VPS это бутылочное горлышко при flood (>10k req/s = 50% CPU только на синтетическую крипту). Атакующий тратит ~0.001 ядро/req на отправку, сервер 50µs CPU; асимметрия плохая.

**Recommendation**: Добавить `strings.HasPrefix(ct, "application/json")` (учёт parameters) AND вынести rate-limit перед `failClosedToDecoy` — иначе timing-oracle-resistance оборачивается DoS-vulnerability. Сейчас Data limiter дёргается только при decrypt-success (handler.go:652) — это правильно от security perspective, но не защищает от probe-flood.

#### S-HIGH-2 — first-frame WS auth пропускает FlagKeepalive с любым valid seq_num вне Outgoing tunnel state

**Files**: `shadowlink/server/websocket.go:57-97`
**Severity**: HIGH (relay starvation)

`authenticateFirstFrame` принимает frame если: hint resolves, GCM tag OK, seq_num accepted, flag == FlagKeepalive, тоннель есть. После этого `runWebSocketSession` запускает relay loop с `streams = make(map[uint16]*wsStream)` — пустой map. То есть фрейм keepalive признан, но **никаких streams ещё нет**.

Что если злоумышленник украл активную HTTP-сессию (token + key через memory leak в клиенте) и параллельно поднял WS upgrade? `authenticateFirstFrame` использует общий `session.AcceptSeqNum` — если параллельно работает legit POST-data flow, WS-злоумышленник может «съесть» seq_num у легита (replay window забьётся). При успешном WS-auth злоумышленник создаёт streams через FlagConnect, и его trafic теперь идёт через тот же session ID.

Это известное ограничение модели «один session = один transport», но в Phase C wire constructed second-transport spec явно не запретил concurrent transports. В текущей реализации поведение **undefined** — кто первым получил FlagConnect, того и сервер relayet.

**Recommendation**: При `authenticateFirstFrame` SUCCESS зарегистрировать в `Tunnel` флаг `WSAttached atomic.Bool` через CAS. Если уже attached — fakeAckAndClose. Иначе при наличии активного `HasDownloadStream` и WS одновременно происходит non-determinism (handleDataChunk skip Outgoing because of HasDownloadStream, runDownloadStreamLoop drain Outgoing, WS reader независимо обслуживает CONNECT — пересечения по streamID).

#### S-HIGH-3 — Goroutine leak в handleConnect при tunnel.done срабатывает между registration и dial

**Files**: `shadowlink/server/handler.go:1263-1310`

Регистрация stream (`tunnel.streams[streamID] = stream`) происходит ДО `SafeDial`. Если tunnel закрылся между шагами:
- registration уже выставлена;
- SafeDial завершился → попадаем в код активации (`stream.TargetConn = conn`), записываем в **закрытый tunnel.streams** (защищён `tunnel.mu`, поэтому не паникуем);
- запускаем goroutine `relayStreamFromTarget`;
- `relayStreamFromTarget` сразу видит `<-tunnel.done` (закрыт) и exit-defer корректно закрывает conn.

Но между shutdown-broadcast и cleanup loop есть гонка: `tunnel.closeTunnel()` закрывает `done`, `Outgoing`, `OutgoingUDP`. `relayStreamFromTarget` читает из buf и пытается `tunnel.Outgoing <- tagged` — `case tunnel.Outgoing <- tagged:` БЕЗ select-arm `<-tunnel.done` ВНЕ select **возможен panic on send on closed channel**. Сейчас select проверяет оба:

```go
select {
case tunnel.Outgoing <- tagged:
case <-tunnel.done:
    ...
    return
}
```

Это OK — но `case tunnel.Outgoing <- tagged:` с **закрытым** Outgoing **паникует**, и select может выбрать его. Go-runtime select randomization: closed channel в send-arm = `panic: send on closed channel`. Defer-recover на месте (`handler.go:1330-1334`), но это смазывает фактическое использование canary: каждый panic recovered увеличивает GC pressure и логируется.

**Recommendation**: В `closeTunnel` (`handler.go:80-87`) сначала `close(t.done)`, затем дать каждой relay-горутине шанс заметить done в **первом** select-iteration (через короткий sleep), и только потом `close(Outgoing)`. ЛИБО переделать relay на `chan []byte` без явного close — пусть Outgoing GC-нется когда все ссылки уйдут.

### MEDIUM

#### S-MED-1 — `dualAuthDetectionSaturation = 10_000` глобальный, не per-IP

**File**: `shadowlink/server/handler.go:274`

После 10k DualAuth detections счётчик саморегулируется и `findSessionByHint`+`DecryptChunkSafe` пропускаются. Атакующий с одного IP легко набивает 10k за минуту простыми crafted POST'ами с Authorization-header, после чего **отключает canary для всего сервера**. Реальные client-rollout-bug-canaries после этой точки не зафиксируются.

**Recommendation**: Saturation per-IP via отдельный rate-limiter, OR per-час reset counter с decay, OR раздельные счётчики `DualAuthDetected_legit` (после strict validation) и `DualAuthDetected_probe`.

#### S-MED-2 — `replayCache` не cleanups сам по себе вне `core.NewReplayCache(10000, 5min)`

**File**: `shadowlink/server/handler.go:105`, `core/replay_cache.go` (outside scope but memory pinned)

Проверял `core.NewReplayCache(10000, 5*time.Minute)`: 10000 entries × ~64 bytes = ~640 KB постоянная память. На 100-client deployment это OK, но при планах >1000 клиентов пересмотреть.

#### S-MED-3 — `runDownloadStreamLoop` Body-write deadline 60s, но `ackJitter()` на keepalive может затянуть до 75s

`writer.go` extendDeadline применяется на старт, но `time.Sleep(ackJitter())` НЕ применяется в loop — keepalive-ticker идёт без jitter. 25s ticker + 60s write timeout — норм. Не баг, но прокомментировано неправильно («distribution-matched response jitter» в `decoy_timing.go:62` — на стриме отсутствует).

#### S-MED-4 — DefaultMaxDevices в `server.go:75-79` применяется только если `mgmt_port>0 && mgmt_key != ""`

```go
if s.config.ManagementPort > 0 && s.config.ManagementKey != "" {
    ...
    if s.config.DefaultMaxDevices > 0 {
        s.handler.clientAuth.defaultMax = s.config.DefaultMaxDevices
    }
    ...
}
```

Default 3 уже зашит в `NewClientAuth` → `defaultMax: 3`, поэтому функционально работает. Но логика явно не отражает intent: «default applies regardless of mgmt API state».

**Recommendation**: вынести `defaultMax` setup из management-block в общий init после `NewHandler`.

#### S-MED-5 — `LiveBlogHandler.fetchUpstream` not pinning DNS resolution

`live_blog.go:107-119` создаёт `http.Client` с `CheckRedirect` валидирующим host против `pinnedHost/pinnedCDNHost`. Но fetch адресуется через `cfg.Upstream` URL (habr.com), и DNS resolves каждый раз свежо. Атака DNS-rebinding на habr.com маловероятна, но если habr.com попадёт в hostile-controlled zone — upstream начнёт fetch'ить SSRF. SafeDial в `safedial.go:50-100` тут НЕ применяется (другой code path).

**Recommendation**: задать `Transport.DialContext = SafeDialContext` чтобы все habr-запросы тоже проходили через privateCIDR check.

### LOW

#### S-LOW-1 — `urls.go:wsURLPool` содержит только `/ws`

Path rotation объявлена в комментарии но ещё не реализована. Это известная limitation, не баг.

#### S-LOW-2 — `server/decoy.go:54-81` default-decoy-page hardcoded `<title>Welcome</title>`

Если operator забыл `-decoy` flag — server раздаёт дефолтную страницу с минимальным content. DPI fingerprint этой страницы стабилен и можно создать сигнатуру «ShadowLink server in default mode». Production deploy всегда ставит `/var/www/shadowlink-decoy`, поэтому маловероятно, но в тестах/staging может произойти.

#### S-LOW-3 — `metrics.go:160-186` BackpressureCheck использует `runtime.MemStats.Alloc` vs `Sys`

Sys = total OS memory обещанный Go runtime'ом (растёт никогда не падает). Alloc/Sys ratio как threshold — флакающий: после долгого uptime Sys раздуется, threshold станет easier to hit.

#### S-LOW-4 — `handler.go:185 ServeHTTP` принимает любой Method='POST' без upper-bound на body

`ReadBodyLimited(r.Body, ChunkSize+8192)` стоит. OK.

#### S-LOW-5 — `BroadcastStreamClose` non-blocking 100ms timeout per tunnel

Если 100 tunnels — 10s overhead в shutdown. Документировано, не баг.

---

## Integration Findings (main NixaVPN)

### CRITICAL

#### I-CRIT-1 — См. S-CRIT-1 (UDP YAML keys silently ignored — это и server и integration finding одновременно).

### HIGH

#### I-HIGH-1 — Все ShadowLink admin endpoints НЕ обёрнуты в `auditMiddleware`

**File**: `cmd/api/main.go:594-604`

```go
admin.GET("/shadowlink/servers", shadowlinkHandler.ListServers)
admin.POST("/shadowlink/deploy/:id", sa, shadowlinkHandler.Deploy)
admin.POST("/shadowlink/update/:id", sa, shadowlinkHandler.UpdateBinary)
admin.GET("/shadowlink/config/:id", shadowlinkHandler.GetConfig)
admin.DELETE("/shadowlink/:id", sa, shadowlinkHandler.Remove)
admin.POST("/shadowlink/migrate-to-yaml/:id", sa, shadowlinkHandler.MigrateToYAML)
admin.POST("/shadowlink/disable-live-blog/:id", sa, shadowlinkHandler.DisableLiveBlog)
admin.GET("/shadowlink/live-blog-config/:id", shadowlinkHandler.GetLiveBlogConfig)
admin.PUT("/shadowlink/live-blog-config/:id", sa, shadowlinkHandler.PutLiveBlogConfig)
admin.POST("/shadowlink/apply-live-blog/:id", sa, shadowlinkHandler.ApplyLiveBlog)
admin.GET("/shadowlink/metrics/:id", shadowlinkHandler.GetMetrics)
```

Сравните с прочими admin routes в `main.go` — большинство destructive endpoint'ов имеют audit middleware (e.g. servers/users/plans). ShadowLink — упущение.

**Impact**: после инцидента невозможно восстановить «кто и когда нажал disable-live-blog». Учитывая что `DisableLiveBlog` это emergency rollback и `MigrateToYAML` пишет новый mgmt_key (потенциально из-под скомпрометированного admin) — отсутствие audit trail bad.

**Fix**: завернуть в `audit.AuditMiddleware()` (паттерн из других модулей) перед отдачей в SA-only branch.

#### I-HIGH-2 — `NIXAVPN_API_IP` env var не валидируется, попадает в nginx config

**Files**: `internal/admin/shadowlink_handlers.go:213-217,991-995`, `internal/deploy/steps_shadowlink.go:86-89`

```go
apiIP := os.Getenv("NIXAVPN_API_IP")
if apiIP == "" {
    return fmt.Errorf("NIXAVPN_API_IP env var required for mgmt API nginx whitelist")
}
// ...
fmt.Sprintf(... `allow %s; deny all;` ..., apiIP, ...)
```

Опечатка `NIXAVPN_API_IP=1.2.3.4 ;ANY` или `\n include /etc/passwd;` → nginx config injection. Defaults: ENV var is set by ops, but **anyone with admin shell access** мог бы навредить.

**Recommendation**: Validate `net.ParseIP(apiIP)` либо CIDR, отклонять иначе. Та же проверка нужна для `cfg.Domain` (используется в server_name nginx config).

#### I-HIGH-3 — `cfg.Domain` пишется в nginx config без валидации

**File**: `internal/admin/shadowlink_handlers.go:1107-1136` (MigrateToYAML), `:530-540` (Deploy)

```go
nginxHTTPS := fmt.Sprintf(`server {
    listen %d ssl http2;
    server_name %s;
    ssl_certificate %s;
    ssl_certificate_key %s;
    ...`, cfg.Port, cfg.Domain, certPath, keyPath, ...)
```

`cfg.Domain` исходит из `protocol_configs.config_json` — записан admin-deploy ранее. Нет валидации, что domain — реально домен (нет ` ; \n { } `). Если admin compromised — можно injection в nginx config через специально сформированный ShadowLinkDeployRequest.Domain.

`Deploy` handler (`internal/admin/shadowlink_handlers.go:136-175`) делает `c.ShouldBindJSON` без validator на Domain, но `binding:"required"` есть. Required не = format-valid.

**Fix**: Регулярка `^[a-zA-Z0-9.-]+$` на Domain в bind validator.

#### I-HIGH-4 — `runApplyLiveBlog` race с Disable+Apply concurrent invocation

**Files**: `internal/admin/shadowlink_handlers.go:1308-1351,1356-1402`

`ApplyLiveBlog` вызывает `LoadOrStore(serverID, true)`, далее в горутине читает `cfg` после lock. `DisableLiveBlog` сначала пишет в DB `LiveBlog.Enabled=false`, ПОТОМ вызывает `LoadOrStore(serverID, true)`. Если оба handler вызваны одновременно (двойной клик или rapid-fire), между read и lock другой handler может изменить DB. Result: applied YAML not match DB state.

**Fix**: оба handler'а должны делать `LoadOrStore` **до** read из DB, либо сериализовать через очередь.

#### I-HIGH-5 — `findShadowLinkBinary` ищет binary в относительных путях из `getwd`

**File**: `internal/admin/shadowlink_handlers.go:599-622`, `internal/deploy/steps_shadowlink.go:551-574`

```go
candidates := []string{
    "shadowlink/shadowlink-server-linux",
    "shadowlink-server-linux",
}
if wd, err := os.Getwd(); err == nil {
    candidates = append(candidates, filepath.Join(wd, "shadowlink", "shadowlink-server-linux"))
}
```

CWD-зависимость в production. Если binary запущен из `/etc/systemd` или `/`, `os.Getwd()` ≠ repo root, и `findShadowLinkBinary` returns empty → deploy fails silently (`runDeploy: "Бинарник не найден"`, `runUpdateBinary: 400`). Это уже укусило в одном инциденте (по comments в логах migrate-to-yaml).

**Fix**: добавить `NIXAVPN_BIN_DIR` env var с явным путём. ИЛИ embed binary через `//go:embed` (~30MB но reproducible).

### MEDIUM

#### I-MED-1 — `assembler_shadowlink.go:11-31` `AssembleShadowLinkURL` НЕ используется

**File**: `internal/config/assembler_shadowlink.go:11-31`

```go
func AssembleShadowLinkURL(node NodeRuntime, userID int64) string { ... }
```

Grep по проекту: только определение. Производит формат `sl://PUBKEY@HOST:PORT?...` который никем не вызывается. Comment гласит «генерирует sl:// ссылку для подписки». Подписочный endpoint `internal/client/config_handlers.go` для shadowlink использует `AssembleShadowLinkConfig` (JSON), не URL.

Dead code. Удалить или подключить к /subscription endpoint.

#### I-MED-2 — `AssembleShadowLinkConfig` не передаёт `client_id` в форме `userID:deviceID`

**File**: `internal/config/assembler_shadowlink.go:49-75`

`ClientID` генерится как `fmt.Sprintf("user_%d", userID)`. Server (`shadowlink/server/ratelimit.go:148-155`) ожидает формат `userID:deviceID` для device-limit logic.

```go
func parseUserID(clientID string) string {
    if idx := strings.IndexByte(clientID, ':'); idx >= 0 {
        return clientID[:idx]
    }
    return clientID  // falls back to entire clientID
}
```

`user_42` (no colon) → parseUserID returns `user_42`, deviceID part = "" → device limit считается per-user, что OK. НО `ClientAuth.activeSessions` индексируется по userID — ВСЕ устройства одного юзера попадают в один slot. Формально limit работает (max 3 sessions для user_42), но identification of separate devices невозможна. Если user_42 переустанавливает приложение, ничего не отличает «новое устройство» от «старого reconnect».

**Fix**: client передаёт `device_id` (HWID) в JSON config request, assembler формирует `user_42:device_xyz`. Добавить device_id query param в `/full-config?protocol=shadowlink&device_id=...`.

#### I-MED-3 — `internal/client/config_handlers.go:253-275` ShadowLink branch не валидирует наличие public_key

```go
body, errSL := config.AssembleShadowLinkConfig(selectedNode, userID)
if errSL != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сборки конфига ShadowLink"})
    return
}
```

`AssembleShadowLinkConfig` возвращает err если `ShadowLinkPublicKey == ""`. Но это указывает «ShadowLink не задеплоен на этом сервере» — не internal server error. Должен быть `503 Service Unavailable` с понятным message.

Также: error.Error() text ("ShadowLink не настроен на этом сервере") **затирается** на «Ошибка сборки конфига ShadowLink». Real reason hidden от клиента.

**Fix**: `c.JSON(http.StatusServiceUnavailable, gin.H{"error": errSL.Error()})`

#### I-MED-4 — `handler.go:LiveBlog` panic-recover в canary loop, но не в LiveBlogHandler.ServeHTTP

`live_blog_canary.go:86-91` имеет defer-recover на canary loop. `live_blog.go:171-187 ServeHTTP` — НЕ имеет. Если в `articleRe.MatchString` или handler-method упало — Go server propagates panic к `ServeHTTP` chain → crash whole process.

**Fix**: добавить outer defer-recover в `LiveBlogHandler.ServeHTTP`, отнести drift counter, вернуть 200 fallback.

#### I-MED-5 — `Cache-Control: no-store` отсутствует на `GetSingboxConfig` для shadowlink

`config_handlers.go:24-50` — `GetSingboxConfig` для VLESS/Reality. ShadowLink branch (line 247) ставит `c.Header("Cache-Control", "no-store")` ✓. Но `GetSingboxConfig` (line 49) использует `c.Data(http.StatusOK, "application/json", body)` без `no-store`. Если CDN перед API кэширует — token leak возможен.

Не shadowlink-specific, но указано для полноты.

#### I-MED-6 — `MigrateToYAML` race — DB UPDATE после apply, no transaction

**File**: `shadowlink_handlers.go:1163-1175`

```go
// 11. Persist updated config (with mgmt_key) to DB
if _, err := h.db.Exec(`UPDATE protocol_configs ...`); err != nil {
    h.sendError(serverID, "⚠ DB update failed после успешного apply ...")
    return
}
```

If apply succeeded на сервере (новый mgmt_key) НО DB UPDATE failed → перманентный split-brain: на VPS живёт mgmt_key #2, в БД — пустой mgmt_key. После любой попытки `ApplyLiveBlog` или `GetMetrics` через scraper — auth fail (401) бесконечно.

Fix: apply НЕ должен делать destructive op до DB UPDATE. Архитектурно: записать в DB сначала с tentative_mgmt_key, потом push на сервер, потом mark applied. (Reverse order = current; нужен compensating action: повторный mgmt_key generation + push на следующий apply.)

### LOW

#### I-LOW-1 — `WB TURN` мёртвые комментарии в `shadowlink_handlers.go`

**Lines**: `:371`, `:568`, `:722-723`

```go
// 6. Open firewall ports (TCP for HTTPS + UDP for WB TURN relay)
EnableUDP:      true, // всегда включаем UDP для WB TURN relay
// 4. Ensure UDP is enabled in systemd service (for WB TURN relay)
h.sendLog(serverID, "Проверка UDP-режима для WB TURN...")
```

WB TURN удалён 2026-04-25. Comments stale. Также log-сообщение в UI вводит operator в заблуждение (нет такой фичи больше).

**Fix**: переименовать в «UDP для system VPN UDP ASSOCIATE» (это и было реальным назначением UDP в ShadowLink — см. `shadowlink/CLAUDE.md` line 11).

#### I-LOW-2 — `runApplyLiveBlog` чмокает emoji в SSH log channel, может падать на не-UTF8 терминалах

**Lines**: `:838,847,853,860,867`

📡, 📄, 🔧, ⚠️, ✅. Если operator смотрит logs через ssh-tty, terminal без UTF-8 поддержки покажет mojibake. Низкий приоритет.

#### I-LOW-3 — `DefaultLiveBlogConfigJSON` не зеркало server.DefaultLiveBlogConfig (см. comment line 798)

Required manual sync. Если кто-то изменит default `CanaryArticleID` в одном файле — другой не сообщит. Тест на equality между двумя default-конфигами добавить в test.

#### I-LOW-4 — `getNodesForPlan` / `getNodeForClient` НЕ проверяют наличие ShadowLink config перед выбором

Если ни один сервер плана не задеплоил ShadowLink, request на `/full-config?protocol=shadowlink` возвращает 503 «Нет доступного сервера» (через generic fallback). Клиент не понимает «сервер есть, но без ShadowLink».

**Fix**: в `getRankedServers` или новой helper-функции фильтровать серверы по наличию `protocol_configs.protocol = 'shadowlink' AND config_json->>'public_key' IS NOT NULL`.

#### I-LOW-5 — LocallyHandled `EnableUDP: true,` hardcoded, не из `req.EnableUDP`

`shadowlink_handlers.go:567-569` — несмотря на флаг `req.EnableUDP` в запросе, всегда выставляется true. Соответствует removed-WB-TURN dead state. Окей, но честнее зашить как `const enableUDP = true` или удалить поле.

---

## Concurrency & Resource Audit

### Race conditions

1. **handler.go Tunnel.streams write через relay defer**: `relayStreamFromTarget` берёт `tunnel.mu.Lock()` для `delete(tunnel.streams, streamID)`. Параллельно `handleConnect` берёт тот же lock для регистрации. ОК, но `len(tunnel.streams)` чтение в hot path `handleDataChunk:786-797` тоже под lock — линеаризуемость есть. Не вижу race.

2. **handler.go HasDownloadStream + Outgoing race**: `handleDataChunk:839` проверяет `!tunnel.HasDownloadStream.Load()` → если false, читает Outgoing. Между Load и select-recv `runDownloadStreamLoop` может стартовать (CAS true) и тоже начать читать Outgoing. Оба тянут одно сообщение → один из них получает nil, другой реальный chunk. Нет паники, но **double-drain race** теоретически возможен. Practical impact: данные не теряются (один из получателей пройдёт), но HasDownloadStream race window короткий и при типичной CDN setup только GET держит download stream.

3. **clientAuth.SyncClients vs OnSessionCreated race**: `SyncClients` под Lock, `OnSessionCreated` тоже Lock. Sequential. ОК.

4. **udp_relay.go Send vs readLoop race на `flow.onReceive`**: Под `r.mu.RLock` в readLoop делается копия `cb := flow.onReceive`, под `r.mu.Lock` в Send обновляется. Race-free.

5. **wsStream.Activate concurrent с Close**: `Activate` устанавливает `connected=true` и flush. `Close` использует sync.Once. Если Close произойдёт ДО Activate — startWriter не запустится но done закрыт; Activate writeAfter тоже закрыт по defer-flow Write. Edge case пройдёт — pending data lost но без panic.

### Goroutine leaks

1. **runWebSocketSession reader goroutine** — exit при ReadMessage err (`websocket.go:399`). При соединение-up но идле бесконечно — ОК, защита через WS pong-handler `60s` timeout. ✓

2. **runDownloadStreamLoop** — `<-ctx.Done()` exit on client disconnect. ✓

3. **relayStreamFromTarget** — defer cleanup. ✓

4. **udpRelay.readLoop** — exit on conn.Read err (incl. timeout). Cleanup tick **ОТСУТСТВУЕТ** — `UDPRelay.Cleanup()` не вызывается из server (только в test). Реально только когда readLoop сам выйдет (по таймауту 60s). Это OK для одного flow per stream, но **no upper bound on concurrent flows** — `r.flows` map растёт. На 100-client deploy ничего не лопнет, но прокомментировано. **Recommendation**: вызвать `udpRelay.Cleanup()` из `Handler.StartCleanup` ticker.

5. **livre_blog canary** — `runCanaryLoop` exit on `ctx.Done`. ✓

### Channel deadlock potential

1. `tunnel.Outgoing cap=256` — `relayStreamFromTarget` пишет non-blocking (через select c done). При 50 streams × 16KB ranges = 800KB pending, cap=256 buffers ~10MB. На 2GB VPS норма. При >256 producers backpressure — relay блокирован на send. Правильно.

2. `OutgoingUDP cap=64` — UDP traffic burst > 64 packets/100ms = drop. Selected `default:` arms in `handler.go:1458-1463` тихо отбрасывают. Acceptable for VoIP / DNS.

3. `WSAsyncWriter queue=512` — на upload burst > 512 messages в секунду блокирует Enqueue. Не вижу select на done в `Enqueue` (внутри `core.WSAsyncWriter` — out of scope). Если writer.Run упал — Enqueue вечно блокирует. Нужно проверить core/ws_async_writer.

### Resource exhaustion

1. **MaxClients=100 hard limit**: `handleHandshake:339` отказ → decoy. ✓

2. **maxStreamsPerSession=256**: enforce во всех CONNECT paths. ✓

3. **handshakeRateLimit=300/min/IP**: split limiter, защищён. ✓

4. **maxRateLimitEntries=10000**: cap на map size. ✓

5. **Live Blog cache**: LRU bounded `CacheMaxEntries=500`. ✓

6. **HTML rewriter MaxOutputBytes=2MiB**: bounded. ✓

7. **CDN body cap 16MiB**: bounded. ✓

8. **goroutines per session**: 1 reader + 1 writer + 1 ping + N stream relays. На MaxClients=100 × 256 streams = ~25k goroutines worst case. Default Go stack 8KB × 25k = 200MB. Но typical SOCKS5 user 5-10 streams, expectations 100×10 = 1000 goroutines, ОК.

---

## Operational Concerns

### Monitoring

- **Готово**: Prometheus metrics на `/metrics?format=prom` через mgmt API. Counters covering migration (`shadowlink_legacy_path_hits_total`, `shadowlink_new_path_hits_total`, `shadowlink_dual_auth_detected_total`), Live Decoy (`decoy_live_blog_*`).
- **Отсутствует**:
  - histogram latency (RTT, decrypt time, dial time) — все p50/p99 вычисляются в exporter из delta-counters, что грубо.
  - `udp_relay_active_flows` gauge — UDP relay не expose'ит FlowCount наружу.
  - `tunnel_active_streams` gauge — есть `ActiveConnections atomic` но fed нигде в коде не вижу `.Add(1)/.Add(-1)` вокруг stream lifecycle (только `ActiveClients`).

### Alerting

- `shadowlink_dual_auth_detected_total > 100` per hour — client rollout regression.
- `decoy_live_blog_canary_last_healthy_unix older than 1h` — habr changed structure or upstream down.
- `decoy_live_blog_rewrite_drift_total > 10/h` — rewriter mismatch.
- `shadowlink_handshakes_failed_total / shadowlink_handshakes_total > 0.5` — DPI probing or client bug.
- `shadowlink_active_clients` gauge → пагинация if > MaxClients × 0.8.

Никакого alerting setup в репо НЕ закоммичено (нет `prometheus/rules/*.yml`). Это responsibility ops, но скрипты scrape (`internal/shadowlink/scraper.go` — out of scope here) уже есть.

### Deploy-rollback guarantees

- `shadowlink-apply-config.sh` (на сервере) делает atomic mv + validate + restart + rollback on validate-fail. **GOOD**.
- `MigrateToYAML` upgrade idempotent (`if cfg.MgmtKey != "" { return already_migrated }`).
- `Deploy` НЕ idempotent: повторный deploy перегенерит keys! (`runDeploy:312-326` always calls `--gen-key`). Если admin клацнул дважды → старые клиенты с pubkey из первого deploy перестают auth-иться. **CRITICAL operational fix needed**: check `protocol_configs` pre-deploy и при наличии записи переиспользовать ключи, либо явно запрещать deploy дважды.

  → Запишу как **I-HIGH-6 — Deploy не idempotent, ломает существующих клиентов**.

#### I-HIGH-6 — `runDeploy` не idempotent

**File**: `internal/admin/shadowlink_handlers.go:209-596`

`runDeploy` всегда вызывает `--gen-key` (line 314), всегда записывает новый mgmt_key (line 379-384), всегда переписывает nginx config. Если деплой запущен повторно (после fix кейс admin: «не работает, попробую ещё раз») — все ключи изменены, существующие клиенты теряют аутентификацию.

`Deploy` handler check `LoadOrStore(serverID, true)` блокирует **concurrent**, не **повторный**. После первого deploy завершившегося → следующий `Deploy` POST допустим.

**Fix**: pre-check в `Deploy`:
```go
var exists bool
h.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM protocol_configs WHERE server_id=$1 AND protocol='shadowlink')`, serverID).Scan(&exists)
if exists {
    c.JSON(409, gin.H{"error": "ShadowLink already deployed; use UpdateBinary or Remove first"})
    return
}
```

---

## Open Questions

1. **WS-only attacker model**: должен ли сервер запретить **первый** WS connect без preceeding POST handshake? Сейчас `authenticateFirstFrame` требует existing tunnel (создаётся handshake POST'ом), что implicit forces sequence. Но если client делает handshake POST на одном CDN edge и WS на другом (CF anycast) — могут попасть на разные origins (если scaling > 1). Документировано ли что ShadowLink требует sticky session?

2. **Migration end-of-life**: Phase B/C/D shipped, legacy Bearer path всё ещё активен. Когда планируется `--no-legacy` flag и удаление `handleLegacyPost`?

3. **Live Decoy + сторонние ссылки**: rewriter strips «tm-header» «tm-footer». Если habr добавит новый class-набор — rewriter тихо пропустит (drift counter сработает, но через 24h grace window). Нужна автоматическая опция emergency-disable от scraper?

4. **`shadowlink/server/server.go:218-249` loadServerKey**: ephemeral key для testing — но если operator забыл `-server-key` в production, server стартует с warning + рандомным ключом. Все клиенты не смогут авторизоваться. Fail-fast предпочтительнее: вернуть error и не стартовать без явного `-allow-ephemeral-key` flag.

5. **`/_mgmt/` access control via nginx allow %s**: a single API IP. Если у NixaVPN несколько API nodes (HA) — нет multi-IP support. Документировать или расширить до `allow_list []string`.

6. **Decoy timing match in failClosedToDecoy**: GenerateKeyPair runs scalar mult ~50-100µs. Real handshake path (`HandleClientHello`) делает 1× ScalarMult + 1× Open. Synthetic is **single** scalar mult. p99 timing match достаточный? Вижу test `decoy_timing_test.go` covers existence but not distribution match.

7. **FCM/Telegram ping-back при canary fail** — реализован?

---

## Summary Table

| ID | Severity | Area | One-liner |
|----|----------|------|-----------|
| S-CRIT-1 / I-CRIT-1 | CRITICAL | Server+Integration | `enable_udp` / `udp_listen` YAML keys silently ignored |
| S-HIGH-1 | HIGH | Server | `Content-Type` strict equality + GenerateKeyPair on every probe = DoS |
| S-HIGH-2 | HIGH | Server | WS first-frame auth allows hijack of session if attacker has token |
| S-HIGH-3 | HIGH | Server | Goroutine race on closed Outgoing channel relies on defer-recover |
| I-HIGH-1 | HIGH | Integration | All `/shadowlink/*` admin endpoints lack audit middleware |
| I-HIGH-2 | HIGH | Integration | `NIXAVPN_API_IP` ENV not validated → nginx config injection vector |
| I-HIGH-3 | HIGH | Integration | `cfg.Domain` not validated before nginx interpolation |
| I-HIGH-4 | HIGH | Integration | ApplyLiveBlog vs DisableLiveBlog race → applied YAML out of sync with DB |
| I-HIGH-5 | HIGH | Integration | `findShadowLinkBinary` CWD-dependent path search |
| I-HIGH-6 | HIGH | Integration | `runDeploy` not idempotent — re-deploy invalidates existing clients |
| S-MED-1 | MED | Server | DualAuth detection saturates globally; attacker disables canary |
| S-MED-2 | MED | Server | replayCache memory pin not bounded by deployment scale |
| S-MED-3 | MED | Server | Keepalive jitter missing on download stream |
| S-MED-4 | MED | Server | DefaultMaxDevices coupled to mgmt API enable |
| S-MED-5 | MED | Server | LiveBlog HTTP client doesn't pin DNS to safe range |
| I-MED-1 | MED | Integration | `AssembleShadowLinkURL` is dead code |
| I-MED-2 | MED | Integration | `client_id = user_<id>` lacks device discriminator |
| I-MED-3 | MED | Integration | ShadowLink config error returned as 500 instead of 503 |
| I-MED-4 | MED | Integration | `LiveBlogHandler.ServeHTTP` lacks panic-recover |
| I-MED-5 | MED | Integration | `GetSingboxConfig` lacks `Cache-Control: no-store` |
| I-MED-6 | MED | Integration | MigrateToYAML split-brain on DB UPDATE failure |
| S-LOW-1..5 | LOW | Server | wsURLPool single-path, default-decoy fingerprint, Sys/Alloc threshold drift, etc |
| I-LOW-1..5 | LOW | Integration | Stale `WB TURN` comments, emoji logs, default-config drift, missing protocol filter, hardcoded EnableUDP |

---

## Recommendations (priority order for next session)

1. **CRITICAL → fix immediately**: I-CRIT-1 (UDP YAML keys), I-HIGH-6 (deploy idempotency).
2. **HIGH next**: I-HIGH-1 (audit middleware), I-HIGH-2/3 (env+domain validation), S-HIGH-1 (Content-Type relax + rate-limit failClosedToDecoy).
3. **Verify R5-style integration test for I-HIGH-4** (concurrent apply/disable).
4. **MEDIUM в плановом порядке**: I-MED-2 (HWID), S-MED-1 (per-IP DualAuth), I-MED-6 (DB UPDATE before push), S-MED-5 (SafeDial для habr fetch).
5. **Cleanup**: I-LOW-1 (WB TURN stale strings), I-MED-1 (dead code AssembleShadowLinkURL).
