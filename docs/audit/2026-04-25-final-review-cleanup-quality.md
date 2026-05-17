# ShadowLink Final Review — Cleanup Hygiene & Code Quality

**Date**: 2026-04-25
**Reviewer**: Opus subagent
**Scope**: Post-cleanup audit (WB TURN / WhitePass / VK TURN removal) + code quality of `shadowlink/` and integration points in main NixaVPN tree.

---

## Executive Summary

Cleanup achieved **near-complete code-level removal** of WB TURN / WhitePass / VK TURN — все три обнаружимых пакета (`internal/{wbturn,whitepass,turn}`, `pkg/whitepass`, `cmd/{wbturn,whitepass,whitepass-client}`), их транспорты в `shadowlink/client/`, `skins/call/`, `server/udp_listener.go`, frontend pages/api/routes — действительно вырезаны. Поиск по `wbturn|WBTurn|whitepass|WhitePass|whitelist_bypass|WhitelistBypass|wbcreds|VkCall|NetworkWhitelist|WBTURN_ENABLED|VkTurn|TURNServer|TURNUsername|TURNPassword|ServerUDPAddr|ProtocolWhitePass|ProtocolTurnProxy|setupWhitePass|wb_turn|call_skin` в `*.go` / `*.ts` / `*.tsx` / `*.yaml` НЕ нашёл ни одной активной ссылки в production-коде. Only matches: archived docs (`shadowlink/docs/archive/2026-03/`), `docs/superpowers/plans/*` (исторические), и memory-файл.

Однако есть **четыре существенных хвоста**, которые memory-нота cleanup'а пропустила — все в области ShadowLink-deploy, который НЕ часть `wbturn/whitepass` пакетов и поэтому не попал в список удаления:

1. **HIGH** — `internal/admin/shadowlink_handlers.go` и `internal/deploy/steps_shadowlink.go` всё ещё пишут systemd-unit + YAML с полями `enable_udp: true` / `udp_listen: ":56000"` и явным комментарием `// всегда включаем UDP для WB TURN relay` (line 568 shadowlink_handlers.go). На деплое это попадает в `/etc/shadowlink/config.yaml`, который текущий `shadowlink-server` бинарник **молча игнорирует** (yaml.Unmarshal по умолчанию пропускает unknown fields в `FileConfig`). НЕ-fatal, но: (a) systemd unit конфиг полон lies, (b) тесты `TestRenderShadowLinkConfigYAML_*` всё ещё ассертят эти поля (`shadowlink_handlers_test.go:27,28,70,71`), фиксируя contract на удалённую фичу.
2. **HIGH** — Orphan dependency: `github.com/pion/turn/v4 v4.1.4` остаётся **прямой** require'ом в `D:/NIXAVPN/go.mod:20` (плюс `pion/dtls/v3` и `pion/logging` indirect). Ни один `*.go` файл этого не импортирует (грep пуст). `go mod tidy` либо не запускался после cleanup'а, либо что-то скрытно тащит — нужен `go mod why github.com/pion/turn/v4` для ясности.
3. **MEDIUM** — `UDPRelay.Cleanup()` (`shadowlink/server/udp_relay.go:131`) определён, но НИКОГДА не вызывается из production-кода. Нет периодического scheduler'а. `flows` map растёт неограниченно при таймаутах readLoop'а (см. ниже).
4. **MEDIUM** — Orphan migrations 061/064 безопасны для DB (UPDATE без WHERE EXISTS не фейлится, ALTER COLUMN IF NOT EXISTS — идемпотентный), но `whitelist_bypass` колонка в `plans` остаётся, prod-данные с `whitelist_bypass = true` (старые планы) **игнорируются** новым кодом — никаких side effects.

---

## Part A: Post-Cleanup Hygiene Audit

### A.1. Dangling references found (grep по списку из задания)

**В production-коде Go/TS:** _None_ — поиск по полному паттерну `wbturn|WBTurn|whitepass|WhitePass|whitelist_bypass|WhitelistBypass|wbcreds|VkCall|NetworkWhitelist|WBTURN_ENABLED|VkTurn|TURNServer|TURNUsername|TURNPassword|ServerUDPAddr|ProtocolWhitePass|ProtocolTurnProxy|setupWhitePass|wb_turn|call_skin` дал zero matches в `**/*.go`, `**/*.ts`, `**/*.tsx`, `**/*.yaml`, `**/*.json`.

**В YAML-конфиге:**
- `D:/NIXAVPN/shadowlink/config.yaml:8` — `wbturn: true`. Это dev-config (используется для запуска `nixavpn-client.exe` в `bin/` локально). Поле игнорируется client-side `LoadClientConfig` (поле в `ClientFileConfig` удалено), так что nothing breaks. **Cleanup task**: убрать строку для гигиены.

**В migrations:**
- `migrations/061_whitepass.sql:2,6` — `UPDATE protocol_configs SET protocol = 'whitepass' WHERE protocol = 'turn_proxy'`. Идемпотентный, безопасен, но переименовывает в название удалённого протокола.
- `migrations/064_whitelist_bypass.sql:1-8` — добавляет колонку `whitelist_bypass` в `plans`. Идемпотентен (`IF NOT EXISTS`).

**В docs/research/archive (намеренно сохранены с disclaimer):**
- `shadowlink/docs/research/2026-04-19-dpi-evasion-state-of-art.md` — disclaimer-блок в начале + упоминания в тексте (исторический контекст). OK.
- `shadowlink/docs/archive/2026-03/specs/2026-03-28-shadowlink-protocol-design.md` — архив. OK.
- `shadowlink/docs/archive/2026-03/plans/2026-03-29-upload-devices-dpi-udp.md`, `2026-03-30-tuning-and-security.md` — архив, с реализацией удалённых полей `EnableUDP`/`UDPListen`. Безопасно — это plans к 2026-03 рефакторингу.
- `docs/superpowers/plans/2026-04-09-ws-pool-implementation.md:781`, `2026-04-07-nixavpn-cli-client.md:652`, `2026-04-03-shadowlink-servers-integration.md:22,544,546` — упоминания `wb_turn` / `ProtocolWhitePass`. Все эти три плана отмечены в memory как "историческая справка"; первый (2026-04-03) даже имеет в Task 0 явный disclaimer. OK как есть.

### A.2. ОПАСНЫЕ остатки в production-коде ShadowLink-deploy (cleanup пропустил)

Cleanup-нота заявляет: «удалены `EnableUDP/UDPPort` поля» — но это касалось только модуля `shadowlink/`. В **главном модуле** все поля живы:

| File | Line(s) | Issue |
|------|---------|-------|
| `internal/admin/shadowlink_handlers.go` | 40-41 | `EnableUDP bool`, `UDPPort int` поля в `ShadowLinkConfig` |
| `internal/admin/shadowlink_handlers.go` | 132 | `EnableUDP bool` в DeployRequest (если есть) |
| `internal/admin/shadowlink_handlers.go` | 394-395 | `EnableUDP: true, UDPPort: 56000` в default deploy params |
| `internal/admin/shadowlink_handlers.go` | 567-569 | **критично**: `EnableUDP: true, // всегда включаем UDP для WB TURN relay` (комментарий явно ссылается на удалённую фичу) |
| `internal/admin/shadowlink_handlers.go` | 723-733 | Полный блок «Проверка UDP-режима для WB TURN», sed-патчит systemd ExecStart на `--enable-udp --udp-listen :56000`. **Этих CLI-флагов больше нет в `shadowlink/cmd/shadowlink-server/main.go`** — следовательно, после такого патча `systemd start shadowlink` упадёт с `flag provided but not defined: -enable-udp` |
| `internal/admin/shadowlink_handlers.go` | 727-728, 731 | sed + ufw allow 56000/udp |
| `internal/admin/shadowlink_handlers.go` | 881-894 | `renderShadowLinkConfigYAML` всё ещё пишет `enable_udp: %t\nudp_listen: ":%d"\n` |
| `internal/deploy/steps_shadowlink.go` | 26-27 | `EnableUDP`, `UDPPort` в `ShadowLinkDeployConfig` |
| `internal/deploy/steps_shadowlink.go` | 40-42 | те же поля в `ShadowLinkYAMLParams` |
| `internal/deploy/steps_shadowlink.go` | 49-67 | YAML template содержит `enable_udp:` / `udp_listen:` строки |
| `internal/deploy/steps_shadowlink.go` | 217-218, 232-234, 261-262 | hardcoded `EnableUDP: true, UDPPort: 56000` + `ufw allow 56000/udp` |
| `internal/deploy/uninstall.go` | 315 | `ports = append(ports, portProto{56000, "udp"})` (uninstall закрывает порт, который deploy открыл) |
| `internal/admin/shadowlink_handlers_test.go` | 27-28, 70-71 | `mustContain(t, out, "enable_udp: true")`, `udp_listen: ":56000"` — тесты **фиксируют orphan-поля как контракт** |

**Severity HIGH рассуждение:**

- На свежий деплой к новому серверу: `WriteShadowLinkConfigYAML` пишет YAML с двумя orphan-ключами + systemd unit шаблон НЕ содержит флагов (он использует `-config /etc/shadowlink/config.yaml`). YAML-парсер shadowlink-server'а молча игнорирует unknown fields → **сервер запустится OK**, но без UDP-функциональности (которая больше и не нужна — нет SOCKS5 UDP relay для WB TURN).
- На редеплой через `Update` handler (line 700-733): код **активно патчит** systemd unit добавляя `--enable-udp --udp-listen :56000` (`sed -i ...`). Эти флаги в новом бинарнике отсутствуют → **systemd start падает**. Это критический regression на upgrade-pass.
- Если `bin/shadowlink-server-linux` пересобран после cleanup'а 2026-04-25 и заливается на pl1 (104.222.177.67) через Update, **рабочий сервер сломается**.

### A.3. DB consistency risks

**Migration 061 (`whitepass`)** — UPDATE без WHERE EXISTS, без триггеров: безопасно. Прод-данные в `protocol_configs` с `protocol IN ('whitepass', 'turn_proxy')` — лежат, но никаких чтений по этим protocol'ам код больше не делает. `GetNodeRuntime` в `internal/config/assembler.go` спрашивает только `protocol = 'VLESS'/'TrustTunnel'/'shadowlink'/'MTProxy'/'VLESS_WS'` (line 306-308, 321-331, 336-338) — записи `whitepass`/`turn_proxy` тихо игнорируются. **Нет каскадных fault'ов.**

**Migration 064 (`whitelist_bypass`)** — ALTER TABLE IF NOT EXISTS, идемпотентен. Колонка `whitelist_bypass` остаётся в `plans`. Нет SELECT'ов из неё в код'е после cleanup'а (грep `whitelist_bypass` в `*.go`: zero matches). **Нет fault'ов.**

**Что произойдёт при попытке деплоя через UI к серверу с старым `whitepass`/`turn_proxy` configom?** Депл-флоу основной orchestrator (`internal/deploy/orchestrator.go:GetProtocolModule`) знает только: VLESS, Hysteria2, Shadowsocks, TrustTunnel, MTProxy (`internal/deploy/protocols.go:514-526`). ShadowLink идёт через отдельный `ShadowLinkHandler` (не через `ProtocolModule`-роутинг). **Если в admin UI для server'а X стоят серверные protocols `whitepass`/`turn_proxy` (это row в `server_protocols` JOIN `protocols` table)** — UI просто не покажет их в списке деплоя (frontend фильтрует по known protocols). Но если они все ещё в БД — `Deploy` handler'у дадут `protocols: []ProtocolType{"whitepass"}` → `GetProtocolModule("whitepass")` возвращает `error("неподдерживаемый протокол")` → 500 с понятным текстом. Не катастрофа.

**Recommendation**: добавить cleanup migration **065** или 071:
```sql
-- 071_cleanup_dead_protocols.sql
DELETE FROM protocol_configs WHERE protocol IN ('whitepass', 'turn_proxy', 'wbturn');
DELETE FROM server_protocols WHERE protocol_id IN (SELECT id FROM protocols WHERE name IN ('whitepass', 'turn_proxy'));
DELETE FROM protocols WHERE name IN ('whitepass', 'turn_proxy');
ALTER TABLE plans DROP COLUMN IF EXISTS whitelist_bypass;
```
(но сам автор прямо просит НЕ удалять migrations 061/064 — для DB-операций они не нужны, потому что код не читает эти поля.)

### A.4. OpenAPI / Frontend orphans

**OpenAPI spec** — `internal/admin/openapi.yaml`: грep по `whitepass|wbturn|WhitePass|WBTurn|whitelist_bypass|turn_proxy|turn-link` дал zero matches. Чисто.

**Frontend (TypeScript)** — `frontend/src/`: грep `whitepass|wbturn|WhitePass|WBTurn|whitelist_bypass|turn_proxy|TurnProxy|wb_turn` дал zero matches. Чисто.

**Prod data с `whitelist_bypass: true` в response API** — backend `/api/admin/plans` (`internal/admin/plans.go:124-148`) НЕ селектит whitelist_bypass из БД, в JSON-ответе поля нет, frontend Plan type его не имеет. Старые row'ы в БД остаются orphan, но invisible для UI. **Нет UI-багов.**

### A.5. Tests fixing orphan contracts

`internal/admin/shadowlink_handlers_test.go:8-36` (TestRenderShadowLinkConfigYAML_BaseSection) и `:38-100` (TestRenderShadowLinkConfigYAML_WithLiveBlog) **активно ассертят** что output содержит `enable_udp: true` (line 27, 70) и `udp_listen: ":56000"` (line 28, 71). Это **фиксирует мёртвый contract** — попытка fix'а render'а под cleanup сломает тесты. Тесты должны быть обновлены или удалены вместе с YAML rendering'ом.

---

## Part B: Code Quality Findings

### CRITICAL

_None_ — `client.go`, `handler.go`, `server.go` написаны очень аккуратно (sync.Once для handshake, atomic.Pointer для wstPtr в client main, errors.As/Is everywhere, replay cache + rate limiter + auth gate'ы во всех правильных местах).

### HIGH

#### H1. `enable_udp`/`udp_listen` orphan-поля в deploy/admin (см. Part A.2 для деталей)

- `internal/admin/shadowlink_handlers.go:40-41,394-395,567-569,723-733,881-894`
- `internal/deploy/steps_shadowlink.go:26-42,49-67,217-234,261-262`
- `internal/deploy/uninstall.go:315`

**Impact**: тихий info-leak в YAML; явный break при Update-flow на pl1 (sed добавляет несуществующие CLI-флаги). **Action**: удалить все ссылки + `bin/shadowlink-server-linux` пересобрать только если эти флаги действительно убраны (verified — pure CLI flags removed in `shadowlink/cmd/shadowlink-server/main.go`).

#### H2. `UDPRelay.flows` map утекает при readLoop exit

- `shadowlink/server/udp_relay.go:95-128`

`readLoop` exits when `flow.conn.Read` returns timeout/error (line 120-126), но **НЕ удаляет `streamID` из `r.flows`**. Закрытый conn остаётся в map. `Cleanup()` определён, но грep по production code не нашёл ни одного callsite — нет периодического scheduler'а. На long-lived servers map растёт unbounded.

**Action**: добавить `defer r.RemoveFlow(streamID)` в начале `readLoop` (RemoveFlow корректно `flow.conn.Close()` уже-закрытого conn — net.UDPConn.Close идемпотентен), ИЛИ вернуть scheduled `Cleanup()` в `Server.Start` (как `handler.StartCleanup(stopCh)`).

#### H3. Orphan `pion/turn/v4` direct require в go.mod

- `D:/NIXAVPN/go.mod:20`

Прямой require, нет ни одного импортирующего `*.go` файла после cleanup'а. Тащит `pion/dtls/v3`, `pion/logging`, `pion/transport/v3`, `pion/randutil` (indirect lines 102+ go.mod). Если `go mod tidy` запускался после удаления `internal/turn` — он бы их вычистил. Не вычистил — значит либо tidy не запускался, либо что-то импортирует pion (test file? generate?). Запуск `go mod why github.com/pion/turn/v4` подтвердит.

**Action**: запустить `go mod tidy` в корне `D:/NIXAVPN`, проверить diff. Если по-прежнему остаются — `go mod why` для трейсинга.

### MEDIUM

#### M1. `UDPRelay` race на `flow.onReceive` callback

- `shadowlink/server/udp_relay.go:75-77,107`

`Send` (line 75-77) перезаписывает `existing.onReceive` под write-lock. `readLoop` (line 107) читает под RLock. После этого **`cb` хранится в локальной переменной**, но callback внутри (если synchronous) дёргает на потенциально устаревшем onReceive если Send-ы конкурентные. Не data race в Go-смысле (lock'и есть), но **logic race**: response от старого target может быть отдан новому handler'у. Маловероятно в реальной топологии (один streamID = один client tunnel), но contract'но не защищено.

**Action**: либо привязать onReceive к streamID одноразово (immutable после Send #1), либо документировать «`onReceive` last-writer-wins» в типе.

#### M2. `ShadowLinkHandler.deploying sync.Map` без TTL

- `internal/admin/shadowlink_handlers.go:30`

Если deploy упадёт panic'ом (что блокирует defer Delete) — `serverID` остаётся залочен навсегда, кнопка Deploy в UI вечно показывает «Deploying…». Защита от concurrent deploy'ев OK, но recovery — нет.

**Action**: `defer h.deploying.Delete(serverID)` + `defer recover()` в горутине, ИЛИ добавить `time.AfterFunc(30*time.Minute, func(){ h.deploying.Delete(serverID) })` как safety-net.

#### M3. `internal/deploy/steps_shadowlink.go:182` saveKeyCmd inline echo

```go
saveKeyCmd := fmt.Sprintf("echo -n '%s' > /etc/shadowlink/server.key && chmod 600 ...", privateKey)
```

`privateKey` — hex-строка из generateShadowLinkKeys (controlled), без shell-spec символов. **Не уязвимо**, но pattern'но shell-injection-prone. На случай если будущий код подставит user-input — лучше через `WriteToRemoteFile` как все остальные binary uploads.

#### M4. `ProtocolType` parameter в `cleanupProtocolDB` приводится к строке для SQL

- `internal/deploy/uninstall.go:328`: `LOWER($2)` где $2 = `string(protocol)`.

Параметризованный query, нет SQL-injection. Но typed `ProtocolType` в строку и обратно везде — wired. Минорно.

#### M5. `Tunnel.closeOnce` защищает закрытие, но send'ы на уже-closed channel могут паниковать

- `shadowlink/server/handler.go:80-87`

`closeTunnel` закрывает Incoming/Outgoing/OutgoingUDP. Если другой goroutine делает `tunnel.Outgoing <- data` после close — panic. Грep по `tunnel.Outgoing <-` показывает ~10+ usages во всём handler.go. Большинство в `select { case ... <-tunnel.Outgoing: ... case <-tunnel.done: return }` форме — корректно. Но `BroadcastStreamClose` (handler.go:~187) шлёт FlagFin без защиты; нужно убедиться что закрытие tunnel'а происходит **после** того как все прокси-горутины убрались.

**Action**: добавить test'ы на race-detected `TestConcurrentTunnelClose` (если ещё нет).

#### M6. `internal/admin/shadowlink_handlers.go:885-894` — fail-open YAML для пустых полей

`udpPort := cfg.UDPPort; if udpPort == 0 { udpPort = 56000 }` — fallback на orphan-port. После H1 fix всё равно становится no-op (поля удаляются), но пока — silently injects 56000.

### LOW (style / idiom)

#### L1. `internal/client/config_handlers.go:69` — `mode := c.Query("mode")` объявляется и используется только в TrustTunnel-ветке

После удаления `mode=wbturn` ветки — `mode` живёт за пределами trust-tunnel-блока, передаётся как 4-й аргумент `AssembleTrustTunnelConfig`. Не баг, но `mode` мог бы быть локальной переменной trust-tunnel-блока.

#### L2. `shadowlink/config.yaml:8` — `wbturn: true` orphan строка в dev-config

Полностью игнорируется новым `LoadClientConfig` (поле не в struct), но мусор в репо.

#### L3. `internal/deploy/uninstall.go:315` — комментарий `// ShadowLink UDP` без объяснения **зачем** UDP закрывается

После cleanup'а UDP относится либо к нативному SOCKS5 UDP ASSOCIATE relay, либо это hangover от WB TURN. Комментарий не помогает читателю понять.

#### L4. `Default*` функции в `LiveBlogConfigJSON` (shadowlink_handlers.go:800-821) дублируют `shadowlink/server.DefaultLiveBlogConfig()` "kept in sync by hand"

Кросс-модульный duplication. На случай rename — баг легко проникнет. OK для нынешнего этапа, но `// TODO: replace with codegen from shadowlink/server` — правильный путь.

---

## Concurrency Audit

### Goroutine leaks

1. **H2 (UDPRelay.flows)** — описан выше.
2. `cmd/shadowlink-client/main.go:247-274` (WS reader reconnect goroutine): exits корректно через `readerCtx.Err()`. OK.
3. `cmd/shadowlink-client/main.go:390-403` (atomic-WST-sync ticker): exits через `socksCtx.Done()`. OK.
4. `shadowlink/server/handler.go` различные `go h.readPump(...)` / `go h.writePump(...)` для WebSocket — все за-defer'ены `defer ws.Close()` + listen на `tunnel.done`. Spot-check OK.

### Race conditions

- `Client.handshakeOnce` reset под `c.mu` (client.go:194-197) — корректно, double-locking pattern.
- `core.Session` (handshake-time created) hand'inty wired в Tunnel — `tunnels` map защищён `tunnelsMu`. OK.
- `UDPRelay.flow.onReceive` (M1) — описан.

### Channel deadlock potential

- `Tunnel.closeOnce` (M5) — close после которого send'ы могут паниковать; защищается select-on-done.
- `OutgoingUDP` отдельный канал — корректно изолирует UDP responses от TCP downstream. OK.

### Error handling

- В `client.go:101-110, 248-249` — `errors.As`/`errors.Is` правильно.
- В `internal/admin/plans.go:214` — `errors.Is(err, sql.ErrNoRows)` правильно.
- В `internal/client/config_handlers.go:300, 312` — устаревший `err == sql.ErrNoRows` (line 300, 312). **LOW**: предпочесть `errors.Is`.

### Resource leaks

- `internal/admin/plans.go:158-166, 169-177, 226-235, 237-245, 637-646` — паттерн `if rows != nil { rows.Close() }` — manual cleanup. Если внутри loop'а return до Close — leak. **MEDIUM**: использовать `defer rows.Close()` после nil-check.
- `Tunnel.targetConn` (handler.go:75) — кто закрывает? Спот-чек: при FIN — `handleFin` закрывает; при server stop — `BroadcastStreamClose` шлёт FIN, но conn реально закрывается клиентом. На force-stop без cooperation — leak.

### Timing leaks in crypto

- `ackJitter()` (handler.go:141-148) — exponential distribution, [0, 150ms]. **Хороший fix** для V6 timing-side-channel.
- `failClosedToDecoy` — упомянут в комментариях, единый точка для всех fail-paths. Defense-in-depth.
- `subtle.ConstantTimeCompare` — спот-чек core/ нашёл правильное использование в session token comparison. OK.

### Input validation на boundary

- `cmd/shadowlink-client/main.go:161-165` — `len(pubKeyBytes) != 32` validation OK.
- `shadowlink/client/client.go:24-35` — `isValidUA` — strict bounds check, printable-ASCII filter. **Excellent**.
- Server `ReadBodyLimited` (handler.go:248) — bounded by chunk size + 1KB, defense against memory inflation. OK.

---

## Test Coverage Gaps

После удаления `testutil/turn_test_server` and friends:

1. **UDPRelay.Cleanup leak test** — отсутствует regression test «map не растёт после N timeout'ов». Нужен.
2. **`TestHybridDispatch*`** в `shadowlink/server/handler_hybrid_test.go` — есть, race-tested per-CLAUDE.md (`go test -race`). OK.
3. **`internal/admin/shadowlink_handlers_test.go`** — фиксирует orphan contract (см. A.5). После H1 fix эти ассерты удалить.
4. **`internal/deploy/steps_shadowlink.go`** — нет unit-test'ов на `WriteShadowLinkConfigYAML` (есть только integration через test server). После H1 fix добавить test'ы что rendered YAML НЕ содержит `enable_udp:` / `udp_listen:`.
5. **Probe.go** — `probe_test.go` есть (`shadowlink/client/probe_test.go`), но логика **после удаления NetworkWhitelist** не имеет test для случая «whitelist-only network возвращает теперь NetworkOffline» — тип удалён, тесты должны быть переадаптированы. Spot-check показал что тесты и `Classify` оба знают только `Open / DPIBlock / Offline` — consistent. OK.

---

## Open Questions

1. **`shadowlink/config.yaml:8 wbturn: true`** — что-то ещё этой строкой пользуется? Грep по `wbturn:` в `*.go` zero matches. Можно удалять.
2. **`pion/turn/v4` direct require** — почему `go mod tidy` его оставляет? Запрос `go mod why` от пользователя нужен для финального вывода.
3. **migration 071 cleanup-script** — добавлять или нет? Плюсы: чистый schema. Минусы: irreversible, может ломать backups. Решение за владельцем.
4. **Bin updates** — нужно ли вручную пересобрать `bin/shadowlink-server-linux` (есть в git'е) и убедиться, что в нём действительно нет CLI-флагов `-enable-udp`/`-udp-listen`? Учитывая что cleanup memory-нота утверждает «свежие билды зелёные», но в `internal/admin/shadowlink_handlers.go:728` activeно патчится systemd unit на эти флаги — **рекомендация**: пересобрать `bin/shadowlink-server-linux` после H1-fix'а, ОТЛОЖИТЬ деплой Update до фикса, либо предупредить пользователя что Update сейчас сломает pl1.

---

## Recommended Action Items (ordered)

1. **HIGH — H1**: вырезать `EnableUDP`/`UDPPort` из `internal/admin/shadowlink_handlers.go`, `internal/deploy/steps_shadowlink.go`, `internal/deploy/uninstall.go:315`, обновить `shadowlink_handlers_test.go`. Удалить sed-патч-блок (line 700-733) полностью.
2. **HIGH — H2**: добавить `defer r.RemoveFlow(streamID)` в `UDPRelay.readLoop` ИЛИ запустить `Cleanup` scheduler в `server.Server.Start()`.
3. **HIGH — H3**: запустить `go mod tidy` в корне, проверить остаток `pion/*` зависимостей. Если не уходят — `go mod why` для трейсинга.
4. **MEDIUM — M2**: TTL safety-net на `ShadowLinkHandler.deploying`.
5. **LOW — L2**: убрать строку `wbturn: true` из `shadowlink/config.yaml`.
6. **Optional — Migration 071**: cleanup-script для protocol_configs / plans.whitelist_bypass.

---

## Stance

Cleanup в **shadowlink/** module был выполнен корректно. Cleanup в **главном модуле NixaVPN** ограничился пакетами `internal/{wbturn,whitepass,turn}` и не coснулся `internal/admin/shadowlink_handlers.go` + `internal/deploy/steps_shadowlink.go`, где осели `EnableUDP`/`UDPPort` поля и явные комментарии «для WB TURN relay». Остаточные orphan-Go-references — **deploy-critical** на upgrade pass. Production-safety после fix'а H1 + H2 — высокая. Code quality базы (client.go / handler.go / core) — **opus-tier**, comments объясняют не только «что», но и «почему» для security-decisions.

Стратегически проект готов к продолжению Tier-1 roadmap'а после закрытия H1-H3. Production deploy на pl1 (Update flow) — **не запускать** до H1 fix'а.
