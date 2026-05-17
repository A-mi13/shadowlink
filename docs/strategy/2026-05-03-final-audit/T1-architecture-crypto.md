# T1 — Architecture + Crypto Audit (2026-05-03)

**Scope:** ShadowLink core crypto primitives, handshake state machine, replay
defense, session lifecycle, key derivation, server-side dispatch, client key
boot, server boot, и at-rest secret hygiene (CF API token / SSH password
encryption через `APP_ENCRYPTION_KEY`, bypass HMAC ключ).

**Baseline sha:** 7c8e99d6 (deployed на pl1 = datacanvases.com, 2026-05-03).

**Reviewed files (top-level):**
- `shadowlink/core/`: crypto.go, handshake.go, session.go, replay_cache.go,
  mimicry_session.go, pool.go, chunk.go, chunk_sizing.go, bufpool.go.
- `shadowlink/server/`: handler.go, websocket.go, config.go, fileconfig.go,
  ratelimit.go, decoy_timing.go, server.go, clientid_exempt.go, tokenbucket.go.
- `shadowlink/client/`: client.go, connmanager.go, datapath.go, ech.go,
  heartbeat.go, domain_pool.go, utls_http.go, split_transport_tls.go,
  bypassroute/admin_fetch.go, bypassroute/admin_cache.go.
- `shadowlink/cmd/shadowlink-server/`: main.go, export.go.
- `shadowlink/cmd/nixavpn-client/`: main.go, config.go.
- `internal/admin/`: shadowlink_token_crypto.go, shadowlink_token_rotation.go.
- `internal/config/config.go` (loadShadowLinkBypassHMACKey).
- `migrations/074_shadowlink_pool_servers_ssh_creds.sql`.

---

## Executive Summary

- **New findings:** P0=0, P1=2, P2=4, P3=3.
- **Regressions:** 0 (все checked baselines confirm closed).
- **Verified-still-closed:** 9 spot-checks (A1, C14, replay-cache encClientID
  key, PQ cold-path symmetry, HKDF protoVersion bind, MimicrySession publish
  ordering, A1-M2 sendEpoch atomic-pointer, atomic stats callbacks publish,
  newborn-orphan eviction).

Под threat model 2026-04 (TSPU active probing, GFW heuristic + 5-вектор
classifier, application-aware MITM на CDN edge, leaked GFW capabilities в
KZ/ET/PK/MM) crypto baseline в порядке. 2 P1 — это application-aware
detection signals, не break-the-protocol; 4 P2 — operational hygiene и
timing-oracle тонкости, эксплуатация требует sustained traffic capture от
network observer + способность связать flows. Никаких break-glass dangers
не найдено.

Главное наблюдение: crypto core (X25519 ECDH → HKDF-SHA256 → AES-256-GCM,
NaCl box для clientID encapsulation) — solid. Все апрельские/майские
закрытия (A1-M1 sliding-window replay, A1-M2 sendEpoch atomic, A1-M3/M4
plaintext zero + clientID strict, C11.2/C11.3 atomic publish ordering,
T1.4 body-prefix wire) hold at sha 7c8e99d6.

---

## New Findings

### P1 — Asymmetric ScalarMult cost between success and failClosedToDecoy

- **File:** `shadowlink/server/decoy_timing.go:143-170` (`runSyntheticDispatch`)
  vs `shadowlink/server/handler.go:494-531` (`handleHandshakeNew` success).
- **What:** На failClosedToDecoy выполняется 1× `core.GenerateKeyPair()`
  (один X25519 ScalarMult) + 1× `gcm.Open` на случайных байтах. На успешном
  handshake — 3× X25519 ScalarMult: один внутри `core.DecryptClientID`
  (`box.Open` делает X25519 ScalarMult по эпh-pub), один в `GenerateKeyPair()`
  (генерация server eph), один в `ComputeSharedSecret` (ECDH). Плюс HKDF
  на ~50 ns и `encryptSessionToken` AES-GCM Seal.
- **Why it matters:** ScalarMult на современном x86_64 — ~50-100µs (Go
  `crypto/ecdh.X25519` после конст-time оптимизаций). Дельта между success
  и fail = ~150-200µs. ackJitter median ≈ 5ms (`handler.go:280`) маскирует
  median-to-median, но **stationary observer на CDN edge** агрегирует
  тысячи запросов и делает per-IP histogram — distribution shift в нижней
  ~10% тейле сохранится. Это application-aware detection signal:
  attacker-CDN может пометить флоу как "real ShadowLink session" vs
  "broken/scanning probe" и применить per-flow rate-limit или DPI hints.
  **Не affects крипто confidentiality, но affects steganographic
  indistinguishability** — а именно она и есть value prop.
- **Repro / signal:** Бенчмарк (`go test -bench`) `failClosedToDecoy` vs
  `handleHandshakeNew` happy-path с одинаковым входом, замерить ratio
  cycles per request; на >10M iter difference будет статистически
  значимая (KS-D > 0.02 ожидается).
- **Mitigation direction:** Add `core.GenerateKeyPair() × 2` and one
  `box.Open`-equivalent ScalarMult to `runSyntheticDispatch` so the
  failClosedToDecoy CPU profile matches success path within the ackJitter
  noise floor. Must NOT short-circuit on early failures
  (`DecryptClientID` invariants like `idLen != 16` already trigger after
  box.Open, so they keep the constant-time property).

---

### P1 — `pqClientHelloSpec` mutates a SHARED Extension slice on hot path

- **File:** `shadowlink/client/utls_http.go:42-77`.
- **What:** `pqClientHelloSpec()` derives a `ClientHelloSpec` via
  `utls.UTLSIdToSpec(utls.HelloChrome_133)`. The returned spec contains
  pointer extensions (`*utls.SupportedCurvesExtension`,
  `*utls.KeyShareExtension`). Function then mutates `v.Curves` and
  `v.KeyShares` in place (`append`), but `UTLSIdToSpec` does NOT
  guarantee a fresh allocation per call — utls v1.8.3 returns extensions
  pointing into a package-level descriptor table shared across goroutines
  and across handshakes.
- **Why it matters:** Two cold-path handshakes racing inside
  `buildUTLSDialTLS` (split_transport, ws warmup, probe.probeHTTPS, ECH
  DoH) may both invoke `pqClientHelloSpec()` concurrently. If utls returns
  shared pointers, the `append`-to-front operation on `v.KeyShares` could
  produce a corrupted slice (Go append on unaliased shared slice is
  data-race UB). The "hasMLKEM" check before append makes the operation
  idempotent on stable utls versions where MLKEM is already present at
  index 1, so in production Chrome_133 the append branch never fires —
  this is currently a latent bug, not a live one. **Risk:** an utls
  upstream bump that drops MLKEM from the canonical Chrome_133 spec would
  silently turn this into a race + ClientHello corruption (TLS
  handshake-level, would surface as random handshake failures).
- **Repro / signal:** `go test -race` against a parallel call to
  `pqClientHelloSpec` after an utls upstream that removes MLKEM would
  flag the data-race. Currently undetectable on v1.8.3 because the
  branch is short-circuited.
- **Mitigation direction:** Make `pqClientHelloSpec` defensively
  deep-copy the spec.Extensions slice and the underlying extension
  structs before mutating. Same defensive pattern used in
  `client/connmanager.go:profileForFingerprint` (which returns a
  fresh value, not a pointer). Adds ~200 ns per cold-path handshake —
  invisible.

---

### P2 — Bypass admin override: HMAC scope omits `etag` (rollback / freshness oracle)

- **File:** `shadowlink/client/bypassroute/admin_fetch.go:85-99`.
- **What:** `FetchAdminOverride` re-marshals the response body as
  `{adds, excludes}` (without `etag`) and verifies HMAC over that. The
  `etag` field carries the version label but is NOT covered by the
  signature — a MITM with TLS-tampering capability (or a compromised CDN
  edge) can rewrite `etag` arbitrarily on top of a legitimate
  `{adds, excludes, sig}` body without breaking signature verification.
- **Why it matters:** Two failure modes.
  (a) **Rollback:** MITM caches an OLD legitimate response and serves it
  with a forged "future" etag. Client persists this as the latest cached
  override; subsequent fetches that get a 304 trust the stale-but-valid
  cache. Practically downgrades the client's CIDR-bypass list to an
  older version — could re-introduce blocked CIDRs that admin already
  removed. Limited blast radius (CIDRs only, not data-path crypto), but
  it silently undermines the kill-switch guarantee that bypass-list
  drives.
  (b) **Freshness oracle / DOS:** MITM rewrites etag on every response
  to match the client's currentEtag → server returns 304 → client never
  refreshes, even when admin pushed a new list. Client believes its
  cache is current.
- **Repro / signal:** N/A in code; passive verification: `etag` does
  not appear in `checkBody` build (line 86-89). Server-side
  counterpart should be checked for the same omission.
- **Mitigation direction:** Either include `etag` in the signed JSON
  body (server side and client side mirrored), OR sign the etag
  separately and require both in the response header. Current
  acceptance test fixtures should be updated to bind the etag.

---

### P2 — `ServerHello` UA field not authenticated; client trusts server-issued strings

- **File:** `shadowlink/server/handler.go:1854-1881` (encodeServerHello UA),
  `shadowlink/client/client.go:423-435` (`isValidUA` check + apply).
- **What:** Server emits a `ua` map in ServerHello (Chrome / Safari /
  Firefox) that the client validates via `isValidUA` and then calls
  `browser.UpdateUserAgents` on. ServerHello is delivered through the
  body-prefix path, decrypted via `decryptSessionToken` — so the UA
  string IS authenticated end-to-end by the session keys (not by a
  separate MAC). That part is fine.
- **Why it matters:** The validation regex in `isValidUA` is permissive
  enough that a **compromised server** (post-key-leak) can push a
  malicious UA string that still parses (length 10-256 ASCII printable +
  contains "Mozilla/" + one of "Chrome|Firefox|Safari/"). For example
  `Mozilla/5.0 Chrome/9999 ;DROP TABLE` (assume future logging
  vulnerability), or a version string old enough to disable PQ on
  CF edge while keeping the JA3 wire-correct. The threat model upgrade
  here is **server compromise + client downgrade** — the server already
  has session keys, so this is not a new disclosure path; but it widens
  the "what a compromised server can do to its clients" surface from
  "decrypt + relay" to "remotely re-fingerprint the client fleet".
- **Repro / signal:** `client/client.go:423-435` — no version
  comparison, no signature. Any UA the server picks is applied
  process-wide via `browser.UpdateUserAgents`.
- **Mitigation direction:** (a) Add a min-version floor in the client
  (refuse UAs older than locked Chrome major). (b) Refuse UAs that
  don't match `LockedChromeMajor` exactly — the lockstep contract from
  F2 (2026-05-02) already establishes a single major source of truth.
  (c) Or scrap the UA-update mechanism entirely; it is described in
  encodeServerHello as "UA update mechanism: server sends current
  browser UA strings so clients stay up-to-date without code changes"
  but with the F2 lockstep that decision now lives in
  `skins/browser/fingerprint.go` constants, not server-issued strings.

---

### P2 — Newborn-orphan eviction iterates the full session map under write lock (DoS amplification)

- **File:** `shadowlink/core/session.go:554-581` (`CleanupNewbornOrphans`).
- **What:** The cleanup loop holds `sm.mu.Lock()` (write lock) while
  iterating ALL sessions and zeroing key material on every orphan via
  `s.mu.Lock()`. With WindowSize = 16384 and `MaxClients` default 100,
  the iteration is small. However, in deployments tuned for high
  concurrency (`MaxClients` set to thousands), every cleanup tick (30s
  default) blocks new handshakes/data POSTs for the duration of the
  scan + per-session lock acquisition.
- **Why it matters:** **Amplifies handshake-abuse DoS.** An attacker
  who triggers handshake POST that succeeds but never WS-attaches
  (which is exactly what the §C10 M2 fix targets) can fill the orphan
  pool faster than the cleanup tick. With per-IP rate limit at
  burst=50 refill=300/min, a botnet of ~20 IPs sustains 100/sec orphan
  creation → in 30s = 3000 orphans → cleanup run holds the write lock
  for ~30ms × per-orphan zero work; concurrent legit handshakes wait.
  Combined with the `clientid_exempt` cache it may flap under cascade.
- **Repro / signal:** Stress test: spawn 100 concurrent handshake
  POSTs without follow-up WS upgrade, observe `OrphanSessionCleaned`
  counter and write-lock contention via `pprof contention`.
- **Mitigation direction:** Two-phase cleanup — collect orphan IDs
  under RLock first, release, then re-acquire per-session write lock
  to zero each. Or shard the sessions map. Plan §C10 M2 was designed
  for the failure case where ONE orphan accumulates per legit-fail; it
  did not size for adversarial volume.

---

### P2 — `serverHelloJSON.UA` map: no per-key ASCII bound on value

- **File:** `shadowlink/client/client.go:422-435`.
- **What:** `isValidUA` is called per UA string but the UA map keys
  themselves (e.g., "chrome", "safari") are not validated. If server
  sends `{"chrome": "ok-ua", "x\x00y": "ok-ua"}` the second key is a
  binary-control-char-injected key that propagates to
  `browser.UpdateUserAgents`. The downstream usage is in fingerprint
  selection, where the keys are matched against `ProfileChrome`
  constants — bogus keys are silently ignored. So practical exploit
  surface = "noisy log entries" if anyone slogs the map keys.
- **Why it matters:** Defensive hygiene. Threat model is server-comprom;
  the worst that can happen is logging malformed strings. Not
  data-path or crypto.
- **Mitigation direction:** Validate keys against a fixed enum
  `{"chrome","safari","firefox"}` before insertion.

---

### P3 — `core.NewSessionManager` ignores `rand.Read` error on initial nextID seed

- **File:** `shadowlink/core/session.go:447-457`.
- **What:** `var buf [4]byte; rand.Read(buf[:]); sm.nextID.Store(...)` —
  err return is dropped. On extremely degraded systems (initramfs
  before urandom seed, broken CSPRNG) the buffer stays zeroed and
  nextID seeds at 0 → first session gets ID = 1 (predictable).
- **Why it matters:** Session ID disclosure is already explicitly
  not a confidentiality boundary (the encryption keys protect the
  data). However, the original A1 audit added the random seed
  specifically to defeat session ID prediction — so silently
  ignoring rand failure regresses that mitigation in degraded
  hosts.
- **Mitigation direction:** Panic on `rand.Read` failure during
  manager construction (server boot path; failing fast at startup
  is better than silently weak ID space at runtime).

---

### P3 — `core.DecryptClientID` 300-second drift window has no monotonic-clock guard

- **File:** `shadowlink/core/crypto.go:188-192`.
- **What:** `if diff := timeNow() - ts; diff > 300 || diff < -300` —
  the check uses Unix wall-clock time. If the server's wall clock
  jumps backwards (NTP step, container snapshot restore, virt-host
  pause/resume), recently-issued legitimate handshakes may fall
  outside the window and be rejected; conversely, replay-window
  semantics shift if clock leaps forward.
- **Why it matters:** Operational, not security-critical for active
  attacks (replay cache provides separate per-cipher protection
  via `Accept(encClientID, ts)` — see line 513). But the 5-min
  window is treated as authoritative by both DecryptClientID and
  ReplayCache; clock-skew between client and server bigger than
  300s causes "handshake timestamp expired" errors that ops
  attribute to other root causes.
- **Mitigation direction:** Document the wall-clock dependency
  explicitly in the godoc; ops runbook should pin chrony / require
  NTP sync. Out of scope for code change.

---

### P3 — `EncryptedClientIDSize=65` constant is wire-frozen but only enforced on encode, decode-side strict check is `idLen != 16` not slot-length

- **File:** `shadowlink/core/handshake.go:11-16`,
  `shadowlink/core/crypto.go:138-208`.
- **What:** Encode rejects clientID > 16 (line 139). Decode now
  rejects `idLen != 16` (line 201, post-C14). However the parser in
  `handleNewFormatPost:768` still uses `EncryptedClientIDSize` (65)
  to slice `payload[32:v1HandshakeMin]` — this is the only authority
  on the field length. If a future server bumps clientID encoding
  (e.g., to support 32-byte IDs), updating `EncryptedClientIDSize`
  alone is insufficient — `ParseHandshakePayload` and the parser
  here both assume 65.
- **Why it matters:** Forward-compat hazard. Today shipping safe;
  any future protocol bump must update both encode-strict bound
  AND parser slot AND DecryptClientID idLen check in one
  atomic change. This is documented in the constant comment but
  not test-pinned.
- **Mitigation direction:** Add a single `coreEncodeAssertion`
  that round-trips one canonical 16-byte UUID through encode →
  parse → decrypt → idLen check, fail loudly if any of those drift.
  Currently the test files do this implicitly per-test; an
  explicit invariant helper would catch a future contributor who
  bumps the constant in one place.

---

## Regressions

None. All baseline-closed findings reviewed (Phase 1 closure 47-finding
ledger, Phase 2 closure 5 detection signals, may-audit P0/P1/P2 packs,
T1.4 body-prefix migration, T1.3 live decoy) hold at sha 7c8e99d6.

---

## Verified-Still-Closed (spot checks)

- **A1 backoff clamp.** `client/client.go:954-961` (`backoffDuration`) —
  exp(2^attempt) capped at 60s with ±25% jitter. Holds. Companion is
  `slotBackoffDuration` for WS pool slow-start (memory note Tier S R.1).

- **C14 strict 16-byte clientID (decode side).**
  `core/crypto.go:201-203` — `if idLen != 16 { return … "invalid
  clientID size" }`. Holds. Symmetric with encode-side bound at line 139.
  Server-side parser slot via `EncryptedClientIDSize=65` const at
  `core/handshake.go:16`.

- **Replay cache key = encClientID ciphertext.**
  `server/handler.go:511-517` — `h.replayCache.Accept(encClientID,
  core.TimeNowUnix())` keys on raw `encClientID` (NaCl box ciphertext
  including 24-byte CSPRNG nonce). Holds — fixes the 2026-04-30 data-plane
  drift bug where keying on decoded clientID broke WS pool of 8 parallel
  handshakes from one device.

- **PQ cold-path symmetry.**
  `client/split_transport_tls.go:65-90` — `usePQ := pqEnabled()` per-dial
  in `buildUTLSDialTLS`, so cold-path reads same env flag as WS-upgrade
  hot-path. Closes Phase 2 closure must-do-soon. Holds.

- **HKDF protoVersion bind.** `core/crypto.go:99-112` — info string
  embeds `protoVersion` byte before clientPub/serverPub/clientID. Different
  versions derive byte-different keys from same X25519 share. Holds —
  downgrade attack closed.

- **MimicrySession publish-before-map.**
  `core/session.go:485-490` — `s.MimicrySession = NewMimicrySession()` ↑
  `sm.sessions[id] = s` ↓. happens-before edge from assignment to every
  reader. Closes §C11.3. Holds.

- **A1-M2 sendEpoch atomic-pointer rekey.**
  `core/session.go:186-209` — `Rekey` builds a fresh `sendEpoch{gcm: …}`
  with counter starting at 0, then `s.sendEpochPtr.Store(newSendEpoch)`.
  Concurrent encrypters observe consistent (gcm, counter) pair via
  single atomic Load. Holds.

- **Atomic stats callbacks publish.**
  `core/session.go:255-285` — `statsCallbacks` struct published via
  `atomic.Pointer[statsCallbacks].Store`; hot-path readers Load once
  and nil-check. Closes §C11.2. Holds.

- **Newborn-orphan eviction wiring.**
  `core/session.go:554-581` (`CleanupNewbornOrphans`) +
  `server/handler.go:1788-1798` (called from `StartCleanup` BEFORE
  `Cleanup`). Holds. (Note: see P2 finding above for DoS-amplification
  concern under attack volume; the closure as designed against the
  legit-fail single-orphan case is intact.)

- **Token cipher version v1.** `internal/admin/shadowlink_token_crypto.go`
  — encrypt always emits `v1.<base64>`; decrypt accepts both v1 and
  legacy unprefixed. Rotation walks both `cf_api_token_enc` and
  `ssh_password_enc` columns. AES-256-GCM with random nonce per encrypt
  via `io.ReadFull(rand.Reader, …)`. Solid.

---

## Out-of-Scope Observations (not P-classified)

1. **`profileForFingerprint` switch fallthrough behavior.**
   `client/connmanager.go:278-289` — `default:` branch returns
   `LockedBogdanfinnChromeProfile()`. If a Safari/Firefox fingerprint
   is set but the locked-profile getters return nil-typed profile in
   the future (currently they don't), default branch silently downgrades
   to Chrome — could mask a fingerprint config bug. Suggest: panic on
   unrecognized profile in test builds, log on prod.

2. **`heartbeat.go` unused in modern paths.** The `Heartbeat` type with
   `MinInterval=3s, MaxInterval=7s` exists but the actual WS keepalive
   path uses `time.NewTicker(20*time.Second)` in
   `server/websocket.go:419` and a separate jittered ticker via
   `client/jitter.go::JitteredInterval`. Dead-code candidate; if kept,
   document that this is the legacy POST-poll heartbeat for the
   3-tier transport fallback (POST-poll path).

3. **`isValidUA` permissive.** Already noted in P2 above — also accepts
   any `Mozilla/` prefix without further validation. The 256-byte ceiling
   prevents log-blast but doesn't anchor to a specific Chrome major.
   Consider a stricter parser if the UA-update mechanism is retained.

4. **`pqClientHelloSpec` allocates a fresh ALPNExtension prepend slice
   on every cold-path call.** `client/split_transport_tls.go:97-103`
   iterates spec.Extensions and reassigns the typed pointer back —
   makes one allocation per dial. Cold-path is rare (handshake +
   warmup), but combined with the P1 share-mutate concern above the
   prepend pattern is structurally dangerous if upstream mutates.
   Defensive copy + immutable spec base would clean both up.

5. **`serverHelloJSON.UA` JSON-tag is `ua,omitempty`.** Empty string
   server sends `{}` map omitted. `client/client.go:423` checks
   `len(sh.UA) > 0`. If a future server emits `{"chrome": ""}` (empty
   value), `isValidUA` returns false and the entry is rejected
   silently — fine, but worth a slog.Debug on rejection ratio for
   ops visibility (currently only Warn'd). Out-of-scope for crypto.

6. **`runHandshakeSequence:296-298` early-return for non-UUID
   clientIDs goes straight to legacy.** `if len(c.clientID) != 16
   { return c.handshakeLegacy(...) }`. Production server has Phase 0
   retired the legacy POST + GET+Auth dispatch (memory
   `phase-0-done.md`) — so a non-UUID-sized client today would
   silently route through `handleHandshakeNew` with
   `len(payload) >= v1HandshakeMin` false (its
   EncryptedClientID is too short to fit `EncryptedClientIDSize=65`)
   and fall through to decoy. End-result: legacy clients with short
   IDs get decoy 200 and never connect. This is documented as
   intentional Phase 0 contract, but the client-side comment still
   mentions hybrid dispatch as if it's available. Doc cleanup.

7. **`ECHConfig.IsExpired` and `ECHCache` state never zeroed on
   rotate.** `client/connmanager.go:226-238` — when `cm.connect()`
   rotates, `cm.echCache` carries over to the new TLS client.
   Caching is intentional (DNS HTTPS RR doesn't change frequently)
   and not key material — but if a future feature stores actual
   secret material in ECHConfig (PQ KEM with persistent state),
   add `core.ZeroBytes` on rotate. Future-proof note.

8. **`buildUTLSHTTPClient` returns a client with
   `DisableKeepAlives=true`.** Cold-path semantics: every request gets
   a fresh TLS handshake. This is correct for fingerprint hygiene
   (no JA3 reuse leak), but it means the DoH client opens a new TLS
   connection per ECH lookup. With ECH cache TTL 5min the rate is
   bounded, but the `newDoHClient()` path is shared with cold-path
   audit code — confirm no caller invokes it in a tight loop.
   Currently `client/connmanager.go:225-238` is the only caller and
   it's gated on cache miss + 5-min TTL. OK.

9. **`shadowlink-server -gen-key` writes private key to stdout
   without warning of terminal scrollback retention.** `cmd/shadowlink-
   server/main.go:79-89`. Operator hygiene note. Nothing to change.

10. **Migration 074: `ssh_password_enc TEXT` (no length cap).**
    `migrations/074_shadowlink_pool_servers_ssh_creds.sql:6`. AES-GCM
    output sizes scale with plaintext + 12B nonce + 16B tag, base64
    overhead 4/3, plus `v1.` prefix → fixed-coefficient growth, so
    practically bounded by what an admin enters. Not a finding;
    documenting that schema doesn't enforce a max length so an admin
    could paste 64KB and hit it.

---

## Open questions

- **`handleNewFormatPost` exemption escape-hatch path silently skips
  per-IP bucket if exemption hits AND pre-cached clientID matches.**
  The §C4 design correctly excludes the second `DecryptClientID` call
  for symmetry, but on the data-path branch (line 696-758) the same
  skip pattern is NOT applied — instead `IsExempt` is checked
  inside the data-path success branch (line 718-726) and bypasses
  the bucket only AFTER decrypt success. This asymmetry is by
  design (`AllowExempted` soft-cap not applied to data path per
  comment line 705-717). Confirm with intent: the X1 Stage 2
  follow-up note (line 717) says the data-path skip is a deliberate
  trade-off, but the comment-block could be referenced by a
  test pin so future contributors don't rebalance the gate
  positions and re-enable soft-cap on data accidentally.

- **`DomainPool` blacklist clear-all when all blacklisted.**
  `client/domain_pool.go:51-55` — when every domain is blacklisted,
  the entire blacklist is cleared and a fresh random pick happens.
  This is intentional last-resort recovery, but it could thrash if
  ALL configured domains are simultaneously TSPU-blocked — client
  oscillates between blocked endpoints every TLS handshake. Out of
  scope for this audit (P0/P1 concern would be on transport paper,
  not crypto).

- **`pqClientHelloSpec` extension iteration uses ALPN prepend
  pattern from `split_transport_tls.go:98-103`** — but
  `pqClientHelloSpec` and `buildUTLSDialTLS` are split files; if
  someone adds a new hot-path that calls `pqClientHelloSpec` directly
  without going through `buildUTLSDialTLS`, ALPN pinning is lost. Not
  currently the case; track in a guard test.

---

End of audit T1.
