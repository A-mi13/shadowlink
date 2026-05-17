# ShadowLink Track 1 Audit — Architecture & Cryptography

**Date:** 2026-05-01
**Scope:** `shadowlink/core/`, `shadowlink/client/`, `shadowlink/server/`, `shadowlink/skins/browser/`, plus `internal/admin/shadowlink_handlers.go::{mergeOrRegenerateKeys, buildShadowLinkConfig, parseGenKeyOutput}`.
**Reviewer:** Track 1, static analysis only (no execution / no test runs).
**Companion:** baseline audit `shadowlink/docs/audit/2026-04-25-final-review-architecture-crypto.md`.

## Code-baseline read

- `shadowlink/CLAUDE.md`; `docs/strategy/2026-04-22-strategic-assessment.md`, `docs/strategy/2026-04-30-current-state-and-improvements.md`
- `shadowlink/core/{session.go, crypto.go, handshake.go, replay_cache.go, wsasyncwriter.go, chunk.go, mimicry_session.go}`
- `shadowlink/server/{handler.go, websocket.go}`
- `shadowlink/client/{ws_pool.go, ws_transport.go, connmanager.go, split_transport_tls.go, utls_http.go, ws_paths.go}`
- `shadowlink/skins/browser/` package boundary inventory; `internal/admin/shadowlink_handlers.go:450-600`

---

## Executive summary

The cryptographic core has held up since the 2026-04-25 baseline. Most baseline H/M items are **closed in code** (see Closed-since-april below): H2 dead `sk` branch, H3 `runtime.KeepAlive` in `ZeroBytes`, M1 replay-cache bucket loophole (sliding window + background eviction), M2 lock contention in `EncryptChunk` (lock-free `sendEpoch` atomic pointer), M3 plaintext zeroization in `EncryptClientID`, M4 long-clientID silent-truncate (now `>16` rejected), M5 rekey threshold bumped to `0xFF000000`. The `_v` threading in `connectSlot` (data-plane drift fix) is correctly implemented and HKDF protoVersion binding still defends against v0 downgrade.

What remains is mostly **lifecycle hygiene**, not cryptographic risk. Two HIGH items warrant attention before the next deploy:

1. **`WSPoolTransport.handleSlotDeath` does not call `slot.session.Destroy()`** — every meltdown / TSPU rotation / reader anomaly replaces the slot with a fresh one and leaves the prior session's AES keys + sendEpoch GC-eligible but un-zeroed. `rotateOneSlot` and `Close` get this right; only the death-driven hot path skips it.
2. **`findSessionByHint` is broken-by-design after `Session.Rekey`** — the token was sealed under the original `RecvKey` but lookup verifies against the rotated key. Today dormant (no production caller invokes Rekey); the moment any feature wires it, every authenticated request collapses to `failClosedToDecoy`.

The unit-test gaps from baseline (H1 nonce-counter invariant, M7 `ParseUploadRequest` JSON fuzz, M3 plaintext-zeroization assertion) are **not addressed** in code — same gap.

The Phase 1 P1 admin helpers (`mergeOrRegenerateKeys` / `buildShadowLinkConfig` / `parseGenKeyOutput`) are clean: pure functions with DI side effects, length-validated keys, sensible reuse semantics, operator-visible warning on the public-key fallback path. **No findings.**

Layer boundaries are clean. `core/` and `skins/browser/` do not import `client/` or `server/`. `client/` and `server/` are mutually independent in production code (only test files cross). `skins/browser` depends on `core` only. The shared `wsURLPool` is intentionally duplicated across `client/ws_paths.go` and `server/urls.go` with cross-references and a test asserting byte-equality.

Stance: **ship at current quality**. Address the two HIGH items in the next maintenance cycle, before turning on Rekey or relying on slot-rotation in low-memory deployments.

---

## Findings

### CRITICAL

_None._

### HIGH

#### H1. `WSPoolTransport.handleSlotDeath` never destroys `slot.session` — AES key material leaks across every reconnect

**File:** `shadowlink/client/ws_pool.go:1128-1159`. Companion: `:733-734` (rotateOneSlot — correct), `:1170-1173` (Close — correct), `:397-481` (connectSlot — overwrites `p.slots[idx]` unconditionally at line 400).

```go
func (p *WSPoolTransport) handleSlotDeath(cl *Client, idx int) {
    slot := p.slots[idx]
    slot.setState(slotDead)
    // ... close streams ...
    if slot.transport != nil { slot.transport.Close() }
    // <-- slot.session.Destroy() MISSING
    // <-- core.ZeroBytes(slot.token) MISSING
    p.recordSlotDeath()
    go p.reconnectLoop(idx)
}
```

Every TSPU byte-budget rotation (`:1091-1099`), every `RSV/opcode/html` anomaly trigger (`:1065-1083`), every meltdown-driven replacement leaves `Session.SendKey` / `Session.RecvKey` / `Session.oldRecvKey` / `sendEpoch.gcm` AES key schedule live until GC. `core.Session.Destroy()` exists specifically to walk these under `s.mu` and zero them — bypassing it negates the H3 baseline fix. Adjacent: `connectSlot` overwrites `p.slots[idx] = slot` at line 400 with no inspection of the prior slot, so a fresh poolSlot orphans the old one before any cleanup.

**Fix.** Add `if slot.session != nil { slot.session.Destroy() }` and `if slot.token != nil { core.ZeroBytes(slot.token) }` after the transport close, mirroring `Close()`. Independently, capture the prior slot into a local before overwriting `p.slots[idx]` so cleanup has a single source of truth.

**Severity.** HIGH for "mechanism exists, is invoked elsewhere, omitted on the hot path". Not network-exploitable; relevant to memory-dump exfiltration and shared-host privilege boundaries.

---

#### H2. `findSessionByHint` cannot resolve a session whose Recv key has been rotated by `Session.Rekey`

**Files:** `shadowlink/server/handler.go:1311-1340`, `shadowlink/core/session.go:173-196` (Rekey), `shadowlink/core/handshake.go:114, 185-205` (encryptSessionToken), `shadowlink/core/session.go:220-224` (RekeyNeeded — set, never read in production).

Server-side, the session token is sealed at handshake with `keys.SendKey` (= server's `session.RecvKey` after the swap in `handshake.go:108`). `findSessionByHint` reconstructs `rk` via `s.Keys()`:

```go
_, rk := s.Keys()
if verifySessionToken(token, s.ID, rk) { return s }
return nil
```

`Session.Rekey` replaces `s.RecvKey` with a fresh key and parks the previous in `s.oldRecvKey` for a 10s grace. **`findSessionByHint` only checks the new key.** The token, however, was sealed under the original key and is what the client always sends. Result: after the first rekey every authenticated request returns `nil` and routes through `failClosedToDecoy`.

Today this is **dormant** — `s.Rekey()` is invoked only by tests (`core/session_test.go`, `core/chunk_invariant_test.go`); `RekeyNeeded()`'s return value is read nowhere in production. The bug surfaces the moment Phase 1+ wires Rekey into the data path. The test surface won't catch it because no test exercises post-rekey `findSessionByHint`.

**Fix.** Either (a) re-seal and re-emit a fresh `EncryptedSessionToken` to the client during `Rekey` (wire change), or (b) extend `findSessionByHint` to verify against the rolling pair (`rk` first, then `s.OldRecvKey()` if non-nil and within grace) — 4-line change mirroring `DecryptChunkSafe`'s grace-period pattern. Add `TestFindSessionByHint_AfterRekey_StillResolves` contract test.

**Severity.** HIGH because the trip-wire is invisible from the unit-test surface.

---

### MEDIUM

#### M1. Server `runWebSocketSession` does not wait on `writer.RunDone()` before `conn.Close()`; client does

**Files:** `shadowlink/server/websocket.go:606-610`, `shadowlink/client/ws_transport.go:818-824`.

Server-side fires `writer.Close(); conn.Close()` back-to-back. `writer.Close()` only signals `done`; `Run` may still be in `gorilla.WriteMessage`. The immediate `conn.Close()` races and `Run` exits with a non-nil write error → slog WARN at `:364` fires every shutdown. Functionally benign; asymmetric with the correct client pattern (`writer.Close(); <-writer.RunDone(); conn.Close()`) and any future logging that gates on writer-error counts will misattribute graceful shutdowns. **Fix:** mirror client.

#### M2. Server-side handshake creates session/tunnel before the WS upgrade lands; orphan sessions linger up to 5 min

**Files:** `shadowlink/server/handler.go:383-401, 1496-1539` (cleanup loop), `shadowlink/client/ws_pool.go:447-471`.

If the client fails between `handshake POST` returning and `UpgradeToWS` succeeding (e.g. TLS handshake error, TSPU-shaped TCP, first-frame send error) the server-side session sits in `SessionManager` + `tunnels` until the cleanup loop fires (5 min default). Under "8 slots cascade-die under hoster throttle, half fail at WS upgrade" this pins dozens of orphans per client. Inflates `MaxClients` saturation; gives `findSessionByHint` extra entries to scan.

**Fix.** Either tighten newborn-never-attached sessions to 30s timeout (cheap), or require WS upgrade arrival within N seconds of handshake (architectural).

#### M3. Per-session `MimicrySession` published without happens-before edge to `buildResponse` readers

**Files:** `shadowlink/server/handler.go:399, :236-245`, `shadowlink/core/mimicry_session.go:1-28`.

The contract documented in `mimicry_session.go` ("set once at handshake completion; read-only after") relies on `handleHandshakeNew` writing `session.MimicrySession = …` outside any lock and `buildResponse` reading it outside any lock. On x86 TSO this works in practice; the correctness argument depends on the implicit ordering that `tunnels[id] = tunnel` happens *after* the `MimicrySession` assign. A future refactor that swaps that order silently produces nil-deref panics in `buildResponse`. **Fix:** move `MimicrySession = browser.NewMimicrySession()` inside `core.SessionManager.Create` so the publish-to-`sessions`-map provides the happens-before edge, OR add a defensive comment locking the line order.

#### M4. `DecryptClientID` does not enforce `idLen == 16` symmetric to encode side

**File:** `shadowlink/core/crypto.go:138-141, 192-197`.

Encode rejects `len > 16`; decode accepts any `idLen ≤ len(decrypted) - 9`. Not an auth bypass (server static key authenticates the box seal) but relaxes the symmetric invariant motivating the encode-side check. **Fix:** add `if idLen != 16 { return nil, errors.New("invalid clientID size") }` after `idLen := int(decrypted[8])`.

#### M5. `connectSlot` failure paths leak server-side handshake state because the client never signals "give up"

**File:** `shadowlink/client/ws_pool.go:402-481`.

When WS upgrade fails (line 469-470), the client has already received `ServerHello` and `slot.session` is populated. The server has a fully provisioned session waiting. The client's next `connectSlot` performs a brand new handshake → a brand new server session. The first orphan stays for 5 min (M2 same root cause from the other direction). With 8 slots × cascading reconnect this adds up.

**Fix.** Best-effort POST FIN (existing `core.NewStreamFinChunk` + body-prefix envelope) on WS-upgrade failure. One cheap goroutine per failed slot; eliminates the most common orphan path.

#### M6. `SetStatsCallbacks` package-global writes race with `EncryptChunk` reads

**File:** `shadowlink/core/session.go:239-250` (baseline open-Q #5, not addressed).

Three plain global function pointers, written by `SetStatsCallbacks`, read by `EncryptChunk`/`DecryptChunkSafe` on the hot path. `-race` flags this if two test goroutines or one test + production overlap call `SetStatsCallbacks`. **Fix:** replace with `atomic.Pointer[func()]` slots, or one `atomic.Value` holding a `*StatsCallbacks` struct.

#### M7. `ParseUploadRequest` JSON fuzz target still missing

**File:** `shadowlink/skins/browser/request.go:181-193`, `request_fuzz_test.go`. Baseline M7 — JSON layer is the first attacker-controlled byte boundary on the body-prefix path and is uncovered. **Fix:** add `FuzzParseUploadRequest` per baseline recommendation.

---

### LOW / Nitpicks

- **L1.** Counter+random vs full-random nonce regimes still co-exist (`core/chunk.go:42-77` vs `:80-115`). Baseline H1 untouched. Add `TestSession_RekeyResetsSendNonce` tripwire — the regression is catastrophic.
- **L2.** `MaxBytesPerSlot` not wired by default (`client/ws_pool.go:230-235, 1091-1099`); TSPU cliff is a documented field condition. Ops contract invisible at this layer.
- **L3.** `runWebSocketSession` does not formally `wg.Wait()` background ping/reader goroutines before return (`server/websocket.go:378-391, 394-595`). Today every path hits `closeDone()` via `defer`; belts-and-braces would tighten.
- **L4.** `connectSlot` writes `p.slots[idx] = slot` at line 400 before any field is set; concurrent `Close` walking the slice observes a partially-zero slot (every read is nil-checked, no crash, but ordering is fragile).
- **L5.** `ZeroBytes` is fine post-H3 fix (`runtime.KeepAlive(&b)`). Optional `subtle.ConstantTimeCopy(1, b, zero)` would be clearer-intent.

---

## Closed-since-april (baseline 2026-04-25 → today)

| Baseline ID | What it was | Closed at |
|---|---|---|
| H2 | `findSessionByHint` decrypts with both `sk` and `rk` | `server/handler.go:1335-1338` — only `rk`, contract test referenced |
| H3 | `ZeroBytes` compiler-eliminable | `core/crypto.go:30-35` — `runtime.KeepAlive(&b)` added |
| M1 | Replay-cache bucket-boundary lets one replay through | `core/replay_cache.go:113-151` — sliding window + background eviction |
| M2 | `EncryptChunk` per-session lock contention | `core/session.go:24-30, 252-277` — lock-free `sendEpoch` atomic pointer |
| M3 | `EncryptClientID` plaintext not zeroed | `core/crypto.go:144-147` — `defer ZeroBytes(plaintext)` |
| M4 (encode) | Long clientID silently truncates | `core/crypto.go:138-141` — `> 16` rejected. Decode-side gap is M4 above |
| M5 | Rekey threshold at half-counter | `core/session.go:220-224` — bumped to `0xFF000000` |
| L8 | `CompleteHandshake` silently maps nil `_v` to v0 | `core/handshake.go:130-155` — explicit-default; client `_v` threading at `client/ws_pool.go:421-445` |

Baseline **H1** (counter+random nonce regime) is **not** addressed in code — only comments. Recorded above as L1.

---

## Open questions

1. **Rekey activation roadmap.** Is `Session.Rekey` planned for the next 30 days? If yes, H2 is P0. If indefinite, document `RekeyNeeded()` as advisory-only and lock with a build-time assertion that no production code path reads it.
2. **Stats callbacks lifecycle.** Are `SetStatsCallbacks` calls expected once at process init (then immutable) or live-updateable? Pin in code or comment.
3. **Orphan handshake cost under load.** With M2 + M5 unaddressed and 8-slot pools cascading under TSPU throttle, what's the steady-state orphan count? Add `shadowlink_orphan_sessions_evicted_total{reason}` to measure, then decide if 5 min default is sufficient.
4. **`MimicrySession` happens-before.** Is there a `-race` test that exercises publish-to-tunnels-map / read-in-buildResponse interleaving? If not, M3 is invisible until production triggers it.
5. **`ConnManager.SetDomainPool(nil)` semantics** (`connmanager.go:140-150`). Clearing the pool does NOT revert `sniOverride` — last picked domain stays. Desired contract or oversight?
6. **`EncryptedClientIDSize=65` UUID assumption.** Hard-coded but not enforced symmetrically (M4 above). Decision: enforce both sides or carry a length prefix?
7. **WS pool `meltdownLogRNG`** seeded once from `time.Now().UnixNano()` (`client/ws_pool.go:300`). Predictable across deployments started near each other (build-stage, `systemctl restart` storms). Cosmetic — RNG is non-security — but `crand.Read` is cheap.

---

## Stance

Cryptographic core remains production-grade. HKDF protoVersion binding survives the data-plane drift fix and `_v` threading in `connectSlot` is correct (closes the field bug at the source). Phase 2 closure detections (PQ ClientHello, BroadcastStreamClose drain, Cover GET, padding decouple) are wired into both hot and cold paths.

Both HIGH items are debt, not vulnerabilities: H1 is a memory-hygiene regression hidden by the existence of correct sibling code; H2 is a future-feature bug invisible to the current test surface. Address before flipping any rekey or deploying into a hosting environment with strict process-memory controls.

The MEDIUMs collectively describe one theme — orphan resources accumulate when one side abandons mid-handshake — and could be swept in one focused session. M7 (fuzz) and M6 (callbacks race) are quick wins.

Recommendation: ship at current quality on the WS Pool R.1+R.3a baseline. Schedule H1+H2 with the M-batch in the next maintenance cycle, before any Tier-A throughput work begins.
