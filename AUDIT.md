# ShadowLink Security Audit Log

Complete history of security audits, found bugs, and fixes. Reference this before any new audit to avoid re-finding known issues.

## Audit Rounds Summary

| Round | Date | Focus | Critical | High | Fixed |
|-------|------|-------|----------|------|-------|
| 1-2 | 2026-03-28 | Crypto + protocol | 3 | 3 | All |
| 3 | 2026-03-28 | DPI evasion (medium) | 3 | 4 | All |
| 4 | 2026-03-28 | Remaining DPI + logs | 0 | 3 | All |
| 5 | 2026-03-28 | Client-side + resources | 0 | 5 | All |
| 6 | 2026-03-28 | TSPU adversarial | 2 | 1 | F2-F4 (F1=deploy) |
| 7-8 | 2026-03-28 | Dual independent review | 2 | 5 | All |
| 9 | 2026-03-28 | Triple independent review | 2 | 4 | All |
| 12 | 2026-03-29 | Phase 1 hardening (4 features) | 0 | 0 | N/A |
| 17 | 2026-04-01 | Anti-fingerprinting + WB TURN + DNS bypass | 1 | 2 | All |

## All Found & Fixed Bugs

### Cryptography
- [x] **C-HKDF**: `io.ReadFull` on HKDF silently discarded errors -> returns error now
- [x] **C-NONCE**: Nonce was `sess_id(4)+seq_num(4)+random(4)` leaking metadata -> fully random 12-byte
- [x] **C-SESSIONID**: SessionID sent in plaintext in ServerHello -> removed, only in encrypted token
- [x] **H-KEYZERO**: Session.Destroy() didn't zero key material -> ZeroBytes on all keys
- [x] **H-REKEY**: No forced rekey at seq overflow -> RekeyNeeded() at seq > 2^31
- [x] **C-TOCTOU**: Cleanup IsExpired+Destroy not atomic -> isExpiredAndDestroy() under single lock
- [x] **H-CLIENTKEY**: Client.Close() didn't zero keys -> session.Destroy() + ZeroBytes(token)

### DPI Evasion
- [x] **C-H2SETTINGS**: Go http2.Transport sent non-browser SETTINGS -> bogdanfinn/tls-client Chrome 133
- [x] **C-XREQUESTID**: X-Request-ID was monotonic seq_num `00000000,00000001...` -> random uint32
- [x] **C-COVERTRAFFIC**: Cover traffic `{"type":"heartbeat"}` different from data `{"events":[...]}` -> encrypted FlagPadding chunks
- [x] **H-STALEUA**: Chrome 131 / Firefox 133 -> updated to Chrome 134, Firefox 136, Safari 18.3.1
- [x] **H-ROUNDROBIN**: Fingerprint rotation Chrome->Safari->Firefox deterministic -> weighted random 65/20/15
- [x] **H-RESPONSEHEADERS**: Data responses missing Server/X-Frame-Options/etc -> setStandardHeaders() on all paths
- [x] **H-TIMING50MS**: Fixed 50ms timeout in handleDataChunk -> random 20-70ms
- [x] **F-JSONORDER**: Go json.Marshal alphabetizes map keys -> struct-based marshal
- [x] **M-DOWNLOADSEQ**: Download response `id` field was monotonic seq_num -> random
- [x] **I-HEADERS**: Missing Accept-Encoding, Origin, Referer -> added
- [x] **I-503DECOY**: 503 on max clients/backpressure -> decoy response

### Server Security
- [x] **C-SSRF**: No SSRF protection in CONNECT handler -> SafeDial blocks private IPs + DNS rebinding
- [x] **H-SANITIZE**: CONNECT errors leaked internal details -> generic "CONNECT_FAIL"
- [x] **H-TLS13**: No TLS minimum version -> TLS 1.3 only (MinVersion)
- [x] **M-RATELIMIT**: Rate limiter map grew unbounded -> cap 10000 + periodic Cleanup()
- [x] **M-XFF**: X-Forwarded-For trusted unconditionally -> BehindProxy flag
- [x] **H-TUNNELLEAK**: Tunnel created before auth check -> moved after auth
- [x] **H-GOROUTINELEAK**: tunnel.Outgoing never closed -> close in handleFin + cleanup
- [x] **H-RELAYPANIC**: relayFromTarget send on closed channel -> defer recover()
- [x] **H-TUNNELRACE**: tunnel.targetConn/connected without sync -> Tunnel.mu Mutex
- [x] **H-USEAFTERDESTROY**: findSession reads keys while Cleanup zeros them -> Keys() copies under lock, EncryptChunk for all server encrypts

### Client
- [x] **H-HALFDUPLEX**: SOCKS5 relay was half-duplex (curl hung) -> full-duplex with adaptive polling
- [x] **H-POLLING**: Constant 50ms polling pattern -> exponential backoff + jitter (20-500ms)
- [x] **H-KEYRACE**: SOCKS5WS accessed session.SendKey without lock -> EncryptChunk/DecryptChunkSafe
- [x] **H-WSWRITERACE**: WS Close() concurrent WriteMessage -> removed WriteMessage from Close
- [x] **H-APPENDCORRUPT**: Unsafe append in TURN transport -> pre-allocated slice
- [x] **C-WSCLOSE**: WS Close() WriteMessage race with goroutine -> just conn.Close()

### Logging / Forensics
- [x] **H-SESSIONLOG**: Session ID / client_id / target in server logs -> all removed
- [x] **H-CLIENTLOG**: Session ID in client logs -> removed

## Known Deferred Items (Not Bugs — Architecture Decisions)

These were found in audits but intentionally deferred:

| Item | Reason | When to Fix |
|------|--------|-------------|
| UDP session_id plaintext prefix | Needed for O(1) lookup on UDP; acceptable for TURN relay MVP | Before VK TURN production |
| ServerHello plaintext JSON | Visible to CDN; mitigated by nginx TLS termination | Before CDN-only deployment |
| 100% POST traffic (no GET) | Architectural; would need fake page loads | Phase 2+ |
| Static Bearer token | Never refreshes; would need token rotation protocol | Phase 2+ |
| WS transport uses Go TLS not tls-client | WS handshake/upgrade via gorilla, not bogdanfinn | Before WS production use |
| O(N) findSession for HTTP | **FIXED** — O(1) with XOR hint prefix, O(N) fallback for legacy | Done |
| HTTP polling pattern | Fundamental to request-response; mitigated by WS mode | Solved by WebSocket mode |
| Base64 payload entropy | Higher than real API data; requires TLS MITM to detect | Low priority |
| Content-Length clustering at VPN chunk sizes | Statistical analysis; requires long observation | Low priority |

## Review Round 11 (2026-03-28) — Post-Multiplexing Stability

Found by dual independent reviewers after WebSocket stream multiplexing deployment.

### CRITICAL (all fixed):
- [x] `tunnel.Outgoing/Incoming` double close — Tunnel.closeTunnel() with sync.Once
- [x] WS reader goroutine never exits — now returns on error
- [x] `wsStream.Write` panic/recover — replaced with done channel + select
- [x] `handleFin` doesn't close streams — now closes all tunnel.streams
- [x] Session keys data race — all paths use EncryptChunk/DecryptChunkSafe (copies key bytes)
- [ ] Polling-mode stream response concatenation — deferred (WS mode is primary)

### HIGH (all fixed except noted):
- [x] 2ms batching deadline — removed, send immediately
- [x] Chunk size exceeds 16KB — buf limited to 12000 bytes
- [x] StreamID uint16 wraparound — checks availability, skips in-use IDs
- [x] wsStream.Write head-of-line blocking — uses done channel select
- [x] wsStream consumer error handling — closes stream on target write error
- [x] WS buffer sizes — increased to 65KB (client dialer)
- [x] Nagle 500μs deadline — REMOVED (root cause of 2 Mbit upload on Windows)
- [x] Cache AES-GCM cipher in Session — **DONE 2026-03-29** (6→3 allocs/op encrypt, ~25% faster)
- [ ] Reduce allocations per packet (sync.Pool) — deferred (optimization)
- [x] SOCKS5 UDP ASSOCIATE — **DONE 2026-03-29** (FlagUDP 0x08, UDPRelay NAT table, both HTTP+WS paths)
- [ ] UDP listener mux — deferred (Phase 2 TURN only)

## Performance Results (2026-03-28 → 2026-03-29, real server Finland)

| Metric | Phase 1 | After mux | After Nagle fix | After GCM cache (2026-03-29) |
|--------|---------|-----------|-----------------|------------------------------|
| Download | ~1 Mbit/s | 190 Mbit/s | 323-437 Mbit/s | **548 Mbit/s** |
| Upload | ~0.5 Mbit/s | ~2 Mbit/s | 10 Mbit/s | **28 Mbit/s** |
| HTTPS sites | Broken | Working | Working | Working |
| System VPN (TUN) | N/A | N/A | TCP only | **TCP + UDP (full)** |
| Blocked sites (RKN) | N/A | N/A | Not working | **Working** |
| QUIC/UDP tunneling | N/A | N/A | Not supported | **Working (UDP ASSOCIATE)** |

## Round 12: Phase 1 Hardening (2026-03-29)

Four features implemented, spec reviewed, code reviewed:

### Upload Optimization (Cached AES-GCM)
- `EncryptWith(gcm, nonceCounter)` / `DecryptWith(data, gcm)` — zero cipher setup per packet
- Session caches `sendGCM`, `recvGCM`, `oldRecvGCM` (10s grace during rekey)
- Counter-based nonce: `[counter(8) + random(4)]` — prevents reuse + unpredictable
- `Create()` and `Rekey()` now return `error` (proper error handling)
- Benchmark: **6→3 allocs/op**, **5200→4100 ns/op** per encrypt

### Device Limits (Management API)
- `ClientAuth` extended with `userLimits`, `activeSessions`, `clientSession` maps
- `CheckDeviceLimit()` counts active sessions per user (not just authorized devices)
- Management API on separate port (127.0.0.1 by default): POST/DELETE /manage/clients, /manage/sync, /manage/set-limit, GET /manage/status
- Protected by X-Management-Key header
- CheckDeviceLimit enforced in handleHandshake (decoy on limit exceeded)
- OnSessionCreated/Destroyed hooks for session lifecycle tracking

### Analytics Mimicry Engine (DPI Shaping)
- `PayloadDistribution`: GA4-realistic sizes (80-2000B upload, 50-8000B download)
- `RatioController`: maintains upload/download ratio 2.5:1–3.5:1, 64KB/sec cover cap
- `SessionLifecycle`: transport rotation 2-8min with 0.5-3s gap pause
- `BuildInflatedDownloadResponse`: adds config_version, experiment_id, variant fields
- Closes 3 ML-detectable anomalies: payload sizes, session duration, upload/download ratio

### SOCKS5 UDP ASSOCIATE
- `FlagUDP = 0x08`, `NewUDPDataChunk`, `ParseUDPChunk` in core/chunk.go
- `UDPRelay` NAT table with per-flow UDP sockets, timeout cleanup
- `handleUDPAssociateWS` / `handleUDPAssociate` in client (both WS and HTTP modes)
- FlagUDP handled in **both** server paths: handler.go (HTTP) and websocket.go (WS)
- WS background reader dispatches FlagUDP chunks to correct stream
- Full return path: server→encrypted→client→SOCKS5 UDP response

### System VPN Fix
- TUN IP changed from `.1` to `.2` with gateway `.1` (Windows can't route through own IP)
- Split-route: `0.0.0.0/1` + `128.0.0.0/1` (more specific than default route, always wins)
- Result: all traffic (TCP + UDP + DNS) routes through TUN → ShadowLink

## Round 13: Tuning & Security (2026-03-30)

Features audited: reconnection backoff, YAML config, mimicry integration, sync.Pool, warmup delay, domain routing.

### CRITICAL (all fixed):
- [x] **X-1**: WS CONNECT handler skipped server-side block-list → added `isBlockedDomain` check before `SafeDial` in websocket.go
- [x] **X-2**: UDP relay had no SSRF protection → added `isPrivateIP` + block-list checks in both HTTP and WS UDP handlers

### HIGH (all fixed):
- [x] **R-1**: `ResetStreams` data race on `streamChans` (wrong mutex) → fixed to use `streamMu` for streams, `mu` for session
- [x] **R-2/R-3**: `wst` variable race in reconnect + old WS leaked → `atomic.Pointer` + explicit close of old wst
- [x] **M-1**: Cover traffic goroutine never received session → `SetSession`/`SetSessionToken` called after handshake in `Connect()`
- [x] **M-3**: `RatioController.Reset()` never called → added 30s reset ticker in cover traffic goroutine
- [x] **X-3**: Management API key comparison not constant-time → `subtle.ConstantTimeCompare`

### MEDIUM (all fixed in Round 14):
- [x] R-4: In-flight SOCKS5 handlers use destroyed session after reconnect → **Round 14**: grace period (5s defer) for session.Destroy()
- [x] C-1: No config file permission check for YAML with secrets → **Round 14**: warnInsecurePermissions() on Unix
- [x] C-2: Management key in plaintext YAML → **Round 14**: expandEnv() for ${ENV_VAR} support
- [x] P-2: PutBufferZero may theoretically be optimized away by future Go compiler → **Round 14**: runtime.KeepAlive prevents dead-store elimination
- [x] D-1: Server block-list bypassable via IP (documented: best-effort domain blocking) → **Round 14**: reverse DNS lookup for IP targets
- [x] D-3: No SSRF protection for ActionDirect bypass connections in client → **Already fixed**: SEC-H1 SSRF check in both handleSOCKS5 and handleSOCKS5WS
- [x] X-4: Unbounded WS stream map allows resource exhaustion → **Round 14**: maxClientStreams=256 limit in RegisterStream()
- [x] X-5: Silent `recover()` in 5 locations (no logging) → **Already fixed**: all 5 recover() have slog.Error() logging

## Round 14: MEDIUM Issue Sweep (2026-03-31)

All 8 MEDIUM issues from Round 13 resolved. 2 were already fixed in code but not marked.

### Fixed (6 issues):
- [x] **R-4**: In-flight SOCKS5 handlers use destroyed session after reconnect → `ResetStreams()` now defers `Destroy()` by 5 seconds, letting in-flight handlers finish. New handlers see `session=nil` immediately.
- [x] **C-1**: Config file permission check → `warnInsecurePermissions()` checks POSIX mode on Unix, warns if group/others have access. Skipped on Windows.
- [x] **C-2**: Management key env expansion → `expandEnv()` supports `${ENV_VAR}` syntax in sensitive YAML fields (management key, server key path).
- [x] **P-2**: Compiler-safe zeroing → `runtime.KeepAlive(&b)` after zeroing loop prevents dead-store elimination.
- [x] **D-1**: Block-list IP bypass → `isBlockedDomain()` now performs reverse DNS lookup for IP targets and checks PTR records against block-list.
- [x] **X-4**: Client stream limit → `RegisterStream()` now returns error if `len(streamChans) >= 256`. All 4 callers updated to handle the error.

### Already fixed (2 issues — marked in AUDIT.md):
- [x] **D-3**: SSRF protection for ActionDirect — SEC-H1 checks already present in both `handleSOCKS5()` and `handleSOCKS5WS()`.
- [x] **X-5**: Silent recover() — all 5 locations already have `slog.Error()` logging with descriptive function names.

## Round 15: Dual Independent Security Audit (2026-03-31)

Two independent hostile auditor agents dispatched: one for goroutine/panic safety, one for security/attack surface. Found 5 CRITICAL + 8 HIGH. All CRITICAL and HIGH fixed.

### CRITICAL (all fixed):
- [x] **CRIT-1**: UDP path accessed `session.RecvKey`/`SendKey` directly without lock (use-after-destroy race) → replaced with `session.DecryptChunkSafe()`/`session.EncryptChunk()` safe wrappers
- [x] **CRIT-2**: UDP handshake missing `CheckDeviceLimit()` and `OnSessionCreated()` → added both, matching HTTP handshake path
- [x] **CRIT-3**: UDP-created `Tunnel` had `done=nil` → panic on `closeTunnel()` → added `done: make(chan struct{})` and `ClientID`
- [x] **CRIT-4**: `relayFromTarget` read `tunnel.targetConn` without lock → snapshot conn under `tunnel.mu.Lock()` before loop
- [x] **CRIT-5**: `wsStream.Write` send on closed `writeCh` via `select` → `Close()` no longer closes `writeCh`, writer goroutine exits via `done` channel

### HIGH (all fixed):
- [x] **HIGH-1**: `time.After` leak in hot data path (thousands of un-GC'd timers) → replaced with `time.NewTimer` + `timer.Stop()` in handler.go and udp_listener.go
- [x] **HIGH-2**: `ResetStreams` close(ch) caused busy-loop in receivers → all 6 receive sites check `ok` flag, exit on closed channel
- [x] **HIGH-3**: Body read limit `ChunkSize*2` = 24KB allocation before auth → reduced to `ChunkSize+1024`
- [x] **HIGH-4**: `handleConnect` in HTTP path had no stream limit → added `maxStreamsPerSession` check (256, same as WS path)
- [x] **HIGH-5**: Management API `/manage/status` exposed all session IDs → `Sessions` field now always nil
- [x] **HIGH-6**: `shiftBitmap` uint32 loop variable underflow corrupted replay-protection window → changed to `int` loop variable
- [x] **HIGH-7**: UDP `handleUDPData` read `tunnel.connected`/`tunnel.targetConn` without lock → snapshot under `tunnel.mu.Lock()`
- [x] **HIGH-8**: HTTP `handleConnect` had no stream limit (65535 goroutines possible) → added `maxStreamsPerSession` check

### MEDIUM (5 fixed, 2 accepted risk):
- [x] MED-2: Reverse DNS in `isBlockedDomain` has no timeout → `context.WithTimeout(2s)` added
- [x] MED-3: `slog.Info` logged full HTTP headers including Bearer token → headers removed from log
- [x] MED-5: Silent data drop when stream channel buffer full → `slog.Warn` added for visibility
- [x] MED-6: `isValidUA` trivially bypassable → added length bounds (10-256), printable ASCII check
- [x] MED-7: SOCKS5 request parsing partial read → `io.ReadAtLeast(conn, buf, 7)` in both handlers
- [x] MED-8: `WebSocketTransport.SendChunk` writes without `writeMu` → added `writeMu.Lock/Unlock`
- [ ] MED-1: Shared replay window across HTTP/UDP — accepted risk (requires wire format change, attack is disruption-only not data theft, same-session cross-transport is rare)
- [ ] MED-4: `EncodeTokenWithHint` XOR reversible by CDN — accepted risk (requires coordinated client+server update; CDN already sees all traffic in CDN mode; session ID is random 32-bit with no user linkability)

## Known Deferred Items (updated 2026-03-31)

| Item | Reason | When to Fix |
|------|--------|-------------|
| UDP session_id plaintext prefix | Needed for O(1) lookup on UDP | Before VK TURN production |
| ServerHello plaintext JSON | Visible to CDN; mitigated by nginx TLS | Before CDN-only deployment |
| 100% POST traffic (no GET) | Architectural; needs fake page loads | Phase 2+ |
| Static Bearer token | Never refreshes; needs rotation protocol | Phase 2+ |
| WS transport uses Go TLS not tls-client | WS upgrade via gorilla, not bogdanfinn | Before WS production use |
| Base64 payload entropy | Higher than real API data; needs TLS MITM to detect | Low priority |
| Content-Length clustering at VPN chunk sizes | Statistical; requires long observation | Low priority |
| D-1 reverse DNS is best-effort | PTR records may not exist for all IPs | Accepted risk |

## Round 16: Re-Review Verification (2026-03-31)

Two independent re-review agents verified ALL Round 14+15 fixes correct. Found 4 minor new issues, all fixed:

- [x] **NEW-1** (HIGH): wsStream drain race — writer goroutine used `default` which missed late items → replaced with 1ms drain timer for thorough cleanup
- [x] **NEW-2** (MEDIUM): `tunnel.targetConn.Close()` outside `tunnel.mu` in handleFin and StartCleanup → moved inside lock
- [x] **NEW-3** (MEDIUM): `client_id` logged in unauthorized handshake warn (regression of H-SESSIONLOG) → removed from log
- [x] **NEW-4** (LOW): `time.After` in ConnManager rotation → replaced with `time.NewTimer` + `Stop()`

**Verdict: codebase clean. 16 rounds of audit completed. All CRITICAL/HIGH/MEDIUM resolved or accepted with documented rationale.**

## Round 17: Anti-Fingerprinting & Transport Hardening (2026-04-01)

### TLS Fingerprint Protection
- [x] **FP-1** (CRITICAL): WebSocket used Go `crypto/tls` — trivially detectable as "Go binary" via JA3 → replaced with `refraction-networking/utls` via `NetDialTLSContext` in gorilla/websocket. `UTLSIdToSpec` + `HelloCustom` + ALPN override to `http/1.1`
- [x] **FP-2** (HIGH): All users shared same rotating fingerprint (5-10min) — suspicious velocity → per-user `FingerprintLease` persisted to `~/.shadowlink/fingerprint.json`, weekly rotation (7 days)
- [x] **FP-3** (HIGH): Fingerprint rotation created JA3 mismatch pattern (Chrome→Firefox→Safari in 30min) → locked profile per device, weighted distribution (70% Chrome, 18% Safari, 12% Firefox)

### DNS Bypass Router (Domain-Based Split Routing)
- [x] **DNS-1**: System VPN (TUN) sent all traffic through tunnel — .ru domains unnecessarily proxied → built-in DNS proxy on 127.0.0.1:53, resolves via 1.1.1.1, adds host routes for bypass domains through real gateway
- [x] **DNS-2**: tun2socks resolves DNS and sends IPs (not domains) to SOCKS5 — routing rules couldn't match → DNS proxy intercepts queries, matches domain patterns, adds `/32` routes dynamically

### WB TURN ("Суперсила") Transport
- [x] **WT-1**: TURN credentials expire after 5 min → `ManagedTunnel` with 4-min refresh + auto-reconnect + exponential backoff
- [x] **WT-2**: System VPN mode: TUN intercepted TURN relay UDP → escape routes for `185.62.200.0/24` + DNS servers, firewall rules on 3 platforms (Windows/macOS/Linux)
- [x] **WT-3**: WB TURN SOCKS5 doesn't support UDP ASSOCIATE → DNS stays on real interface (not TUN), only TCP through TURN tunnel

### Known Deferred Items (updated 2026-04-01)

| Item | Reason | When to Fix |
|------|--------|-------------|
| ~~WS transport uses Go TLS not tls-client~~ | **FIXED** — uTLS via `NetDialTLSContext` | Done |
| JA4 normalized fingerprint | ТСПУ not using JA4 yet | Monitor |
| Post-quantum key exchange (X25519MLKEM768) | uTLS doesn't support it; ТСПУ blocks PQ, not its absence | When uTLS adds support |
| WB TURN TUN mode: UDP-only apps fail | wbturn SOCKS5 = TCP only, DNS bypasses TUN | Phase 2: add UDP ASSOCIATE to wbturn |
| 100% POST traffic (no GET) | Architectural; needs fake page loads | Phase 2+ |
| Static Bearer token | Never refreshes; needs rotation protocol | Phase 2+ |

## Test Coverage

- **Passing**: 7 packages, all tests PASS
- **New tests (2026-03-30)**: backoff duration (6 cases), ConnectWithRetry cancel, server YAML config (8 tests), client YAML config (5 tests), ApplyTo merge, domain routing (14 cases + empty + port), buffer pool sizes + zero + benchmark
- **Covered**: crypto roundtrip, replay protection, SSRF (TCP+UDP), DPI 16KB threshold, decoy, E2E handshake+data, TURN relay, keepalive, entropy analysis, stream multiplexing, cached GCM, device limits, analytics mimicry, UDP relay, reconnection backoff, YAML config loading/merge, domain routing (bypass/force/block/CIDR), buffer pool tiers
- **Not covered**: WS relay E2E, concurrent clients, key rotation under load, mimicry integration E2E, cover traffic E2E
