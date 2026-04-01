# ShadowLink: Upload Optimization, Device Limits, DPI Shaping, System VPN

**Date:** 2026-03-29
**Status:** Draft
**Scope:** 4 features for ShadowLink Phase 1 hardening

---

## 1. Upload Optimization

### Problem

AES-256-GCM cipher is recreated on every `Encrypt()` call in `core/chunk.go`:
- `aes.NewCipher(key)` — alloc
- `cipher.NewGCM(block)` — alloc
- `crypto/rand.Read(nonce)` — syscall + alloc

This causes ~7 allocations per packet. Download achieves 437 Mbit/s, upload only 10 Mbit/s.

### Solution

Cache `cipher.AEAD` in Session struct. Use counter-based nonce instead of random.

#### Changes to `core/session.go`

Add fields to Session:
```go
type Session struct {
    // ... existing fields ...
    sendGCM    cipher.AEAD  // cached for encrypt
    recvGCM    cipher.AEAD  // cached for decrypt
    sendNonce  uint64       // counter-based nonce (atomic)
}
```

Initialize in `SessionManager.Create()` — **must return error** if cipher init fails:
```go
func (sm *SessionManager) Create(sendKey, recvKey []byte) (*Session, error) {
    block, err := aes.NewCipher(sendKey)
    if err != nil { return nil, fmt.Errorf("send cipher: %w", err) }
    s.sendGCM, err = cipher.NewGCM(block)
    if err != nil { return nil, fmt.Errorf("send gcm: %w", err) }
    // same for recvGCM with recvKey
}
```

#### Changes to `core/chunk.go`

`Encrypt()` becomes `EncryptWith(gcm cipher.AEAD, nonceCounter uint64)`:
- No `aes.NewCipher` / `cipher.NewGCM` calls
- Nonce: `[counter(8 bytes) + random(4 bytes)]` — counter prevents reuse, random prevents predictability
- Zero allocations for cipher setup

`Session.EncryptChunk()` passes cached `sendGCM` and atomically increments `sendNonce`.

#### Nonce safety

Counter-based nonce with 8 bytes of counter gives 2^64 unique nonces per key. Combined with rekey at 2^31 seq_num (already implemented), nonce reuse is impossible.

The 4 random bytes prevent nonce prediction by DPI (unlike pure counter which leaks packet ordering).

#### Nonce asymmetry (send vs receive)

The counter is **sender-side only**. The receiver reads the nonce from the first 12 bytes of the incoming packet (same as current code). There is no `recvNonce` counter — the receiver does not verify or track nonce ordering (replay protection uses seq_num in the encrypted payload, not the nonce).

This means **backward compatibility is automatic**: a peer using counter-based nonces produces the same wire format as one using random nonces. The receiver doesn't care how the nonce was generated.

#### Rekey() changes

When `Rekey(newSendKey, newRecvKey)` is called:
1. Create new `sendGCM` from `newSendKey`
2. Create new `recvGCM` from `newRecvKey`
3. Store old `recvGCM` as `oldRecvGCM` for 10-second grace period (matches existing `oldRecvKey` pattern)
4. Reset `sendNonce` to 0 (new key = new nonce space)
5. Zero old key material after grace period expires

#### Expected result

Upload: 50-100 Mbit/s (5-10x improvement). Bottleneck moves from crypto to network/IO.

#### Files changed

| File | Change |
|------|--------|
| `core/session.go` | Add `sendGCM`, `recvGCM`, `oldRecvGCM`, `sendNonce` fields. Init in Create() (returns error). Update Rekey() to recreate GCMs, store old recvGCM, reset sendNonce. `EncryptChunk()` / `DecryptChunkSafe()` use cached GCM. |
| `core/chunk.go` | New `EncryptWith(gcm, nonce)` / `DecryptWith(gcm)`. Keep old `Encrypt(key)` / `DecryptChunk(data, key)` for tests. |
| `core/chunk_test.go` | Benchmark: before/after comparison |

---

## 2. System VPN — SOCKS5 UDP ASSOCIATE

### Problem

`cmd/shadowlink-client/main.go` only handles SOCKS5 CONNECT (cmd 0x01). UDP ASSOCIATE (cmd 0x03) returns error. This means:
- Browser tries QUIC (UDP:443) for blocked sites, fails, slow fallback to TCP
- DNS queries over UDP may be poisoned by ISP
- System VPN mode can't tunnel UDP traffic

### Solution

Add SOCKS5 UDP ASSOCIATE handler (RFC 1928 section 6).

#### UDP ASSOCIATE flow

1. Client sends SOCKS5 request with cmd=0x03
2. Server opens a local UDP port, replies with BND.ADDR:BND.PORT
3. Client sends UDP datagrams to that port with SOCKS5 UDP header:
   ```
   [RSV(2)] [FRAG(1)] [ATYP(1)] [DST.ADDR(var)] [DST.PORT(2)] [DATA]
   ```
4. Server encapsulates UDP data into ShadowLink stream (new stream per UDP "flow")
5. ShadowLink server dials target UDP addr, relays data
6. Return path: server → encrypted stream → client UDP port → original sender

#### Stream multiplexing for UDP

Reuse existing StreamID mechanism. New flag: `FlagUDP = 0x08` in chunk flags (0x01-0x07 are taken: Data, Ack, Padding, Keepalive, Fin, Control, Connect).

UDP streams are identified by `(clientAddr, targetAddr)` pair. Server maintains a NAT table mapping StreamID → UDP socket.

#### Timeout

UDP flows timeout after 60 seconds of inactivity (configurable). Cleanup runs with existing session cleanup goroutine.

#### Files changed

| File | Change |
|------|--------|
| `cmd/shadowlink-client/main.go` | Add `handleUDPAssociate()` for both poll and WS modes |
| `core/chunk.go` | Add `FlagUDP = 0x08`, `NewUDPDataChunk()` |
| `server/handler.go` | Detect FlagUDP, route to UDP relay instead of TCP tunnel |
| `server/udp_relay.go` | **NEW** — UDP NAT table, relay logic, timeout cleanup |

---

## 3. Device Limits (Push Model)

### Problem

ShadowLink has no per-user device limits. One user can connect unlimited devices. Need limits tied to subscription plans, manageable from NixaVPN admin panel.

### Architecture

NixaVPN backend is the source of truth for users, plans, and devices. ShadowLink server receives authorized client lists via a Management API.

#### clientID format

```
{userID}:{deviceID}
```

Examples: `u42:d1`, `u42:d2`, `u108:d1`

**Constraint**: userID and deviceID must not contain `:` character. NixaVPN uses numeric IDs so this is safe. For other integrations, use URL-safe alphanumeric strings.

ShadowLink parses the userID prefix (everything before first `:`) to count active sessions per user.

For standalone use (without NixaVPN), any clientID format works — if no `:` is found, the entire clientID is treated as userID (one device per "user"). In open mode, limits are not enforced.

#### Management API

Runs on a **separate port** from client traffic, **bound to 127.0.0.1 by default** (localhost only). Protected by `X-Management-Key` header. If external access is needed, use SSH tunnel or deploy behind TLS reverse proxy. Rate limited: 100 requests/minute.

Endpoints:

```
POST   /manage/clients          — authorize a client
  Body: {"client_id": "u42:d1"}

DELETE /manage/clients/{id}     — deauthorize + kill session
  URL:  /manage/clients/u42:d1

POST   /manage/sync             — full replacement of all clients + limits
  Body: {
    "clients": ["u42:d1", "u42:d2", "u108:d1"],
    "limits": {"u42": 5, "u108": 2}
  }

POST   /manage/set-limit        — set device limit for one user
  Body: {"user_id": "u42", "max_devices": 5}

GET    /manage/status            — list all clients, sessions, limits
```

#### ClientAuth extensions

```go
type ClientAuth struct {
    mu         sync.RWMutex
    authorized map[string]bool       // clientID → authorized
    openMode   bool

    // NEW
    userLimits map[string]int        // userID → max devices
    defaultMax int                   // default if no specific limit (e.g., 3)
}
```

New methods:
- `SetUserLimit(userID string, max int)`
- `CheckDeviceLimit(clientID string) bool` — parses userID, counts authorized devices for that user, returns true if under limit
- `SyncClients(clients []string, limits map[string]int)` — atomic full replacement
- `RemoveClientAndSession(clientID string, sessions *SessionManager)` — remove + destroy active session

#### Handshake enforcement

In `handler.go:handleHandshake()`, after `clientAuth.IsAuthorized(clientID)`:

```go
if !h.clientAuth.CheckDeviceLimit(clientID) {
    // User has too many devices — return decoy
    h.decoy.ServeHTTP(w, r)
    return
}
```

DPI cannot distinguish "device limit exceeded" from "unauthorized" or "rate limited" — all return decoy.

#### Session tracking by user

**Data structure**: `ClientAuth` gains `activeSessions map[string][]uint32` (userID → list of active sessionIDs), protected by existing `ca.mu`.

**Hooks**: `SessionManager` gets a callback interface:
```go
type SessionHook interface {
    OnSessionCreated(clientID string, sessionID uint32)
    OnSessionDestroyed(clientID string, sessionID uint32)
}
```
`ClientAuth` implements `SessionHook`. Handler registers it at startup.

**CheckDeviceLimit** counts entries in `activeSessions[userID]`, not authorized clientIDs.

This means: a user with limit=3 can have 5 authorized devices, but only 3 can be **simultaneously connected**.

#### Behavior on device removal

`DELETE /manage/clients/u42:d2`:
1. Remove from `authorized` map
2. Find active session for this clientID
3. Call `session.Destroy()` — zeroes keys, closes tunnels
4. Client gets disconnected immediately
5. Slot freed for new device

#### Config

```go
type Config struct {
    // ... existing ...
    ManagementPort int    // default: 0 (disabled)
    ManagementBind string // default: "127.0.0.1" (localhost only)
    ManagementKey  string // required if ManagementPort > 0
    DefaultMaxDevices int // default: 3
}
```

CLI flags: `--mgmt-port`, `--mgmt-bind`, `--mgmt-key`, `--default-max-devices`

#### Files changed

| File | Change |
|------|--------|
| `server/ratelimit.go` | Extend ClientAuth with userLimits, CheckDeviceLimit, SyncClients |
| `server/management.go` | **NEW** — HTTP handlers for /manage/* endpoints |
| `server/handler.go` | Add CheckDeviceLimit call in handleHandshake |
| `server/server.go` | Start management listener on separate port |
| `server/config.go` | ManagementPort, ManagementKey, DefaultMaxDevices |
| `cmd/shadowlink-server/main.go` | CLI flags for management |

---

## 4. Analytics Mimicry Engine

### Problem

Three ML-detectable anomalies in ShadowLink traffic:

1. **Payload sizes**: MTU-aligned packets (~1300 bytes) dominate. Real analytics = 50-400 bytes.
2. **Session duration**: Single connection for hours. Real analytics = 2-8 minute sessions.
3. **Upload/Download ratio**: VPN ~1:1. Real analytics ~3:1 (upload-heavy).

### Solution: MimicryEngine

New component in `skins/browser/mimicry.go` that shapes traffic to match real analytics SDK behavior.

#### 4.1 Payload Size Distribution

**Upload distribution (client→server):**

| Size range | Frequency | Mimics |
|-----------|-----------|--------|
| 80-150 bytes | 45% | pageview/screen_view events |
| 150-350 bytes | 35% | click, scroll, custom events |
| 350-800 bytes | 15% | form submissions, batch events |
| 800-2000 bytes | 5% | large batch, session summary |

**Download distribution (server→client):**

| Size range | Frequency | Mimics |
|-----------|-----------|--------|
| 50-100 bytes | 40% | simple ack `{"status":"ok"}` |
| 200-600 bytes | 35% | config updates, consent status |
| 600-2000 bytes | 20% | A/B test configs, audience segments |
| 2-8 KB | 5% | feature flags, full config refresh |

**Implementation — chunking:**

Large payloads (e.g., 1300B of tunnel data) are split into multiple "events" in the JSON array:
```json
{"events": [
  {"type": "scroll", "ts": 1711..., "data": "<base64 chunk 1>"},
  {"type": "click",  "ts": 1711..., "data": "<base64 chunk 2>"},
  {"type": "metric", "ts": 1711..., "data": "<base64 chunk 3>"}
]}
```

Each event is 80-350 bytes (matching GA4 event sizes). All events in a single HTTP request belong to the same stream and are processed **sequentially by server** — each carries its own encrypted chunk with its own seq_num. Server decrypts each event independently and reassembles the original payload by concatenating decrypted payloads in seq_num order (same as existing multi-chunk processing).

**Implementation — padding:**

Small payloads are padded to target size selected from the distribution using weighted random. Padding bytes are encrypted (FlagPadding already exists).

**Implementation — response inflation:**

Server adds realistic JSON fields to responses:
```json
{
  "status": "ok",
  "config_version": "2026.03.29.1",
  "experiment_id": "exp_a8f3",
  "variant": "control",
  "next_poll": 45,
  "results": [{"id": "evt_...", "payload": "..."}]
}
```

These fields are ignored by the client but inflate response size to match analytics config responses.

#### 4.2 Session Lifecycle Pattern

**Current**: One TLS/WS connection for the entire VPN session (hours).

**Target**: Multiple "browse sessions" of 2-8 minutes with 0.5-3 second gaps.

**Implementation:**

The existing `connmanager.go` rotation interval (5-10 min) is reduced to 2-8 min with jitter.

Between rotations, a **gap pause** is introduced:
- Duration: 0.5-3 seconds (weighted: 70% under 1.5s)
- During gap: upload data buffered on client, download data buffered on server
- **Buffer limit**: 4 MB per direction. If exceeded, TCP flow control applies backpressure (stops reading from SOCKS5 client / upstream), so no data loss occurs.
- **Reconnect failure**: If new connection fails after gap, retry with exponential backoff (0.5s, 1s, 2s). After 3 failures, report error to SOCKS5 client.
- After reconnect: flush buffers
- User impact: imperceptible (0.5-3 sec latency spike)

**Critical**: The ShadowLink session (keys, seq_num, replay window) is NOT interrupted. Only the transport (TCP/TLS connection) rotates. From the protocol's perspective, nothing changes. From DPI's perspective, the user "navigated away and came back."

For WebSocket mode: WS close → gap pause → new WS connection with same session token.

**Session lifecycle state machine:**

```
ACTIVE (2-8 min) → GAP (0.5-3 sec) → ACTIVE → GAP → ...
                    ↑ buffer traffic    ↑ flush & resume
```

#### 4.3 Upload/Download Ratio Controller

**Current ratio**: ~1:1 to 1:1.5 (upload:download). VPN fingerprint.

**Target ratio**: 2.5:1 to 3.5:1 (upload:download). Analytics fingerprint.

**Implementation:**

`RatioController` maintains a 30-second sliding window of upload/download byte counts.

```go
type RatioController struct {
    window     time.Duration // 30s
    uploadBytes  int64
    downloadBytes int64
    targetLow    float64 // 2.5
    targetHigh   float64 // 3.5
}

func (rc *RatioController) CoverBudget() int {
    if rc.downloadBytes == 0 {
        return 0 // no download yet, no cover needed
    }
    ratio := float64(rc.uploadBytes) / float64(rc.downloadBytes)
    if ratio < rc.targetLow {
        // Need more upload — return bytes of cover to add
        needed := int64(rc.targetLow * float64(rc.downloadBytes)) - rc.uploadBytes
        return int(needed)
    }
    return 0 // ratio is fine
}
```

**Upload inflation**: Client adds cover events (existing FlagPadding mechanism). The number of cover bytes is determined by `CoverBudget()`.

**Download deflation**: Server uses compact JSON for responses. No unnecessary padding in download direction.

**Overhead**: Typically ~5-10% bandwidth increase from cover traffic. **Upper bound**: CoverBudget is capped at 64 KB/sec to prevent runaway inflation during download-heavy activity (e.g., large file downloads). When real ratio diverges sharply (e.g., streaming video), the controller operates best-effort — it won't try to match 3:1 if that would require >64 KB/sec of cover. This is acceptable: even partial ratio correction makes traffic less VPN-like.

#### Files changed

| File | Change |
|------|--------|
| `skins/browser/mimicry.go` | **NEW** — MimicryEngine, PayloadDistribution, SessionLifecycle, RatioController |
| `skins/browser/mimicry_test.go` | **NEW** — distribution tests, ratio convergence, session timing |
| `skins/browser/shaping.go` | Replace fixed padding with MimicryEngine.ShapeUpload/ShapeDownload |
| `skins/browser/request.go` | Multi-event chunking, response inflation fields |
| `client/connmanager.go` | Rotation interval 2-8 min, gap pause |
| `client/ws_transport.go` | WS disconnect/reconnect during rotation, buffer during gap |
| `client/transport.go` | Integrate RatioController for cover budget |

---

## DPI Resistance Summary

After all fixes:

| Attack Vector | Before | After |
|--------------|--------|-------|
| IP blacklist | OK (CDN fallback) | OK |
| TLS fingerprint (JA3) | OK (Chrome-identical) | OK |
| HTTP/2 SETTINGS | Partial (nginx needed) | Same (nginx remains required for prod) |
| HTTP content pattern | OK (JSON analytics) | OK |
| Payload size distribution | VULNERABLE | FIXED — analytics-realistic sizes |
| Session duration | VULNERABLE | FIXED — 2-8 min browse sessions |
| Upload/Download ratio | VULNERABLE | FIXED — 3:1 ratio (analytics) |
| Active probing | OK (decoy) | OK |
| SNI/Certificate | Partial (nginx+LE) | Same (deployment requirement) |

---

## Implementation Order

1. **Upload optimization** — independent, high impact, quick win
2. **Device limits** — independent, needed for production
3. **Analytics Mimicry Engine** — depends on understanding current shaping.go
4. **UDP ASSOCIATE** — independent, improves system VPN
