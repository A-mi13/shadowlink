# ShadowLink Protocol — Design Specification

**Date:** 2026-03-28
**Status:** Draft
**Authors:** NixaVPN Team

---

## 1. Overview

ShadowLink — собственный VPN-протокол-хамелеон, полностью имитирующий поведение конкретных приложений (браузер, видеозвонок, облако), а не просто маскирующий заголовки. Написан на Go, криптография на стандартных примитивах.

### Goals

- Обход жёсткого DPI (ТСПУ) включая сигнатурный анализ, 16-20 КБ порог, JA3/JA4 fingerprinting, поведенческий/ML анализ, active probing
- Обход белых списков (whitelist mode) через relay на российских облачных платформах и TURN-серверах
- Универсальность: автоматическое определение условий сети и переключение транспорта
- Производительность: 15+ Мбит/с даже в режиме белого списка, 30-80+ Мбит/с в обычном режиме
- Ресурсоэффективность: работа на VPS 2 vCPU / 2-4 ГБ RAM
- Платформы: Android, iOS, Desktop (Windows, macOS, Linux)

### Non-Goals (Phase 1)

- Cloud Skin (WebDAV/S3 маскировка) — Phase 3
- Post-quantum cryptography — Phase 3
- Стеганография VP8 в Call Skin — Phase 2b

---

## 2. Architecture

```
+---------------------------------------------+
|              ShadowLink Core                 |
|  +-------------+  +--------+  +----------+  |
|  | Crypto Layer |  |Session |  |  Probe   |  |
|  | X25519+AES  |  |Mux/Auth|  |  Engine  |  |
|  +------+------+  +---+----+  +----+-----+  |
|         +-------------|-------------+        |
|                       |                      |
|         +-------------+-------------+        |
|         v             v             v        |
|  +----------+  +----------+  +----------+   |
|  | Browser  |  | Call     |  | Cloud    |   |
|  | Skin     |  | Skin     |  | Skin     |   |
|  | (HTTP/1.1|  | (WebRTC/ |  | (WebDAV/ |   |
|  | +TLS 1.3)|  |  DTLS+   |  |  S3)     |   |
|  |          |  |  TURN)   |  |          |   |
|  +----------+  +----------+  +----------+   |
|    Phase 1       Phase 2       Phase 3      |
+---------------------------------------------+
```

### Components

| Component | Purpose | Language |
|---|---|---|
| `shadowlink-core` | Crypto, sessions, mux | Go (shared) |
| `shadowlink-server` | Server binary (systemd) | Go |
| `shadowlink-client` | Client library | Go (+gomobile) |
| `shadowlink-probe` | Network detection, transport selection | Go (part of client) |

### Ports

- 443/TCP — Browser Skin TCP (HTTP/1.1 + TLS 1.3) + decoy site
- 443/UDP — Browser Skin QUIC (HTTP/3, Phase 1b)
- 56000/UDP — Call Skin (DTLS/TURN relay, Phase 2)

---

## 3. Crypto Layer

### Principles

- Своя архитектура, стандартные примитивы
- Не изобретаем шифры — изобретаем как их комбинировать и скрывать

### Primitives

| Component | Choice | Rationale |
|---|---|---|
| Key exchange | X25519 (Curve25519 ECDH) | Fast, proven, 128-bit security |
| Key derivation | HKDF-SHA256 | TLS 1.3 standard |
| Encryption | AES-256-GCM | Hardware acceleration everywhere (AES-NI, ARMv8). GCM provides both encryption AND authentication (AEAD), no separate MAC needed. |
| Client identity | NaCl Box (X25519+XSalsa20+Poly1305) | Encrypts client_id during handshake. Random padding added before encryption to vary ciphertext size. |
| Hashing | BLAKE3 | Used for session_token derivation and content hashing where needed |
| Post-quantum (Phase 3) | ML-KEM-768 hybrid | Future-proofing |

### Handshake

```
Client                                    Server
  |                                         |
  |-- 1. ClientHello (skin-specific) ------>|
  |   [X25519 ephemeral pubkey]             |
  |   [client_id encrypted with server      |
  |    static pubkey (NaCl Box)]            |
  |                                         |
  |<-- 2. ServerHello ----------------------|
  |   [X25519 ephemeral pubkey]             |
  |   [encrypted session_token]             |
  |                                         |
  |   === Shared secret derived ===         |
  |   HKDF-SHA256(                          |
  |     IKM:  ECDH(client_eph, server_eph)  |
  |     salt: client_eph_pub || server_eph_pub |
  |     info: "ShadowLink-v1" || client_id  |
  |   )                                     |
  |                                         |
  |-- 3. Data frames (AES-256-GCM) ------->|
  |<-- 4. Data frames (AES-256-GCM) -------|
```

**Key point:** Handshake data is embedded INSIDE skin-specific traffic:
- Browser Skin: ephemeral pubkey in TLS ClientHello extension
- Call Skin: ephemeral pubkey in STUN Binding Request attribute

DPI sees only the legitimate protocol. Keys are hidden in standard fields.

### Unified Chunk Format (post-handshake)

There is ONE wire format. Each HTTP request/response body carries one encrypted chunk:

```
+----------+---------+-------+----------+---------+
| sess_id  | seq_num | flags | payload  | GCM tag |
| 4B       | 4B      | 1B    | variable | 16B     |
+----------+---------+-------+----------+---------+
<--------- encrypted with AES-256-GCM ----------->

flags: 0x01=data, 0x02=ack, 0x03=padding, 0x04=keepalive,
       0x05=fin, 0x06=control (chunk_size negotiation, rekeying)
```

The entire chunk (including sess_id and seq_num) is encrypted. No metadata leaks — DPI sees only the HTTP/JSON envelope and base64-encoded ciphertext.

`sess_id` is included in AES-GCM AAD (Additional Authenticated Data) to prevent cross-session replay attacks.

### Replay Protection

- 12-byte nonce = 4-byte sess_id + 4-byte seq_num + 4-byte random
- Nonce is **per-session**: each session has its own counter space
- Server maintains per-session sliding window (size 256) for reordering tolerance
- Nonce reuse across different sessions is impossible (different session keys)

### Key Rotation

New session keys every hour via in-band rekeying:
1. Client sends `flags=0x06` control chunk with new ephemeral pubkey
2. Server responds with its new ephemeral pubkey
3. Both derive new keys via HKDF (same params as initial handshake)
4. Switchover on next seq_num — no data transfer interruption
5. Old keys kept for 10 seconds (for in-flight chunks), then zeroed

### Server Authentication

Client verifies server identity at TWO levels:
1. **TLS level:** Let's Encrypt certificate validates domain (prevents MITM by network)
2. **ShadowLink level:** Server proves knowledge of `server_static_privkey` by decrypting NaCl Box in ClientHello. If server can't decrypt → can't derive session keys → connection fails.

In CDN mode (Cloudflare terminates TLS), ShadowLink-level auth is critical — CF can see HTTP traffic but cannot decrypt ShadowLink chunks without `server_static_privkey`.

---

## 4. Anti-TSPU Measures

### TSPU Detection Layers & Countermeasures

| TSPU Layer | Attack | ShadowLink Defense |
|---|---|---|
| Signature (first 16-32 bytes) | Pattern matching | Real TLS 1.3 ClientHello, no custom magic bytes |
| Observation (first 5 packets) | Connection record | First 5 packets = real TLS handshake + legitimate HTTP |
| **16-20 KB threshold** | TCP freeze after threshold | **Multi-connection: each <=12 KB, pool of 4-16 connections** |
| JA3/JA4 fingerprint | ClientHello hash | Fingerprint rotation Chrome/Safari/Firefox, GREASE, shuffling |
| Behavioral/ML | Entropy, timings, patterns | Behavior Shaping: jitter, bimodal sizes, entropy masking |
| IP/ASN reputation | Foreign DC = suspicious | CDN relay (Cloudflare), Cloud relay (Yandex), TURN relay |
| Active probing | Server probing | Server responds as real web server (decoy site) without valid auth |

### 16-20 KB Threshold Defense (Critical)

```
Traditional VPN (blocked):
  Client ---- 1 TCP conn ---- Server
  [200 KB in one connection -> FROZEN after 16 KB]

ShadowLink Browser Skin:
  Client ---- conn 1 (GET /page.html)     ---- Server  [<=12 KB]
  Client ---- conn 2 (GET /style.css)      ---- Server  [<=12 KB]
  Client ---- conn 3 (GET /script.js)      ---- Server  [<=12 KB]
  ...parallel 4-16 connections, rotation...

  Each connection <=12 KB (below 15-20 KB threshold)
  Data streams through connection pool
  DPI sees: "browser loading website with resources" -- normal
```

### JA3/JA4 Defense

1. Real Go `crypto/tls` with Chrome/Safari/Firefox-matching parameters
2. GREASE extensions (random, as in real Chrome)
3. Extension order shuffling (Chrome does this natively)
4. Cipher suite order identical to current Chrome stable
5. Fingerprint rotation: each pool connection uses DIFFERENT fingerprint
6. Updatable fingerprint database (via server push with each Chrome release)

### Behavior Shaping Engine

1. **Timing jitter:** Packets sent with browser-like pauses (50-300ms burst, 1-5s pause)
2. **Packet sizes:** Bimodal distribution matching real HTTP (~200B headers + 1-14KB body)
3. **Upload/download ratio:** 1:5..1:10 (browser-like)
4. **Keepalive:** TCP keepalive every 30-60s (Chrome pattern)
5. **Real HTTP headers:** User-Agent, Accept, Referer, Cookie
6. **Entropy masking:** Encrypted payload encoded as base64 (~6 bits/byte, not 8.0 of raw ciphertext). Additionally, ~10% of requests are "cover traffic" — real-looking JSON without base64 payload (e.g., `{"type":"heartbeat","ts":1711...}`) to break the pattern of every request containing base64 data. Vary JSON structure: some requests use arrays, some objects, some include nested data.

### Freeze Recovery

1. Heartbeat probe every 3-7 seconds (randomized jitter, not fixed interval — fixed intervals are a behavioral fingerprint)
2. 3 missed heartbeats -> connection considered dead
3. Immediate reopening via different connection in pool
4. If all TCP connections die -> auto-switch to Call Skin or CDN mode
5. Session continuity: session preserved across transport switches

---

## 5. Session Layer

Transforms multiple short-lived (<=12 KB) HTTP connections into one reliable bidirectional VPN tunnel.

### Session Token

On first connect, client receives `session_token` (32 bytes, encrypted). Token is sent in every new connection's encrypted payload — server links all connections to one session.

### Multiplexing

Uses the Unified Chunk Format defined in section 3. Each HTTP request body contains one encrypted chunk. Each HTTP response body contains one encrypted chunk.

- Client numbers each chunk (seq_num)
- Server reassembles in correct order using per-session sliding window
- Lost chunks retransmitted through any free connection
- No chunk-to-connection binding — any chunk can go through any conn
- sess_id in AAD prevents cross-session replay

### Adaptive Connection Pool

```
Start: 4 connections
If throughput < target: +2 connections (max 16)
If throughput > target and idle conns > 2: -1 connection
Each connection: open -> write <=12KB -> graceful close
Preopen: 2 connections opened ahead (zero-wait rotation)
```

### Resilience

- If one connection is frozen by TSPU -> data rerouted to others automatically
- Session state kept on server for 5 minutes -> full reconnect without data loss
- When switching skins (Browser -> Call) -> session_token carries over

---

## 6. Browser Skin (Phase 1)

Primary skin for DPI bypass. Indistinguishable from real browser loading a website.

### HTTP Masquerade

**Connection model:** HTTP/1.1 over TLS 1.3 (NOT HTTP/2). Each TCP connection carries one request-response pair, then closes. Why HTTP/1.1:
- HTTP/2 multiplexes streams in one TCP connection → cumulative data exceeds 16 KB threshold
- HTTP/1.1 one-request-per-connection naturally limits data per TCP connection
- TLS 1.3 session resumption (0-RTT) eliminates repeated handshake cost
- Simpler implementation, no HPACK/SETTINGS overhead

**TLS 1.3 Session Resumption:** After first full handshake (2 RTT), subsequent connections use 0-RTT resumption (1 RTT = TCP handshake only, TLS piggybacked). Combined with preopen pipeline, this eliminates handshake overhead.

**Upload (client -> server):**
```http
POST /api/v2/events HTTP/1.1
Host: mysite.com
Connection: close
Content-Type: application/json
Authorization: Bearer eyJ...  <- session_token (encrypted, looks like JWT)
X-Request-ID: a3f8...         <- seq_num (encrypted)
User-Agent: Mozilla/5.0 (Linux; Android 14) Chrome/131.0

{"events":[{"type":"page_view","ts":1711...,"data":"BASE64_PAYLOAD"}]}
```

**Download (server -> client):**
```http
HTTP/2 200
Content-Type: application/json
Cache-Control: no-cache
X-Trace-ID: b7e2...           <- seq_num (encrypted)

{"status":"ok","results":[{"id":"...","payload":"BASE64_PAYLOAD"}]}
```

### URL Rotation

Pool of URLs generated by server, rotated every hour:
- Upload: `/api/v2/events`, `/api/v2/sync`, `/api/metrics`, `/graphql`
- Download: `/api/v2/feed`, `/api/v2/notifications`, `/api/content`

Each connection uses random URL from pool. DPI sees diverse API requests, not repetitive calls.

### Decoy Site (Built-in)

Server hosts a real website out of the box. Any unauthenticated request -> decoy site.

- Browser -> sees website
- curl -> sees website
- TSPU active probe -> sees website
- Google bot -> indexes website (additional legitimacy)

**Key difference from VLESS+Reality:** Reality proxies someone else's site (google.com). ShadowLink **hosts its own real site**. No proxying — direct response. Active probing gets real content with normal timing.

### TLS Certificate

**Requirement:** Real domain with Let's Encrypt certificate.

- Self-signed cert = instant red flag for DPI
- LE cert + real domain + decoy site = legitimate server
- CT logs confirm domain is real (TSPU can check CT logs)

### Operating Modes

**Mode 1 — Direct TCP:**
```
User --TCP/TLS--> ShadowLink Server (port 443)
Best compatibility, works everywhere TCP works
Speed: 30-100 Mbit/s
```

**Mode 2 — Direct QUIC (Phase 1b):**
```
User --UDP/QUIC--> ShadowLink Server (port 443/UDP)
Better for UDP-heavy traffic (gaming, VoIP, QUIC sites)
No TCP head-of-line blocking
Speed: 30-100 Mbit/s
```

**Mode 3 — CDN (Cloudflare Orange Cloud):**
```
User --TCP/TLS--> Cloudflare CDN (104.16.x.x) ---> ShadowLink Server
Server IP completely hidden behind Cloudflare
Speed: 30-80 Mbit/s
```

### TCP vs QUIC Transport

ShadowLink supports two transport protocols for Browser Skin:

| | TCP (HTTP/1.1 + TLS 1.3) | QUIC (HTTP/3) |
|---|---|---|
| Phase | Phase 1 | Phase 1b |
| Port | 443/TCP | 443/UDP |
| User UDP traffic | Encapsulated in TCP (works but adds latency) | Native UDP (optimal for games, VoIP, DNS) |
| DPI resistance | High (normal HTTPS) | High (growing HTTP/3 traffic = 40-60% of web) |
| CDN compatible | Yes (Cloudflare) | Yes (Cloudflare supports HTTP/3) |
| TSPU 16KB threshold | Applies (multi-conn defense) | May not apply (UDP-based, different DPI path) |
| Fallback | Primary | Falls back to TCP if UDP blocked |

**Probe Engine selects automatically:**
- Try QUIC first (lower latency for all traffic)
- If UDP blocked → fallback to TCP
- CDN mode: use whichever Cloudflare supports for this domain

**Implementation note:** Same Unified Chunk Format, same session management, same JSON wrapping. Only the transport layer changes (TCP socket → QUIC stream). The `Transport` interface in client code already supports this — just a new implementation.

### CDN Mode Details (Cloudflare)

**Setup:**
1. Domain with DNS on Cloudflare
2. A record -> Cloudflare Proxy ON (orange cloud)
3. Cloudflare Origin Certificate on server
4. Client connects to domain -> resolves to CF IP -> CF proxies to origin

**Why Cloudflare won't ban us:**
- CF sees: standard HTTP/2 POST/GET requests to REST API
- Content-Type: application/json, sizes 1-12 KB
- Pattern: typical SPA application
- No WebSocket long-lived connections (we use short HTTP)
- Better than VLESS+WS through CF (one WebSocket lives hours -> suspicious)

**Cloudflare Free Plan limits:**
- Bandwidth: unlimited
- Request body: 100 MB (our requests <=12 KB)
- Connections: unlimited
- gRPC: unmetered (Level 3 option for heavy users)

**Risk: Cloudflare ToS (Section 2.8)** prohibits proxy/VPN on free plan. Mitigation:
- Our traffic looks like normal API, not proxy/VPN
- For production at scale: use CF Pro ($20/mo) or CF Business
- Fallback: Yandex Cloud relay if CF bans account
- Each ShadowLink server uses its own CF account/domain (blast radius limited)

### CDN Sub-levels

| Level | Method | Speed | Cost |
|---|---|---|---|
| Level 1 | CF Proxy (orange cloud) | 30-80 Mbit/s | Free |
| Level 2 | CF Workers (serverless relay) | 15-50 Mbit/s | Free 100K req/day, $5/mo for 10M |
| Level 3 | gRPC via CF (unmetered) | 30-80 Mbit/s | Free |

### Performance

**With TLS 1.3 session resumption + preopen pipeline:**

```
Connection lifecycle with 0-RTT resumption:
  1. TCP SYN/ACK (1 RTT) + TLS resumption (piggybacked, 0 extra RTT)
  2. HTTP request with chunk (piggybacked on TLS)
  3. HTTP response with chunk
  4. TCP FIN
  Total: ~2 RTT per chunk (connect + request/response)
  With preopen: connection ready BEFORE data needed → effective 1 RTT

Effective throughput (with preopen, 0-RTT):
  8 conns, 9KB useful data*, 20ms RTT:
    8 x 9KB / 20ms = 3.6 MB/s ~ 29 Mbit/s

  16 conns, 9KB useful data*, 20ms RTT:
    16 x 9KB / 20ms = 7.2 MB/s ~ 58 Mbit/s

  8 conns, 9KB useful data*, 50ms RTT (poor):
    8 x 9KB / 50ms = 1.4 MB/s ~ 11 Mbit/s
    → increase to 12 conns: 12 x 9KB / 50ms = 2.2 MB/s ~ 17 Mbit/s

Without preopen (cold connections, first handshake):
  8 conns, 9KB useful, 20ms RTT, 2 RTT per conn:
    8 x 9KB / 40ms = 1.8 MB/s ~ 14 Mbit/s (ramps up as preopen kicks in)

* 12KB chunk contains ~9KB useful data after base64 encoding (+33%)
  and HTTP/JSON wrapper (~300-500B overhead)
```

Minimum 15 Mbit/s achievable with 12 connections at 50ms RTT.

---

## 7. Call Skin (Phase 2) — Whitelist Bypass

For when **whitelist mode is active** — only Russian IPs accessible (VK, Yandex, government sites). Neither Direct nor Cloudflare work.

### Architecture

```
+--------+     +----------+     +-----------+     +--------+
| User   |---->| VK/OK    |---->| ShadowLink|---->|Internet|
| (client)| UDP| TURN     | UDP | Server    |     |        |
|        |<----| Relay    |<----| (:56000)  |<----|        |
+--------+DTLS +----------+DTLS +-----------+     +--------+

DPI sees: UDP traffic to VK IP -> "video call" -> allows
```

### Channel Bandwidth Reality

**Tested with WhitePass + TrustTunnel:**
```
1 VK Call  = ~5 Mbit/s
2 VK Calls = ~5 Mbit/s (does NOT stack! VK limits per-user/per-IP)

Different platforms DO stack (different TURN infrastructure):
  VK Call    = ~5 Mbit/s (VK TURN)
  OK.ru Call = ~5 Mbit/s (OK TURN -- separate infra)

Realistic maximum: VK + OK = ~10 Mbit/s
```

**MAX Messenger:** Uses VK's TURN infrastructure -> likely same 5 Mbit/s limit, bonding won't help. Also detects VPN usage (pings gosuslugi.ru). **Research only, don't depend on it.**

### Credential Rotation

Background process pre-fetches TURN credentials:
- Pool of 5-10 ready credentials
- Auto-rotate every 30 minutes
- If VK blocks API -> fallback to OK.ru
- Credentials cached and shared between reconnects

### Media Steganography (Phase 2b)

VPN data packed into RTP/SRTP frames:
```
+----------+---------+----------------------+
| RTP hdr  | VP8 hdr | VPN payload          |
| 12 bytes | 1-3 B   | (looks like video)   |
+----------+---------+----------------------+

- Packet sizes: 200-1200 bytes (real VP8 720p pattern)
- Timing: 30 fps -> packet every ~33ms
- DPI sees: SRTP video stream on TURN relay -> "video call"
```

### Cloud Relay Alternative (Yandex Cloud Functions)

```
User --> Yandex Cloud Function (relay) --> ShadowLink Server

DPI sees: HTTPS to functions.yandexcloud.net -> Yandex -> whitelisted
```

**Yandex Cloud Functions free tier:**
- 1,000,000 invocations/month
- 10 GB*hr execution time
- At 12 KB per invocation = ~12 GB traffic free
- Sufficient for 1-3 active users

The relay function is minimal — receives HTTP request, proxies to origin ShadowLink server. Browser Skin requests work through it unchanged.

**VK Cloud VPS:** No serverless functions, but a minimal VPS (~200 RUB/month) on whitelisted VK Cloud IP can serve as a relay with no invocation limits. Plan B for heavy usage.

### Whitelist Bypass Priority Chain

```
Priority 1: Cloudflare CDN (Browser Skin CDN mode)
  - CF IP whitelisted? -> work through CF
  - Speed: 30-80 Mbit/s
  - Probability: ~60% (CF too big to block)

Priority 2: Yandex Cloud Functions relay
  - Yandex IP 100% whitelisted
  - Speed: 15-30 Mbit/s
  - Cost: free up to 1M invocations

Priority 3: VK Cloud VPS relay
  - VK IP 100% whitelisted
  - Speed: 15-50 Mbit/s
  - Cost: ~200 RUB/month

Priority 4: VK/OK TURN relay (Call Skin)
  - VK/OK IP 100% whitelisted
  - Speed: 5-10 Mbit/s (VK + OK bonding)
  - Cost: free
  - Worst case but ALWAYS works while VK is alive
```

---

## 8. Probe Engine

Automatically detects network conditions and selects the best transport.

### Cold Start (first connection, <=3 seconds)

```
Step 1: Quick Probe (parallel, 3 sec timeout)
  Probe A: TCP connect to server :443       -> timeout?
  Probe B: HTTPS GET to CF domain           -> timeout?
  Probe C: HTTPS GET to ya.ru               -> accessible?
  Probe D: DNS resolve server               -> NXDOMAIN?

Step 2: Classify Network
  A=ok, B=ok       -> OPEN (normal internet)
  A=fail, B=ok     -> DPI_BLOCK (IP blocked)
  A=fail, B=fail, C=ok -> WHITELIST
  A=fail, B=fail, C=fail -> OFFLINE

Step 3: Select Transport
  OPEN      -> Direct (max speed)
  DPI_BLOCK -> CDN mode (Cloudflare)
  WHITELIST -> Cloud Relay (Yandex) or Call Skin (VK TURN)
  OFFLINE   -> show error
```

### Warm Start (reconnection)

Client remembers last working transport. On reconnect:
1. Immediately try last working transport (0 delay)
2. Parallel Quick Probe in background
3. If Probe finds better option -> smooth migration

Result: connection in <1 sec on repeated launches.

### Hot Switch (real-time monitoring)

```
Every 30 sec:
  - Heartbeat to server via current transport
  - Measure RTT + throughput
  - If 2 heartbeats lost -> ALERT

Every 5 min:
  - Quick Probe on ALL transports
  - Better one available? -> suggest migration
  - Direct available again? -> migrate back

On ALERT (transport died):
  0ms   -- heartbeat timeout detected
  100ms -- start handshake on fallback transport
  300ms -- fallback active, data flowing
  500ms -- Quick Probe running in background
  3s    -- optimal transport selected, migrate if needed

User experience: ~300ms pause (like a slight lag)
```

### Transport Priority

```
Priority 1: Direct QUIC        [30-100 Mbit/s, +0ms, best for UDP traffic]
Priority 2: Direct TLS         [30-100 Mbit/s, +0ms latency]
Priority 3: CDN Cloudflare     [30-80 Mbit/s, +10-30ms]
Priority 4: Yandex Cloud Relay [15-30 Mbit/s, +20-50ms]
Priority 5: VK Cloud VPS Relay [15-50 Mbit/s, +20-40ms]
Priority 6: VK TURN + OK TURN  [5-10 Mbit/s, +30-80ms]
```

### Edge Cases

| Situation | Handling |
|---|---|
| TSPU freezes connection at 16 KB in Direct | First: reduce chunk_size to 8 KB via control chunk (flags=0x06) — server and client negotiate new size. If still frozen -> CDN mode. Adaptive chunk_size remembered for this network. |
| CF IP blocked by SNI | Try another domain. All blocked -> Cloud Relay. |
| Yandex Cloud Functions rate limit | Track usage, show warning, auto-switch to VK TURN until month end. |
| VK changes TURN API | Graceful degradation, try OK.ru TURN, notify admin. |
| Wi-Fi -> mobile network (IP change) | Session token preserved, new Quick Probe on new network, seamless reconnect. |
| Mobile (whitelist) -> Wi-Fi (no restrictions) | Background Probe detects Direct available -> migrate (speed x10). |

---

## 9. Server Resource Management

### Target Hardware

- **Minimum:** 2 vCPU, 2 GB RAM
- **Recommended:** 2 vCPU, 4 GB RAM
- **Client limit:** configurable per-server in NixaVPN admin panel

### Per-Connection Cost

```
TCP connection    = ~4 KB (kernel socket buffer, minimal)
TLS state         = ~40 KB (session keys, buffers)
HTTP/2 framing    = ~2 KB
Session context   = ~1 KB (seq_num, auth, metadata)
Total per-conn:   ~47 KB

Per-client cost (8 connections): ~376 KB ~ 0.4 MB

Scale (2 GB RAM VPS, ~1.2 GB available):
  50 clients   = ~20 MB   -- easy
  100 clients  = ~40 MB   -- normal
  300 clients  = ~120 MB  -- fine for 2 GB
  500 clients  = ~200 MB  -- needs 4 GB VPS
```

### Optimizations

1. **Short-lived connections:** No long-lived WebSockets eating memory. Go `net/http` auto-releases resources after each chunk.
2. **Lazy TLS buffer allocation:** Idle connection ~4 KB instead of ~47 KB. Most of 8 client connections idle at any moment.
3. **sync.Pool for session state:** Reuse session objects (GC friendly). Zero-alloc hot path for encryption.
4. **AES-NI hardware acceleration:** Minimal CPU load from encryption on x86 and ARMv8.

### Configurable Limits

```yaml
max_clients:          100     # default for 2 GB VPS, configurable in NixaVPN admin panel
max_conns_per_client: 8       # reduce to 4 if low on resources
                              # server advertises this limit in ServerHello
                              # client respects server limit (won't open more than allowed)
chunk_size:           12288   # bytes
session_timeout:      5m      # cleanup dead sessions
idle_conn_timeout:    30s     # close idle connections
```

**Admin panel integration:** NixaVPN admin sets `max_clients` per server. Exceeding limit -> HTTP 503 -> client tries another server.

### Backpressure

- RAM > 80% -> reduce max_conns_per_client to 4
- RAM > 90% -> reject new connections (503)
- CPU > 90% -> enable rate limiting on crypto operations

### Monitoring (NixaVPN agent integration)

Server exposes metrics:
- `active_clients` (gauge)
- `active_connections` (gauge)
- `memory_usage_bytes` (gauge)
- `cpu_usage_percent` (gauge)
- `chunks_per_second` (counter)
- `bytes_relayed_total` (counter)

Consumed by NixaVPN agent -> admin dashboard.

---

## 10. Testing & Validation Strategy

### Level 1: Lab Testing (no TSPU)

**When:** Phase 1, weeks 1-2
**Where:** Local network / 2 VPS in same DC

| ID | Test | Pass Criteria |
|---|---|---|
| T1.1 | Handshake completes | Keys negotiated, session established |
| T1.2 | Transfer 1 GB through tunnel | 0 data loss, correct reassembly |
| T1.3 | Multi-conn chunking | 8 connections, chunks reassemble correctly |
| T1.4 | Throughput benchmark | >50 Mbit/s on LAN |
| T1.5 | Kill connection -> auto-recovery | Reconnect <1 sec |
| T1.6 | 50 clients RAM usage | <100 MB total for ShadowLink |
| T1.7 | 50 clients x 10 Mbit/s CPU | <80% CPU on 2 vCPU |
| T1.8 | Unauthenticated request | Returns decoy site HTML |
| T1.9 | Probe Engine: simulate 4 network types | Correct classification each time |
| T1.10 | Session migration Direct -> CDN -> Direct | Zero data loss |

### Level 2: DPI Emulation (local censor)

**When:** Phase 1, week 3
**Where:** Local network with DPI proxy between client and server

Custom DPI Emulator (Go program) tests each TSPU layer:

**Signature layer:**

| ID | Test | Pass Criteria |
|---|---|---|
| T2.1 | First 32 bytes = valid TLS ClientHello | Matches TLS 1.3 spec |
| T2.2 | No ShadowLink magic bytes in cleartext | Nothing identifiable |
| T2.3 | SNI present and looks normal | Standard domain format |

**16 KB threshold:**

| ID | Test | Pass Criteria |
|---|---|---|
| T2.4 | Emulator cuts TCP after 16 KB from server | ShadowLink continues (multi-conn) |
| T2.5 | Reduce threshold to 8 KB | Adaptive chunk_size adjusts |
| T2.6 | Threshold 4 KB | Still works (chunks shrink) |

**TLS fingerprint:**

| ID | Test | Pass Criteria |
|---|---|---|
| T2.7 | Capture JA3/JA4 hash | Matches real Chrome within acceptable range |
| T2.8 | 10 connections -> fingerprint diversity | 10 different JA3 hashes |
| T2.9 | GREASE extensions present | Yes, random values |

**Behavioral:**

| ID | Test | Pass Criteria |
|---|---|---|
| T2.10 | Record 5 min traffic, analyze payload entropy | ~5.17 bits/byte (base64 range) |
| T2.11 | Packet size distribution | Bimodal, matches real HTTP |
| T2.12 | Timing analysis | No uniform intervals |
| T2.13 | Upload/download ratio | 1:5..1:10 |

**Active probing:**

| ID | Test | Pass Criteria |
|---|---|---|
| T2.14 | curl without auth | Decoy site (HTML, 200 OK) |
| T2.15 | Replay captured ClientHello | Server doesn't reveal proxy |
| T2.16 | Invalid session token | Decoy site |
| T2.17 | Partial handshake (RST after ClientHello) | Server behaves like nginx |

### Level 3: Live Testing (real TSPU)

**When:** Phase 1, week 4 (after passing Level 1-2)
**Where:** Russian mobile operator + home ISP

**Stage A — Home internet:**

| ID | Test | Pass Criteria |
|---|---|---|
| T3.1 | Direct mode connect + speedtest | >30 Mbit/s |
| T3.2 | Hold connection 1 hour | Stable, no drops |
| T3.3 | Download 1 GB file | No interruptions |
| T3.4 | YouTube 1080p through tunnel | No buffering |
| T3.5 | CDN mode connect | Works, >15 Mbit/s |
| T3.6 | Switch Direct <-> CDN | <1 sec delay |

**Stage B — Mobile network (stricter DPI):**

| ID | Test | Pass Criteria |
|---|---|---|
| T3.7 | Direct mode on 4G | Works or gracefully falls back |
| T3.8 | If 16 KB freeze -> auto fallback CDN | Automatic, <3 sec |
| T3.9 | CDN mode on 4G speedtest | >15 Mbit/s |
| T3.10 | Hold 30 min on mobile | Stable |
| T3.11 | Switch Wi-Fi <-> 4G | Session survives |

**Stage C — Whitelist simulation:**

| ID | Test | Pass Criteria |
|---|---|---|
| T3.12 | Router firewall: block all except VK, Yandex, CF | Simulated whitelist |
| T3.13 | Yandex Cloud Relay | Works |
| T3.14 | VK TURN | Works |
| T3.15 | Probe Engine detects WHITELIST | Correct classification |
| T3.16 | Speedtest through relay | >5 Mbit/s |

**Stage D — Stress & long-term stability:**

| ID | Test | Pass Criteria |
|---|---|---|
| T3.17 | 24 hours continuous operation | No memory leaks |
| T3.18 | Server metrics over 24h | RAM stable, CPU <50% avg |
| T3.19 | A/B test vs VLESS+Reality | Compare speed, stability, latency |
| T3.20 | A/B test vs TrustTunnel | Same comparison |

### Phase 1 Success Criteria

**MUST (no release without these):**
- [ ] Direct mode: >30 Mbit/s on good connection
- [ ] CDN mode: >15 Mbit/s through Cloudflare
- [ ] 16 KB TSPU threshold: bypassed (multi-conn)
- [ ] Active probing: server indistinguishable from web server
- [ ] Stability: 1 hour without drops on home internet
- [ ] Reconnect: <1 sec on connection loss
- [ ] Server RAM: <100 MB at 50 clients on 2 GB VPS

**SHOULD (desirable):**
- [ ] JA3 fingerprint indistinguishable from Chrome
- [ ] Behavioral analysis: not detected
- [ ] Mobile 4G: stable
- [ ] Wi-Fi <-> 4G: seamless switch

---

## 11. Phased Development

### Phase 1: Browser Skin (weeks 1-4)

Core protocol + Browser Skin with Direct and CDN modes.
- Crypto Layer (handshake, frames, replay protection)
- Session Layer (multi-conn mux, seq_num, recovery)
- Browser Skin (HTTP masquerade, decoy site, URL rotation)
- CDN Mode (Cloudflare orange cloud integration)
- Probe Engine (Direct vs CDN auto-switch)
- Server binary with resource management
- Client library (Go + gomobile)
- DPI emulator for testing
- Live testing on Russian networks

**Deliverable:** Working VPN protocol that bypasses TSPU DPI through Direct or Cloudflare CDN, with automatic switching.

### Phase 1b: QUIC Transport (weeks 4-5, parallel with Phase 1 testing)

Add UDP/QUIC transport to Browser Skin.
- QUIC transport implementation (quic-go library)
- Same chunk format and session management over QUIC streams
- Probe Engine: QUIC vs TCP auto-selection
- Test: QUIC bypasses 16KB threshold (UDP path in TSPU)
- CDN mode over HTTP/3 (Cloudflare supports it)

**Deliverable:** ShadowLink works over both TCP and QUIC, auto-selecting the best option. UDP-heavy user traffic (games, VoIP) benefits from native UDP transport.

### Phase 2: Call Skin (weeks 5-8)

Whitelist bypass via TURN relays and cloud functions.
- VK TURN credential extraction (reuse from WhitePass)
- OK.ru TURN integration
- Multi-platform bonding (VK + OK)
- Yandex Cloud Functions relay
- VK Cloud VPS relay option
- Probe Engine: WHITELIST detection + full priority chain
- Live testing in whitelist simulation

**Deliverable:** Full whitelist bypass with automatic transport selection.

### Phase 2b: Media Steganography (weeks 9-10)

- RTP/SRTP frame wrapping for Call Skin
- VP8 header emulation
- Timing shaping (30fps video pattern)

### Phase 3: Cloud Skin + Advanced (weeks 11-16)

- Cloud Skin (WebDAV/S3 masquerade)
- Post-quantum key exchange (ML-KEM-768 hybrid)
- ML-resistant adaptive traffic shaping
- NixaVPN admin panel integration
- Full multi-server deployment support

---

## 12. File Structure

```
shadowlink/
  docs/
    specs/              -- this document and future specs
    plans/              -- implementation plans per phase
    research/           -- DPI research, TSPU analysis, protocol analysis
  core/
    crypto.go           -- X25519, AES-GCM, BLAKE3, HKDF
    crypto_test.go
    session.go          -- session management, mux, seq_num, key rotation
    session_test.go
    handshake.go        -- ClientHello/ServerHello, ECDH key exchange
    handshake_test.go
    chunk.go            -- unified chunk format encoding/decoding
    chunk_test.go
    pool.go             -- connection pool manager
    pool_test.go
  server/
    server.go           -- main server, TLS termination, routing
    server_test.go
    decoy.go            -- decoy site handler
    config.go           -- server configuration
    metrics.go          -- resource monitoring
  client/
    client.go           -- main client library
    client_test.go
    probe.go            -- Probe Engine
    probe_test.go
    heartbeat.go        -- keepalive with jitter, freeze detection
    heartbeat_test.go
    transport.go        -- Transport interface + Direct TCP
    transport_cdn.go    -- Cloudflare CDN transport
    transport_quic.go   -- QUIC/HTTP3 transport (Phase 1b)
  skins/
    browser/
      browser.go        -- HTTP masquerade, JSON wrapping
      browser_test.go
      cdn.go            -- Cloudflare CDN mode
      cdn_test.go
      fingerprint.go    -- JA3/JA4 rotation
      shaping.go        -- behavior shaping engine
    call/
      call.go           -- TURN relay, DTLS
      call_test.go
      credentials.go    -- VK/OK credential extraction
      bonding.go        -- multi-channel bonding
      stego.go          -- RTP/VP8 steganography (Phase 2b)
    cloud/
      cloud.go          -- WebDAV/S3 masquerade (Phase 3)
  relay/
    yandex.go           -- Yandex Cloud Functions relay code
    vkcloud.go          -- VK Cloud VPS relay setup
  mobile/
    api.go              -- gomobile-compatible API (exported types only)
    api_test.go
  cmd/
    shadowlink-server/
      main.go           -- server entrypoint
    shadowlink-test/
      main.go           -- DPI emulator / test tools
  testutil/
    dpi_emulator.go     -- local DPI emulation for testing
    traffic_analyzer.go -- entropy, timing, size analysis
```

All ShadowLink code lives in `shadowlink/` at repo root.
Integration with NixaVPN (deploy steps, assembler, admin handlers) only happens when ShadowLink is ready — Phase 3.
