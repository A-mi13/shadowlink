# NixaVPN Client — Architecture Reference for Mobile Development

This is a working desktop CLI prototype. Use it as a reference to build native mobile clients (iOS/Android).

## Quick Start (Desktop)

```bash
# Build
cd shadowlink/
go build -o nixavpn-client ./cmd/nixavpn-client/

# Run with VLESS link
./nixavpn-client connect --import "vless://UUID@IP:PORT?sni=...&pbk=...&sid=...&flow=xtls-rprx-vision"

# Run with ShadowLink link
./nixavpn-client connect --import "sl://PUBKEY@domain.com:443?tls=1&ws=1"

# Run with config file
./nixavpn-client connect --config client.yaml

# Run with API (how mobile clients will work)
./nixavpn-client connect --api https://api.nixavpn.com --token "JWT_TOKEN"

# System VPN mode (TUN interface, requires admin/root)
./nixavpn-client connect --import "vless://..." --system-vpn
```

After connecting, SOCKS5 proxy is available at `127.0.0.1:1080`.

---

## Architecture

```
                         +-----------------------+
                         |    nixavpn-client      |
                         |                       |
  --import vless://  --> |  +---> VLESSEngine    |---> SOCKS5 :1080
  --import sl://     --> |  |     (xray-core)    |        |
  --config yaml      --> |  |                    |        v
  --api + --token    --> |  +---> ShadowLink     |   [tun2socks]
                         |        Engine         |        |
                         |        (client lib)   |        v
                         |                       |   TUN interface
                         +-----------------------+   (system VPN)
```

**Key principle:** Both protocols are "engines" that expose a local SOCKS5 proxy. Everything above (TUN, LeakGuard, routing) is shared. Switching protocols = switching the engine, nothing else changes.

---

## File Map

```
shadowlink/cmd/nixavpn-client/
  main.go                 # CLI entry point, signal handling, lifecycle
  engine.go               # Engine interface (the core abstraction)
  engine_shadowlink.go    # ShadowLink protocol engine
  engine_vless.go         # VLESS+Reality engine (embedded xray-core)
  config.go               # Config types, YAML/URL/API parsers
  tunnel.go               # tun2socks TUN integration, routing

shadowlink/client/            # ShadowLink client library (reuse via gomobile)
  client.go               # Client struct, Connect(), Close()
  transport.go            # DirectTransport, CDNTransport
  ws_transport.go         # WebSocket full-duplex transport
  probe.go                # Network detection, AutoConnect()
  leakguard/              # DNS/IPv6 leak prevention, kill switch
  dnsrouter/              # Domain-based bypass routing
  routing.go              # Split-tunnel rules
  slurl.go                # sl:// URL parser
  fileconfig.go           # YAML config loader

shadowlink/proxy/socks5/      # SOCKS5 proxy server (extracted from client)
  server.go               # Listener, handshake, dispatch
  tcp.go                  # TCP CONNECT relay
  udp.go                  # UDP ASSOCIATE relay
  parse.go                # Address parsing
  direct.go               # Direct dial (bypass mode)

shadowlink/core/              # Cryptography
  handshake.go            # X25519 key exchange
  session.go              # AES-256-GCM session encryption
  chunk.go                # Wire format (nonce + encrypted payload)
```

---

## Engine Interface (the core abstraction)

```go
type Engine interface {
    Connect(ctx context.Context) error   // connect + start SOCKS5
    SOCKSAddr() string                   // "127.0.0.1:1080"
    Name() string                        // "shadowlink" | "vless"
    Close() error                        // disconnect
}
```

**For mobile:** Implement this interface in Swift/Kotlin. Each platform gets its own Engine wrapper.

---

## Protocol: VLESS+Reality

**How it works in the CLI:**
1. Parse vless:// URL -> extract UUID, server IP, port, public key, SNI, fingerprint
2. Build xray-core JSON config (SOCKS5 inbound + VLESS outbound)
3. Start embedded xray-core instance
4. xray-core handles everything: TLS, Reality handshake, VLESS protocol, SOCKS5 proxy

**For mobile:** Use xray-core via gomobile binding, or use libXray (existing iOS/Android library). The JSON config format is the same.

**xray config structure (built in engine_vless.go):**
```json
{
  "inbounds": [{
    "protocol": "socks",
    "listen": "127.0.0.1",
    "port": 1080,
    "settings": { "auth": "noauth", "udp": true }
  }],
  "outbounds": [{
    "protocol": "vless",
    "settings": {
      "vnext": [{
        "address": "SERVER_IP",
        "port": 8443,
        "users": [{ "id": "UUID", "encryption": "none", "flow": "xtls-rprx-vision" }]
      }]
    },
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "fingerprint": "chrome",
        "serverName": "SNI_DOMAIN",
        "password": "PUBLIC_KEY_BASE64",
        "shortId": "SHORT_ID"
      }
    }
  }]
}
```

**Important:** Field is `"password"` (not `"publicKey"`) in xray-core v1.251208+.

---

## Protocol: ShadowLink

**How it works:**
1. Parse sl:// URL or YAML config
2. Create `client.Client` with server address + X25519 public key
3. Connect (with optional AutoConnect for network detection)
4. Optionally upgrade to WebSocket for full-duplex
5. Start SOCKS5 server that tunnels through ShadowLink

**ShadowLink is HTTP-level steganography:**
- VPN data is AES-256-GCM encrypted, base64-encoded
- Wrapped in fake analytics JSON: `{"events":[{"type":"page_view","data":"BASE64"}]}`
- Works through Cloudflare CDN (CF can't see the payload)
- 3 transport modes: Direct, CDN, WebSocket

**For mobile:** Import `shadowlink/client` via gomobile. Key API:
```go
cl := client.NewClient(client.ClientConfig{
    ServerAddr:   "domain.com:443",
    ServerPubKey: pubKeyBytes,  // 32 bytes
    ClientID:     []byte("mobile-client"),
    UseTLS:       true,
    CDNDomain:    "cdn.example.com",
})
err := cl.Connect(ctx)
defer cl.Close()

// Or auto-detect network:
cl, err := client.AutoConnect(ctx, config, probeConfig)
```

---

## Config Delivery (API)

Mobile clients should get config from the server API:

```
GET /api/v1/client/full-config?protocol=vless
GET /api/v1/client/full-config?protocol=shadowlink
Authorization: Bearer JWT_TOKEN
```

**Auth flow:**
```
POST /api/v1/client/auth/register   { email, password }
POST /api/v1/client/auth/login      { email, password } -> { access_token, refresh_token }
POST /api/v1/client/auth/refresh    { refresh_token }   -> { access_token }
```

See `config.go:FetchConfigFromAPI()` for the reference implementation.

---

## System VPN (TUN)

**How it works:**
1. Engine connects -> SOCKS5 proxy on localhost:1080
2. tun2socks creates TUN interface
3. All system traffic -> TUN -> tun2socks -> SOCKS5 -> VPN tunnel
4. Split routing: 0.0.0.0/1 + 128.0.0.0/1 (doesn't replace default route)
5. Escape route for VPN server IP through real gateway
6. LeakGuard: DNS leak prevention, IPv6 disable, kill switch

**For mobile:**
- iOS: Use `NEPacketTunnelProvider` (Network Extension)
- Android: Use `VpnService` + `tun2socks` (or `libcore` from sing-box)
- The SOCKS5 -> TUN pattern is the same, just different TUN APIs

---

## Dependencies

| Library | Purpose | Mobile equivalent |
|---------|---------|-------------------|
| xray-core | VLESS+Reality | libXray / gomobile binding |
| tun2socks | TUN interface | NEPacketTunnelProvider / VpnService |
| shadowlink/client | ShadowLink protocol | gomobile binding |
| shadowlink/core | X25519 + AES-256-GCM | Platform crypto (CryptoKit / javax.crypto) |

---

## Data Flow

```
User taps "Connect"
    |
    v
App calls GET /api/v1/client/full-config?protocol=vless
    |
    v
Receives: { address, port, uuid, public_key, short_id, sni }
    |
    v
Builds xray JSON config (see above)
    |
    v
Starts xray-core instance -> SOCKS5 on localhost:1080
    |
    v
Creates TUN interface (NEPacketTunnelProvider / VpnService)
    |
    v
Routes traffic: TUN -> tun2socks -> SOCKS5 -> xray-core -> VPN server
    |
    v
User sees: "Connected. Exit IP: X.X.X.X"
```

---

## Testing

```bash
# Build
go build -o nixavpn-client ./cmd/nixavpn-client/

# Test VLESS (replace with real link)
./nixavpn-client connect --import "vless://UUID@IP:PORT?..."

# Test ShadowLink
./nixavpn-client connect --import "sl://PUBKEY@domain:443?tls=1&ws=1"

# Verify SOCKS5 works (in another terminal)
curl -x socks5://127.0.0.1:1080 https://api.ipify.org
# Should return VPN server IP, not your real IP

# Test system VPN (admin required)
./nixavpn-client connect --import "vless://..." --system-vpn
# All traffic now goes through VPN
```

---

## Key Decisions for Mobile

1. **Start with VLESS only** — it's simpler (just embed xray-core). Add ShadowLink later.
2. **Use gomobile** for ShadowLink — the Go library works on both iOS and Android via gomobile binding.
3. **Config from API** — don't hardcode servers. Use the API flow (login -> get config -> connect).
4. **Engine pattern** — keep the Engine interface. Makes it easy to add more protocols later.
5. **Test with curl** — `curl -x socks5://127.0.0.1:1080 https://api.ipify.org` is the quickest way to verify the tunnel works.
