# ShadowLink Protocol — Deployment & Architecture Reference

Custom steganographic VPN protocol. All code MUST stay in `shadowlink/` at repo root.

## Protocol Overview

- HTTP-level steganography (NOT TLS-level) — VPN data is AES-256-GCM encrypted, base64-encoded, wrapped in JSON analytics events: `{"events":[{"type":"page_view","data":"<base64>"}]}`
- Traffic pattern mimics SPA analytics (Google Analytics 4 / Mixpanel)
- X25519 key exchange, AES-256-GCM payload encryption
- Works through Cloudflare orange cloud — CF cannot decrypt the payload
- SOCKS5 proxy with UDP ASSOCIATE for system VPN mode

## Architecture

```
Client (CDNTransport) → Cloudflare Edge → nginx (TLS term) → ShadowLink Server (unix socket)
```

Handler routing (`server/handler.go`):
- POST + `Content-Type: application/json` → ShadowLink VPN session
- `Upgrade: websocket` → WebSocket transport
- Everything else → decoy site (static files)

## Server CLI (`cmd/shadowlink-server/main.go`)

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | — | YAML config file |
| `-listen` | `:443` | Listen address |
| `-cert`, `-key` | — | TLS certificate/key |
| `-server-key` | — | Static key file (64 hex chars) |
| `-decoy` | — | Decoy site directory |
| `-max-clients` | `100` | Max concurrent sessions |
| `-max-conns` | `8` | Max connections per client |
| `-chunk-size` | `12288` | Max chunk payload bytes |
| `-behind-proxy` | `false` | Trust X-Forwarded-For |
| `-enable-udp` | `false` | UDP listener for TURN relay |
| `-udp-listen` | `:56000` | UDP listen address |
| `-mgmt-port` | `0` | Management API port (0=off) |
| `-mgmt-bind` | `127.0.0.1` | Management API bind |
| `-mgmt-key` | — | Management API key |
| `-default-max-devices` | `3` | Device limit per user |
| `-gen-key` | — | Generate new key pair and exit |

Subcommand: `export-client-config` — export client config from server state.

## Key Generation

```bash
shadowlink-server -gen-key
# Private key: <hex>   ← save to file, use with --server-key
# Public key:  <hex>   ← give to client for handshake auth
```

## CDNTransport (`client/transport.go`)

- `NewCDNTransport(cdnDomain)` — standard CDN mode (wraps DirectTransport)
- `NewCDNTransportWithECH(cdnDomain, echEnabled)` — with ECH support (resolves DNS HTTPS records)

## Cloudflare Deployment (Step by Step)

1. **Domain**: Buy foreign TLD (NOT .ru — Russian registrar can seize it)
2. **CF setup**: Add to Cloudflare, **gray cloud** first, A record → server IP
3. **Server deploy**: Install shadowlink-server + nginx + decoy site
4. **nginx**: Configure as reverse proxy to unix socket (template below)
5. **TLS cert**: `certbot certonly --standalone -d your-domain.com` (while gray cloud)
6. **Verify**: Direct HTTPS access works, decoy site serves
7. **Orange cloud**: Switch to orange, SSL mode → "Full (strict)"
8. **CF settings**: WebSockets ON, Bot Fight Mode OFF, Under Attack Mode OFF

## nginx Config Template

```nginx
server {
    listen 443 ssl;  # NO http2! CF connects via h2 to origin, but WS upgrade requires HTTP/1.1
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://unix:/run/shadowlink.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

**Critical**: MUST use nginx in production — Go's `net/http` sends non-browser HTTP/2 SETTINGS frames (JA3/fingerprint detection risk).

## systemd Unit Template

```ini
[Unit]
Description=ShadowLink Server
After=network.target

[Service]
ExecStart=/usr/local/bin/shadowlink-server \
    -config /etc/shadowlink/config.yaml \
    -behind-proxy \
    -decoy /var/www/decoy
Restart=always
User=www-data

[Install]
WantedBy=multi-user.target
```

## Key Components

| Package | Purpose |
|---------|---------|
| `core/` | Crypto (X25519, AES-256-GCM), session manager, key pairs |
| `server/` | HTTP handler, tunnels, multiplexing, decoy, rate limiter, client auth, UDP relay |
| `client/` | DirectTransport, CDNTransport, ConnManager, SOCKS5 proxy |
| `skins/browser/` | Analytics Mimicry Engine (response inflation, session rotation) |
| `cmd/shadowlink-server/` | Server entry point + export-client-config subcommand |
| `cmd/shadowlink-client/` | Client entry point (not in this dir — binary only) |
| `testutil/` | Test helpers |
| `docs/` | Specs and plans |

## Analytics Mimicry Engine (`skins/browser/`)

- Response inflation: pads responses to match real analytics payload distributions
- Session rotation: 2-8 min rotation with gap pause to mimic browser sessions
- Ratio controller: maintains realistic request/response size ratios

## Troubleshooting

| Problem | Check |
|---------|-------|
| jq parse error on config | File might have BOM or comments — `cat -v config.yaml` |
| No connections in logs | CF orange cloud on? DNS resolves to CF IP? |
| Connection timeout | nginx `proxy_pass` matches socket path? shadowlink-server running? |
| HTTP/2 fingerprint detected | Are you running without nginx? Go's net/http is detectable |
| Device limit errors | Check `-default-max-devices` flag or per-user config |
| UDP not working | Need `-enable-udp` flag + firewall open on `-udp-listen` port |

## Isolation Rules

- All ShadowLink code: `shadowlink/` (NOT `internal/shadowlink/`)
- Docs & specs: `shadowlink/docs/`
- Tests: colocated (`*_test.go`)
- Only integration points (deploy, assembler, admin handlers) go into main NixaVPN tree

## Completed Features

- **uTLS fingerprint mimicry** — DONE. `client/ws_transport.go` uses `refraction-networking/utls` with Chrome/Safari/Firefox profiles. `skins/browser/fingerprint.go` manages weighted rotation.
- **Client auth** — DONE. `server/ratelimit.go` implements whitelist mode via `authorized_clients` in YAML config. Empty list = open mode (testing). Management API allows runtime sync.
- **LeakGuard** — DONE. `client/leakguard/` — DNS leak prevention, IPv6 disable, kill switch (Darwin/Linux/Windows).
- **SOCKS5 UDP ASSOCIATE** — DONE. UDP tunneling for system VPN mode.

## Planned Work

1. **Embedded tun2socks** — system VPN works but tun2socks is external binary (users download separately). Need to embed as Go package or bundle.
2. **NixaVPN integration** — deploy via orchestrator, config assembler, admin handlers.
