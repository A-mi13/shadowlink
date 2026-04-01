# ShadowLink Admin Panel Integration — Plan

## Goal
One-click deploy ShadowLink to any NixaVPN server from admin panel.
Sidebar sub-item → page with server/port selection → deploy button → modal with terminal output.

## Architecture (follows existing deploy patterns)

### Backend

**1. Deploy steps: `internal/deploy/steps_shadowlink.go`**
Pattern: same as `steps_trusttunnel.go`, `steps_xray.go`

Steps:
1. Cross-compile `shadowlink-server` binary for linux/amd64 (from `shadowlink/cmd/shadowlink-server/`)
2. Upload binary to VPS via SSH: `/opt/shadowlink/shadowlink-server`
3. Generate server key pair on VPS
4. Save key to `/opt/shadowlink/server.key`
5. Create systemd unit: `/etc/systemd/system/shadowlink.service`
6. UFW allow selected port
7. Start + enable service
8. Save config to `protocol_configs` table (server_id, protocol="shadowlink", config_json with port, public_key)
9. Return public key to admin for client config

Systemd unit template:
```ini
[Unit]
Description=ShadowLink VPN Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/opt/shadowlink/shadowlink-server --listen :PORT --server-key /opt/shadowlink/server.key --max-clients 100
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

**2. Admin handler: `internal/admin/shadowlink_handlers.go`**

Endpoints:
- `POST /api/admin/servers/:id/deploy-shadowlink` — start deploy (port in body)
- `GET /api/admin/servers/:id/shadowlink-status` — check if shadowlink is running
- `DELETE /api/admin/servers/:id/shadowlink` — stop and remove

Deploy streams logs via existing WebSocket hub (`ws.Instance`).

**3. Route registration: `cmd/api/main.go`**
Add routes under admin group, same pattern as platform-deploy, trusttunnel-sync, etc.

### Frontend

**4. Sidebar: `frontend/src/components/Sidebar.tsx`**
Add sub-item under "Управление" section:
```
Серверы
ShadowLink    ← NEW
SNI Pool
...
```

**5. Page: `frontend/src/pages/ShadowLinkPage.tsx`**
- Table of servers showing ShadowLink status (deployed/not deployed/running/stopped)
- For each server: port, public key, active sessions count
- Deploy button → opens modal
- Status badges: 🟢 running, 🔴 stopped, ⚪ not deployed

**6. Deploy Modal (reuse pattern from ServersPage deploy)**
- Step 1: Select port (default 9443, or any free port)
- Step 2: Click "Deploy" → WebSocket terminal shows real-time progress
- Step 3: Done → shows public key for client config
- Copy button for public key

**7. API wrapper: `frontend/src/api/shadowlink.ts`**
```typescript
export const deployShadowLink = (serverId: number, port: number) => ...
export const getShadowLinkStatus = (serverId: number) => ...
export const removeShadowLink = (serverId: number) => ...
```

### Database

**Migration `064_shadowlink.sql`:**
```sql
-- ShadowLink uses existing protocol_configs table
-- protocol = 'shadowlink'
-- config_json = {"port": 9443, "public_key": "hex...", "max_clients": 100}
-- No new table needed
```

## Implementation Order
1. `internal/deploy/steps_shadowlink.go` (SSH deploy logic)
2. `internal/admin/shadowlink_handlers.go` (API endpoints)
3. Routes in `main.go`
4. `frontend/src/api/shadowlink.ts`
5. `frontend/src/pages/ShadowLinkPage.tsx`
6. Sidebar entry
7. Test: deploy to real VPS from admin panel

## Quick Manual Test (before admin integration)

For testing RIGHT NOW without admin panel:

```bash
# On your Windows machine:
cd D:/NIXAVPN/shadowlink

# Cross-compile for Linux:
GOOS=linux GOARCH=amd64 go build -o shadowlink-server-linux ./cmd/shadowlink-server/

# Copy to VPS:
scp shadowlink-server-linux user@VPS_IP:/opt/shadowlink/shadowlink-server

# SSH to VPS and run:
ssh user@VPS_IP
chmod +x /opt/shadowlink/shadowlink-server
/opt/shadowlink/shadowlink-server --gen-key
# Save private key → server.key, remember public key
echo "PRIVATE_KEY" > /opt/shadowlink/server.key
/opt/shadowlink/shadowlink-server --listen :9443 --server-key /opt/shadowlink/server.key

# Back on Windows — connect:
./shadowlink-client.exe --server VPS_IP:9443 --pubkey PUBLIC_KEY

# Test:
curl --socks5-hostname 127.0.0.1:1080 http://ifconfig.me
# Should show VPS IP
```
