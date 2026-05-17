# T1.3 Live Decoy — Flip-On Canary Procedure

**Use after Phase A/D/B/C merged.** 24h watch on ONE canary server before fleet-wide enable.

## Prerequisites

- Admin panel accessible, super_admin role available.
- ShadowLink deployed on target canary server, `mgmt_key` set (migrated if legacy).
- Phase A binary on VPS (has C1/C2/C3 fixes + validate-config flag).

## Step 1: Choose canary

Recommended: lowest-traffic ShadowLink server in production. Current: `104.222.177.67` (datacanvases.com).

## Step 2: Configure live_blog via admin

1. Open admin → Servers → ShadowLink tab → select canary server.
2. Switch to "Live Decoy" tab.
3. Set:
   - Enabled: **on**
   - Upstream: `https://habr.com`
   - CDN Upstream: `https://dr.habracdn.net`
   - Canary Article ID: `723128` (default — real habr article)
   - Brand: `DataCanvases`
   - Leave rest as defaults.
4. Click **Save**.
5. Click **Apply** (super_admin only). Confirm SSH password prompt. Watch log stream.
6. Success when log shows "OK: config applied, shadowlink active".

## Step 3: Immediate verification (first 10 min)

From admin → Metrics tab:
- `canary_ok_total` should increment within 1x canary_interval (default 15 min).
- `rewrite_drift_total` should stay 0.
- `fallback_spa_total / requests_total` should stay below 1%.

Manual probe (from workstation):
```
curl -v https://datacanvases.com/blog/723128 2>&1 | grep -E "^(HTTP|Content|Server|$)" | head -20
curl -s https://datacanvases.com/blog/723128 | grep -c "DataCanvases"  # must be > 0
curl -s https://datacanvases.com/blog/723128 | grep -c "Хабр"          # must be 0
```

## Step 4: 24h watch

Check admin metrics every 4h:
- Canary health: green (ok_total ticks up).
- Drift: 0.
- Fallback ratio: < 5%.
- Upstream err ratio: < 10%.

## Step 5: DPI timing probe simulation

Run from a server outside our network:
```
for i in {1..100}; do
  curl -w "%{time_total}\n" -o /dev/null -s "https://datacanvases.com/blog/$((RANDOM % 100 + 1))"
done | sort -n | awk 'BEGIN{print "p50 p95 p99"} { a[NR]=$1 } END { print a[int(NR*0.5)], a[int(NR*0.95)], a[int(NR*0.99)] }'
```

Most IDs are fake → fail-path with jitter. Expected: all values ≈ 150ms ± 20ms + network RTT. If p99 >> p50 by more than 100ms — investigate (likely C1/C3 regression).

## Rollback triggers

Any of:
- `rewrite_drift_total > 0` (habr changed HTML, rewriter missed something).
- `fallback_spa_total / requests_total > 10%` (upstream dead).
- User reports VPN blocked / slow after enable.
- Timing probe shows outlier distribution.

## Rollback procedure

Admin → canary server → Live Decoy tab → click red "Disable Live Decoy" button. Confirms, runs Apply with `enabled=false`. Watch logs — same flow as enable but reverses.

Alternative (direct SSH emergency):
```bash
ssh root@<vps>
sed -i 's/^  enabled: true/  enabled: false/' /etc/shadowlink/config.yaml
systemctl restart shadowlink
```

## After 24h clean

If metrics green and timing probe uniform — safe to enable on next server. Do NOT fleet-wide enable without per-server canary (each fleet may have different upstream conditions).
