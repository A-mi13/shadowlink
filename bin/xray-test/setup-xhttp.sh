#!/bin/bash
set -e

echo "=== 1. Creating Xray XHTTP server config ==="
cat > /tmp/xray-test/server.json << 'JSONEOF'
{
  "log": {"loglevel": "info"},
  "inbounds": [{
    "port": 10444,
    "protocol": "vless",
    "settings": {
      "clients": [{"id": "f47ac10b-58cc-4372-a567-0e02b2c3d479"}],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "xhttp",
      "xhttpSettings": {
        "path": "/xhttp-test"
      }
    }
  }],
  "outbounds": [{"protocol": "freedom"}]
}
JSONEOF
echo "Config created: /tmp/xray-test/server.json"

echo "=== 2. Adding nginx location for XHTTP ==="
if grep -q "xhttp-test" /etc/nginx/sites-enabled/shadowlink; then
    echo "Already exists, skipping"
else
    python3 << 'PYEOF'
data = open('/etc/nginx/sites-enabled/shadowlink').read()
block = """    location /xhttp-test {
        proxy_pass http://127.0.0.1:10444;
        proxy_buffering off;
        gzip off;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

"""
data = data.replace('    location / {', block + '    location / {')
open('/etc/nginx/sites-enabled/shadowlink', 'w').write(data)
print("nginx config updated")
PYEOF
fi

echo "=== 3. Testing and reloading nginx ==="
nginx -t && systemctl reload nginx
echo "nginx reloaded OK"

echo "=== 4. Starting Xray XHTTP server ==="
chmod +x /tmp/xray-test/xray
# Kill any existing test instance
pkill -f "xray-test/xray" 2>/dev/null || true
nohup /tmp/xray-test/xray run -c /tmp/xray-test/server.json > /tmp/xray-test/xray.log 2>&1 &
sleep 1
echo "Xray PID: $(pgrep -f 'xray-test/xray')"
tail -5 /tmp/xray-test/xray.log

echo ""
echo "=== DONE ==="
echo "Xray XHTTP server running on port 10444"
echo "nginx proxying /xhttp-test -> 10444"
