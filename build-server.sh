#!/usr/bin/env bash
# build-server.sh — собирает Linux-сервер ShadowLink для деплоя на pl1.
# Запуск из каталога shadowlink/:  bash build-server.sh
#
# Цель — pl1 (linux/amd64). CGO выключен — статичный бинарь без зависимостей,
# переносится на сервер как есть. Стрипуется (-s -w): на сервере debug-символы
# не нужны, бинарь меньше.
set -euo pipefail

cd "$(dirname "$0")"                       # shadowlink/
OUT="../bin/shadowlink-server-linux"
STAMP="$(date +%Y%m%d-%H%M%S)"

echo ">> компиляция всего модуля + vet серверной части"
go build ./...
go vet ./cmd/shadowlink-server/ ./server/... ./core/...

if [ -f "$OUT" ]; then
  cp "$OUT" "${OUT}.bak-${STAMP}"
  echo ">> бэкап: ${OUT}.bak-${STAMP}"
fi

echo ">> build linux/amd64 -> $OUT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o "$OUT" ./cmd/shadowlink-server/

ls -la "$OUT"
echo ">> готово."
echo ">> ДЕПЛОЙ (сервер первым, по правилу staged):"
echo "   scp $OUT root@104.222.177.67:/usr/local/bin/shadowlink-server.new"
echo "   ssh root@104.222.177.67 'systemctl stop shadowlink && \\"
echo "       cp /usr/local/bin/shadowlink-server /usr/local/bin/shadowlink-server.bak-${STAMP} && \\"
echo "       mv /usr/local/bin/shadowlink-server.new /usr/local/bin/shadowlink-server && \\"
echo "       chmod +x /usr/local/bin/shadowlink-server && systemctl start shadowlink'"
echo "   ssh root@104.222.177.67 'systemctl status shadowlink --no-pager | head'"
