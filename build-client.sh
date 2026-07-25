#!/usr/bin/env bash
# build-client.sh — собирает Windows-клиент ShadowLink.
# Запуск из каталога shadowlink/:  bash build-client.sh
#
# Клиент НЕ стрипуется (-s -w НЕ применяется): connect-vpn-DEBUG.bat гоняет
# его с `-log debug`, а strip убирает символы из стектрейсов. CGO выключен —
# чистая Go-сборка, gcc не нужен.
#
# Каталог вывода задаётся $CLIENT_BIN_DIR. По умолчанию — d:/NIXAVPN/bin/, где
# рядом лежат wintun.dll и connect-vpn-*.bat: клиент без них не запускается,
# поэтому бинарь кладётся к ним, а не в bin/ каталога shadowlink.
set -euo pipefail

cd "$(dirname "$0")"                       # shadowlink/
CLIENT_BIN_DIR="${CLIENT_BIN_DIR:-/d/NIXAVPN/bin}"
mkdir -p "$CLIENT_BIN_DIR"
OUT="$CLIENT_BIN_DIR/nixavpn-client-graceful-drain.exe"
STAMP="$(date +%Y%m%d-%H%M%S)"

echo ">> go test (быстрая проверка перед сборкой)"
go build ./...                              # компиляция всего модуля
go vet ./cmd/nixavpn-client/ ./client/...

if [ -f "$OUT" ]; then
  cp "$OUT" "${OUT}.bak-${STAMP}"
  echo ">> бэкап: ${OUT}.bak-${STAMP}"
fi

echo ">> build windows/amd64 -> $OUT"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -o "$OUT" ./cmd/nixavpn-client/

ls -la "$OUT"
echo ">> готово. Запускать: $CLIENT_BIN_DIR/connect-vpn-DEBUG.bat (от администратора)"
