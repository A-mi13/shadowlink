#!/usr/bin/env bash
# build-client.sh — собирает Windows-клиент ShadowLink в d:/NIXAVPN/bin/.
# Запуск из каталога shadowlink/:  bash build-client.sh
#
# Клиент НЕ стрипуется (-s -w НЕ применяется): connect-vpn-DEBUG.bat гоняет
# его с `-log debug`, а strip убирает символы из стектрейсов. CGO выключен —
# чистая Go-сборка, gcc не нужен.
set -euo pipefail

cd "$(dirname "$0")"                       # shadowlink/
OUT="../bin/nixavpn-client-graceful-drain.exe"
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
echo ">> готово. Запускать: d:/NIXAVPN/bin/connect-vpn-DEBUG.bat (от администратора)"
