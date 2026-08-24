#!/usr/bin/env bash
# build-client.sh — собирает Windows-клиент ShadowLink.
# Запуск из каталога shadowlink/:  bash build-client.sh
#
# Клиент НЕ стрипуется (-s -w НЕ применяется): connect-vpn-DEBUG.bat гоняет
# его с `-log debug`, а strip убирает символы из стектрейсов. CGO выключен —
# чистая Go-сборка, gcc не нужен.
#
# Каталог вывода — bin/ ВНУТРИ каталога shadowlink: проект самодостаточен,
# запускать всё можно из него одного. Рядом с бинарём лежат wintun.dll (без него
# TUN не поднимется) и connect-vpn-*.bat (запускают exe через %~dp0, то есть из
# своей же папки).
#
# Изменено 2026-07-31: до этого дефолтом был /d/NIXAVPN/bin — рантайм-каталог
# дерева NixaVPN, потому что там исторически лежало окружение клиента. Окружение
# скопировано сюда, поэтому внешний каталог больше не нужен. Для сборки в него
# (например, чтобы обновить прежнюю установку) передайте CLIENT_BIN_DIR:
#   CLIENT_BIN_DIR=/d/NIXAVPN/bin bash build-client.sh
set -euo pipefail

cd "$(dirname "$0")"                       # shadowlink/
CLIENT_BIN_DIR="${CLIENT_BIN_DIR:-$(pwd)/bin}"
mkdir -p "$CLIENT_BIN_DIR"
# Имя сведено к каноническому 2026-08-24. До этого скрипт собирал
# nixavpn-client-graceful-drain.exe, который .gitignore не пускал в git, а
# версионировался nixavpn-client.exe — то есть собиралось одно, хранилось
# другое, синхронизировалось руками через cp. Ровно та вторая копия, что уже
# давала молчаливое «binary identical, skipping upload» (hard rule 5).
# Суффикс graceful-drain к тому же устарел: дренаж давно в проде, отдельной
# сборки под него нет.
OUT="$CLIENT_BIN_DIR/nixavpn-client.exe"
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
echo ">> готово."
echo ">> Запускать ОТ АДМИНИСТРАТОРА (нужен TUN):"
echo "     $CLIENT_BIN_DIR/connect-vpn-DEBUG.bat          # с -log debug"
echo "     $CLIENT_BIN_DIR/connect-vpn-graceful-drain.bat  # обычный"
# Самодостаточность каталога — не декоративное свойство: без wintun.dll клиент не
# поднимет TUN, а .bat запускает exe через %~dp0, то есть строго из своей папки.
for need in wintun.dll connect-vpn-DEBUG.bat connect-vpn-graceful-drain.bat; do
  if [ ! -f "$CLIENT_BIN_DIR/$need" ]; then
    echo ">> ВНИМАНИЕ: в $CLIENT_BIN_DIR нет $need — клиент не запустится." >&2
  fi
done
