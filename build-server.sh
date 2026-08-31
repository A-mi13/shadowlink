#!/usr/bin/env bash
# build-server.sh — собирает Linux-сервер ShadowLink для деплоя на pl1.
# Запуск из каталога shadowlink/:  bash build-server.sh
#
# Цель — pl1 (linux/amd64). CGO выключен — статичный бинарь без зависимостей,
# переносится на сервер как есть. Стрипуется (-s -w): на сервере debug-символы
# не нужны, бинарь меньше.
set -euo pipefail

cd "$(dirname "$0")"                       # shadowlink/
# Вывод в bin/ ВНУТРИ каталога shadowlink — единственный источник истины, который
# ищет internal/slpath (см. $SHADOWLINK_DIR). Каталог может лежать вне дерева
# NixaVPN, поэтому путь наружу (`../bin/`) больше не используется.
OUT="bin/shadowlink-server-linux"
mkdir -p bin
STAMP="$(date +%Y%m%d-%H%M%S)"

echo ">> компиляция всего модуля + vet серверной части"
go build ./...
go vet ./cmd/shadowlink-server/ ./server/... ./core/...

if [ -f "$OUT" ]; then
  cp "$OUT" "${OUT}.bak-${STAMP}"
  echo ">> бэкап: ${OUT}.bak-${STAMP}"
  # Ротация: держим 2 последних (см. тот же комментарий в build-client.sh).
  ls -t "${OUT}".bak-* 2>/dev/null | tail -n +3 | xargs -r rm -f
fi

echo ">> build linux/amd64 -> $OUT"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o "$OUT" ./cmd/shadowlink-server/

ls -la "$OUT"
echo ">> готово."

# Путь на сервере СПРАШИВАЕТСЯ у systemd, а не зашивается здесь.
#
# 2026-08-31: в подсказке стоял хардкод /usr/local/bin/shadowlink-server, тогда
# как юнит запускает /opt/shadowlink/shadowlink-server. Деплой по подсказке
# обновлял копию, которую никто не запускает: бинарь ложился рядом, systemctl
# restart проходил успешно, приёмка «сервис active» тоже — а на проде
# продолжала работать сборка трёхнедельной давности. Обнаружилось только
# потому, что новых метрик не оказалось в /metrics при совпадающем md5 на
# «обновлённом» пути. Ровно тот класс ошибки, от которого предостерегает
# hard rule 5: вторая копия бинаря даёт молчаливый неверный деплой.
SRV_HOST="${SHADOWLINK_DEPLOY_HOST:-root@104.222.177.67}"
echo ">> путь на сервере (читаю ExecStart из юнита):"
REMOTE_BIN="$(ssh -o ConnectTimeout=10 -o BatchMode=yes "$SRV_HOST" \
  "systemctl show -p ExecStart --value shadowlink 2>/dev/null | grep -oP 'path=\K[^ ;]+'" 2>/dev/null || true)"

if [ -z "$REMOTE_BIN" ]; then
  echo "   !! не удалось прочитать ExecStart (нет доступа по ssh?)."
  echo "   !! УЗНАЙТЕ ПУТЬ ПЕРЕД ДЕПЛОЕМ, не угадывайте:"
  echo "      ssh $SRV_HOST 'systemctl show -p ExecStart --value shadowlink'"
  REMOTE_BIN="<путь-из-ExecStart>"
else
  echo "   $REMOTE_BIN"
fi

echo ">> ДЕПЛОЙ (сервер первым, по правилу staged):"
echo "   scp $OUT $SRV_HOST:${REMOTE_BIN}.new"
echo "   ssh $SRV_HOST '${REMOTE_BIN}.new -validate-config /etc/shadowlink/config.yaml'"
echo "   ssh $SRV_HOST 'systemctl stop shadowlink && \\"
echo "       cp ${REMOTE_BIN} ${REMOTE_BIN}.bak-${STAMP} && \\"
echo "       mv ${REMOTE_BIN}.new ${REMOTE_BIN} && \\"
echo "       chmod +x ${REMOTE_BIN} && systemctl start shadowlink'"
echo ">> ПРИЁМКА (обязательна — «active» не доказывает, что запущен новый бинарь):"
echo "   ssh $SRV_HOST 'md5sum ${REMOTE_BIN}' && md5sum $OUT"
echo "   go run ./tools/facade-probe/ -url '<sl://...>' -check"
