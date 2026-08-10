#!/usr/bin/env bash
# deploy-round18.sh — деплой серверного бинаря раунда 18 с проверками до и после.
#
# Запуск (из каталога shadowlink/):
#   source ~/.claude/projects/D--shadowlink/.deploy-env   # креды вне репозитория
#   bash deploy-round18.sh
#
# Переменные окружения:
#   SL_HOST / SL_USER / SL_PASS — доступ (SL_PASS → sshpass; без него ssh-ключ)
#   SL_DOMAIN                   — домен для Host в smoke-проверках
#   SL_KEEP_OLD_TIMEOUTS=1      — оставить прежние 5m/30s вместо новых 90s/10s
#   SL_REMOTE_BIN / SL_REMOTE_CFG — пути на сервере (дефолты ниже)
#
# Почему скриптом, а не тремя командами: в этом раунде изменились ДВА стартовых
# инварианта (decoy-baseline strict, минимальная длина mgmt-ключа), каждый из
# которых может не дать серверу подняться. Проверять их после `systemctl start`
# значит узнать о проблеме, когда прод уже лежит.
#
# ВАЖНО про удалённое исполнение: команды уезжают на сервер ФАЙЛОМ (rrun), а не
# через `ssh "..."` и не heredoc'ом функции. Причина конкретная: на границе двух
# шеллов по очереди теряются кавычки, трубы и скобки, а `<<'EOS'` для
# shell-функции всё равно разбирается ЛОКАЛЬНЫМ bash — одна одинарная кавычка
# внутри grep-шаблона рвала парсинг всего файла. Файл снимает вопрос целиком.
set -euo pipefail

cd "$(dirname "$0")"

HOST="${SL_HOST:-104.222.177.67}"
USER="${SL_USER:-root}"
TARGET="${USER}@${HOST}"
BIN="bin/shadowlink-server-linux"
STAMP="$(date +%Y%m%d-%H%M%S)"

# Реальные пути на pl1 (проверено 2026-07-31): бинарь в /opt/shadowlink,
# настройки — в /etc/shadowlink/config.yaml, а НЕ во флагах ExecStart.
REMOTE_BIN="${SL_REMOTE_BIN:-/opt/shadowlink/shadowlink-server}"
REMOTE_CFG="${SL_REMOTE_CFG:-/etc/shadowlink/config.yaml}"

say()  { printf '\n\033[1m>> %s\033[0m\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*"; }
die()  { printf '\033[31mXX %s\033[0m\n' "$*" >&2; exit 1; }

SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
if [ -n "${SL_PASS:-}" ]; then
  command -v sshpass >/dev/null || die "нужен sshpass (или заведите ssh-ключ)"
  SSH_CMD=(sshpass -p "$SL_PASS" ssh "${SSH_OPTS[@]}" "$TARGET")
  SCP_CMD=(sshpass -p "$SL_PASS" scp "${SSH_OPTS[@]}")
else
  SSH_CMD=(ssh "${SSH_OPTS[@]}" -o BatchMode=yes "$TARGET")
  SCP_CMD=(scp "${SSH_OPTS[@]}" -o BatchMode=yes)
fi

# rrun <файл> — залить скрипт и выполнить на сервере, затем удалить.
rrun() {
  local local_script="$1" remote="/tmp/.sl-deploy-$$-${RANDOM}.sh"
  "${SCP_CMD[@]}" "$local_script" "${TARGET}:${remote}" >/dev/null
  "${SSH_CMD[@]}" "bash ${remote}; rc=\$?; rm -f ${remote}; exit \$rc"
}

# rsh — одна простая команда без кавычек/труб.
rsh() { "${SSH_CMD[@]}" "$@"; }

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

say "проверка связи с ${TARGET}"
rsh 'echo "   ok: $(hostname) $(uname -r)"' || die "нет доступа к серверу"

[ -f "$BIN" ] || die "нет $BIN — сначала bash build-server.sh"

# --- 0. Локальный бинарь точно свежий? --------------------------------------
say "проверка, что локальный бинарь содержит код раунда 18"
for marker in \
  "session destroyed: key material zeroed" \
  "management key too short" \
  "cleanup-interval"
do
  grep -qa "$marker" "$BIN" || die "в бинаре нет маркера «$marker» — пересоберите: bash build-server.sh"
done
echo "   ok — маркеры на месте"

# --- 1. Предполётные проверки НА СЕРВЕРЕ -------------------------------------
{
  echo 'set -u'
  echo "CFG=\"$REMOTE_CFG\""
  echo "BINP=\"$REMOTE_BIN\""
  cat <<'PREFLIGHT'
yamlval() {
  grep -E "^[[:space:]]*$1:" "$CFG" 2>/dev/null | head -1 | cut -d: -f2- | tr -d " \"'\r"
}
echo "current_bin_date=$(date -r "$BINP" '+%Y-%m-%d %H:%M' 2>/dev/null || echo unknown)"
DECOY="$(yamlval decoy)"
echo "decoy_dir=$DECOY"
echo "mgmt_bind=$(yamlval bind)"
echo "mgmt_key_len=$(yamlval key | tr -d '\n' | wc -c)"
# Проверка СТРУКТУРНАЯ, не по литералу (2026-08-08). Раньше здесь стоял
# `grep -q rl-state`: этот идентификатор был одинаков на всех серверах, и один
# интернет-скан по подстроке находил весь парк. Теперь propertyID выводится из
# хоста (core.DeriveRLPropertyID), то есть у каждого сервера свой, и искать
# фиксированную строку больше нельзя — иначе деплой будет валиться именно на
# правильно сгенерированных шаблонах.
#
# Ищем то, что действительно обязано присутствовать: JSON-LD блок с
# PropertyValue-идентификатором. Ширину value проверяет сам сервер при старте
# (LoadDecoySnapshots), дублировать её разбором HTML в bash смысла нет.
if [ -n "$DECOY" ] && [ -f "$DECOY/index.html" ] &&
   grep -q 'application/ld+json' "$DECOY/index.html" 2>/dev/null &&
   grep -q 'PropertyValue' "$DECOY/index.html" 2>/dev/null; then
  echo "baseline=present"
  # Отдельный сигнал: шаблон всё ещё несёт fleet-wide литерал. Не ошибка
  # (сервер стартует, клиент такой маркер понимает), но свойство «нашли один
  # ≠ нашли все» при этом не работает.
  if grep -q '"propertyID"[[:space:]]*:[[:space:]]*"rl-state"' "$DECOY/index.html" 2>/dev/null; then
    echo "baseline_propertyid=LEGACY"
  else
    echo "baseline_propertyid=per-host"
  fi
else
  echo "baseline=MISSING"
fi
echo "ws_burst=$(yamlval burst)"
echo "active_before=$(ss -tn state established 2>/dev/null | grep -c ':443 ' || echo 0)"
PREFLIGHT
} >"$TMPD/preflight.sh"

say "предполётные проверки на сервере"
PRE="$(rrun "$TMPD/preflight.sh")"
echo "$PRE" | sed 's/^/   /'

# H-1 шаг 4a: -decoy-snapshot-strict теперь true. Без Schema.org baseline сервер
# НЕ СТАРТУЕТ — намеренный fail-fast (раньше тихо деградировал в header-only).
if echo "$PRE" | grep -q 'baseline_propertyid=LEGACY'; then
  warn "decoy-шаблон несёт legacy propertyID \"rl-state\" — он одинаков на всех"
  warn "серверах, и один скан по этой строке перечисляет весь парк."
  warn "Перегенерируйте шаблон под свой хост (core.DeriveRLPropertyID)."
  warn "Деплой продолжается: сервер стартует, клиент такой маркер понимает."
fi

if echo "$PRE" | grep -q 'baseline=MISSING'; then
  warn "Schema.org baseline (JSON-LD + PropertyValue) НЕ найден в decoy-шаблоне."
  warn "Сервер не поднимется со strict=true. Варианты:"
  warn "  а) обновить шаблоны decoy — правильный путь"
  warn "  б) добавить -decoy-snapshot-strict=false в ExecStart — временно"
  # SL_FORCE=1 пропускает вопрос — нужно для неинтерактивного запуска
  # (в фоне read вешает скрипт навсегда: наступал 2026-07-31).
  if [ "${SL_FORCE:-0}" = "1" ]; then
    warn "SL_FORCE=1 — продолжаю несмотря на отсутствие baseline"
  elif [ -t 0 ]; then
    read -r -p "   продолжать деплой? [y/N] " ans
    [ "${ans:-N}" = "y" ] || die "деплой отменён"
  else
    die "нет baseline и нет TTY для подтверждения — запустите с SL_FORCE=1, если осознанно"
  fi
fi

# MEDIUM: короткий mgmt-ключ при НЕ-loopback bind валит старт (fail-fast).
MGMT_BIND="$(echo "$PRE" | sed -n 's/^mgmt_bind=//p')"
MGMT_LEN="$(echo "$PRE" | sed -n 's/^mgmt_key_len=//p')"
if [ "${MGMT_BIND:-127.0.0.1}" != "127.0.0.1" ] && [ "${MGMT_LEN:-0}" -lt 32 ]; then
  die "mgmt-ключ короче 32 симв. при публичном bind ($MGMT_BIND) → fail-fast. Ротируйте ключ."
fi

# --- 2. Заливка --------------------------------------------------------------
say "заливка бинаря"
"${SCP_CMD[@]}" "$BIN" "${TARGET}:${REMOTE_BIN}.new"

# Сверка хеша залитой копии с локальной. Добавлено 2026-08-10 после инцидента:
# деплой 8 августа выглядел успешным, но на прод не доехал — сервер двое суток
# работал на бинаре от 31 июля, и заметили это только случайной сверкой md5.
# Без этой проверки "тихий недодеплой" неотличим от успешного: скрипт печатает
# ГОТОВО, systemd рапортует active, а в бою старый код.
#
# Проверяем ДО остановки сервиса: если копия побилась, прод не трогаем вовсе.
LOCAL_MD5="$(md5sum "$BIN" | cut -d' ' -f1)"
{
  echo 'set -eu'
  echo "md5sum \"${REMOTE_BIN}.new\" | cut -d' ' -f1"
} >"$TMPD/verify_upload.sh"
REMOTE_MD5="$(rrun "$TMPD/verify_upload.sh" | tr -d '\r' | tail -1)"
if [ "$LOCAL_MD5" != "$REMOTE_MD5" ]; then
  rsh "rm -f ${REMOTE_BIN}.new" || true
  die "хеш залитого бинаря не совпал: локально $LOCAL_MD5, на сервере $REMOTE_MD5 — прод не тронут"
fi
echo "   ok — хеш совпал: $LOCAL_MD5"

# --- 3. H-18: таймауты -------------------------------------------------------
# Idle-таймаут сужается 5m → 90s (значения DefaultConfig; ретроспектива инцидента
# 2026-05-17 называет прежние 5m/30s причиной decoy lockout).
if [ "${SL_KEEP_OLD_TIMEOUTS:-0}" = "1" ]; then
  say "H-18: сохраняю прежние 5m/30s через новые YAML-ключи"
  {
    echo 'set -e'
    echo "CFG=\"$REMOTE_CFG\""
    echo 'grep -q session_timeout_sec "$CFG" || printf "session_timeout_sec: 300\ncleanup_interval_sec: 30\n" >> "$CFG"'
    echo 'echo "   ok: $CFG"'
  } >"$TMPD/timeouts.sh"
  rrun "$TMPD/timeouts.sh"
else
  warn "H-18: сервер поедет на значениях DefaultConfig (90s/10s), если в YAML"
  warn "      нет session_timeout_sec/cleanup_interval_sec. Фактическое значение"
  warn "      печатает сам сервер при старте — см. session_timeout_sec_runtime"
  warn "      в блоке «стартовые предупреждения» ниже, а не это сообщение."
  warn "      Откат: SL_KEEP_OLD_TIMEOUTS=1 bash deploy-round18.sh"
fi

# --- 4. Переключение ---------------------------------------------------------
{
  echo 'set -e'
  echo "BINP=\"$REMOTE_BIN\""
  echo "BAK=\"${REMOTE_BIN}.bak-round18-${STAMP}\""
  cat <<'SWITCH'
systemctl stop shadowlink
cp "$BINP" "$BAK"
mv "${BINP}.new" "$BINP"
chmod +x "$BINP"
systemctl start shadowlink
SWITCH
} >"$TMPD/switch.sh"

say "переключение бинаря"
rrun "$TMPD/switch.sh"
sleep 3

# --- 5. Проверка, что поднялся ----------------------------------------------
{
  echo 'set -u'
  echo "BINP=\"$REMOTE_BIN\""
  cat <<'STATUS'
if systemctl is-active --quiet shadowlink; then
  echo "STATE=active"
else
  echo "STATE=dead"
fi
echo "RUNNING_MD5=$(md5sum "$BINP" | cut -d' ' -f1)"
systemctl status shadowlink --no-pager 2>/dev/null | head -5
echo "--- фактические тайминги из лога сервера ---"
journalctl -u shadowlink -n 80 --no-pager 2>/dev/null | grep -oE "session_timeout_sec_runtime=[0-9]+ cleanup_interval_sec_runtime=[0-9]+" | tail -1 ||
  echo "нет строки mimicry config — старый бинарь? (до 2026-08-10 лог печатал зашитое 300)"
echo "--- стартовые предупреждения ---"
journalctl -u shadowlink -n 80 --no-pager 2>/dev/null | grep -iE "snapshot|open mode|management key|too short|panic" || echo "нет - это хорошо"
STATUS
} >"$TMPD/status.sh"

say "статус после старта"
ST="$(rrun "$TMPD/status.sh" || true)"
echo "$ST" | sed 's/^/   /'

# Вторая половина защиты от тихого недодеплоя: под нагрузкой сверяем не то, что
# залили, а то, что реально лежит на боевом пути после mv.
RUNNING_MD5="$(echo "$ST" | sed -n 's/^RUNNING_MD5=//p' | tr -d '\r' | tail -1)"
if [ -n "$RUNNING_MD5" ] && [ "$RUNNING_MD5" != "$LOCAL_MD5" ]; then
  die "на боевом пути НЕ наш бинарь: ожидали $LOCAL_MD5, лежит $RUNNING_MD5"
fi
echo "   ok — в бою наш бинарь: $LOCAL_MD5"

if ! echo "$ST" | grep -q 'STATE=active'; then
  echo 'journalctl -u shadowlink -n 40 --no-pager' >"$TMPD/logs.sh"
  warn "СЕРВЕР НЕ ПОДНЯЛСЯ. Логи:"
  rrun "$TMPD/logs.sh" || true
  warn "Откат:"
  warn "  systemctl stop shadowlink"
  warn "  cp ${REMOTE_BIN}.bak-round18-${STAMP} ${REMOTE_BIN}"
  warn "  systemctl start shadowlink"
  die "деплой неуспешен"
fi

# --- 6. Smoke-проверки регрессий раунда 18 ----------------------------------
if [ -z "${SL_DOMAIN:-}" ]; then
  warn "SL_DOMAIN не задан → smoke-проверки пропущены."
else
  WSKEY="$(head -c16 /dev/urandom | base64)"

  say "C-2: тело decoy на rate-limit-пути НЕ должно быть пустым"
  OUT="$(curl -sk -o /dev/null -w 'status=%{http_code} size=%{size_download}' \
    "https://${HOST}/socket.io/" -H "Host: ${SL_DOMAIN}" \
    -H "Upgrade: websocket" -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: ${WSKEY}" || echo curl_failed)"
  echo "   $OUT"
  case "$OUT" in
    *size=0*) warn "ПУСТОЕ ТЕЛО — регрессия C-2, детерминированный оракул" ;;
    *)        echo "   ok" ;;
  esac

  say "H-6: несуществующий WS-путь не должен отвечать быстрее обычного GET"
  T_WS="$(curl -sk -o /dev/null -w '%{time_total}' "https://${HOST}/definitely-not-ws" \
    -H "Host: ${SL_DOMAIN}" -H "Upgrade: websocket" -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: ${WSKEY}" || echo 0)"
  T_PLAIN="$(curl -sk -o /dev/null -w '%{time_total}' "https://${HOST}/definitely-not-ws" \
    -H "Host: ${SL_DOMAIN}" || echo 0)"
  echo "   с Upgrade: ${T_WS}s   без Upgrade: ${T_PLAIN}s"
  echo "   должны быть сопоставимы; кратная разница = регрессия H-6"
fi

say "ГОТОВО. Бэкап прежнего бинаря: ${REMOTE_BIN}.bak-round18-${STAMP}"
echo "   Мониторинг: journalctl -u shadowlink -f"
