#!/usr/bin/env bash
# install-server.sh — установка ShadowLink-сервера на ЧИСТЫЙ Debian/Ubuntu VPS.
#
# Запуск на самом VPS, от root:
#
#   export GITHUB_TOKEN=ghp_xxx
#   bash <(curl -H "Authorization: Bearer $GITHUB_TOKEN" -sSL \
#     https://raw.githubusercontent.com/A-mi13/shadowlink/main/install-server.sh) \
#     --domain example.com --email admin@example.com
#
# Отличие от deploy-round18.sh: тот ОБНОВЛЯЕТ уже работающую установку
# (заливает бинарь по ssh, сверяет хеш, переключает systemd). Этот ставит с
# нуля и запускается НА САМОМ сервере.
#
# ⚠ Классическая строка Reality/Xray `bash <(curl -sSL .../install.sh)` БЕЗ
# токена у нас не работает, и притворяться нельзя. Замерено владельцем:
# репозиторий приватный (`private: true`), анонимный curl и на raw-файл, и на
# релизный ассет отдаёт HTTP 404 — то есть «нет доступа» выглядит как «нет
# файла». Приватность — осознанное решение: исходники стеганографического
# протокола не должны попасть к ТСПУ.
#
# Отсюда два пути доставки бинаря, и оба явные:
#   а) GITHUB_TOKEN/GH_TOKEN — скачать ассет приватного релиза через API;
#   б) SL_BINARY=/path (или --binary) — файл, залитый заранее по scp.
# Если репозиторий когда-нибудь станет публичным, (б) продолжит работать
# как есть, а (а) сведётся к обычному curl.
set -euo pipefail

# ---------------------------------------------------------------------------
# Параметры
# ---------------------------------------------------------------------------

DOMAIN=""
EMAIL=""
# SL_BINARY — запасной путь доставки: бинарь, залитый по scp. Он же остаётся
# рабочим, если репозиторий станет публичным. --binary переопределяет.
BINARY_SRC="${SL_BINARY:-}"
CERT_PATH=""
KEY_PATH=""
REPO="${SL_REPO:-A-mi13/shadowlink}"
RELEASE_TAG="${SL_RELEASE_TAG:-latest}"
ASSET_NAME="shadowlink-server-linux"   # имя ассета в релизе (.github/workflows/release.yml)

# Токен только из окружения — ни в файлы, ни в аргументы командной строки:
# аргументы видны в `ps` любому пользователю машины и оседают в history.
# GH_TOKEN понимает gh CLI, поэтому принимается как синоним.
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
SKIP_CERT=0
SKIP_NGINX=0
ASSUME_YES=0

# Пути. Совпадают с боевыми (сверено с deploy-round18.sh и skill deployment):
# бинарь в /opt/shadowlink, конфиг в /etc/shadowlink — чтобы обновление тем же
# deploy-скриптом легло на установку без правки путей.
INSTALL_DIR="/opt/shadowlink"
CONFIG_DIR="/etc/shadowlink"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
KEY_FILE="${CONFIG_DIR}/server.key"
DECOY_DIR="/var/www/decoy"
SERVICE_NAME="shadowlink"
SERVICE_USER="shadowlink"
BIN_PATH="${INSTALL_DIR}/shadowlink-server"

# Go слушает loopback, наружу смотрит только nginx. Порт тот же, что в проде.
BACKEND_PORT=10443
MGMT_PORT=9443

say()  { printf '\n\033[1m>> %s\033[0m\n' "$*"; }
info() { printf '   %s\n' "$*"; }
warn() { printf '\033[33m!! %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mXX %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Usage: bash install-server.sh --domain <domain> [options]

Обязательное:
  --domain <fqdn>        домен сервера; A-запись ДОЛЖНА уже указывать на этот VPS

Источник бинаря (ровно один из двух):
  GITHUB_TOKEN=<токен>   в окружении — скачает ассет приватного релиза через API
  --binary <path>        путь к shadowlink-server-linux, залитому заранее (scp);
                         то же самое, что SL_BINARY=<path> в окружении

TLS:
  --email <addr>         email для Let's Encrypt (обязателен, если не --cert/--key)
  --cert <path> --key <path>
                         готовые fullchain/privkey вместо certbot
  --skip-cert            не трогать сертификаты (уже настроены вручную)

Прочее:
  --skip-nginx           не переписывать конфиг nginx (сломает маршрутизацию,
                         если nginx не настроен вручную — см. hard rule 4)
  --yes                  не задавать вопросов
  --help

Переменные окружения:
  GITHUB_TOKEN (или GH_TOKEN)
                         токен с правом чтения этого репозитория. Достаточно
                         fine-grained token только на A-mi13/shadowlink с
                         Contents: Read. read:org НЕ нужен.
  SL_BINARY              путь к готовому бинарю вместо скачивания
  SL_REPO                owner/repo (default A-mi13/shadowlink)
  SL_RELEASE_TAG         тег релиза (default latest)

Идемпотентность: повторный запуск НЕ перегенерирует ключ сервера и не
перезаписывает существующий конфиг без подтверждения.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --email)  EMAIL="${2:-}"; shift 2 ;;
    --binary) BINARY_SRC="${2:-}"; shift 2 ;;
    --cert)   CERT_PATH="${2:-}"; shift 2 ;;
    --key)    KEY_PATH="${2:-}"; shift 2 ;;
    --skip-cert)  SKIP_CERT=1; shift ;;
    --skip-nginx) SKIP_NGINX=1; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; die "неизвестный аргумент: $1" ;;
  esac
done

confirm() {
  [ "$ASSUME_YES" = "1" ] && return 0
  [ -t 0 ] || die "$1 — и нет TTY для подтверждения; перезапустите с --yes, если осознанно"
  read -r -p "   $1 [y/N] " ans
  [ "${ans:-N}" = "y" ]
}

# ---------------------------------------------------------------------------
# 1. Проверка окружения — до единой правки на диске
# ---------------------------------------------------------------------------
# Всё, что может провалиться, проверяется ЗДЕСЬ. Полуустановка хуже отказа:
# после неё непонятно, что уже сделано, а systemd рапортует failed без причины.

say "проверка окружения"

[ "$(id -u)" = "0" ] || die "нужен root (нужны systemd, nginx, порт 443)"

[ -n "$DOMAIN" ] || { usage >&2; die "--domain обязателен"; }
# Домен уходит в nginx server_name, в certbot и в sl://-ссылку. Мусор здесь
# даёт неработающий конфиг nginx, а не понятную ошибку.
case "$DOMAIN" in
  *[!a-zA-Z0-9.-]*|-*|.*|*.) die "домен выглядит неправильно: $DOMAIN" ;;
  *.*) : ;;
  *) die "домен должен быть FQDN (есть точка): $DOMAIN" ;;
esac

# ОС. Скрипт ставит пакеты через apt и пишет systemd-юнит — на не-Debian
# семействе это молча не сработает, поэтому отказ, а не «попробуем».
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}${ID_LIKE:-}" in
    *debian*|*ubuntu*) info "ОС: ${PRETTY_NAME:-$ID}" ;;
    *) die "поддерживаются только Debian/Ubuntu (обнаружено: ${PRETTY_NAME:-$ID})" ;;
  esac
else
  die "нет /etc/os-release — не могу определить ОС"
fi

# Архитектура. Релизный ассет собирается ТОЛЬКО под linux/amd64
# (см. release.yml), поэтому на arm64 скачанный бинарь не запустится —
# лучше сказать сразу, чем получить «Exec format error» из journalctl.
ARCH="$(uname -m)"
[ "$ARCH" = "x86_64" ] || die "нужен x86_64 (обнаружено: $ARCH); релизный бинарь собирается под linux/amd64"

command -v systemctl >/dev/null || die "нет systemd"
command -v curl >/dev/null || die "нет curl — apt-get install -y curl"

# Порт 443 займёт nginx. Если он уже кем-то занят (apache, другой прокси,
# запущенный вручную сервер) — nginx не поднимется, и увидели бы мы это уже
# после установки пакетов и записи конфигов.
if command -v ss >/dev/null; then
  LISTENER="$(ss -lntpH 'sport = :443' 2>/dev/null | head -1 || true)"
  if [ -n "$LISTENER" ]; then
    case "$LISTENER" in
      *nginx*) info "порт 443 держит nginx — это ожидаемо, конфиг будет обновлён" ;;
      *) die "порт 443 занят не-nginx процессом: $LISTENER" ;;
    esac
  fi
  # Бэкенд-порт: если его кто-то держит, сервер не стартует.
  if ss -lntH "sport = :${BACKEND_PORT}" 2>/dev/null | grep -q .; then
    if ! systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
      die "порт ${BACKEND_PORT} занят, и это не наш сервис"
    fi
    info "порт ${BACKEND_PORT} держит уже установленный ${SERVICE_NAME} — переустановка"
  fi
else
  warn "нет ss — проверку занятости портов пропускаю"
fi

# Источник бинаря — ровно один. Две ветки разом означают неопределённость:
# какой из двух окажется в проде, зависело бы от порядка в коде.
if [ -n "$BINARY_SRC" ] && [ -n "$TOKEN" ]; then
  info "заданы и локальный бинарь, и токен — беру локальный файл"
fi
if [ -z "$BINARY_SRC" ] && [ -z "$TOKEN" ]; then
  # Падаем ЗДЕСЬ, а не на скачивании: анонимный запрос к приватному репо
  # вернёт HTTP 404, и «нет доступа» стало бы неотличимо от «нет релиза».
  # Замерено владельцем: и raw-файл, и релизный ассет без токена дают 404.
  cat >&2 <<EOF

Нет источника серверного бинаря.

Репозиторий ${REPO} приватный (это осознанное решение: исходники
стеганографического протокола не должны попасть к ТСПУ), поэтому анонимный
curl из GitHub Releases отдаёт 404, а не файл. Нужен токен или готовый бинарь.

  а) токен — fine-grained personal access token, выданный ТОЛЬКО на
     репозиторий ${REPO}, с единственным правом Contents: Read.
     Классический token с областью 'repo' тоже подойдёт. read:org НЕ нужен.

       export GITHUB_TOKEN=ghp_xxx
       bash install-server.sh --domain $DOMAIN --email you@example.com

  б) бинарь, залитый заранее с рабочей машины:

       scp bin/shadowlink-server-linux root@<vps>:/tmp/
       SL_BINARY=/tmp/shadowlink-server-linux \\
         bash install-server.sh --domain $DOMAIN --email you@example.com

EOF
  die "нужен GITHUB_TOKEN (или GH_TOKEN), либо SL_BINARY/--binary"
fi
if [ -n "$BINARY_SRC" ]; then
  [ -f "$BINARY_SRC" ] || die "нет файла: $BINARY_SRC"
fi

# TLS. Сертификат нужен nginx'у; без него нечего слушать на 443.
if [ "$SKIP_CERT" = "0" ]; then
  if [ -n "$CERT_PATH" ] || [ -n "$KEY_PATH" ]; then
    [ -n "$CERT_PATH" ] && [ -n "$KEY_PATH" ] || die "--cert и --key задаются только вместе"
    [ -f "$CERT_PATH" ] || die "нет файла сертификата: $CERT_PATH"
    [ -f "$KEY_PATH" ]  || die "нет файла ключа: $KEY_PATH"
  else
    [ -n "$EMAIL" ] || die "нужен --email для Let's Encrypt (или --cert/--key, или --skip-cert)"
    case "$EMAIL" in *@*.*) : ;; *) die "email выглядит неправильно: $EMAIL" ;; esac
  fi
fi

info "домен:  $DOMAIN"
info "бинарь: ${BINARY_SRC:-релиз ${RELEASE_TAG} из ${REPO} по токену}"
info "все проверки пройдены"

# ---------------------------------------------------------------------------
# 2. Пакеты
# ---------------------------------------------------------------------------

say "установка пакетов"

NEED_PKGS=()
[ "$SKIP_NGINX" = "1" ] || command -v nginx >/dev/null || NEED_PKGS+=("nginx")
if [ "$SKIP_CERT" = "0" ] && [ -z "$CERT_PATH" ]; then
  command -v certbot >/dev/null || NEED_PKGS+=("certbot" "python3-certbot-nginx")
fi

if [ ${#NEED_PKGS[@]} -gt 0 ]; then
  info "ставлю: ${NEED_PKGS[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq "${NEED_PKGS[@]}" >/dev/null
else
  info "всё уже установлено"
fi

# ---------------------------------------------------------------------------
# 3. Бинарь
# ---------------------------------------------------------------------------

say "установка бинаря"

install -d -m 0755 "$INSTALL_DIR"
TMP_BIN="$(mktemp)"
# Убирается и .json с ответом API: без него временный файл оставался бы на
# диске при любом раннем die в ветке скачивания.
trap 'rm -f "$TMP_BIN" "${TMP_BIN}.json"' EXIT

if [ -n "$BINARY_SRC" ]; then
  cp "$BINARY_SRC" "$TMP_BIN"
  info "взят из $BINARY_SRC"
else
  # Приватный релиз качается ТОЛЬКО через API:
  #   /releases/assets/<id> + Accept: application/octet-stream
  # Привычный /releases/download/<tag>/<file> для приватного репо не работает
  # даже с токеном — он обслуживается редиректом на CDN, который заголовок
  # Authorization не принимает.
  say "скачивание ассета ${ASSET_NAME} (релиз ${RELEASE_TAG})"

  if [ "$RELEASE_TAG" = "latest" ]; then
    API="https://api.github.com/repos/${REPO}/releases/latest"
  else
    API="https://api.github.com/repos/${REPO}/releases/tags/${RELEASE_TAG}"
  fi

  # Токен уезжает через --config со stdin, а не аргументом командной строки:
  # аргументы видны в `ps` любому пользователю машины. В сообщениях об ошибке
  # печатается только URL, никогда не заголовок.
  CURL_AUTH="header = \"Authorization: Bearer ${TOKEN}\""

  HTTP_STATUS="$(printf '%s\n' "$CURL_AUTH" \
    | curl -sSL --config - \
        -H "Accept: application/vnd.github+json" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        -o "${TMP_BIN}.json" -w '%{http_code}' \
        --max-time 60 "$API" 2>/dev/null || echo 000)"

  case "$HTTP_STATUS" in
    200) : ;;
    401) die "GitHub отверг токен (401). Проверьте GITHUB_TOKEN — возможно, он протух" ;;
    403) die "GitHub ответил 403. Токену не хватает прав: нужен Contents: Read на ${REPO}" ;;
    404) die "404 на ${API}. Для приватного репо это обычно НЕТ ДОСТУПА, а не отсутствие релиза: у токена нет прав на ${REPO}, либо тега ${RELEASE_TAG} действительно нет" ;;
    000) die "нет связи с api.github.com (таймаут/DNS)" ;;
    *)   die "api.github.com ответил HTTP ${HTTP_STATUS} на ${API}" ;;
  esac

  # id ассета вытаскивается без jq: на чистом VPS его нет, а тянуть пакет ради
  # одного поля — лишняя зависимость в пути установки.
  #
  # Разбор НЕ полагается ни на порядок полей, ни на форматирование: JSON
  # приводится к одному токену на строку, дальше это конечный автомат —
  # запоминаем последний увиденный "id" и печатаем его, когда встретим
  # "name" с нужным значением.
  #
  # Первая версия резала по '{' и требовала, чтобы id и name оказались на
  # ОДНОЙ строке. На минифицированном ответе GitHub это работает, а на
  # pretty-printed (прокси, ручное сохранение) молча возвращало пусто — тест
  # это и поймал. Ловушка, которую разбор снимает отдельно: у самого релиза
  # тоже есть "id", и наивный «первый id в файле» вернул бы его, а не ассет.
  ASSET_ID="$(tr ',{}[]' '\n\n\n\n\n' < "${TMP_BIN}.json" \
    | awk -v want="$ASSET_NAME" '
        /"id"[ \t]*:[ \t]*[0-9]+/ {
          s = $0; sub(/.*"id"[ \t]*:[ \t]*/, "", s); sub(/[^0-9].*/, "", s)
          if (s != "") last_id = s
          next
        }
        /"name"[ \t]*:[ \t]*"/ {
          s = $0; sub(/.*"name"[ \t]*:[ \t]*"/, "", s); sub(/".*/, "", s)
          if (s == want && last_id != "") { print last_id; exit }
        }')"
  rm -f "${TMP_BIN}.json"

  [ -n "${ASSET_ID:-}" ] || die "в релизе ${RELEASE_TAG} репозитория ${REPO} нет ассета ${ASSET_NAME}"
  info "asset id: ${ASSET_ID}"

  DL_STATUS="$(printf '%s\n' "$CURL_AUTH" \
    | curl -sSL --config - \
        -H "Accept: application/octet-stream" \
        -o "$TMP_BIN" -w '%{http_code}' \
        --max-time 600 \
        "https://api.github.com/repos/${REPO}/releases/assets/${ASSET_ID}" 2>/dev/null || echo 000)"
  [ "$DL_STATUS" = "200" ] || die "скачивание ассета ${ASSET_ID} вернуло HTTP ${DL_STATUS}"
  unset CURL_AUTH
  info "скачано из релиза"
fi

# Проверка ДО подмены боевого бинаря, и она нужна на ОБЕИХ ветках.
# В ветке скачивания HTTP-код уже проверен выше, но код 200 не гарантирует, что
# в теле бинарь: прокси или капча отдают 200 с HTML. В ветке --binary/SL_BINARY
# проверки нет вовсе — там путь указывает человек, и указать он может что
# угодно. ELF-сигнатура отсекает оба случая за одно сравнение.
chmod +x "$TMP_BIN"
file_head="$(head -c 4 "$TMP_BIN" | od -An -tx1 | tr -d ' \n')"
[ "$file_head" = "7f454c46" ] || die "это не ELF-бинарь (сигнатура $file_head) — скачался мусор или указан не тот файл"

# Живой ли он на этой машине: -gen-key ничего не пишет на диск и не требует
# конфига, поэтому это самый дешёвый способ отличить рабочий бинарь от
# собранного под другую архитектуру или битого.
"$TMP_BIN" -gen-key >/dev/null 2>&1 || die "бинарь не запускается на этой машине (архитектура? битый файл?)"

# Бэкап прежней версии с таймстампом — как в deploy-round18.sh: без него
# откат после неудачного обновления делать нечем.
if [ -f "$BIN_PATH" ]; then
  BAK="${BIN_PATH}.bak-$(date +%Y%m%d-%H%M%S)"
  cp "$BIN_PATH" "$BAK"
  info "прежний бинарь сохранён: $BAK"
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
fi
install -m 0755 "$TMP_BIN" "$BIN_PATH"
info "установлен: $BIN_PATH"

# ---------------------------------------------------------------------------
# 4. Пользователь и каталоги
# ---------------------------------------------------------------------------

say "пользователь и каталоги"

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  # Системный пользователь без shell и без home: сервису нужен только сокет на
  # loopback и чтение двух файлов.
  useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
  info "создан пользователь $SERVICE_USER"
else
  info "пользователь $SERVICE_USER уже есть"
fi

install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
install -d -m 0755 "$DECOY_DIR"

# ---------------------------------------------------------------------------
# 5. Ключ сервера — ГЛАВНАЯ точка идемпотентности
# ---------------------------------------------------------------------------
# Перезапись ключа рвёт ВСЕХ уже выданных клиентов: их sl://-ссылка несёт
# публичную половину, и после регенерации handshake перестаёт сходиться. Поэтому
# существующий ключ не трогаем никогда — даже с --yes.

say "ключ сервера"

if [ -s "$KEY_FILE" ]; then
  info "ключ уже есть, НЕ трогаю: $KEY_FILE"
else
  # -gen-key печатает две строки ("Private key: <hex>" / "Public key: <hex>").
  # В файл идёт только hex приватной половины — loadServerKey ждёт ровно
  # 64 hex-символа (server/server.go:363).
  GEN_OUT="$("$BIN_PATH" -gen-key)"
  PRIV="$(printf '%s\n' "$GEN_OUT" | awk '/^Private key:/ {print $3}')"
  [ "${#PRIV}" = "64" ] || die "не удалось получить приватный ключ из -gen-key (получено ${#PRIV} символов)"
  umask 077
  printf '%s\n' "$PRIV" > "$KEY_FILE"
  chown root:"$SERVICE_USER" "$KEY_FILE"
  chmod 0640 "$KEY_FILE"
  info "сгенерирован новый ключ: $KEY_FILE"
fi

# ---------------------------------------------------------------------------
# 6. Decoy-сайт
# ---------------------------------------------------------------------------
# ⚠ Готового decoy-сайта в репозитории НЕТ — ни каталога, ни шаблона. Сервер
# при пустом -decoy отдаёт встроенную заглушку "under construction"
# (server/decoy.go:288), в которой НЕТ Schema.org-блока, а значит нет
# body-носителя rate-limit сигнала: остаётся только заголовок X-SL-RL, которого
# не отдаёт ни один реальный сайт — прямая сигнатура для активного зонда.
#
# Поэтому минимальный валидный шаблон генерируется здесь. Он обязан пройти
# LoadDecoySnapshots (server/decoy_snapshots.go): JSON-LD блок, identifier
# типа PropertyValue, непустой propertyID и value ДЛИНОЙ РОВНО 80 байт.
#
# ⚠ propertyID здесь — legacy-литерал "rl-state", и это осознанная уступка, а
# не недосмотр. Правильное значение выводится HMAC'ом от хоста
# (core.DeriveRLPropertyID), посчитать его в bash нечем, а генератора шаблонов
# в репозитории не существует — это прямо записано в core/rlpropertyid.go:50
# («receiving side only»). Клиент legacy-литерал принимает
# (client/ratelimit_carriers.go:63), поэтому канал работает; цена в том, что
# литерал одинаков на всех серверах, и один скан по подстроке перечисляет парк.
# Пока сервер один, «перечислить парк из одного хоста» = «найти этот хост»,
# то есть потери нет. Перед вторым хостом шаблон надо перегенерировать.

say "decoy-сайт"

# Ровно 80 байт: "v1;bucket=none;refill_in=0;burst_left=100;exempt=0" (49) +
# 31 точка с запятой добивкой. Так же строит MakeBaselineValue
# (server/decoy_snapshots.go:269) — padToWidth хвостовыми ';'.
BASELINE_CORE="v1;bucket=none;refill_in=0;burst_left=100;exempt=0"
PAD=""
i=${#BASELINE_CORE}
while [ "$i" -lt 80 ]; do PAD="${PAD};"; i=$((i + 1)); done
BASELINE_VALUE="${BASELINE_CORE}${PAD}"
[ "${#BASELINE_VALUE}" = "80" ] || die "внутренняя ошибка: baseline value ${#BASELINE_VALUE} байт вместо 80"

if [ -f "${DECOY_DIR}/index.html" ] && grep -q 'application/ld+json' "${DECOY_DIR}/index.html" 2>/dev/null; then
  info "decoy уже на месте, не перезаписываю: ${DECOY_DIR}/index.html"
else
  if [ -f "${DECOY_DIR}/index.html" ]; then
    warn "в ${DECOY_DIR}/index.html нет JSON-LD baseline — сервер со strict-режимом не стартует"
    confirm "перезаписать его шаблоном по умолчанию?" || die "оставлено как есть; добавьте baseline вручную"
  fi
  # JSON-LD пишется ОДНОЙ строкой и плоским объектом намеренно: клиентский
  # детектор ищет его регуляркой `>(\{[^<]+\})</script>`
  # (client/ratelimit_carriers.go:44), которая не переживёт ни переносов с
  # вложенностью, ни '<' внутри. Красивое форматирование здесь молча убило бы
  # body-носитель.
  cat > "${DECOY_DIR}/index.html" <<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${DOMAIN}</title>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"${DOMAIN}","url":"https://${DOMAIN}/","identifier":{"@type":"PropertyValue","propertyID":"rl-state","value":"${BASELINE_VALUE}"}}</script>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:720px;margin:72px auto;padding:0 24px;color:#24292f;line-height:1.65}
h1{font-weight:600;font-size:1.9rem;color:#111}
p{margin:1em 0}a{color:#0969da;text-decoration:none}a:hover{text-decoration:underline}
footer{margin-top:64px;padding-top:16px;border-top:1px solid #d0d7de;color:#57606a;font-size:.875rem}
</style>
</head>
<body>
<h1>${DOMAIN}</h1>
<p>Documentation and service status for this deployment.</p>
<p>This host serves API endpoints for internal tooling. Public documentation is
being prepared; in the meantime please refer to your onboarding materials.</p>
<p><a href="/status">Service status</a> &middot; <a href="mailto:admin@${DOMAIN}">Contact</a></p>
<footer>&copy; $(date +%Y) ${DOMAIN}</footer>
</body>
</html>
HTML
  info "создан ${DECOY_DIR}/index.html (propertyID=rl-state — legacy, см. комментарий в скрипте)"
fi
chmod 0644 "${DECOY_DIR}/index.html"

# ---------------------------------------------------------------------------
# 7. Конфиг сервера
# ---------------------------------------------------------------------------
# listen — ТОЛЬКО loopback: наружу смотрит nginx, Go-процесс на 443 напрямую
# отдал бы non-browser HTTP/2 SETTINGS (hard rule 4, JA3-риск).
# cert/key в конфиге НЕ задаются: TLS терминирует nginx, а сервер за ним
# работает открытым HTTP на 127.0.0.1 (server/server.go:74 — TLS включается
# только при непустых CertFile/KeyFile).

say "конфиг сервера"

if [ -f "$CONFIG_FILE" ]; then
  info "конфиг уже есть: $CONFIG_FILE"
  info "не перезаписываю — правьте вручную; ключи сверяйте с docs/operations/server-install.md"
else
  # Ключ management API генерируется случайным: пустой ключ при непустом порте
  # означал бы открытый админ-интерфейс. Bind оставлен на loopback.
  MGMT_KEY="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  umask 077
  cat > "$CONFIG_FILE" <<YAML
# ShadowLink server config — создан install-server.sh $(date -u +%Y-%m-%dT%H:%M:%SZ)
# Схема: server/fileconfig.go (FileConfig). Дефолты: server/config.go (DefaultConfig).

# Слушаем ТОЛЬКО loopback. Наружу на :443 смотрит nginx, он же терминирует TLS.
# Прямой выход Go на 443 запрещён: net/http шлёт non-browser HTTP/2 SETTINGS.
listen: "127.0.0.1:${BACKEND_PORT}"

# Приватный ключ ShadowLink (64 hex). НЕ перегенерировать: публичная половина
# уже роздана клиентам в sl://-ссылках.
server_key: "${KEY_FILE}"

# Статический сайт для неаутентифицированных запросов (активные зонды).
decoy: "${DECOY_DIR}"

# За nginx'ом — иначе клиентский IP везде будет 127.0.0.1 (rate-limit по IP
# перестанет различать клиентов). Loopback доверяется неявно, поэтому
# trusted_proxies для схемы «nginx на этой же машине» не нужен.
behind_proxy: true

max_clients: 500
max_conns: 8
chunk_size: 12288

# Idle-таймаут сессии и период уборки. Значения = DefaultConfig; прежние
# 5m/30s ретроспектива инцидента 2026-05-17 называет причиной decoy lockout.
session_timeout_sec: 90
cleanup_interval_sec: 10

management:
  port: ${MGMT_PORT}
  bind: "127.0.0.1"
  key: "${MGMT_KEY}"
  default_max_devices: 3

mimicry:
  inflation: true
YAML
  chown root:"$SERVICE_USER" "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
  info "создан $CONFIG_FILE"
fi

# Валидация штатным путём самого сервера, а не глазами: -validate-config
# парсит YAML и выходит с ненулевым кодом на ошибке (main.go:116).
if ! "$BIN_PATH" -validate-config "$CONFIG_FILE" >/dev/null; then
  die "конфиг не проходит валидацию: $BIN_PATH -validate-config $CONFIG_FILE"
fi
info "конфиг валиден"

# ---------------------------------------------------------------------------
# 8. TLS-сертификат
# ---------------------------------------------------------------------------
# Порядок важен: certbot --nginx требует, чтобы nginx уже отвечал на :80 по
# этому server_name. Поэтому сначала ставится HTTP-заглушка, потом берётся
# сертификат, и только потом пишется боевой 443-конфиг.

say "TLS-сертификат"

LE_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ "$SKIP_CERT" = "1" ]; then
  info "--skip-cert: сертификаты не трогаю"
  CERT_PATH="${CERT_PATH:-${LE_DIR}/fullchain.pem}"
  KEY_PATH="${KEY_PATH:-${LE_DIR}/privkey.pem}"
elif [ -n "$CERT_PATH" ]; then
  info "использую готовые: $CERT_PATH"
elif [ -f "${LE_DIR}/fullchain.pem" ]; then
  info "сертификат Let's Encrypt уже выпущен, продлением занимается таймер certbot"
  CERT_PATH="${LE_DIR}/fullchain.pem"
  KEY_PATH="${LE_DIR}/privkey.pem"
else
  if [ "$SKIP_NGINX" = "1" ]; then
    die "--skip-nginx и нет сертификата: certbot --nginx нужен рабочий nginx-конфиг для ${DOMAIN}"
  fi
  info "выпускаю сертификат через certbot (нужна A-запись ${DOMAIN} → этот сервер)"
  cat > "/etc/nginx/sites-available/${DOMAIN}-acme" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root ${DECOY_DIR};
    location / { try_files \$uri \$uri/ =404; }
}
NGINX
  ln -sf "/etc/nginx/sites-available/${DOMAIN}-acme" "/etc/nginx/sites-enabled/${DOMAIN}-acme"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t >/dev/null 2>&1 || die "временный nginx-конфиг невалиден — nginx -t покажет причину"
  systemctl reload nginx 2>/dev/null || systemctl start nginx

  certbot certonly --nginx -d "$DOMAIN" --email "$EMAIL" \
      --agree-tos --non-interactive --no-eff-email \
    || die "certbot не выпустил сертификат. Частая причина — A-запись ${DOMAIN} не указывает на этот VPS или 80/tcp закрыт файрволом"

  CERT_PATH="${LE_DIR}/fullchain.pem"
  KEY_PATH="${LE_DIR}/privkey.pem"
  info "сертификат выпущен"
fi

[ "$SKIP_NGINX" = "1" ] || [ -f "$CERT_PATH" ] || die "нет файла сертификата: $CERT_PATH"

# ---------------------------------------------------------------------------
# 9. nginx
# ---------------------------------------------------------------------------
# Hard rule 4: nginx обязателен. Конфиг обязан сохранить маршрутизацию
# server/handler.go: POST+application/json → VPN, Upgrade: websocket → WS,
# всё прочее → decoy. Всё это делает сам Go-сервер, поэтому задача nginx —
# доставить запрос НЕИСКАЖЁННЫМ: один location на всё, с Upgrade-заголовками.
# Разложить пути по разным location значило бы решать за сервер, что куда
# идёт, и сломать decoy-ветку.

if [ "$SKIP_NGINX" = "1" ]; then
  say "nginx — пропущен (--skip-nginx)"
  warn "убедитесь сами: proxy_pass на 127.0.0.1:${BACKEND_PORT}, Upgrade/Connection,"
  warn "proxy_read_timeout/proxy_send_timeout 86400, БЕЗ http2"
else
  say "конфиг nginx"

  NGINX_SITE="/etc/nginx/sites-available/${SERVICE_NAME}-443"
  cat > "$NGINX_SITE" <<NGINX
# ShadowLink — создан install-server.sh. Правки переживут только до следующего
# запуска установщика.

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # ACME оставляем на месте: без него certbot renew не пройдёт webroot-проверку.
    location /.well-known/acme-challenge/ { root ${DECOY_DIR}; }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    # http2 НЕ включаем намеренно: WebSocket-upgrade требует HTTP/1.1, а с
    # http2 nginx отдаёт клиенту h2 и Upgrade-путь исчезает.
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${DOMAIN};

    ssl_certificate     ${CERT_PATH};
    ssl_certificate_key ${KEY_PATH};
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    # Management API — только с этой машины. Наружу его выставлять нельзя:
    # ключ лежит в открытом виде в конфиге.
    location /_mgmt/ {
        allow 127.0.0.1;
        deny all;
        proxy_pass http://127.0.0.1:${MGMT_PORT}/;
    }

    # ОДИН location на всё. Разбор (VPN / WS / decoy) делает сам сервер по
    # методу, Content-Type и заголовку Upgrade — server/handler.go. Любое
    # деление по путям здесь сломало бы этот разбор.
    location / {
        proxy_pass http://127.0.0.1:${BACKEND_PORT};
        proxy_http_version 1.1;

        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        proxy_set_header Upgrade    \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;

        # ОБЯЗАТЕЛЬНО. Дефолт nginx — 60 с, и он попадает внутрь интервала
        # серверного WS-ping (22.5–90 с). Без явных значений nginx сам рвал бы
        # долгие WS-соединения, а на клиенте это неотличимо от реза посредником.
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;

        # Буферизация выключена: она копит ответ целиком и ломает потоковый
        # характер туннеля, добавляя рваную форму трафика.
        proxy_buffering off;
        proxy_request_buffering off;
    }
}
NGINX

  # $connection_upgrade — map, а не литерал: при обычном (не-WS) запросе
  # Upgrade пуст, и жёсткое Connection: upgrade сломало бы keep-alive для
  # decoy-запросов. map объявляется на уровне http{}, поэтому отдельным файлом
  # в conf.d, а не в sites-available.
  MAPFILE="/etc/nginx/conf.d/shadowlink-upgrade-map.conf"
  if ! grep -rqs 'connection_upgrade' /etc/nginx/conf.d/ /etc/nginx/nginx.conf; then
    cat > "$MAPFILE" <<'NGINX'
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}
NGINX
    info "создан $MAPFILE"
  else
    info "map \$connection_upgrade уже объявлен — не дублирую"
  fi

  ln -sf "$NGINX_SITE" "/etc/nginx/sites-enabled/${SERVICE_NAME}-443"
  rm -f "/etc/nginx/sites-enabled/${DOMAIN}-acme" /etc/nginx/sites-enabled/default

  nginx -t || die "конфиг nginx невалиден — см. вывод nginx -t выше"
  info "nginx -t: ok"
fi

# ---------------------------------------------------------------------------
# 10. systemd
# ---------------------------------------------------------------------------
# Юнита в репозитории нет — пишется здесь.
#
# Про hardening: включено то, что не мешает работе. AmbientCapabilities с
# CAP_NET_BIND_SERVICE НЕ нужен — сервер слушает 127.0.0.1:10443, порт
# непривилегированный. ProtectSystem=strict закрывает диск на запись целиком,
# исключения открываются точечно.

say "systemd-юнит"

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=ShadowLink server
Documentation=https://github.com/${REPO}/blob/main/docs/operations/server-install.md
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${BIN_PATH} -config ${CONFIG_FILE}
Restart=always
RestartSec=3
# Без этого пять быстрых падений подряд (например, из-за битого конфига)
# заглушили бы юнит навсегда, и после починки он бы не поднялся сам.
StartLimitIntervalSec=0

# Файловые дескрипторы: пул из 8 WS-слотов на клиента при сотнях клиентов
# упирается в дефолтный лимит 1024 задолго до MaxClients.
LimitNOFILE=65535

NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
# Только IP-сокеты: юникс-сокеты серверу не нужны, а AF_NETLINK/AF_PACKET —
# тем более.
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
info "юнит записан и включён в автозапуск"

# ---------------------------------------------------------------------------
# 11. Запуск и проверка
# ---------------------------------------------------------------------------

say "запуск"

systemctl restart "$SERVICE_NAME"
[ "$SKIP_NGINX" = "1" ] || systemctl reload nginx 2>/dev/null || systemctl restart nginx

# Пауза перед проверкой: fail-fast'ы сервера (decoy snapshot strict, короткий
# mgmt-ключ) срабатывают на старте, и systemctl is-active сразу после restart
# успел бы увидеть ещё живой процесс.
sleep 3

if ! systemctl is-active --quiet "$SERVICE_NAME"; then
  warn "сервер НЕ поднялся. Последние строки журнала:"
  journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 || true
  cat >&2 <<EOF

Типовые причины:
  · decoy без Schema.org baseline → fail-fast (-decoy-snapshot-strict по
    умолчанию true). Проверьте ${DECOY_DIR}/index.html
  · порт ${BACKEND_PORT} занят
  · ключ сервера не 64 hex-символа: ${KEY_FILE}
EOF
  die "установка не завершена"
fi
info "systemd: active"

# Проверка НА ПРОВОДЕ, а не по статусу юнита: active означает лишь «процесс
# жив», а не «отвечает». Идём через nginx по петле, с Host — так же, как пойдёт
# настоящий клиент.
if [ "$SKIP_NGINX" = "0" ]; then
  HTTP_CODE="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 10 \
      -H "Host: ${DOMAIN}" "https://127.0.0.1/" || echo 000)"
  case "$HTTP_CODE" in
    200) info "decoy отвечает 200 через nginx" ;;
    000) warn "curl не достучался до https://127.0.0.1/ — проверьте nginx" ;;
    *)   warn "decoy ответил HTTP ${HTTP_CODE} (ожидался 200)" ;;
  esac

  # Body-носитель rate-limit сигнала: если baseline не доехал до ответа,
  # единственным носителем остаётся X-SL-RL — сигнатура для активного зонда.
  if curl -sk --max-time 10 -H "Host: ${DOMAIN}" "https://127.0.0.1/" 2>/dev/null \
       | grep -q 'application/ld+json'; then
    info "Schema.org baseline виден в ответе"
  else
    warn "baseline НЕ виден в ответе decoy — работает только header-carrier (X-SL-RL)"
  fi
fi

# ---------------------------------------------------------------------------
# 12. Клиентская ссылка
# ---------------------------------------------------------------------------
# Порт 443 задаётся явно: export-client-config иначе возьмёт порт из `listen`
# конфига (export.go:95), а там loopback-овый 10443 — ссылка вела бы клиента
# на внутренний порт.

say "клиентская конфигурация"

SL_URL="$("$BIN_PATH" export-client-config \
    -config "$CONFIG_FILE" \
    -domain "$DOMAIN" \
    -port 443 \
    -format url 2>/dev/null | tr -d '\r' | grep '^sl://' || true)"

if [ -z "$SL_URL" ]; then
  warn "не удалось получить sl://-ссылку. Вручную:"
  warn "  $BIN_PATH export-client-config -config $CONFIG_FILE -domain $DOMAIN -port 443"
else
  printf '\n\033[1m   Ссылка для клиента:\033[0m\n\n   %s\n\n' "$SL_URL"
  warn "Это доступ к серверу — передавайте по защищённому каналу и не кладите в репозиторий."
fi

say "ГОТОВО"
cat <<EOF
   сервис:  systemctl status ${SERVICE_NAME}
   логи:    journalctl -u ${SERVICE_NAME} -f
   конфиг:  ${CONFIG_FILE}
   ключ:    ${KEY_FILE}   (НЕ перегенерировать — сломает выданные ссылки)
   decoy:   ${DECOY_DIR}/index.html
   nginx:   /etc/nginx/sites-available/${SERVICE_NAME}-443

   Осталось СДЕЛАТЬ ВРУЧНУЮ (скрипт этого не делает намеренно):
     · открыть 80/tcp и 443/tcp в файрволе провайдера и в ufw/nftables
     · проверить, что A-запись ${DOMAIN} указывает на этот сервер
   Подробности: docs/operations/server-install.md
EOF
