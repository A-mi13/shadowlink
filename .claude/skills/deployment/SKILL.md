---
name: deployment
description: Use when building, deploying, or troubleshooting a running server/client — nginx config, systemd, build scripts, server CLI flags, key generation, binary placement rules, connection failures.
---

# Deployment & сборка

## Сборка

```bash
bash build-server.sh    # → bin/shadowlink-server-linux (linux/amd64, CGO off, стрипуется)
bash build-client.sh    # → $CLIENT_BIN_DIR (default /d/NIXAVPN/bin), windows/amd64, CGO off, НЕ стрипуется
```

Оба скрипта сами делают `go build ./...` + `go vet` перед сборкой и бэкапят
предыдущий бинарь с таймстампом.

**Клиент не стрипуется намеренно** — `connect-vpn-DEBUG.bat` гоняет его с
`-log debug`, strip убил бы символы в стектрейсах. Кладётся в
`/d/NIXAVPN/bin` рядом с `wintun.dll` и `connect-vpn-*.bat`: без них не
запускается.

## Правило единственного бинаря (важно)

Серверный бинарь — **единственная копия**: `bin/shadowlink-server-linux` в этом
репозитории. Вторая копия в дереве NixaVPN однажды вызвала silent
«binary identical, skipping upload» и деплой трёхдневного кода. Путь к каталогу
основной проект резолвит через `internal/slpath` / env `SHADOWLINK_DIR` —
хардкода пути быть не должно.

## Staged деплой (сервер первым)

`build-server.sh` печатает готовые команды. Порядок: **сервер, потом клиент**.
Схема — stop → backup с таймстампом → mv → chmod → start → проверить status.

## nginx (обязателен)

```nginx
server {
    listen 443 ssl;  # NO http2 — WS upgrade требует HTTP/1.1
    server_name your-domain.com;
    ssl_certificate     /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    location / {
        proxy_pass http://unix:/run/shadowlink.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

Причина обязательности — Go `net/http` шлёт non-browser HTTP/2 SETTINGS (JA3-риск).

## systemd

```
ExecStart=/usr/local/bin/shadowlink-server -config /etc/shadowlink/config.yaml \
          -behind-proxy -decoy /var/www/decoy
Restart=always
User=www-data
```

## Server CLI (`cmd/shadowlink-server/main.go`)

`-config` YAML · `-listen :443` · `-cert -key` · `-server-key` (64 hex) ·
`-decoy` dir · `-max-clients 100` · `-max-conns 8` · `-chunk-size 12288` ·
`-behind-proxy` · `-mgmt-port 0` `-mgmt-bind 127.0.0.1` `-mgmt-key` ·
`-default-max-devices 3` · `-gen-key`.

Генерация ключей: `shadowlink-server -gen-key` → private (в файл для
`--server-key`) + public (в client handshake auth).

Экспорт клиентского конфига: подкомманда `export-client-config`.

## Прод-режим

Direct origin: `?origin=<IP>` — dial по литеральному IP, SNI = домен, без DNS на
data-path. Никакого CDN (см. skill `mimicry-model`).

## Troubleshooting

| Problem | Check |
|---|---|
| jq parse error на config | BOM/комменты — `cat -v config.yaml` |
| No connections в логах | origin IP достижим? nginx живой? |
| Connection timeout | nginx `proxy_pass` = socket path? сервер запущен? |
| HTTP/2 fingerprint detected | запущен без nginx? Go net/http детектируется |
| Device limit errors | `-default-max-devices` / per-user config |
| Деплой «не подхватился» | вторая копия бинаря? см. правило единственного бинаря |

## Мониторинг

- `docs/grafana/cold-start-bypass-board.json` — борд cold-start/bypass
- `docs/operations/live-decoy-flipon-canary.md` — канареечный флип decoy
- `server/metrics.go` — источник метрик
