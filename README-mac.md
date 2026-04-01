# ShadowLink — macOS

## Файлы

```
shadowlink-client-mac      — клиент (17 MB, ARM64 M1/M2/M3)
config.yaml                — конфигурация сервера + bypass правила
connect-browser-mac.sh     — VPN только в браузере (без sudo)
connect-system-vpn-mac.sh  — полный System VPN (sudo + tun2socks)
```

## Быстрый старт (браузер)

```bash
chmod +x shadowlink-client-mac connect-browser-mac.sh
xattr -d com.apple.quarantine shadowlink-client-mac
./connect-browser-mac.sh
```

Chrome откроется через VPN. Финский IP. .ru сайты — напрямую.

## Full System VPN

### 1. Установить tun2socks (один раз)

```bash
curl -L -o tun2socks.zip https://github.com/xjasonlyu/tun2socks/releases/download/v2.6.0/tun2socks-darwin-arm64.zip && unzip -o tun2socks.zip && chmod +x tun2socks-darwin-arm64 && mv tun2socks-darwin-arm64 tun2socks && xattr -d com.apple.quarantine tun2socks && rm tun2socks.zip
```

### 2. Подготовить (один раз)

```bash
chmod +x shadowlink-client-mac connect-system-vpn-mac.sh tun2socks
xattr -d com.apple.quarantine shadowlink-client-mac tun2socks
```

### 3. Подключиться

```bash
sudo ./connect-system-vpn-mac.sh
```

Весь трафик через Финляндию. .ru домены — напрямую. Enter для отключения.

## Bypass .ru

Домены из `config.yaml` → `routing.bypass` идут **напрямую**:
- Все .ru и .рф домены
- vk.com, ok.ru, mail.ru, yandex.ru, wb.ru
- wildberries.ru, ozon.ru, avito.ru, gosuslugi.ru

Остальное (google, youtube, telegram) → через VPN.

Добавить свои: отредактируй `routing.bypass` в `config.yaml`.

## Проверка

- `whatismyipaddress.com` → Helsinki, Finland
- `2ip.ru` → ваш город, Россия (bypass)

## Troubleshooting

| Проблема | Решение |
|----------|---------|
| `permission denied` | `chmod +x shadowlink-client-mac` |
| `cannot be opened` (Gatekeeper) | `xattr -d com.apple.quarantine shadowlink-client-mac` |
| `tun2socks not found` | Положи `tun2socks` в ту же папку |
| DNS не работает | Скрипт ставит DNS на 127.0.0.1 (DNS bypass router) |
