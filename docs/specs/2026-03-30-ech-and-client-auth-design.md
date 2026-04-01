# ShadowLink — ECH + Client Authentication

**Дата:** 2026-03-30
**Статус:** Design approved
**Scope:** 2 фичи: ECH в CDN mode + Client ID whitelist auth

## 1. ECH (Encrypted Client Hello) в CDN Mode

### Проблема

ТСПУ видит SNI в ClientHello и может заблокировать домен. ECH шифрует ClientHello, скрывая SNI от DPI. Cloudflare поддерживает ECH для всех доменов за их CDN.

### Решение

Опциональный ECH режим в CDN transport. Включается через `--ech` флаг или `ech: true` в YAML.

**Как работает:**
1. Клиент делает DNS HTTPS record (type 65) lookup для CDN домена
2. Извлекает `ECHConfigList` из DNS ответа
3. Передаёт ECHConfigList в tls-client при создании TLS соединения (через custom utls spec)
4. TLS ClientHello зашифрован — ТСПУ видит только "outer SNI" (обычно `cloudflare-ech.com`)
5. Cloudflare расшифровывает, видит реальный домен, проксирует на наш origin

**Fallback:** Если ECH handshake fail (DNS без HTTPS record, сервер не поддерживает) → обычный TLS без ECH. Логируется warning.

**Ограничения:**
- Только CDN mode — в Direct mode ECH бесполезен (IP = наш сервер)
- Требует Cloudflare (или другой CDN с ECH)
- DNS lookup добавляет ~50-100ms к первому подключению

### Реализация

**Новая зависимость:** `github.com/miekg/dns` — для DNS HTTPS record (type 65) запросов. Стандартная библиотека Go (`net.Resolver`) не поддерживает type 65.

**Новый файл `client/ech.go`:**
```go
// ResolveECHConfig queries DNS HTTPS record for domain and extracts ECHConfigList.
// Uses miekg/dns to query HTTPS record (type 65) via DNS-over-UDP to 1.1.1.1.
// Returns raw ECHConfigList bytes or error.
func ResolveECHConfig(domain string) ([]byte, error)
```

**Модификация `client/connmanager.go`:**
- Новые поля в ConnManagerConfig: `ECHEnabled bool`, `ECHDomain string`
- Новое поле в ConnManager: `echConfig []byte` — кэшированный ECHConfigList
- В `connect()`: если echEnabled → resolve ECHConfig (один раз, кэшировать с TTL) → создать custom utls ClientHelloSpec с ECH extension → передать в tls-client через `WithCustomTlsProfile`
- При ротации (`rotate()`): проверить TTL кэша ECHConfig, обновить если устарел
- ECH fallback: если resolve/handshake fail → `slog.Warn("ECH not available, falling back")` → обычный TLS

**Подход к tls-client + ECH:** bogdanfinn/tls-client оборачивает utls. Для ECH нужно создать custom `tls.ClientHelloSpec` с ECH extension через utls API, и передать его в tls-client через `WithCustomTlsProfile(spec)` или `WithClientHelloSpec(spec)` (проверить наличие метода в текущей версии). Если прямой поддержки нет — использовать utls напрямую для ECH-соединений в CDN mode.

**Модификация `client/fileconfig.go`:**
- Поле `ECH bool` в ClientFileConfig

**Модификация `cmd/shadowlink-client/main.go`:**
- Флаг `--ech`
- Передать в ConnManagerConfig

### Конфиг

```yaml
# client config
cdn: "my-analytics.io"
ech: true  # enable ECH (only works in CDN mode)
```

CLI: `shadowlink-client --cdn my-analytics.io --ech --tls`

## 2. Client ID Whitelist Authentication

### Проблема

Сейчас pubkey + server address = полный доступ. Любой с этими данными подключается. Нет авторизации клиентов.

### Текущее состояние (ревью кода показал!)

Проверка client_id **уже реализована** в `handleHandshake`:
- `server/handler.go:207-214` — вызов `h.clientAuth.IsAuthorized(clientID)`
- `server/ratelimit.go:96,113-116` — `openMode`: если `AuthorizedClients` пустой → все допущены, если задан → whitelist
- Management API `/manage/clients`, `/manage/sync` — уже работают
- `ClientHello.EncryptedClientID` — уже передаётся и расшифровывается

**Проблема:** whitelist можно задать только через Management API (runtime). Нельзя загрузить из YAML конфига при старте.

### Решение

Отдельный флаг `RequireAuth` **не нужен** — семантика `openMode` уже правильная:
- `AuthorizedClients` пустой → open mode (все допущены)
- `AuthorizedClients` не пустой → whitelist mode (только допущенные)

Нужно:
1. Добавить `authorized_clients` в FileConfig для загрузки из YAML
2. Добавить `--authorized-clients` CLI флаг (или через config.yaml)
3. Это передаст начальный whitelist в `Config.AuthorizedClients` → `ClientAuth` включит whitelist mode

### Реализация

**Модификация `server/config.go`:**
Добавить поле если отсутствует (проверить):
```go
AuthorizedClients []string // initial whitelist (empty = open mode, non-empty = whitelist)
```

**Модификация `server/fileconfig.go`:**
Добавить в FileConfig:
```go
AuthorizedClients []string `yaml:"authorized_clients"`
```

В `ApplyTo()`:
```go
if len(fc.AuthorizedClients) > 0 {
    cfg.AuthorizedClients = fc.AuthorizedClients
}
```

**Модификация `cmd/shadowlink-server/main.go`:**
Если загружен config.yaml с `authorized_clients` → они попадут в Config → ClientAuth включит whitelist mode.

Дополнительный runtime whitelist management через Management API работает как раньше.

### Конфиг

```yaml
# server config — whitelist mode
authorized_clients:
  - "user-123"
  - "user-456"
management:
  port: 9100
  key: "secret"
```

Без `authorized_clients` (или пустой список) → open mode как сейчас.

### Workflow для админа

1. Создать config.yaml с `authorized_clients` → задеплоить
2. Или: задеплоить в open mode → добавлять клиентов через Management API `/manage/sync`
3. Дать клиенту: `client_id`, pubkey, server address
4. Клиент подключается с `--id user-123` → handshake проверяет whitelist → допуск или decoy

### Интеграция с NixaVPN (будущее)

NixaVPN основной сервер может автоматически синхронизировать whitelist через Management API `/manage/sync`:
```
POST /manage/sync
{"clients": ["user-1", "user-2", "user-3"], "limits": {"user-1": 3, "user-2": 5}}
```

## Порядок реализации

1. **Client ID Whitelist Auth** — добавить `authorized_clients` в FileConfig/ApplyTo (минимальные изменения)
2. **ECH** — `miekg/dns` зависимость, DNS HTTPS lookup, utls ECH integration

## Зависимости

- `github.com/miekg/dns` — для ECH DNS HTTPS record lookup
- Все остальные — существующие

## Файлы

### Новые:
- `client/ech.go` — DNS HTTPS record lookup, ECHConfigList extraction
- `client/ech_test.go` — тесты ECH resolution

### Модифицированные:
- `server/fileconfig.go` — `AuthorizedClients []string` в FileConfig + ApplyTo
- `client/connmanager.go` — ECH config в connect(), кэш с TTL, fallback
- `client/fileconfig.go` — ECH field
- `cmd/shadowlink-client/main.go` — --ech flag
