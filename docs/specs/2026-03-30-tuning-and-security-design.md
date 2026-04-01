# ShadowLink — Донастройка и безопасность

**Дата:** 2026-03-30
**Статус:** Design approved
**Scope:** 7 задач + security audit round 13

## Контекст

Phase 1 задеплоен (548 Мбит/с download, 28 Мбит/с upload, Finland 150.241.86.160:9443).
12 раундов security audit пройдены. Остались TODO по стабильности, DPI-evasion интеграции и оптимизации.

## 1. Reconnection Backoff

**Проблема:** `Client.Connect()` выполняет handshake один раз. При любом дисконнекте клиент падает — непригоден для production.

**Решение:**

Новый метод `Client.ConnectWithRetry(ctx context.Context) error`:
- Exponential backoff: 1s → 2s → 4s → 8s → ... → cap 60s
- Jitter ±25% на каждом шаге (предотвращает thundering herd)
- Бесконечные retry, пока `ctx` не отменён
- Логирование: `slog.Warn("reconnect attempt", "attempt", n, "backoff", d)`
- При reconnect: полный новый handshake + новая сессия (старые ключи зануляются)

**Интеграция с SOCKS5 proxy:**
- SOCKS5 loop (client.go) при ошибке транспорта вызывает `ConnectWithRetry`
- Текущие SOCKS5 соединения получают error + close (клиентские приложения сами реконнектятся к SOCKS5)

**WS mode reconnect:**
- При WebSocket close / read error — автоматический reconnect через `ConnectWithRetry`
- После reconnect: перезапуск WS background reader горутины (новый `startWSReader()`)
- Все зарегистрированные streams (`RegisterStream` / `incomingCh`) — очищаются при reconnect. SOCKS5 соединения, привязанные к старым streams, получают EOF и закрываются. Клиентские приложения сами реконнектятся к SOCKS5 proxy.
- Порядок: `session.Destroy()` → `ConnectWithRetry()` → `startWSReader()` → ready

**Файлы:**
- `client/client.go` — новый метод `ConnectWithRetry`, интеграция в Run loop, `resetStreams()`
- `client/transport.go` — error wrapping для определения "recoverable" ошибок
- `client/ws_transport.go` — `startWSReader()` как отдельный метод для перезапуска

## 2. Config YAML

**Проблема:** 16 флагов в main.go — длинная строка ExecStart в systemd, неудобно менять настройки, mgmt-key виден в process list.

**Решение:**

Новый файл `server/config.go`:
```go
// Указатели (*int, *bool, *string) — для отличия "не указано в YAML" (nil) от "указано 0/false/пустая строка".
// Строковые поля без указателей — пустая строка означает "не указано" (валидное поведение).
type FileConfig struct {
    Listen      string         `yaml:"listen"`
    Cert        string         `yaml:"cert"`
    Key         string         `yaml:"key"`
    ServerKey   string         `yaml:"server_key"`
    Decoy       string         `yaml:"decoy"`
    MaxClients  *int           `yaml:"max_clients"`
    MaxConns    *int           `yaml:"max_conns"`
    ChunkSize   *int           `yaml:"chunk_size"`
    BehindProxy *bool          `yaml:"behind_proxy"`
    EnableUDP   *bool          `yaml:"enable_udp"`
    UDPListen   string         `yaml:"udp_listen"`
    Management  *MgmtConfig    `yaml:"management"`
    Mimicry     *MimicryConfig `yaml:"mimicry"`
}

type MgmtConfig struct {
    Port              *int   `yaml:"port"`
    Bind              string `yaml:"bind"`
    Key               string `yaml:"key"`
    DefaultMaxDevices *int   `yaml:"default_max_devices"`
}

type MimicryConfig struct {
    CoverTraffic *bool `yaml:"cover_traffic"` // default true
    Inflation    *bool `yaml:"inflation"`     // default true
}
```

Хелпер `setIfNotNil(dst *int, src *int)` и аналоги — для merge без boilerplate.

**Приоритет загрузки:** CLI флаги > YAML файл > defaults.

**Merge-логика:** Используем указатели в `FileConfig` для отличия nil от zero-value. После `yaml.Unmarshal` — nil означает "не указано в YAML". Для CLI флагов используем `flag.Visit()` чтобы определить, какие флаги были явно переданы. Порядок:
1. Заполнить `Config` значениями из YAML (где не nil)
2. Перезаписать значения из CLI флагов, которые были явно переданы (`flag.Visit`)
3. Для непереданных — оставить значения из YAML или defaults

**Пример:** `max_clients: 500` в YAML, CLI без `--max-clients` → используется 500. CLI с `--max-clients 200` → используется 200.

**Permissions:** При загрузке YAML сервер проверяет permissions файла. Если файл содержит `management.key` или `server_key` и permissions шире 0600 — warning в лог (не блокирующий, но заметный).

**Флаг:** `--config /etc/shadowlink/config.yaml` (сервер + клиент).

**Зависимость:** gopkg.in/yaml.v3 (добавить в go.mod).

**Файлы:**
- `server/config.go` — `FileConfig`, `LoadConfigFile()`, `MergeWithFlags()`
- `cmd/shadowlink-server/main.go` — `--config` флаг, логика merge
- `cmd/shadowlink-client/main.go` — аналогичный `--config` для клиента (опционально, `ClientFileConfig`)

## 3. Mimicry Engine Integration

**Проблема:** 4 компонента (PayloadDistribution, RatioController, SessionLifecycle, BuildInflatedDownloadResponse) написаны и протестированы, но ни один не подключён к реальному трафику. DPI может обнаружить протокол по нехарактерным размерам пакетов, соотношению upload/download, отсутствию cover traffic.

### 3a. RatioController + Cover Traffic (клиент)

В `DirectTransport` / `CDNTransport`:
- Поле `rc *browser.RatioController`
- Поле `session *core.Session` — ссылка на текущую сессию (устанавливается через `SetSession()` после handshake, nil во время reconnect)
- После `SendChunk()`: `rc.RecordUpload(n)`
- После получения ответа: `rc.RecordDownload(n)`
- Фоновая горутина (каждые 5-10с с jitter):
  - Если `session == nil` — skip (reconnect в процессе)
  - `budget := rc.CoverBudget()`
  - Если budget > 0: создать FlagPadding chunk через `core.NewPaddingChunk()`, зашифровать через `session.EncryptChunk()`, отправить через `BuildCoverTrafficRequest()`
- `rc.Reset()` каждые 30с
- Capped: max 64 KB/sec cover traffic

### 3b. PayloadDistribution (клиент)

**Важно:** `ChunkForUpload()` разбивает данные на куски 80-2000B. В HTTP polling mode каждый chunk = 1 HTTP round-trip, что убьёт перфоманс. Поэтому:

- **WS mode (primary):** один WS message = один chunk, нет overhead от round-trip. Здесь применять `ChunkForUpload()` для больших upload'ов и `PadToSize()` для мелких.
- **HTTP polling mode:** НЕ применять `ChunkForUpload()` (оставить текущее поведение). Только `PadToSize()` для мелких control chunks (FlagConnect, FlagFin).
- Не применять к FlagData при System VPN (перфоманс важнее stealth для full-tunnel)
- Применять к FlagConnect / FlagFin / малым HTTP запросам

### 3c. BuildInflatedDownloadResponse (сервер)

В `handler.go` заменить `BuildDownloadResponse()` → `BuildInflatedDownloadResponse()` во **всех** response paths, где используется `BuildDownloadResponse`:
- `handleDataChunk` (строка ~391) — data ответы
- `handleKeepalive` (строка ~405) — keepalive ответы
- `handleConnect` (строка ~437) — connect ответы
- `handleFin` — fin ответы
- `handleUDPData` (строка ~578) — UDP data ответы

Причина: если inflation только на data, а keepalive/connect/fin/udp остаются plain — DPI может классифицировать типы запросов по размеру ответа. Единообразие важнее.

Исключения (оставить plain):
- `handleHandshake` — первый ответ фиксированной структуры, inflation нарушит handshake protocol
- `handleControl` — возвращает plaintext JSON `{"status":"ok","type":"control_ack"}` без шифрования, это internal control path, не data

Конфиг: `mimicry.inflation: true/false`

### 3d. SessionLifecycle (клиент)

В `ConnManager.startRotation()`:
- Заменить hardcoded 2-10min на `SessionLifecycle.NextActiveInterval()`
- Gap pause уже частично реализован — заменить hardcoded значения на `NextGapDuration()`

**Файлы:**
- `client/transport.go` — RatioController, cover traffic горутина, PayloadDistribution
- `client/connmanager.go` — SessionLifecycle интеграция
- `server/handler.go` — BuildInflatedDownloadResponse
- `skins/browser/mimicry.go` — без изменений (уже готов)

## 4. sync.Pool Buffer Optimization

**Проблема:** 0 sync.Pool в проекте. 10+ аллокаций на hot path (каждый пакет). Upload 28 Мбит/с — можно улучшить.

**Решение:**

Новый файл `core/bufpool.go` — tiered buffer pool (NB: `core/pool.go` уже занят HTTP connection pool):
```go
var pools = [...]sync.Pool{
    {New: func() any { b := make([]byte, 512); return &b }},    // tier 0: ≤512
    {New: func() any { b := make([]byte, 4096); return &b }},   // tier 1: ≤4KB
    {New: func() any { b := make([]byte, 16384); return &b }},  // tier 2: ≤16KB
    {New: func() any { b := make([]byte, 65536); return &b }},  // tier 3: ≤64KB
}

func GetBuffer(minSize int) []byte   // выбирает минимальный tier ≥ minSize
func PutBuffer(buf []byte)           // возвращает в pool (с занулением если крипто)
func PutBufferZero(buf []byte)       // занулить + вернуть (для крипто-буферов)
```

**Точки применения (по приоритету):**

1. `server/websocket.go:48` — `wsStream.Write()` копия данных
2. `server/handler.go:477,496` — `relayFromTarget`, `relayStreamFromTarget` копии
3. `core/chunk.go:85,98` — `EncryptWith()` plaintext + output buffers
4. `server/udp_relay.go:96` — UDP datagram копии
5. `core/chunk.go:92` — nonce: заменить `make([]byte, 12)` на `[12]byte{}` (stack alloc)

**Безопасность:** `PutBufferZero()` для буферов содержащих:
- Plaintext перед шифрованием (user data)
- Расшифрованный plaintext после обработки
- Любые промежуточные буферы с ключами

Правило для разработчика: если буфер прошёл через `Encrypt`/`Decrypt` или содержит данные пользователя — `PutBufferZero()`. Для ciphertext и nonce — обычный `PutBuffer()` (они и так не секретны).

Zeroing: `for i := range buf { buf[i] = 0 }` (компилятор Go не оптимизирует away в текущих версиях; если понадобится — `crypto/subtle`).

**Файлы:**
- `core/bufpool.go` — pool реализация + тесты
- `server/handler.go` — применить GetBuffer/PutBuffer в relay
- `server/websocket.go` — применить в wsStream.Write
- `core/chunk.go` — применить в EncryptWith

## 5. Gap Pause Warmup

**Проблема:** Первый `Connect()` начинает слать данные мгновенно. Реальные analytics SDK имеют warmup delay (инициализация, получение конфига). DPI может заметить отсутствие warmup.

**Решение:**
- В `ConnManager` после первого успешного handshake: задержка 200-800ms (random)
- Не блокировать handshake — задержка между handshake и первым data chunk
- Применяется только при холодном старте клиента (первый connect), НЕ при reconnect (чтобы не задерживать восстановление)
- Конфигурируемо через YAML: `warmup: true` (default true)

**Файлы:**
- `client/connmanager.go` — warmup delay после первого connect

## 6. Domain Routing Rules (Split Tunneling)

**Проблема:** Сейчас весь трафик идёт через туннель. Нет возможности:
- Исключить домены (например *.ru) — они ходят через финский сервер, что медленнее и не нужно
- Заблокировать запрещённые законом сайты — защита сервера от abuse
- Принудительно направить конкретные домены через туннель (даже если попадают под bypass правило)

**Решение — два уровня:**

### 6a. Клиентский routing (bypass + force-tunnel)

Новый файл `client/routing.go`:
```go
type RoutingRules struct {
    Bypass []string // домены/паттерны для прямого доступа: "*.ru", "vk.com", "10.0.0.0/8"
    Force  []string // домены обязательно через туннель (перекрывает bypass): "youtube.com"
    Block  []string // блокировать на клиенте (connection refused): "example.com"
}

type Router struct {
    bypass []matcher
    force  []matcher
    block  []matcher
}

func (r *Router) Decide(host string) Action // ActionTunnel, ActionDirect, ActionBlock
```

**Матчинг:**
- `*.ru` — суффикс-матч (vk.ru, mail.ru, но не myru.com)
- `vk.com` — точное совпадение + поддомены (api.vk.com)
- `10.0.0.0/8` — CIDR-матч для IP-адресов

**Приоритет правил:** Block > Force > Bypass > Default(tunnel)

**Интеграция в SOCKS5 handler** (`cmd/shadowlink-client/main.go`):
- Перед `cl.ConnectToStream(target)` → `router.Decide(host)`
- `ActionDirect` → открыть TCP напрямую (`net.Dial`), relay без туннеля
- `ActionBlock` → вернуть SOCKS5 error (connection refused, 0x05)
- `ActionTunnel` → текущее поведение через ShadowLink

**Конфиг (YAML, клиентский):**
```yaml
routing:
  bypass:
    - "*.ru"
    - "*.рф"
    - "10.0.0.0/8"
    - "192.168.0.0/16"
  force:
    - "youtube.com"
    - "twitter.com"
  block:
    - "illegal-site.com"
```

### 6b. Серверный block-list (SafeDial)

В `server/handler.go` в `SafeDial()` — дополнительная проверка домена перед подключением:
- Загружать block-list из конфига или файла
- При попадании в block-list — возвращать generic "CONNECT_FAIL" (как для SSRF)
- Логировать blocked domains (для мониторинга abuse)

**Конфиг (YAML, серверный):**
```yaml
block_domains:
  - "illegal-site.com"
  # или путь к файлу:
  # file: /etc/shadowlink/blocklist.txt
```

**Зачем два уровня?**
- Клиентский bypass — экономит трафик и снижает latency для локальных сайтов
- Серверный block — нельзя обойти модификацией клиента, защищает от abuse

**Файлы:**
- `client/routing.go` — Router, матчинг, RoutingRules (+ тесты)
- `cmd/shadowlink-client/main.go` — интеграция router.Decide() в SOCKS5 handlers
- `server/handler.go` — block-list в SafeDial()
- `server/config.go` — BlockDomains в FileConfig

## 7. Security Audit Round 13

После реализации всех пунктов — полный security review нового кода.

**Scope аудита:**
- **Reconnection:** утечка ключей при reconnect? Старые сессии зачищаются? Race conditions?
- **Config:** чувствительные данные (mgmt-key) в памяти? Permissions на config file?
- **Mimicry:** cover traffic не создаёт новый detectable паттерн? Timing side-channels?
- **sync.Pool:** буферы зануляются перед возвратом? Нет use-after-return?
- **Routing:** bypass не раскрывает pattern (DPI видит direct+tunnel трафик с одного IP)? Block-list DoS?
- **Общее:** review всех deferred items из AUDIT.md + новый код
- Dual independent reviewer pattern (как в раундах 7-9)

## Порядок реализации

1. Reconnection backoff (критично для production)
2. Config YAML (упрощает деплой и настройку всего остального)
3. Mimicry engine integration (anti-DPI — ключевая ценность)
4. sync.Pool optimization (перфоманс upload)
5. Gap pause warmup (мелкий fix)
6. Domain routing rules (split tunneling + block)
7. Security audit round 13 (финальная проверка)

**Device limits:** не требуют кода — только добавить `--mgmt-port 9100 --mgmt-key <key>` в systemd unit на сервере (или через config.yaml после шага 2).

## Зависимости

- `gopkg.in/yaml.v3` — для Config YAML
- Все остальные изменения используют существующие зависимости
