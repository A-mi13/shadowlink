# ShadowLink — Донастройка и безопасность: Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Довести ShadowLink до production-ready: reconnection, YAML config, mimicry integration, buffer pools, warmup, domain routing, security audit.

**Architecture:** Клиент получает reconnect loop, YAML config, domain router и mimicry integration в transport layer. Сервер получает YAML config, inflated responses, domain block-list. Shared core получает buffer pool. Все изменения изолированы в `shadowlink/`.

**Tech Stack:** Go 1.24, gopkg.in/yaml.v3, existing deps (gorilla/websocket, bogdanfinn/tls-client, pion)

**Spec:** `shadowlink/docs/specs/2026-03-30-tuning-and-security-design.md`

---

## File Map

### New files:
- `server/fileconfig.go` — YAML config loading, merge with flags
- `client/fileconfig.go` — client YAML config loading
- `client/routing.go` — domain routing rules (bypass/force/block)
- `core/bufpool.go` — tiered sync.Pool buffer pool

### New test files:
- `server/fileconfig_test.go`
- `client/fileconfig_test.go`
- `client/routing_test.go`
- `core/bufpool_test.go`
- `client/reconnect_test.go`

### Modified files:
- `cmd/shadowlink-server/main.go` — `--config` flag, YAML merge
- `cmd/shadowlink-client/main.go` — `--config` flag, routing integration in SOCKS5 handlers
- `client/client.go` — `ConnectWithRetry()`, `resetStreams()`, reconnect loop
- `client/ws_transport.go` — `startWSReader()` as restartable method
- `client/transport.go` — RatioController + cover traffic goroutine, `SetSession()`
- `client/connmanager.go` — SessionLifecycle integration, warmup delay
- `server/handler.go` — `BuildInflatedDownloadResponse` calls, domain block-list in SafeDial
- `server/config.go` — `BlockDomains` field
- `server/server.go` — pass block-list to handler
- `core/chunk.go` — use bufpool in EncryptWith
- `server/websocket.go` — use bufpool in wsStream.Write
- `server/udp_relay.go` — use bufpool in readLoop

---

## Chunk 1: Reconnection Backoff

### Task 1.1: Reconnect logic — test

**Files:**
- Create: `client/reconnect_test.go`

- [ ] **Step 1: Write failing test for exponential backoff calculation**

```go
// client/reconnect_test.go
package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackoffDuration(t *testing.T) {
	tests := []struct {
		attempt int
		minExp  time.Duration
		maxExp  time.Duration
	}{
		{0, 750 * time.Millisecond, 1250 * time.Millisecond},   // 1s ±25%
		{1, 1500 * time.Millisecond, 2500 * time.Millisecond},  // 2s ±25%
		{2, 3 * time.Second, 5 * time.Second},                   // 4s ±25%
		{5, 24 * time.Second, 40 * time.Second},                 // 32s ±25%
		{10, 45 * time.Second, 75 * time.Second},                // cap 60s ±25%
		{20, 45 * time.Second, 75 * time.Second},                // still capped
	}
	for _, tt := range tests {
		d := backoffDuration(tt.attempt)
		assert.GreaterOrEqual(t, d, tt.minExp, "attempt %d too short", tt.attempt)
		assert.LessOrEqual(t, d, tt.maxExp, "attempt %d too long", tt.attempt)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test ./client/ -run TestBackoffDuration -v`
Expected: FAIL — `backoffDuration` not defined

- [ ] **Step 3: Implement backoffDuration in client.go**

```go
// client/client.go — add near top, after imports

// backoffDuration returns exponential backoff with ±25% jitter.
// Base: 1s, factor: 2x, cap: 60s.
func backoffDuration(attempt int) time.Duration {
	base := float64(time.Second) * math.Pow(2, float64(attempt))
	if base > float64(60*time.Second) {
		base = float64(60 * time.Second)
	}
	jitter := 0.75 + rand.Float64()*0.5 // [0.75, 1.25]
	return time.Duration(base * jitter)
}
```

Add `"math"` and `"math/rand/v2"` to imports.

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test ./client/ -run TestBackoffDuration -v`
Expected: PASS

- [ ] **Step 5: Commit**

```
feat(shadowlink): add exponential backoff calculation with jitter
```

### Task 1.2: ConnectWithRetry method

**Files:**
- Modify: `client/client.go`
- Modify: `client/reconnect_test.go`

- [ ] **Step 1: Write failing test for ConnectWithRetry**

```go
// client/reconnect_test.go — add

func TestConnectWithRetry_CancelledContext(t *testing.T) {
	// ConnectWithRetry should return ctx error when cancelled
	cl := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	err := cl.ConnectWithRetry(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test ./client/ -run TestConnectWithRetry -v`
Expected: FAIL — `ConnectWithRetry` not defined

- [ ] **Step 3: Implement ConnectWithRetry**

```go
// client/client.go — add after Close() method

// ConnectWithRetry attempts to connect with exponential backoff.
// Retries indefinitely until ctx is cancelled.
// On each attempt: full new handshake + new session (old keys zeroed).
func (c *Client) ConnectWithRetry(ctx context.Context) error {
	for attempt := 0; ; attempt++ {
		err := c.Connect(ctx)
		if err == nil {
			if attempt > 0 {
				slog.Info("reconnected", "attempts", attempt+1)
			}
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		d := backoffDuration(attempt)
		slog.Warn("connect failed, retrying", "attempt", attempt+1, "backoff", d, "error", err)

		timer := time.NewTimer(d)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd shadowlink && go test ./client/ -run TestConnectWithRetry -v`
Expected: PASS

- [ ] **Step 5: Commit**

```
feat(shadowlink): add ConnectWithRetry with exponential backoff
```

### Task 1.3: Stream cleanup on reconnect

**Files:**
- Modify: `client/client.go`

- [ ] **Step 1: Add resetStreams method**

```go
// client/client.go — add after ConnectWithRetry

// resetStreams closes all registered stream channels so SOCKS5 handlers get EOF.
// Called before reconnect to clean up stale state.
func (c *Client) resetStreams() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, ch := range c.streamChans {
		close(ch)
		delete(c.streamChans, id)
	}
	// Zero old session keys
	if c.session != nil {
		c.session.Destroy()
		c.session = nil
	}
	if c.token != nil {
		core.ZeroBytes(c.token)
		c.token = nil
	}
}
```

- [ ] **Step 2: Run all client tests**

Run: `cd shadowlink && go test ./client/ -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```
feat(shadowlink): add resetStreams for reconnect cleanup
```

### Task 1.4: Extract WS reader as restartable method

**Files:**
- Modify: `client/ws_transport.go`

- [ ] **Step 1: Add StartReader method to WebSocketTransport**

Currently the WS reader loop lives in `cmd/shadowlink-client/main.go:123-146` as an anonymous goroutine. Extract to a method so it can be restarted on reconnect.

```go
// client/ws_transport.go — add method

// StartReader runs the background WS message reader.
// Dispatches decrypted chunks to the client's stream router.
// Returns on WS error (caller should reconnect).
func (t *WebSocketTransport) StartReader(ctx context.Context, cl *Client) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := t.ReadMessage(0)
		if err != nil {
			return fmt.Errorf("ws read: %w", err)
		}

		session := cl.Session()
		if session == nil {
			continue
		}

		chunk, err := session.DecryptChunkSafe(data)
		if err != nil {
			continue
		}

		if len(chunk.Payload) < 2 {
			continue
		}

		streamID := uint16(chunk.Payload[0])<<8 | uint16(chunk.Payload[1])

		if chunk.Flags == core.FlagUDP {
			cl.RouteToStream(streamID, chunk.Payload)
		} else {
			cl.RouteToStream(streamID, chunk.Payload[2:])
		}
	}
}
```

- [ ] **Step 2: Update cmd/shadowlink-client/main.go to use StartReader**

Replace the anonymous goroutine at lines 123-146 with:

```go
// Start WS background reader
readerCtx, readerCancel := context.WithCancel(ctx)
defer readerCancel()
go func() {
    for {
        err := wst.StartReader(readerCtx, cl)
        if readerCtx.Err() != nil {
            return // shutting down
        }
        slog.Warn("ws reader stopped, reconnecting", "error", err)
        cl.resetStreams()
        if err := cl.ConnectWithRetry(readerCtx); err != nil {
            return
        }
        // Re-upgrade to WebSocket after reconnect
        // UpgradeToWebSocket(serverAddr string, useTLS, skipVerify bool)
        newWst, err := cl.UpgradeToWebSocket(globalServerAddr, globalUseTLS, globalSkipVerify)
        if err != nil {
            slog.Error("ws upgrade failed after reconnect", "error", err)
            continue
        }
        wst = newWst
    }
}()
```

- [ ] **Step 3: Run build to verify compilation**

Run: `cd shadowlink && go build ./...`
Expected: Success

- [ ] **Step 4: Commit**

```
feat(shadowlink): extract WS reader as restartable method + reconnect loop
```

---

## Chunk 2: Config YAML

### Task 2.1: Server YAML config — test

**Files:**
- Create: `server/fileconfig.go`
- Create: `server/fileconfig_test.go`

- [ ] **Step 1: Write failing test for LoadConfigFile**

```go
// server/fileconfig_test.go
package server

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigFile(t *testing.T) {
	yaml := `
listen: ":9443"
cert: /etc/ssl/cert.pem
key: /etc/ssl/key.pem
server_key: /etc/shadowlink/server.key
decoy: /var/www/decoy
max_clients: 200
behind_proxy: true
management:
  port: 9100
  bind: "127.0.0.1"
  key: "secret-key"
  default_max_devices: 5
mimicry:
  cover_traffic: true
  inflation: false
`
	f, err := os.CreateTemp("", "sl-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	fc, err := LoadConfigFile(f.Name())
	require.NoError(t, err)

	assert.Equal(t, ":9443", fc.Listen)
	assert.Equal(t, "/etc/ssl/cert.pem", fc.Cert)
	assert.NotNil(t, fc.MaxClients)
	assert.Equal(t, 200, *fc.MaxClients)
	assert.NotNil(t, fc.BehindProxy)
	assert.True(t, *fc.BehindProxy)
	assert.NotNil(t, fc.Management)
	assert.NotNil(t, fc.Management.Port)
	assert.Equal(t, 9100, *fc.Management.Port)
	assert.Equal(t, "secret-key", fc.Management.Key)
	assert.NotNil(t, fc.Mimicry)
	assert.NotNil(t, fc.Mimicry.Inflation)
	assert.False(t, *fc.Mimicry.Inflation)
}

func TestLoadConfigFile_Empty(t *testing.T) {
	f, _ := os.CreateTemp("", "sl-config-*.yaml")
	defer os.Remove(f.Name())
	f.Close()

	fc, err := LoadConfigFile(f.Name())
	require.NoError(t, err)
	assert.Nil(t, fc.MaxClients)
	assert.Nil(t, fc.BehindProxy)
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test ./server/ -run TestLoadConfigFile -v`
Expected: FAIL — `LoadConfigFile` not defined

- [ ] **Step 3: Implement FileConfig and LoadConfigFile**

```go
// server/fileconfig.go
package server

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// FileConfig — YAML config for the server.
// Pointer fields allow distinguishing "not set" (nil) from zero values.
type FileConfig struct {
	Listen      string       `yaml:"listen"`
	Cert        string       `yaml:"cert"`
	Key         string       `yaml:"key"`
	ServerKey   string       `yaml:"server_key"`
	Decoy       string       `yaml:"decoy"`
	MaxClients  *int         `yaml:"max_clients"`
	MaxConns    *int         `yaml:"max_conns"`
	ChunkSize   *int         `yaml:"chunk_size"`
	BehindProxy *bool        `yaml:"behind_proxy"`
	EnableUDP   *bool        `yaml:"enable_udp"`
	UDPListen   string       `yaml:"udp_listen"`
	Management  *MgmtConfig  `yaml:"management"`
	Mimicry     *MimicryConfig `yaml:"mimicry"`
	BlockDomains []string    `yaml:"block_domains"`
}

type MgmtConfig struct {
	Port              *int   `yaml:"port"`
	Bind              string `yaml:"bind"`
	Key               string `yaml:"key"`
	DefaultMaxDevices *int   `yaml:"default_max_devices"`
}

type MimicryConfig struct {
	CoverTraffic *bool `yaml:"cover_traffic"`
	Inflation    *bool `yaml:"inflation"`
}

// LoadConfigFile reads and parses YAML config.
func LoadConfigFile(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var fc FileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &fc, nil
}

// ApplyTo merges FileConfig into server Config.
// Only sets fields that are non-nil / non-empty in FileConfig.
func (fc *FileConfig) ApplyTo(cfg *Config) {
	if fc.Listen != "" {
		cfg.ListenAddr = fc.Listen
	}
	if fc.Cert != "" {
		cfg.CertFile = fc.Cert
	}
	if fc.Key != "" {
		cfg.KeyFile = fc.Key
	}
	if fc.ServerKey != "" {
		cfg.ServerKeyFile = fc.ServerKey
	}
	if fc.Decoy != "" {
		cfg.DecoyDir = fc.Decoy
	}
	if fc.MaxClients != nil {
		cfg.MaxClients = *fc.MaxClients
	}
	if fc.MaxConns != nil {
		cfg.MaxConnsPerClient = *fc.MaxConns
	}
	if fc.ChunkSize != nil {
		cfg.ChunkSize = *fc.ChunkSize
	}
	if fc.BehindProxy != nil {
		cfg.BehindProxy = *fc.BehindProxy
	}
	if fc.EnableUDP != nil {
		cfg.EnableUDP = *fc.EnableUDP
	}
	if fc.UDPListen != "" {
		cfg.UDPListenAddr = fc.UDPListen
	}
	if fc.Management != nil {
		if fc.Management.Port != nil {
			cfg.ManagementPort = *fc.Management.Port
		}
		if fc.Management.Bind != "" {
			cfg.ManagementBind = fc.Management.Bind
		}
		if fc.Management.Key != "" {
			cfg.ManagementKey = fc.Management.Key
		}
		if fc.Management.DefaultMaxDevices != nil {
			cfg.DefaultMaxDevices = *fc.Management.DefaultMaxDevices
		}
	}
}
```

- [ ] **Step 4: Ensure gopkg.in/yaml.v3 is a direct dependency**

Note: yaml.v3 is already in go.mod as indirect. Run `go mod tidy` after adding the import — it will promote to direct.

Run: `cd shadowlink && go mod tidy`

- [ ] **Step 5: Run tests**

Run: `cd shadowlink && go test ./server/ -run TestLoadConfigFile -v`
Expected: PASS

- [ ] **Step 6: Commit**

```
feat(shadowlink): add YAML config loading for server
```

### Task 2.2: Integrate --config flag into server main.go

**Files:**
- Modify: `cmd/shadowlink-server/main.go`

- [ ] **Step 1: Add --config flag and YAML merge logic**

After `flag.Parse()`, before building `server.Config{}`:

```go
configFile := flag.String("config", "", "YAML config file path")
```

After building `config` from flags:
```go
// Apply YAML config (flags override YAML via flag.Visit)
if *configFile != "" {
    fc, err := server.LoadConfigFile(*configFile)
    if err != nil {
        slog.Error("failed to load config file", "path", *configFile, "error", err)
        os.Exit(1)
    }
    // Apply YAML first
    fc.ApplyTo(&config)
    // Re-apply explicitly passed CLI flags (they take priority)
    flag.Visit(func(f *flag.Flag) {
        switch f.Name {
        case "listen":
            config.ListenAddr = *listen
        case "cert":
            config.CertFile = *cert
        case "key":
            config.KeyFile = *key
        case "server-key":
            config.ServerKeyFile = *serverKey
        case "decoy":
            config.DecoyDir = *decoy
        case "max-clients":
            config.MaxClients = *maxClients
        case "max-conns":
            config.MaxConnsPerClient = *maxConns
        case "chunk-size":
            config.ChunkSize = *chunkSize
        case "behind-proxy":
            config.BehindProxy = *behindProxy
        case "enable-udp":
            config.EnableUDP = *enableUDP
        case "udp-listen":
            config.UDPListenAddr = *udpListen
        case "mgmt-port":
            config.ManagementPort = *mgmtPort
        case "mgmt-bind":
            config.ManagementBind = *mgmtBind
        case "mgmt-key":
            config.ManagementKey = *mgmtKey
        case "default-max-devices":
            config.DefaultMaxDevices = *defaultMaxDevices
        }
    })
    slog.Info("config loaded", "path", *configFile)
}
```

- [ ] **Step 2: Build to verify compilation**

Run: `cd shadowlink && go build ./cmd/shadowlink-server/`
Expected: Success

- [ ] **Step 3: Commit**

```
feat(shadowlink): integrate --config YAML flag in server
```

### Task 2.3: Client YAML config

**Files:**
- Create: `client/fileconfig.go`
- Create: `client/fileconfig_test.go`
- Modify: `cmd/shadowlink-client/main.go`

- [ ] **Step 1: Write test for client config**

```go
// client/fileconfig_test.go
package client

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientLoadConfigFile(t *testing.T) {
	yaml := `
server: "1.2.3.4:9443"
pubkey: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
client_id: "my-client"
socks: "127.0.0.1:2080"
tls: true
websocket: true
routing:
  bypass:
    - "*.ru"
    - "10.0.0.0/8"
  force:
    - "youtube.com"
  block:
    - "bad-site.com"
`
	f, _ := os.CreateTemp("", "sl-client-*.yaml")
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	cc, err := LoadClientConfig(f.Name())
	require.NoError(t, err)
	assert.Equal(t, "1.2.3.4:9443", cc.Server)
	assert.True(t, cc.TLS)
	assert.Equal(t, 2, len(cc.Routing.Bypass))
	assert.Equal(t, "*.ru", cc.Routing.Bypass[0])
}
```

- [ ] **Step 2: Implement LoadClientConfig**

```go
// client/fileconfig.go
package client

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ClientFileConfig struct {
	Server    string        `yaml:"server"`
	PubKey    string        `yaml:"pubkey"`
	ClientID  string        `yaml:"client_id"`
	Socks     string        `yaml:"socks"`
	TLS       bool          `yaml:"tls"`
	SkipVerify bool         `yaml:"skip_verify"`
	CDN       string        `yaml:"cdn"`
	WebSocket bool          `yaml:"websocket"`
	Auto      bool          `yaml:"auto"`
	Routing   RoutingConfig `yaml:"routing"`
	Warmup    *bool         `yaml:"warmup"`
}

type RoutingConfig struct {
	Bypass []string `yaml:"bypass"`
	Force  []string `yaml:"force"`
	Block  []string `yaml:"block"`
}

func LoadClientConfig(path string) (*ClientFileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read client config: %w", err)
	}
	var cc ClientFileConfig
	if err := yaml.Unmarshal(data, &cc); err != nil {
		return nil, fmt.Errorf("parse client config: %w", err)
	}
	return &cc, nil
}
```

- [ ] **Step 3: Run tests**

Run: `cd shadowlink && go test ./client/ -run TestClientLoadConfigFile -v`
Expected: PASS

- [ ] **Step 4: Integrate --config in client main.go**

Add `--config` flag. If provided, load config file and use values as defaults (CLI flags override).

- [ ] **Step 5: Commit**

```
feat(shadowlink): add YAML config for client with routing rules
```

---

## Chunk 3: Mimicry Engine Integration

### Task 3.1: Server-side inflated responses

**Files:**
- Modify: `server/handler.go`

- [ ] **Step 1: Replace BuildDownloadResponse with BuildInflatedDownloadResponse**

In `server/handler.go`, replace at these exact locations:
- Line ~391 (`handleDataChunk`): `BuildDownloadResponse` → `BuildInflatedDownloadResponse`
- Line ~405 (`handleKeepalive`): `BuildDownloadResponse` → `BuildInflatedDownloadResponse`
- Line ~437 (`handleConnect` error): `BuildDownloadResponse` → `BuildInflatedDownloadResponse`
- Line ~461 (`handleConnect` success): `BuildDownloadResponse` → `BuildInflatedDownloadResponse`
- Line ~578 (`handleUDPData`): `BuildDownloadResponse` → `BuildInflatedDownloadResponse`

Leave `handleHandshake` (line ~246) as `BuildDownloadResponse` — handshake has fixed structure.

NOTE: `handleFin` (строки ~584-608) НЕ вызывает `BuildDownloadResponse` — ответ пишется inline как `{"status":"ok"}` в строках ~302-304. Замена для inline-ответа после `handleFin()` — отдельный вопрос, можно обернуть в `BuildInflatedDownloadResponse` если нужно единообразие, но приоритет ниже.

Find-and-replace `BuildDownloadResponse` → `BuildInflatedDownloadResponse` safe for the 5 calls above.

- [ ] **Step 2: Build to verify**

Run: `cd shadowlink && go build ./server/`
Expected: Success

- [ ] **Step 3: Run existing server tests**

Run: `cd shadowlink && go test ./server/ -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```
feat(shadowlink): use inflated download responses for DPI evasion
```

### Task 3.2: Client RatioController + cover traffic

**Files:**
- Modify: `client/transport.go`

- [ ] **Step 1: Add RatioController and session to DirectTransport**

Add fields to `DirectTransport` struct:
```go
rc      *browser.RatioController
session *core.Session // set via SetSession after handshake
coverMu sync.Mutex
stopCover chan struct{}
```

Add `SetSession` method:
```go
func (t *DirectTransport) SetSession(s *core.Session) {
	t.coverMu.Lock()
	defer t.coverMu.Unlock()
	t.session = s
}
```

- [ ] **Step 2: Instrument SendChunk with byte recording**

After successful send in `SendChunk()`, add:
```go
if t.rc != nil {
    t.rc.RecordUpload(len(encryptedChunk))
}
```

After response parse, add:
```go
if t.rc != nil {
    t.rc.RecordDownload(len(respBody))
}
```

- [ ] **Step 3: Add cover traffic goroutine**

```go
func (t *DirectTransport) startCoverTraffic(ctx context.Context) {
	t.stopCover = make(chan struct{})
	go func() {
		ticker := time.NewTicker(7 * time.Second) // 5-10s average
		defer ticker.Stop()
		resetTicker := time.NewTicker(30 * time.Second)
		defer resetTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-t.stopCover:
				return
			case <-resetTicker.C:
				if t.rc != nil {
					t.rc.Reset()
				}
			case <-ticker.C:
				t.coverMu.Lock()
				sess := t.session
				t.coverMu.Unlock()
				if sess == nil || t.rc == nil {
					continue
				}
				budget := t.rc.CoverBudget()
				if budget <= 0 {
					continue
				}
				// Send cover traffic via BuildCoverTrafficRequest (same envelope as data)
				padding, err := core.NewPaddingChunk(sess.ID, sess.NextSeqNum(), int(budget))
				if err != nil {
					continue
				}
				encrypted, err := sess.EncryptChunk(padding)
				if err != nil {
					continue
				}
				fp := t.connManager.ActiveFingerprint()
				req, err := browser.BuildCoverTrafficRequest(
					t.baseURL, nil, t.urlPool, fp.UserAgent(), encrypted,
				)
				if err != nil {
					continue
				}
				req = req.WithContext(ctx)
				resp, err := t.connManager.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
		}
	}()
}
```

- [ ] **Step 4: Initialize RatioController in NewDirectTransport**

```go
rc: browser.NewRatioController(2.5, 3.5),
```

- [ ] **Step 5: Build and test**

Run: `cd shadowlink && go build ./... && go test ./client/ -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```
feat(shadowlink): integrate RatioController + cover traffic in transport
```

### Task 3.3: SessionLifecycle in ConnManager

**Files:**
- Modify: `client/connmanager.go`

- [ ] **Step 1: Replace hardcoded rotation timing with SessionLifecycle**

In `connmanager.go`, add field:
```go
lifecycle *browser.SessionLifecycle
```

Initialize in constructor:
```go
lifecycle: browser.NewSessionLifecycle(),
```

In `startRotation()`, replace hardcoded interval with:
```go
// NextActiveInterval() returns int (seconds) — convert to time.Duration
intervalSec := cm.lifecycle.NextActiveInterval()
timer := time.NewTimer(time.Duration(intervalSec) * time.Second)
```

Replace hardcoded gap pause with:
```go
// NextGapDuration() returns int (milliseconds)
gapMs := cm.lifecycle.NextGapDuration()
time.Sleep(time.Duration(gapMs) * time.Millisecond)
```

- [ ] **Step 2: Build and test**

Run: `cd shadowlink && go build ./... && go test ./client/ -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```
feat(shadowlink): use SessionLifecycle for rotation timing
```

### Task 3.4: PayloadDistribution integration (WS mode only)

**Files:**
- Modify: `client/ws_transport.go`

- [ ] **Step 1: Add PayloadDistribution to WebSocketTransport**

Add field:
```go
pd *browser.PayloadDistribution
```

Initialize in constructor:
```go
pd: browser.NewPayloadDistribution(),
```

- [ ] **Step 2: Apply PadToSize for small control chunks**

In WS write path, for FlagConnect and FlagFin chunks (small payloads), pad to realistic size:
```go
// For control chunks (< 80 bytes), pad to analytics-realistic size
if len(payload) < 80 {
    payload = t.pd.PadToSize(payload, t.pd.UploadSize())
}
```

- [ ] **Step 3: Apply ChunkForUpload for large WS uploads**

For FlagData chunks in WS mode (NOT System VPN full-tunnel), split large payloads:
```go
// Only in WS mode — HTTP mode doesn't benefit (1 chunk = 1 round-trip)
if len(data) > 2000 {
    chunks := t.pd.ChunkForUpload(data)
    for _, chunk := range chunks {
        // send each sub-chunk as separate WS message
    }
}
```

Note: this is WS-only optimization. HTTP polling mode skips ChunkForUpload (per spec).

- [ ] **Step 4: Build and test**

Run: `cd shadowlink && go build ./... && go test ./client/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```
feat(shadowlink): integrate PayloadDistribution in WS transport
```

---

## Chunk 4: sync.Pool Buffer Optimization

### Task 4.1: Tiered buffer pool

**Files:**
- Create: `core/bufpool.go`
- Create: `core/bufpool_test.go`

- [ ] **Step 1: Write failing test**

```go
// core/bufpool_test.go
package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBuffer_Sizes(t *testing.T) {
	tests := []struct {
		minSize  int
		wantCap  int // minimum expected capacity
	}{
		{100, 512},
		{512, 512},
		{513, 4096},
		{4000, 4096},
		{4097, 16384},
		{16000, 16384},
		{16385, 65536},
	}
	for _, tt := range tests {
		buf := GetBuffer(tt.minSize)
		assert.GreaterOrEqual(t, cap(buf), tt.wantCap, "minSize=%d", tt.minSize)
		PutBuffer(buf)
	}
}

func TestPutBufferZero_Clears(t *testing.T) {
	buf := GetBuffer(100)
	for i := range buf[:100] {
		buf[i] = 0xff
	}
	PutBufferZero(buf)
	// After zeroing and getting again, data should be clear
	// (can't guarantee same buffer from pool, but zeroing itself is testable)
}

func BenchmarkGetPutBuffer(b *testing.B) {
	for b.Loop() {
		buf := GetBuffer(4096)
		PutBuffer(buf)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test ./core/ -run TestGetBuffer -v`
Expected: FAIL — `GetBuffer` not defined

- [ ] **Step 3: Implement bufpool**

```go
// core/bufpool.go
package core

import "sync"

// Tiered buffer pool: 512B, 4KB, 16KB, 64KB.
var bufPools = [4]sync.Pool{
	{New: func() any { b := make([]byte, 512); return &b }},
	{New: func() any { b := make([]byte, 4096); return &b }},
	{New: func() any { b := make([]byte, 16384); return &b }},
	{New: func() any { b := make([]byte, 65536); return &b }},
}

var tierSizes = [4]int{512, 4096, 16384, 65536}

func tierIndex(minSize int) int {
	for i, s := range tierSizes {
		if minSize <= s {
			return i
		}
	}
	return 3 // largest tier
}

// GetBuffer returns a byte slice with cap >= minSize from the pool.
func GetBuffer(minSize int) []byte {
	idx := tierIndex(minSize)
	bp := bufPools[idx].Get().(*[]byte)
	return (*bp)[:tierSizes[idx]]
}

// PutBuffer returns a buffer to the pool.
func PutBuffer(buf []byte) {
	c := cap(buf)
	idx := -1
	for i, s := range tierSizes {
		if c == s {
			idx = i
			break
		}
	}
	if idx < 0 {
		return // not from our pool
	}
	b := buf[:c]
	bufPools[idx].Put(&b)
}

// PutBufferZero zeros the buffer then returns it to the pool.
// Use for buffers that contained plaintext or key material.
func PutBufferZero(buf []byte) {
	b := buf[:cap(buf)]
	for i := range b {
		b[i] = 0
	}
	PutBuffer(buf)
}
```

- [ ] **Step 4: Run tests + benchmark**

Run: `cd shadowlink && go test ./core/ -run TestGetBuffer -v && go test ./core/ -bench BenchmarkGetPut -benchmem`
Expected: PASS, ~0 allocs/op on benchmark

- [ ] **Step 5: Commit**

```
feat(shadowlink): add tiered sync.Pool buffer pool
```

### Task 4.2: Apply bufpool in hot paths

**Files:**
- Modify: `server/websocket.go` — wsStream.Write
- Modify: `server/handler.go` — relayFromTarget, relayStreamFromTarget
- Modify: `server/udp_relay.go` — readLoop datagram copy
- Modify: `core/chunk.go` — EncryptWith nonce to stack alloc

- [ ] **Step 1: Apply in wsStream.Write (server/websocket.go)**

Replace `make([]byte, len(data))` copy with `GetBuffer` + defer `PutBuffer`.

- [ ] **Step 2: Apply in relayFromTarget (server/handler.go)**

Replace `data := make([]byte, n)` copy with `GetBuffer(n)` + `PutBuffer` after use.

- [ ] **Step 2.5: Apply in UDP relay readLoop (server/udp_relay.go)**

Replace `datagram := make([]byte, n)` copy (line ~96) with `GetBuffer(n)` + `PutBuffer` after send.

- [ ] **Step 3: Stack-allocate nonce in EncryptWith (core/chunk.go)**

Replace `nonce := make([]byte, 12)` (line ~92) with:
```go
var nonce [12]byte
binary.BigEndian.PutUint64(nonce[:8], nonceCounter)
_, _ = rand.Read(nonce[8:])
```

- [ ] **Step 4: Run all tests**

Run: `cd shadowlink && go test ./... -v`
Expected: All PASS

- [ ] **Step 5: Run benchmarks to measure improvement**

Run: `cd shadowlink && go test ./core/ -bench . -benchmem`

- [ ] **Step 6: Commit**

```
perf(shadowlink): apply sync.Pool buffers in hot paths + stack nonce
```

---

## Chunk 5: Gap Pause Warmup

### Task 5.1: Warmup delay on first connect

**Files:**
- Modify: `client/connmanager.go`

- [ ] **Step 1: Add warmup flag and cold-start delay**

Add field to `ConnManager`:
```go
warmupDone bool
warmupEnabled bool
```

Set `warmupEnabled: true` in constructor (default).

In `startRotation()` or after first successful connect, add:
```go
if cm.warmupEnabled && !cm.warmupDone {
	delay := time.Duration(200+rand.IntN(600)) * time.Millisecond
	time.Sleep(delay)
	cm.warmupDone = true
}
```

- [ ] **Step 2: Build and test**

Run: `cd shadowlink && go build ./... && go test ./client/ -v`
Expected: All PASS

- [ ] **Step 3: Commit**

```
feat(shadowlink): add warmup delay on first connect (200-800ms)
```

---

## Chunk 6: Domain Routing Rules

### Task 6.1: Router implementation — test

**Files:**
- Create: `client/routing.go`
- Create: `client/routing_test.go`

- [ ] **Step 1: Write comprehensive routing tests**

```go
// client/routing_test.go
package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouter_Decide(t *testing.T) {
	r := NewRouter(RoutingConfig{
		Bypass: []string{"*.ru", "*.рф", "10.0.0.0/8", "192.168.0.0/16", "vk.com"},
		Force:  []string{"youtube.com", "blocked-in-ru.com"},
		Block:  []string{"illegal.com", "*.illegal.org"},
	})

	tests := []struct {
		host   string
		expect Action
	}{
		// Bypass: .ru domains go direct
		{"mail.ru", ActionDirect},
		{"api.vk.ru", ActionDirect},
		{"vk.com", ActionDirect},
		{"sub.vk.com", ActionDirect},

		// Force overrides bypass
		{"youtube.com", ActionTunnel},
		{"www.youtube.com", ActionTunnel},

		// Block takes highest priority
		{"illegal.com", ActionBlock},
		{"sub.illegal.org", ActionBlock},

		// Default: tunnel
		{"google.com", ActionTunnel},
		{"example.net", ActionTunnel},

		// CIDR bypass
		{"10.0.1.1", ActionDirect},
		{"192.168.1.100", ActionDirect},
		{"8.8.8.8", ActionTunnel},

		// Edge: not a suffix match for non-wildcard
		{"notvk.com", ActionTunnel},
		{"fakeru.com", ActionTunnel}, // not *.ru
	}

	for _, tt := range tests {
		got := r.Decide(tt.host)
		assert.Equal(t, tt.expect, got, "host=%s", tt.host)
	}
}

func TestRouter_Empty(t *testing.T) {
	r := NewRouter(RoutingConfig{})
	assert.Equal(t, ActionTunnel, r.Decide("anything.com"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd shadowlink && go test ./client/ -run TestRouter -v`
Expected: FAIL — `NewRouter` not defined

- [ ] **Step 3: Implement Router**

```go
// client/routing.go
package client

import (
	"net"
	"strings"
)

type Action int

const (
	ActionTunnel Action = iota // default: send through ShadowLink
	ActionDirect               // bypass: connect directly
	ActionBlock                // refuse connection
)

type matcher struct {
	pattern string
	cidr    *net.IPNet
}

func newMatcher(pattern string) matcher {
	// Try CIDR
	_, cidr, err := net.ParseCIDR(pattern)
	if err == nil {
		return matcher{cidr: cidr}
	}
	return matcher{pattern: strings.ToLower(pattern)}
}

func (m matcher) matches(host string) bool {
	host = strings.ToLower(host)

	if m.cidr != nil {
		ip := net.ParseIP(host)
		return ip != nil && m.cidr.Contains(ip)
	}

	p := m.pattern
	if strings.HasPrefix(p, "*.") {
		// Suffix match: *.ru matches mail.ru, sub.mail.ru
		suffix := p[1:] // ".ru"
		return strings.HasSuffix(host, suffix)
	}

	// Exact match + subdomain match
	return host == p || strings.HasSuffix(host, "."+p)
}

type Router struct {
	block  []matcher
	force  []matcher
	bypass []matcher
}

func NewRouter(cfg RoutingConfig) *Router {
	r := &Router{}
	for _, p := range cfg.Block {
		r.block = append(r.block, newMatcher(p))
	}
	for _, p := range cfg.Force {
		r.force = append(r.force, newMatcher(p))
	}
	for _, p := range cfg.Bypass {
		r.bypass = append(r.bypass, newMatcher(p))
	}
	return r
}

// Decide returns the routing action for a given host.
// Priority: Block > Force > Bypass > Tunnel (default).
func (r *Router) Decide(host string) Action {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	for _, m := range r.block {
		if m.matches(host) {
			return ActionBlock
		}
	}
	for _, m := range r.force {
		if m.matches(host) {
			return ActionTunnel
		}
	}
	for _, m := range r.bypass {
		if m.matches(host) {
			return ActionDirect
		}
	}
	return ActionTunnel
}
```

- [ ] **Step 4: Run tests**

Run: `cd shadowlink && go test ./client/ -run TestRouter -v`
Expected: PASS

- [ ] **Step 5: Commit**

```
feat(shadowlink): add domain routing rules (bypass/force/block)
```

### Task 6.2: Integrate Router into SOCKS5 handlers

**Files:**
- Modify: `cmd/shadowlink-client/main.go`

- [ ] **Step 1: Create Router from config and pass to handlers**

After loading config, create router:
```go
var router *client.Router
if clientConfig != nil {
    router = client.NewRouter(clientConfig.Routing)
} else {
    router = client.NewRouter(client.RoutingConfig{}) // no rules
}
```

- [ ] **Step 2: Add routing decision in handleSOCKS5WS**

Before `ConnectToStream`, add:
```go
action := router.Decide(destAddr)
switch action {
case client.ActionBlock:
    conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
    return
case client.ActionDirect:
    // Direct connection bypassing tunnel
    target, err := net.DialTimeout("tcp", destAddr, 10*time.Second)
    if err != nil {
        conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // host unreachable
        return
    }
    defer target.Close()
    conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // success
    // Simple bidirectional relay
    go io.Copy(target, conn)
    io.Copy(conn, target)
    return
}
// ActionTunnel: existing behavior
```

Apply same logic in `handleSOCKS5` (non-WS handler).

- [ ] **Step 3: Build and verify**

Run: `cd shadowlink && go build ./cmd/shadowlink-client/`
Expected: Success

- [ ] **Step 4: Commit**

```
feat(shadowlink): integrate domain routing in SOCKS5 handlers
```

### Task 6.3: Server-side block-list in SafeDial

**Files:**
- Modify: `server/config.go` — add `BlockDomains []string` field
- Modify: `server/handler.go` — check block-list in SafeDial or handleConnect

- [ ] **Step 1: Add BlockDomains to server Config**

```go
BlockDomains []string // domains to block (server-side)
```

- [ ] **Step 2: Add domain check before SafeDial in handleConnect**

```go
// Check server block-list
host, _, _ := net.SplitHostPort(target)
if host == "" {
    host = target
}
for _, blocked := range h.config.BlockDomains {
    blocked = strings.ToLower(blocked)
    hostLower := strings.ToLower(host)
    if hostLower == blocked || strings.HasSuffix(hostLower, "."+blocked) {
        slog.Debug("blocked domain", "host", host)
        // Return generic error (same as SSRF)
        // ... send CONNECT_FAIL response
        return
    }
}
```

- [ ] **Step 3: Wire BlockDomains from FileConfig.ApplyTo**

In `fileconfig.go` `ApplyTo()`, add:
```go
if len(fc.BlockDomains) > 0 {
    cfg.BlockDomains = fc.BlockDomains
}
```

- [ ] **Step 4: Build and test**

Run: `cd shadowlink && go build ./... && go test ./server/ -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```
feat(shadowlink): add server-side domain block-list
```

---

## Chunk 7: Security Audit Round 13

### Task 7.1: Dispatch security audit

- [ ] **Step 1: Run full test suite as pre-audit baseline**

Run: `cd shadowlink && go test ./... -v -count=1`
Expected: All PASS

- [ ] **Step 2: Dispatch dual independent security review agents**

Focus areas:
1. **Reconnection:** key zeroing on reconnect, race conditions in resetStreams, old session reuse
2. **Config:** sensitive data in YAML (mgmt-key, server-key path), file permissions check
3. **Mimicry:** cover traffic timing patterns, RatioController budget leaks
4. **sync.Pool:** buffer reuse after zero, use-after-return
5. **Routing:** bypass pattern doesn't leak traffic patterns, block-list bypass via IP
6. **All deferred items** from AUDIT.md

- [ ] **Step 3: Fix all CRITICAL and HIGH findings**

- [ ] **Step 4: Re-run security review to verify fixes**

- [ ] **Step 5: Update AUDIT.md with Round 13 results**

- [ ] **Step 6: Run full test suite as post-audit verification**

Run: `cd shadowlink && go test ./... -v -count=1`
Expected: All PASS

- [ ] **Step 7: Commit**

```
security(shadowlink): audit round 13 — tuning and security features
```
