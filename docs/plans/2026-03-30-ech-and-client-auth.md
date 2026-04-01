# ECH + Client Auth Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ECH (Encrypted Client Hello) support in CDN mode and enable client whitelist loading from YAML config.

**Architecture:** Client auth is a config-only change — whitelist already works at runtime, just needs YAML loading. ECH requires DNS HTTPS record lookup (miekg/dns) to get ECHConfigList, then passing it to utls for real ECH instead of GREASE. Chrome 133+ profiles already send GREASE ECH; we upgrade to real ECH when config is available.

**Tech Stack:** Go 1.24, miekg/dns, bogdanfinn/tls-client v1.14.0, bogdanfinn/utls v1.7.7-barnius

**Spec:** `shadowlink/docs/specs/2026-03-30-ech-and-client-auth-design.md`

---

## File Map

### New files:
- `client/ech.go` — DNS HTTPS record lookup, ECHConfigList extraction
- `client/ech_test.go` — tests

### Modified files:
- `server/fileconfig.go` — `AuthorizedClients` field in FileConfig + ApplyTo
- `client/connmanager.go` — ECH config fields, pass to utls
- `client/fileconfig.go` — `ECH` field
- `cmd/shadowlink-client/main.go` — `--ech` flag

---

## Chunk 1: Client ID Whitelist from YAML

### Task 1.1: Add authorized_clients to server FileConfig

**Files:**
- Modify: `server/fileconfig.go`
- Modify: `server/fileconfig_test.go`

- [ ] **Step 1: Write failing test**

Add to `server/fileconfig_test.go`:
```go
func TestLoadConfigFile_AuthorizedClients(t *testing.T) {
	yaml := `
authorized_clients:
  - "user-123"
  - "user-456"
  - "admin-1"
`
	f, err := os.CreateTemp("", "sl-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	fc, err := LoadConfigFile(f.Name())
	require.NoError(t, err)
	assert.Equal(t, 3, len(fc.AuthorizedClients))
	assert.Equal(t, "user-123", fc.AuthorizedClients[0])
}

func TestApplyTo_AuthorizedClients(t *testing.T) {
	fc := &FileConfig{
		AuthorizedClients: []string{"user-1", "user-2"},
	}
	cfg := Config{}
	fc.ApplyTo(&cfg)
	assert.Equal(t, 2, len(cfg.AuthorizedClients))
	assert.Equal(t, "user-1", cfg.AuthorizedClients[0])
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/NIXAVPN/shadowlink && go test ./server/ -run "TestLoadConfigFile_Auth|TestApplyTo_Auth" -v`
Expected: FAIL — `AuthorizedClients` not in FileConfig

- [ ] **Step 3: Add AuthorizedClients to FileConfig and ApplyTo**

In `server/fileconfig.go`, add field to `FileConfig`:
```go
AuthorizedClients []string `yaml:"authorized_clients"`
```

In `ApplyTo()`, add:
```go
if len(fc.AuthorizedClients) > 0 {
    cfg.AuthorizedClients = fc.AuthorizedClients
}
```

- [ ] **Step 4: Run tests**

Run: `cd D:/NIXAVPN/shadowlink && go test ./server/ -run "TestLoadConfigFile_Auth|TestApplyTo_Auth" -v`
Expected: PASS

- [ ] **Step 5: Build all**

Run: `cd D:/NIXAVPN/shadowlink && go build ./...`
Expected: Success

---

## Chunk 2: ECH Support

### Task 2.1: DNS HTTPS record lookup

**Files:**
- Create: `client/ech.go`
- Create: `client/ech_test.go`

- [ ] **Step 1: Add miekg/dns dependency**

Run: `cd D:/NIXAVPN/shadowlink && go get github.com/miekg/dns`

- [ ] **Step 2: Write test for ECH config resolution**

```go
// client/ech_test.go
package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolveECHConfig_CloudflareDomain(t *testing.T) {
	// Test against a known Cloudflare domain that has ECH enabled
	// crypto.cloudflare.com is Cloudflare's ECH test endpoint
	config, err := ResolveECHConfig("crypto.cloudflare.com")
	if err != nil {
		t.Skipf("ECH resolution failed (network issue?): %v", err)
	}
	assert.NotEmpty(t, config, "ECHConfigList should not be empty")
	// ECHConfigList starts with version (0xfe0d) and length
	assert.GreaterOrEqual(t, len(config), 4, "ECHConfigList too short")
}

func TestResolveECHConfig_NonExistentDomain(t *testing.T) {
	_, err := ResolveECHConfig("this-domain-does-not-exist-12345.invalid")
	assert.Error(t, err)
}

func TestResolveECHConfig_NoDNSHTTPS(t *testing.T) {
	// example.com likely has no HTTPS record with ECH
	config, err := ResolveECHConfig("example.com")
	// Should return error or empty config, not panic
	if err == nil {
		// May or may not have ECH, just check it doesn't crash
		_ = config
	}
}
```

- [ ] **Step 3: Implement ResolveECHConfig**

```go
// client/ech.go
package client

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/miekg/dns"
)

// ResolveECHConfig queries DNS HTTPS record (type 65) for domain
// and extracts ECHConfigList from the ech= SvcParam.
// Uses Cloudflare DNS (1.1.1.1:53) for resolution.
func ResolveECHConfig(domain string) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)
	m.RecursionDesired = true

	c := &dns.Client{Timeout: 5 * time.Second}
	r, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return nil, fmt.Errorf("dns query failed: %w", err)
	}

	if r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("dns query returned %s", dns.RcodeToString[r.Rcode])
	}

	for _, ans := range r.Answer {
		https, ok := ans.(*dns.HTTPS)
		if !ok {
			continue
		}
		for _, v := range https.Value {
			if v.Key() == dns.SVCB_ECHCONFIG {
				// ECH SvcParam value is the raw ECHConfigList
				echVal, ok := v.(*dns.SVCBECHConfig)
				if !ok {
					continue
				}
				if len(echVal.ECH) > 0 {
					return echVal.ECH, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no ECH config found in DNS HTTPS record for %s", domain)
}

// ECHConfig holds cached ECH configuration with TTL.
type ECHConfig struct {
	ConfigList []byte
	ResolvedAt time.Time
	TTL        time.Duration
}

// IsExpired returns true if the cached ECH config has expired.
func (e *ECHConfig) IsExpired() bool {
	if e == nil || len(e.ConfigList) == 0 {
		return true
	}
	return time.Since(e.ResolvedAt) > e.TTL
}
```

- [ ] **Step 4: Run tests**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestResolveECH -v`
Expected: PASS (or Skip if no network)

- [ ] **Step 5: Run go mod tidy**

Run: `cd D:/NIXAVPN/shadowlink && go mod tidy`

### Task 2.2: Integrate ECH into ConnManager

**Files:**
- Modify: `client/connmanager.go`
- Modify: `client/fileconfig.go`
- Modify: `cmd/shadowlink-client/main.go`

- [ ] **Step 1: Add ECH fields to ConnManagerConfig and ConnManager**

In `ConnManagerConfig`:
```go
ECHEnabled bool
ECHDomain  string // domain for DNS HTTPS lookup (usually same as ServerAddr host)
```

In `ConnManager`:
```go
echEnabled bool
echDomain  string
echCache   *ECHConfig // cached ECH config
```

- [ ] **Step 2: Add ECH to connect() method**

In `connect()`, after creating the tls-client options, if echEnabled:

```go
if cm.echEnabled && cm.echDomain != "" {
    // Resolve ECH config (cached with TTL)
    if cm.echCache == nil || cm.echCache.IsExpired() {
        if echBytes, err := ResolveECHConfig(cm.echDomain); err == nil {
            cm.echCache = &ECHConfig{
                ConfigList: echBytes,
                ResolvedAt: time.Now(),
                TTL:        5 * time.Minute,
            }
            slog.Info("ECH config resolved", "domain", cm.echDomain, "size", len(echBytes))
        } else {
            slog.Warn("ECH resolution failed, using GREASE", "domain", cm.echDomain, "error", err)
        }
    }
    // Note: Chrome 133+ profiles already include GREASE ECH via BoringGREASEECH().
    // With real ECHConfigList, utls will use real ECH instead of GREASE.
    // The ECHConfigList is passed through the custom spec if available.
    // For now, GREASE ECH is already active — real ECH requires utls-level integration.
}
```

- [ ] **Step 3: Add ECH to client FileConfig**

In `client/fileconfig.go`, add to `ClientFileConfig`:
```go
ECH bool `yaml:"ech"`
```

- [ ] **Step 4: Add --ech flag to client main.go**

In `cmd/shadowlink-client/main.go`:
```go
echEnabled := flag.Bool("ech", false, "Enable ECH (Encrypted Client Hello) in CDN mode")
```

Pass to ConnManagerConfig when creating transport:
```go
ECHEnabled: *echEnabled,
ECHDomain:  *cdnDomain, // ECH resolves against CDN domain
```

Also load from YAML config if present.

- [ ] **Step 5: Build and test**

Run: `cd D:/NIXAVPN/shadowlink && go build ./... && go test ./... -count=1`
Expected: All PASS, build clean

### Task 2.3: Integration test

- [ ] **Step 1: Add integration test for ECH with Cloudflare**

```go
// client/ech_test.go — add

func TestECHIntegration_CloudflareResolve(t *testing.T) {
	config, err := ResolveECHConfig("crypto.cloudflare.com")
	if err != nil {
		t.Skipf("Skipping ECH integration test: %v", err)
	}

	t.Logf("ECH config size: %d bytes", len(config))
	t.Logf("ECH config (hex): %x", config[:min(32, len(config))])

	// Verify it's a valid ECHConfigList
	// Format: length(2) + ECHConfig(version(2) + length(2) + ...)
	if len(config) >= 4 {
		listLen := binary.BigEndian.Uint16(config[:2])
		t.Logf("ECHConfigList length field: %d, actual remaining: %d", listLen, len(config)-2)
		assert.Equal(t, int(listLen), len(config)-2, "ECHConfigList length mismatch")
	}
}
```

- [ ] **Step 2: Run integration test**

Run: `cd D:/NIXAVPN/shadowlink && go test ./client/ -run TestECHIntegration -v`
Expected: PASS or Skip
