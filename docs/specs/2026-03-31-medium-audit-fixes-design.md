# ShadowLink — MEDIUM Audit Fixes (Round 13)

**Дата:** 2026-03-31
**Статус:** Design approved
**Scope:** 5 реальных фиксов + обновление AUDIT.md

## Triage Result

| Issue | Status | Action |
|-------|--------|--------|
| R-4 | UNFIXED | Fix |
| C-1 | UNFIXED | Fix |
| C-2 | UNFIXED | Fix |
| P-2 | UNFIXED | Fix |
| D-1 | UNFIXED (by design) | Strengthen |
| D-3 | ALREADY FIXED | Update AUDIT.md |
| X-4 | PARTIALLY FIXED | Fix client-side |
| X-5 | ALREADY FIXED | Update AUDIT.md |

## Fix 1: R-4 — Stale session after reconnect

**Problem:** SOCKS5 handlers snapshot `session` via `c.mu.Lock()`, then call `session.EncryptChunk()`. Meanwhile `ResetStreams()` calls `session.Destroy()` which zeroes keys. If EncryptChunk's internal `Keys()` runs after Destroy, it gets zeroed bytes → encryption fails silently.

**Fix:** Grace period for session destruction. `ResetStreams()` sets `c.session = nil` immediately (new handlers get "not connected" error), but defers `Destroy()` by 5 seconds via goroutine. In-flight handlers that already snapshotted the session can finish their operations.

**File:** `client/client.go` — `ResetStreams()` method

```go
func (c *Client) ResetStreams() {
    c.streamMu.Lock()
    for id, ch := range c.streamChans {
        close(ch)
        delete(c.streamChans, id)
    }
    c.streamMu.Unlock()

    c.mu.Lock()
    oldSession := c.session
    oldToken := c.token
    c.session = nil
    c.token = nil
    c.mu.Unlock()

    // R-4 fix: defer destruction so in-flight handlers can finish
    if oldSession != nil || oldToken != nil {
        go func() {
            time.Sleep(5 * time.Second)
            if oldSession != nil {
                oldSession.Destroy()
            }
            if oldToken != nil {
                core.ZeroBytes(oldToken)
            }
        }()
    }
}
```

## Fix 2: C-1 — Config file permission check

**Problem:** YAML config with management key loaded without checking file permissions.

**Fix:** On Linux/macOS, check `os.Stat` mode. Warn (not error) if mode is wider than 0640. On Windows, skip (no simple POSIX permission model). This is a warning, not a hard block — operators may have valid reasons.

**Files:** `server/fileconfig.go`, `client/fileconfig.go`

```go
func warnInsecurePermissions(path string) {
    info, err := os.Stat(path)
    if err != nil || runtime.GOOS == "windows" {
        return
    }
    mode := info.Mode().Perm()
    if mode&0o077 != 0 { // others/group have access
        slog.Warn("config file has insecure permissions",
            "path", path, "mode", fmt.Sprintf("%04o", mode),
            "recommended", "0600")
    }
}
```

## Fix 3: C-2 — Env variable expansion in YAML

**Problem:** Management key stored as plaintext in YAML.

**Fix:** Support `${ENV_VAR}` syntax in string values. After YAML parse, expand env references in sensitive fields (management key). Operators can set `MGMT_KEY=secret` and use `key: ${MGMT_KEY}` in YAML.

**File:** `server/fileconfig.go`

```go
func expandEnv(s string) string {
    if strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}") {
        envKey := s[2 : len(s)-1]
        if val := os.Getenv(envKey); val != "" {
            return val
        }
    }
    return s
}
```

Apply after YAML parse to `fc.Management.Key`, `fc.ServerKey`.

## Fix 4: P-2 — Compiler-safe buffer zeroing

**Problem:** Simple `for i := range b { b[i] = 0 }` may be optimized away if compiler detects the buffer is not read after zeroing.

**Fix:** Use `crypto/subtle.XORBytes` or `clear()` builtin (Go 1.21+). Go's `clear()` builtin is guaranteed to not be optimized away. Alternatively, use `runtime.KeepAlive` after the loop.

**File:** `core/bufpool.go`

```go
func PutBufferZero(buf []byte) {
    b := buf[:cap(buf)]
    clear(b) // Go 1.21+ builtin — guaranteed not optimized away
    PutBuffer(buf)
}
```

Note: Go 1.24 is our target, `clear()` is available. However, `clear()` for slices sets all elements to zero value — exactly what we need. But actually, the Go spec doesn't explicitly guarantee `clear()` won't be optimized. The safest approach is volatile-style:

```go
func PutBufferZero(buf []byte) {
    b := buf[:cap(buf)]
    for i := range b {
        b[i] = 0
    }
    runtime.KeepAlive(&b) // prevent dead-store elimination
    PutBuffer(buf)
}
```

## Fix 5: D-1 — DNS resolve for blocked domains

**Problem:** Block-list checks domain names only. Client sends IP → bypasses check.

**Fix:** If host looks like an IP, do reverse DNS lookup and check the result against block-list. Also resolve blocked domains to IPs at startup and maintain a blocked-IP set. This is best-effort — IPs can change.

**File:** `server/handler.go`

Better approach: resolve blocked domain IPs once at startup + refresh periodically. Cache as a `map[string]bool` of IPs. In `handleConnect`, if target is an IP, check the cache.

Actually, simpler: just add reverse DNS lookup in `isBlockedDomain`:

```go
func isBlockedDomain(host string, blockDomains []string) bool {
    // Existing domain check...

    // D-1 fix: if host is IP, try reverse DNS
    if ip := net.ParseIP(host); ip != nil {
        names, err := net.LookupAddr(host)
        if err == nil {
            for _, name := range names {
                name = strings.TrimSuffix(name, ".") // remove trailing dot
                if matchesBlockList(name, blockDomains) {
                    return true
                }
            }
        }
    }
    return false
}
```

## Fix 6: X-4 — Client stream limit

**Problem:** Client `streamChans` map grows without bound. Server is protected (256 limit) but client is not.

**Fix:** Add `maxStreams` constant (256) and check in `RegisterStream()`.

**File:** `client/client.go`

```go
const maxClientStreams = 256

func (c *Client) RegisterStream(streamID uint16) (chan []byte, error) {
    c.streamMu.Lock()
    defer c.streamMu.Unlock()
    if c.streamChans == nil {
        c.streamChans = make(map[uint16]chan []byte)
    }
    if len(c.streamChans) >= maxClientStreams {
        return nil, errors.New("max streams exceeded")
    }
    ch := make(chan []byte, 512)
    c.streamChans[streamID] = ch
    return ch, nil
}
```

Note: This changes the signature — callers must handle the error.

## AUDIT.md updates

Mark D-3 and X-5 as fixed (they already have logging/SSRF checks in code).
