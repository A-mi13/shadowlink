# ShadowLink Phase 1 Hardening: Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Optimize upload speed (10→50+ Mbit/s), add per-user device limits with management API, harden DPI resistance with analytics mimicry engine, and enable UDP tunneling for system VPN.

**Architecture:** Four independent features touching ShadowLink's crypto layer (cached GCM), server management (new HTTP API on separate port), traffic shaping (mimicry engine replacing fixed padding), and SOCKS5 extension (UDP ASSOCIATE). Each feature is self-contained and can be implemented/tested independently.

**Tech Stack:** Go 1.23, crypto/aes, crypto/cipher, sync/atomic, net/http, gorilla/websocket, bogdanfinn/tls-client

**Spec:** `shadowlink/docs/specs/2026-03-29-upload-devices-dpi-design.md`

---

## File Structure

### New files

| File | Responsibility |
|------|---------------|
| `shadowlink/server/management.go` | Management API handlers (/manage/*) for device limits |
| `shadowlink/server/management_test.go` | Tests for management API |
| `shadowlink/server/udp_relay.go` | UDP NAT table + relay logic for UDP ASSOCIATE |
| `shadowlink/server/udp_relay_test.go` | Tests for UDP relay |
| `shadowlink/skins/browser/mimicry.go` | Analytics Mimicry Engine (payload distribution, session lifecycle, ratio controller) |
| `shadowlink/skins/browser/mimicry_test.go` | Tests for mimicry engine |

### Modified files

| File | What changes |
|------|-------------|
| `shadowlink/core/chunk.go` | Add FlagUDP=0x08, EncryptWith/DecryptWith, NewUDPDataChunk |
| `shadowlink/core/chunk_test.go` | Benchmarks for cached vs non-cached encrypt |
| `shadowlink/core/session.go` | Cached GCM, sendNonce, SessionHook, Create() returns error |
| `shadowlink/server/ratelimit.go` | ClientAuth: userLimits, activeSessions, CheckDeviceLimit, SyncClients |
| `shadowlink/server/handler.go` | CheckDeviceLimit in handshake, FlagUDP routing, SessionHook registration |
| `shadowlink/server/config.go` | ManagementPort/Bind/Key, DefaultMaxDevices |
| `shadowlink/server/server.go` | Start management listener |
| `shadowlink/cmd/shadowlink-server/main.go` | CLI flags for management |
| `shadowlink/cmd/shadowlink-client/main.go` | UDP ASSOCIATE in SOCKS5 handler |
| `shadowlink/skins/browser/shaping.go` | Integrate MimicryEngine |
| `shadowlink/skins/browser/request.go` | Multi-event chunking, response inflation |
| `shadowlink/client/connmanager.go` | Rotation 2-8min, gap pause |
| `shadowlink/client/ws_transport.go` | Buffer during gap, reconnect logic |

---

## Chunk 1: Upload Optimization

### Task 1: Add EncryptWith / DecryptWith to chunk.go

**Files:**
- Modify: `shadowlink/core/chunk.go:12-20` (flag constants), `shadowlink/core/chunk.go:43-77` (Encrypt)
- Test: `shadowlink/core/chunk_test.go`

- [ ] **Step 1: Write benchmark test for current Encrypt**

In `shadowlink/core/chunk_test.go`, add:

```go
func BenchmarkEncryptOld(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	chunk := &Chunk{
		SessionID: 1,
		SeqNum:    1,
		Flags:     FlagData,
		Payload:   make([]byte, 9000),
	}
	rand.Read(chunk.Payload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chunk.SeqNum = uint32(i)
		_, err := chunk.Encrypt(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}
```

- [ ] **Step 2: Run benchmark to get baseline**

Run: `cd shadowlink && go test ./core/ -bench BenchmarkEncryptOld -benchmem -count=3`
Expected: shows ns/op and allocs/op (expect ~7 allocs)

- [ ] **Step 3: Add FlagUDP constant and EncryptWith function**

In `shadowlink/core/chunk.go`, after line 19 (`FlagConnect`), add:

```go
FlagUDP byte = 0x08 // payload = [StreamID(2)] + [UDP data]
```

After the existing `Encrypt()` function (line 77), add:

```go
// EncryptWith encrypts using a pre-cached GCM cipher and counter-based nonce.
// Nonce format: [counter(8 bytes big-endian) + random(4 bytes)].
// Counter prevents reuse, random prevents predictability by DPI.
func (c *Chunk) EncryptWith(gcm cipher.AEAD, nonceCounter uint64) ([]byte, error) {
	plaintext := make([]byte, HeaderSize+len(c.Payload))
	binary.BigEndian.PutUint32(plaintext[0:4], c.SessionID)
	binary.BigEndian.PutUint32(plaintext[4:8], c.SeqNum)
	plaintext[8] = c.Flags
	copy(plaintext[HeaderSize:], c.Payload)

	nonce := make([]byte, NonceSize)
	binary.BigEndian.PutUint64(nonce[0:8], nonceCounter)
	_, err := rand.Read(nonce[8:12])
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// DecryptWith decrypts using a pre-cached GCM cipher.
// Nonce is read from the first 12 bytes of data (same wire format as Encrypt).
func DecryptWith(data []byte, gcm cipher.AEAD) (*Chunk, error) {
	if len(data) < MinChunk {
		return nil, fmt.Errorf("chunk too small: %d < %d", len(data), MinChunk)
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if len(plaintext) < HeaderSize {
		return nil, fmt.Errorf("plaintext too short: %d", len(plaintext))
	}

	return &Chunk{
		SessionID: binary.BigEndian.Uint32(plaintext[0:4]),
		SeqNum:    binary.BigEndian.Uint32(plaintext[4:8]),
		Flags:     plaintext[8],
		Payload:   plaintext[HeaderSize:],
	}, nil
}
```

Ensure `crypto/cipher` and `"fmt"` are in the import block. The current chunk.go uses `"errors"` but `DecryptWith` needs `fmt.Errorf`.

- [ ] **Step 4: Write test for EncryptWith / DecryptWith**

In `shadowlink/core/chunk_test.go`, add:

```go
func TestEncryptWithDecryptWith(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	chunk := &Chunk{
		SessionID: 42,
		SeqNum:    7,
		Flags:     FlagData,
		Payload:   []byte("hello shadowlink"),
	}

	encrypted, err := chunk.EncryptWith(gcm, 1)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := DecryptWith(encrypted, gcm)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted.SessionID != 42 || decrypted.SeqNum != 7 || decrypted.Flags != FlagData {
		t.Fatalf("header mismatch: got %+v", decrypted)
	}
	if string(decrypted.Payload) != "hello shadowlink" {
		t.Fatalf("payload mismatch: %q", decrypted.Payload)
	}
}

func TestEncryptWithCrossCompatibility(t *testing.T) {
	// EncryptWith output must be decryptable by DecryptChunk (old API)
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)

	chunk := &Chunk{SessionID: 1, SeqNum: 1, Flags: FlagData, Payload: []byte("cross")}
	encrypted, err := chunk.EncryptWith(gcm, 99)
	if err != nil {
		t.Fatal(err)
	}

	// Old API should decrypt it fine (reads nonce from packet)
	decrypted, err := DecryptChunk(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted.Payload) != "cross" {
		t.Fatalf("cross-compat failed: %q", decrypted.Payload)
	}
}

func BenchmarkEncryptWith(b *testing.B) {
	key := make([]byte, 32)
	rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	chunk := &Chunk{SessionID: 1, SeqNum: 1, Flags: FlagData, Payload: make([]byte, 9000)}
	rand.Read(chunk.Payload)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		chunk.SeqNum = uint32(i)
		_, err := chunk.EncryptWith(gcm, uint64(i))
		if err != nil {
			b.Fatal(err)
		}
	}
}
```

- [ ] **Step 5: Run tests**

Run: `cd shadowlink && go test ./core/ -v -run "TestEncryptWith|TestEncryptWithCross"`
Expected: PASS

- [ ] **Step 6: Run benchmarks and compare**

Run: `cd shadowlink && go test ./core/ -bench "BenchmarkEncrypt" -benchmem -count=3`
Expected: EncryptWith shows ~2 allocs/op vs ~7 for old. Significant ns/op improvement.

- [ ] **Step 7: Commit**

```bash
git add shadowlink/core/chunk.go shadowlink/core/chunk_test.go
git commit -m "feat(shadowlink): add EncryptWith/DecryptWith with cached GCM + FlagUDP constant"
```

---

### Task 2: Cache GCM in Session, update Create/Rekey/EncryptChunk

**Files:**
- Modify: `shadowlink/core/session.go:14-31` (struct), `shadowlink/core/session.go:260-270` (Create), `shadowlink/core/session.go:113-122` (Rekey), `shadowlink/core/session.go:159-184` (EncryptChunk/DecryptChunkSafe)

- [ ] **Step 1: Write test for cached session encrypt/decrypt**

In existing `shadowlink/core/session_test.go`, add:

```go
func TestSessionCachedEncryptDecrypt(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	rand.Read(sendKey)
	rand.Read(recvKey)

	sess, err := sm.Create(sendKey, recvKey)
	if err != nil {
		t.Fatal(err)
	}

	chunk := &Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     FlagData,
		Payload:   []byte("cached test"),
	}

	encrypted, err := sess.EncryptChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}

	// Decrypt using sendKey (which was the encryption key)
	decrypted, err := DecryptChunk(encrypted, sendKey)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted.Payload) != "cached test" {
		t.Fatalf("payload mismatch: %q", decrypted.Payload)
	}
}

func TestSessionCachedRoundTrip(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	sendKey := make([]byte, 32)
	recvKey := make([]byte, 32)
	rand.Read(sendKey)
	rand.Read(recvKey)

	// Sender session: encrypts with sendKey, decrypts with recvKey
	sender, err := sm.Create(sendKey, recvKey)
	if err != nil {
		t.Fatal(err)
	}

	// Receiver session: encrypts with recvKey, decrypts with sendKey
	// (simulates the other end of the tunnel)
	receiver, err := sm.Create(recvKey, sendKey)
	if err != nil {
		t.Fatal(err)
	}

	chunk := &Chunk{
		SessionID: sender.ID,
		SeqNum:    sender.NextSeqNum(),
		Flags:     FlagData,
		Payload:   []byte("round trip"),
	}

	encrypted, err := sender.EncryptChunk(chunk)
	if err != nil {
		t.Fatal(err)
	}

	// Receiver's recvGCM was built from sendKey (sender's send key)
	decrypted, err := receiver.DecryptChunkSafe(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if string(decrypted.Payload) != "round trip" {
		t.Fatalf("payload mismatch: %q", decrypted.Payload)
	}
}

func TestSessionCreateReturnsError(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	// Bad key length should error
	_, err := sm.Create([]byte("short"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for bad key length")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd shadowlink && go test ./core/ -v -run "TestSessionCached|TestSessionCreateReturns"`
Expected: FAIL — Create() doesn't return error yet, sendGCM not exported

- [ ] **Step 3: Update Session struct with cached GCM fields**

In `shadowlink/core/session.go`, modify the Session struct (lines 14-31):

```go
type Session struct {
	ID      uint32
	SendKey []byte
	RecvKey []byte

	sendSeq     uint32
	recvHighest uint32
	recvBitmap  [WindowSize / 64]uint64
	CreatedAt   time.Time

	oldRecvKey    []byte
	oldKeyExpiry  time.Time
	lastRekey     time.Time
	lastActivity  time.Time

	// Cached GCM ciphers for zero-alloc encrypt/decrypt
	sendGCM    cipher.AEAD
	recvGCM    cipher.AEAD
	oldRecvGCM cipher.AEAD  // grace period during rekey
	sendNonce  uint64       // counter-based nonce (atomic increment)

	mu sync.Mutex
}
```

Add `"crypto/aes"` and `"crypto/cipher"` to imports if not already present.

- [ ] **Step 4: Update Create() to return error and init GCM**

Replace `Create()` (lines 260-270) with:

```go
func (sm *SessionManager) Create(sendKey, recvKey []byte) (*Session, error) {
	id := sm.nextID.Add(1)
	if id == 0 {
		id = sm.nextID.Add(1) // skip 0
	}

	sendBlock, err := aes.NewCipher(sendKey)
	if err != nil {
		return nil, fmt.Errorf("send cipher: %w", err)
	}
	sendGCM, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return nil, fmt.Errorf("send gcm: %w", err)
	}

	recvBlock, err := aes.NewCipher(recvKey)
	if err != nil {
		return nil, fmt.Errorf("recv cipher: %w", err)
	}
	recvGCM, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return nil, fmt.Errorf("recv gcm: %w", err)
	}

	s := NewSession(id, sendKey, recvKey)
	s.sendGCM = sendGCM
	s.recvGCM = recvGCM

	sm.mu.Lock()
	sm.sessions[id] = s
	sm.mu.Unlock()
	return s, nil
}
```

Add `"fmt"` to imports.

- [ ] **Step 5: Update Rekey() to recreate GCM ciphers**

Replace `Rekey()` (lines 113-122) with:

```go
func (s *Session) Rekey(newSendKey, newRecvKey []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sendBlock, err := aes.NewCipher(newSendKey)
	if err != nil {
		return fmt.Errorf("send cipher: %w", err)
	}
	newSendGCM, err := cipher.NewGCM(sendBlock)
	if err != nil {
		return fmt.Errorf("send gcm: %w", err)
	}

	recvBlock, err := aes.NewCipher(newRecvKey)
	if err != nil {
		return fmt.Errorf("recv cipher: %w", err)
	}
	newRecvGCM, err := cipher.NewGCM(recvBlock)
	if err != nil {
		return fmt.Errorf("recv gcm: %w", err)
	}

	s.oldRecvKey = s.RecvKey
	s.oldRecvGCM = s.recvGCM
	s.oldKeyExpiry = time.Now().Add(10 * time.Second)
	s.SendKey = newSendKey
	s.RecvKey = newRecvKey
	s.sendGCM = newSendGCM
	s.recvGCM = newRecvGCM
	s.sendNonce = 0 // reset for new key
	s.lastRekey = time.Now()
	return nil
}
```

- [ ] **Step 6: Update EncryptChunk() to use cached GCM**

Replace `EncryptChunk()` (lines 159-165) with:

```go
func (s *Session) EncryptChunk(chunk *Chunk) ([]byte, error) {
	s.mu.Lock()
	gcm := s.sendGCM
	nonce := s.sendNonce
	s.sendNonce++
	s.mu.Unlock()

	if gcm == nil {
		// Fallback for sessions created without GCM (e.g., tests using NewSession directly)
		key := make([]byte, len(s.SendKey))
		s.mu.Lock()
		copy(key, s.SendKey)
		s.mu.Unlock()
		return chunk.Encrypt(key)
	}

	return chunk.EncryptWith(gcm, nonce)
}
```

- [ ] **Step 7: Update DecryptChunkSafe() to use cached GCM**

Replace `DecryptChunkSafe()` (lines 168-184) with:

```go
func (s *Session) DecryptChunkSafe(data []byte) (*Chunk, error) {
	s.mu.Lock()
	gcm := s.recvGCM
	var oldGCM cipher.AEAD
	if s.oldRecvGCM != nil && time.Now().Before(s.oldKeyExpiry) {
		oldGCM = s.oldRecvGCM
	}
	s.lastActivity = time.Now()
	s.mu.Unlock()

	if gcm == nil {
		// Fallback for sessions created without GCM
		s.mu.Lock()
		key := make([]byte, len(s.RecvKey))
		copy(key, s.RecvKey)
		var oldKey []byte
		if s.oldRecvKey != nil && time.Now().Before(s.oldKeyExpiry) {
			oldKey = make([]byte, len(s.oldRecvKey))
			copy(oldKey, s.oldRecvKey)
		}
		s.mu.Unlock()
		chunk, err := DecryptChunk(data, key)
		if err != nil && oldKey != nil {
			chunk, err = DecryptChunk(data, oldKey)
		}
		return chunk, err
	}

	chunk, err := DecryptWith(data, gcm)
	if err != nil && oldGCM != nil {
		chunk, err = DecryptWith(data, oldGCM)
	}
	return chunk, err
}
```

- [ ] **Step 8: Fix ALL callers of Create() and Rekey() to handle error**

**Create() callers (all must change `s := sm.Create(...)` to `s, err := sm.Create(...)`):**
- `shadowlink/core/handshake.go:88` — `session := sm.Create(keys.RecvKey, keys.SendKey)`
- `shadowlink/core/session_test.go` — **8 call sites** (lines 120, 121, 129, 141, 148, 161, 171, 172)
- `shadowlink/core/handshake_test.go` — check for any `sm.Create(` calls
- `shadowlink/server/handler.go` — in `handleHandshake()`

For test files, simple fix: change `s := sm.Create(k1, k2)` to:
```go
s, err := sm.Create(k1, k2)
if err != nil {
    t.Fatal(err)
}
```

**Rekey() callers (now returns error):**
- `shadowlink/core/session_test.go:85` — `s.Rekey(newSend, newRecv)`
- `shadowlink/core/session_test.go:97` — `s.Rekey(make([]byte, 32), make([]byte, 32))`

Change to:
```go
if err := s.Rekey(newSend, newRecv); err != nil {
    t.Fatal(err)
}
```

- [ ] **Step 9: Run all tests**

Run: `cd shadowlink && go test ./... -v -count=1`
Expected: ALL PASS

- [ ] **Step 10: Commit**

```bash
git add shadowlink/core/session.go shadowlink/core/session_test.go shadowlink/server/handler.go
git commit -m "feat(shadowlink): cache AES-GCM in Session for zero-alloc encrypt/decrypt"
```

---

## Chunk 2: Device Limits

### Task 3: Extend ClientAuth with device tracking

**Files:**
- Modify: `shadowlink/server/ratelimit.go:89-136`
- Test: `shadowlink/server/ratelimit_test.go` (create if not exists)

- [ ] **Step 1: Write tests for device limit logic**

Create `shadowlink/server/ratelimit_test.go`:

```go
package server

import (
	"testing"
)

func TestClientAuthDeviceLimit(t *testing.T) {
	ca := NewClientAuth(nil) // open mode initially
	ca.openMode = false
	ca.defaultMax = 2

	// Add clients for user u1
	ca.AddClient("u1:d1")
	ca.AddClient("u1:d2")

	// Both should be authorized
	if !ca.IsAuthorized("u1:d1") {
		t.Fatal("u1:d1 should be authorized")
	}

	// Simulate active sessions
	ca.OnSessionCreated("u1:d1", 100)
	ca.OnSessionCreated("u1:d2", 101)

	// Third device should fail limit check (2 active sessions, limit=2)
	ca.AddClient("u1:d3")
	if ca.CheckDeviceLimit("u1:d3") {
		t.Fatal("u1:d3 should exceed device limit")
	}

	// Destroy one session — now d3 should pass
	ca.OnSessionDestroyed("u1:d1", 100)
	if !ca.CheckDeviceLimit("u1:d3") {
		t.Fatal("u1:d3 should pass after d1 disconnected")
	}
}

func TestClientAuthSetUserLimit(t *testing.T) {
	ca := NewClientAuth(nil)
	ca.openMode = false
	ca.defaultMax = 1

	ca.AddClient("u5:d1")
	ca.OnSessionCreated("u5:d1", 200)

	// Default limit = 1, so d2 should fail
	ca.AddClient("u5:d2")
	if ca.CheckDeviceLimit("u5:d2") {
		t.Fatal("should exceed default limit of 1")
	}

	// Set user limit to 3
	ca.SetUserLimit("u5", 3)
	if !ca.CheckDeviceLimit("u5:d2") {
		t.Fatal("should pass with limit 3")
	}
}

func TestClientAuthSyncClients(t *testing.T) {
	ca := NewClientAuth([]string{"old:d1"})
	ca.SyncClients(
		[]string{"u1:d1", "u2:d1"},
		map[string]int{"u1": 3, "u2": 5},
	)

	if ca.IsAuthorized("old:d1") {
		t.Fatal("old client should be removed after sync")
	}
	if !ca.IsAuthorized("u1:d1") {
		t.Fatal("u1:d1 should be authorized after sync")
	}
	if ca.openMode {
		t.Fatal("should not be open mode after sync")
	}
}

func TestParseUserID(t *testing.T) {
	tests := []struct {
		clientID string
		expected string
	}{
		{"u42:d1", "u42"},
		{"u108:d2", "u108"},
		{"nocolon", "nocolon"}, // no colon = whole ID is userID
	}
	for _, tt := range tests {
		got := parseUserID(tt.clientID)
		if got != tt.expected {
			t.Errorf("parseUserID(%q) = %q, want %q", tt.clientID, got, tt.expected)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd shadowlink && go test ./server/ -v -run "TestClientAuth|TestParseUser"`
Expected: FAIL — methods don't exist yet

- [ ] **Step 3: Implement device limit logic in ClientAuth**

In `shadowlink/server/ratelimit.go`, modify `ClientAuth` struct (lines 91-95):

```go
type ClientAuth struct {
	mu             sync.RWMutex
	authorized     map[string]bool   // clientID → authorized
	openMode       bool

	userLimits     map[string]int    // userID → max devices
	activeSessions map[string][]uint32 // userID → active sessionIDs
	clientSession  map[string]uint32   // clientID → sessionID
	defaultMax     int
}
```

Replace `NewClientAuth` (lines 99-111):

```go
func NewClientAuth(clientIDs []string) *ClientAuth {
	ca := &ClientAuth{
		authorized:     make(map[string]bool),
		userLimits:     make(map[string]int),
		activeSessions: make(map[string][]uint32),
		clientSession:  make(map[string]uint32),
		defaultMax:     3,
	}
	if len(clientIDs) == 0 {
		ca.openMode = true
		return ca
	}
	for _, id := range clientIDs {
		ca.authorized[id] = true
	}
	return ca
}
```

Add helper and new methods after `RemoveClient` (line 136):

```go
func parseUserID(clientID string) string {
	for i, c := range clientID {
		if c == ':' {
			return clientID[:i]
		}
	}
	return clientID
}

func (ca *ClientAuth) SetUserLimit(userID string, max int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.userLimits[userID] = max
}

func (ca *ClientAuth) CheckDeviceLimit(clientID string) bool {
	if ca.openMode {
		return true
	}
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	userID := parseUserID(clientID)
	limit := ca.defaultMax
	if ul, ok := ca.userLimits[userID]; ok {
		limit = ul
	}
	return len(ca.activeSessions[userID]) < limit
}

// SessionHook interface implementation
func (ca *ClientAuth) OnSessionCreated(clientID string, sessionID uint32) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	userID := parseUserID(clientID)
	ca.activeSessions[userID] = append(ca.activeSessions[userID], sessionID)
	ca.clientSession[clientID] = sessionID
}

func (ca *ClientAuth) OnSessionDestroyed(clientID string, sessionID uint32) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	userID := parseUserID(clientID)
	sessions := ca.activeSessions[userID]
	for i, sid := range sessions {
		if sid == sessionID {
			ca.activeSessions[userID] = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}
	if len(ca.activeSessions[userID]) == 0 {
		delete(ca.activeSessions, userID)
	}
	delete(ca.clientSession, clientID)
}

func (ca *ClientAuth) SyncClients(clients []string, limits map[string]int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.authorized = make(map[string]bool)
	for _, id := range clients {
		ca.authorized[id] = true
	}
	ca.userLimits = make(map[string]int)
	for uid, lim := range limits {
		ca.userLimits[uid] = lim
	}
	ca.openMode = false
}

func (ca *ClientAuth) ActiveSessionCount(userID string) int {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return len(ca.activeSessions[userID])
}
```

- [ ] **Step 4: Run tests**

Run: `cd shadowlink && go test ./server/ -v -run "TestClientAuth|TestParseUser"`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add shadowlink/server/ratelimit.go shadowlink/server/ratelimit_test.go
git commit -m "feat(shadowlink): add device limits to ClientAuth with session tracking"
```

---

### Task 4: Management API

**Files:**
- Create: `shadowlink/server/management.go`
- Create: `shadowlink/server/management_test.go`
- Modify: `shadowlink/server/config.go:6-53`
- Modify: `shadowlink/server/server.go:59-95`
- Modify: `shadowlink/cmd/shadowlink-server/main.go:18-29`

- [ ] **Step 1: Write test for management API**

Create `shadowlink/server/management_test.go`:

```go
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestManagementAddClient(t *testing.T) {
	ca := NewClientAuth(nil)
	ca.openMode = false
	m := NewManagementHandler(ca, nil, "test-key")

	body, _ := json.Marshal(map[string]string{"client_id": "u1:d1"})
	req := httptest.NewRequest("POST", "/manage/clients", bytes.NewReader(body))
	req.Header.Set("X-Management-Key", "test-key")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !ca.IsAuthorized("u1:d1") {
		t.Fatal("client should be authorized after add")
	}
}

func TestManagementBadKey(t *testing.T) {
	ca := NewClientAuth(nil)
	m := NewManagementHandler(ca, nil, "correct-key")

	req := httptest.NewRequest("GET", "/manage/status", nil)
	req.Header.Set("X-Management-Key", "wrong-key")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestManagementSync(t *testing.T) {
	ca := NewClientAuth([]string{"old:d1"})
	m := NewManagementHandler(ca, nil, "key")

	body, _ := json.Marshal(map[string]interface{}{
		"clients": []string{"u1:d1", "u2:d1"},
		"limits":  map[string]int{"u1": 5, "u2": 2},
	})
	req := httptest.NewRequest("POST", "/manage/sync", bytes.NewReader(body))
	req.Header.Set("X-Management-Key", "key")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ca.IsAuthorized("old:d1") {
		t.Fatal("old client should be gone after sync")
	}
	if !ca.IsAuthorized("u1:d1") {
		t.Fatal("u1:d1 should be authorized")
	}
}

func TestManagementSetLimit(t *testing.T) {
	ca := NewClientAuth(nil)
	ca.openMode = false
	ca.defaultMax = 1
	m := NewManagementHandler(ca, nil, "key")

	body, _ := json.Marshal(map[string]interface{}{
		"user_id":     "u1",
		"max_devices": 10,
	})
	req := httptest.NewRequest("POST", "/manage/set-limit", bytes.NewReader(body))
	req.Header.Set("X-Management-Key", "key")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	ca.AddClient("u1:d1")
	ca.OnSessionCreated("u1:d1", 1)
	// With limit 10, d2 should pass
	if !ca.CheckDeviceLimit("u1:d2") {
		t.Fatal("should pass with limit 10")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd shadowlink && go test ./server/ -v -run TestManagement`
Expected: FAIL — NewManagementHandler doesn't exist

- [ ] **Step 3: Implement management handler**

Create `shadowlink/server/management.go`:

```go
package server

import (
	"encoding/json"
	"net/http"
	"strings"
)

type ManagementHandler struct {
	mux        *http.ServeMux
	clientAuth *ClientAuth
	apiKey     string
}

func NewManagementHandler(ca *ClientAuth, sessions interface{}, apiKey string) *ManagementHandler {
	m := &ManagementHandler{
		mux:        http.NewServeMux(),
		clientAuth: ca,
		apiKey:     apiKey,
	}
	m.mux.HandleFunc("POST /manage/clients", m.addClient)
	m.mux.HandleFunc("DELETE /manage/clients/", m.removeClient)
	m.mux.HandleFunc("POST /manage/sync", m.syncClients)
	m.mux.HandleFunc("POST /manage/set-limit", m.setLimit)
	m.mux.HandleFunc("GET /manage/status", m.status)
	return m
}

func (m *ManagementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Management-Key") != m.apiKey {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	m.mux.ServeHTTP(w, r)
}

func (m *ManagementHandler) addClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ClientID == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m.clientAuth.AddClient(req.ClientID)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (m *ManagementHandler) removeClient(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimPrefix(r.URL.Path, "/manage/clients/")
	if clientID == "" {
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}
	m.clientAuth.RemoveClient(clientID)
	// If there's an active session, destroy it
	m.clientAuth.mu.RLock()
	sessID, hasSess := m.clientAuth.clientSession[clientID]
	m.clientAuth.mu.RUnlock()
	if hasSess {
		m.clientAuth.OnSessionDestroyed(clientID, sessID)
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (m *ManagementHandler) syncClients(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Clients []string       `json:"clients"`
		Limits  map[string]int `json:"limits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m.clientAuth.SyncClients(req.Clients, req.Limits)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "count": len(req.Clients)})
}

func (m *ManagementHandler) setLimit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string `json:"user_id"`
		MaxDevices int    `json:"max_devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" || req.MaxDevices <= 0 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	m.clientAuth.SetUserLimit(req.UserID, req.MaxDevices)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (m *ManagementHandler) status(w http.ResponseWriter, r *http.Request) {
	m.clientAuth.mu.RLock()
	defer m.clientAuth.mu.RUnlock()

	clients := make([]string, 0, len(m.clientAuth.authorized))
	for id := range m.clientAuth.authorized {
		clients = append(clients, id)
	}

	resp := map[string]interface{}{
		"clients":         clients,
		"limits":          m.clientAuth.userLimits,
		"active_sessions": m.clientAuth.activeSessions,
		"open_mode":       m.clientAuth.openMode,
	}
	json.NewEncoder(w).Encode(resp)
}
```

- [ ] **Step 4: Run tests**

Run: `cd shadowlink && go test ./server/ -v -run TestManagement`
Expected: ALL PASS

- [ ] **Step 5: Add config fields and CLI flags**

In `shadowlink/server/config.go`, add to Config struct (after `EnableUDP` field):

```go
ManagementPort    int    // default: 0 (disabled)
ManagementBind    string // default: "127.0.0.1"
ManagementKey     string
DefaultMaxDevices int    // default: 3
```

In `DefaultConfig()`, add:

```go
ManagementBind:    "127.0.0.1",
DefaultMaxDevices: 3,
```

In `shadowlink/cmd/shadowlink-server/main.go`, add flags after the existing flag definitions:

```go
mgmtPort := flag.Int("mgmt-port", 0, "Management API port (0=disabled)")
mgmtBind := flag.String("mgmt-bind", "127.0.0.1", "Management API bind address")
mgmtKey := flag.String("mgmt-key", "", "Management API key")
defaultMaxDevices := flag.Int("default-max-devices", 3, "Default device limit per user")
```

And add to config construction:

```go
ManagementPort:    *mgmtPort,
ManagementBind:    *mgmtBind,
ManagementKey:     *mgmtKey,
DefaultMaxDevices: *defaultMaxDevices,
```

- [ ] **Step 6: Add management listener to server.go**

In `shadowlink/server/server.go`, add a `mgmtSrv *http.Server` field to Server struct.

In `Start()`, after existing listener setup, add:

```go
if s.config.ManagementPort > 0 && s.config.ManagementKey != "" {
	mgmtHandler := NewManagementHandler(s.handler.clientAuth, nil, s.config.ManagementKey)
	s.handler.clientAuth.defaultMax = s.config.DefaultMaxDevices
	addr := fmt.Sprintf("%s:%d", s.config.ManagementBind, s.config.ManagementPort)
	s.mgmtSrv = &http.Server{Addr: addr, Handler: mgmtHandler}
	go func() {
		if err := s.mgmtSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("management API error: %v", err)
		}
	}()
	log.Printf("Management API listening on %s", addr)
}
```

In `Stop()`, add `if s.mgmtSrv != nil { s.mgmtSrv.Close() }`.

- [ ] **Step 7: Add CheckDeviceLimit to handshake**

In `shadowlink/server/handler.go`, in `handleHandshake()`, after the `IsAuthorized` check (~line 204), add:

```go
if !h.clientAuth.CheckDeviceLimit(string(clientID)) {
	h.decoy.ServeHTTP(w, r)
	return
}
```

After session creation in `handleHandshake()`, add:

```go
h.clientAuth.OnSessionCreated(string(clientID), session.ID)
```

In the session cleanup (`StartCleanup`), when a session is removed, call:

```go
h.clientAuth.OnSessionDestroyed(clientID, sessionID)
```

This requires tracking clientID per session. Add `ClientID string` field to the Tunnel struct, set it during handshake.

- [ ] **Step 8: Run all tests**

Run: `cd shadowlink && go test ./... -v -count=1`
Expected: ALL PASS

- [ ] **Step 9: Commit**

```bash
git add shadowlink/server/management.go shadowlink/server/management_test.go shadowlink/server/config.go shadowlink/server/server.go shadowlink/server/handler.go shadowlink/cmd/shadowlink-server/main.go
git commit -m "feat(shadowlink): add Management API for device limits (push model)"
```

---

## Chunk 3: Analytics Mimicry Engine

### Task 5: MimicryEngine core — payload distribution + ratio controller

**Files:**
- Create: `shadowlink/skins/browser/mimicry.go`
- Create: `shadowlink/skins/browser/mimicry_test.go`

- [ ] **Step 1: Write tests for payload distribution and ratio controller**

Create `shadowlink/skins/browser/mimicry_test.go`:

```go
package browser

import (
	"math"
	"testing"
)

func TestPayloadDistributionUpload(t *testing.T) {
	pd := NewPayloadDistribution()
	counts := map[string]int{"small": 0, "medium": 0, "large": 0, "xlarge": 0}

	for i := 0; i < 10000; i++ {
		size := pd.UploadSize()
		switch {
		case size >= 80 && size <= 150:
			counts["small"]++
		case size > 150 && size <= 350:
			counts["medium"]++
		case size > 350 && size <= 800:
			counts["large"]++
		case size > 800 && size <= 2000:
			counts["xlarge"]++
		default:
			t.Fatalf("unexpected size: %d", size)
		}
	}

	// Check rough distribution (±10% tolerance)
	total := float64(10000)
	if math.Abs(float64(counts["small"])/total-0.45) > 0.10 {
		t.Errorf("small bucket off: %.2f (want ~0.45)", float64(counts["small"])/total)
	}
	if math.Abs(float64(counts["medium"])/total-0.35) > 0.10 {
		t.Errorf("medium bucket off: %.2f (want ~0.35)", float64(counts["medium"])/total)
	}
}

func TestRatioControllerNoCoverNeeded(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	// Upload 300, download 100 → ratio 3:1 → in range
	rc.RecordUpload(300)
	rc.RecordDownload(100)
	if budget := rc.CoverBudget(); budget != 0 {
		t.Fatalf("expected 0 budget, got %d", budget)
	}
}

func TestRatioControllerNeedsCover(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	// Upload 100, download 200 → ratio 0.5:1 → way below target
	rc.RecordUpload(100)
	rc.RecordDownload(200)
	budget := rc.CoverBudget()
	// Need: 2.5 * 200 - 100 = 400 bytes of cover
	if budget < 300 || budget > 500 {
		t.Fatalf("expected ~400 budget, got %d", budget)
	}
}

func TestRatioControllerZeroDownload(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	rc.RecordUpload(1000)
	// No download yet — budget should be 0
	if budget := rc.CoverBudget(); budget != 0 {
		t.Fatalf("expected 0 budget with zero download, got %d", budget)
	}
}

func TestRatioControllerCap(t *testing.T) {
	rc := NewRatioController(2.5, 3.5)
	rc.RecordUpload(0)
	rc.RecordDownload(1_000_000) // 1MB download → would need 2.5MB cover
	budget := rc.CoverBudget()
	if budget > maxCoverBudget {
		t.Fatalf("budget %d exceeds cap %d", budget, maxCoverBudget)
	}
}

func TestChunkPayload(t *testing.T) {
	pd := NewPayloadDistribution()
	// 1300B payload should be split into multiple chunks
	data := make([]byte, 1300)
	chunks := pd.ChunkForUpload(data)
	if len(chunks) < 2 {
		t.Fatalf("expected >1 chunks for 1300B, got %d", len(chunks))
	}
	// Reassemble
	var reassembled []byte
	for _, c := range chunks {
		reassembled = append(reassembled, c...)
	}
	if len(reassembled) != 1300 {
		t.Fatalf("reassembly length mismatch: %d vs 1300", len(reassembled))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd shadowlink && go test ./skins/browser/ -v -run "TestPayload|TestRatio|TestChunk"`
Expected: FAIL

- [ ] **Step 3: Implement MimicryEngine**

Create `shadowlink/skins/browser/mimicry.go`:

```go
package browser

import (
	"math/rand"
	"sync"
	"sync/atomic"
)

const maxCoverBudget = 65536 // 64 KB/sec cap

// PayloadDistribution generates analytics-realistic payload sizes.
type PayloadDistribution struct{}

func NewPayloadDistribution() *PayloadDistribution {
	return &PayloadDistribution{}
}

// UploadSize returns a target size matching GA4 analytics event distribution.
func (pd *PayloadDistribution) UploadSize() int {
	r := rand.Float64()
	switch {
	case r < 0.45:
		return 80 + rand.Intn(71) // 80-150
	case r < 0.80:
		return 151 + rand.Intn(200) // 151-350
	case r < 0.95:
		return 351 + rand.Intn(450) // 351-800
	default:
		return 801 + rand.Intn(1200) // 801-2000
	}
}

// DownloadSize returns a target size matching analytics config response distribution.
func (pd *PayloadDistribution) DownloadSize() int {
	r := rand.Float64()
	switch {
	case r < 0.40:
		return 50 + rand.Intn(51) // 50-100
	case r < 0.75:
		return 201 + rand.Intn(400) // 201-600
	case r < 0.95:
		return 601 + rand.Intn(1400) // 601-2000
	default:
		return 2001 + rand.Intn(6000) // 2001-8000
	}
}

// ChunkForUpload splits a large payload into analytics-sized pieces.
func (pd *PayloadDistribution) ChunkForUpload(data []byte) [][]byte {
	if len(data) == 0 {
		return nil
	}
	var chunks [][]byte
	offset := 0
	for offset < len(data) {
		targetSize := pd.UploadSize()
		if targetSize > len(data)-offset {
			targetSize = len(data) - offset
		}
		if targetSize == 0 {
			targetSize = len(data) - offset
		}
		chunks = append(chunks, data[offset:offset+targetSize])
		offset += targetSize
	}
	return chunks
}

// PadToSize pads data to targetSize with random bytes.
func PadToSize(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padded := make([]byte, targetSize)
	copy(padded, data)
	rand.Read(padded[len(data):])
	return padded
}

// RatioController maintains upload/download ratio in target range.
type RatioController struct {
	uploadBytes   atomic.Int64
	downloadBytes atomic.Int64
	targetLow     float64
	targetHigh    float64
	mu            sync.Mutex
}

func NewRatioController(targetLow, targetHigh float64) *RatioController {
	return &RatioController{
		targetLow:  targetLow,
		targetHigh: targetHigh,
	}
}

func (rc *RatioController) RecordUpload(n int) {
	rc.uploadBytes.Add(int64(n))
}

func (rc *RatioController) RecordDownload(n int) {
	rc.downloadBytes.Add(int64(n))
}

func (rc *RatioController) CoverBudget() int {
	dl := rc.downloadBytes.Load()
	if dl == 0 {
		return 0
	}
	ul := rc.uploadBytes.Load()
	ratio := float64(ul) / float64(dl)
	if ratio >= rc.targetLow {
		return 0
	}
	needed := int64(rc.targetLow*float64(dl)) - ul
	if needed > maxCoverBudget {
		needed = maxCoverBudget
	}
	if needed < 0 {
		return 0
	}
	return int(needed)
}

// Reset clears counters (call periodically, e.g., every 30s).
func (rc *RatioController) Reset() {
	rc.uploadBytes.Store(0)
	rc.downloadBytes.Store(0)
}

// SessionLifecycle controls transport rotation timing.
type SessionLifecycle struct {
	minActive  int // seconds (default 120 = 2min)
	maxActive  int // seconds (default 480 = 8min)
	minGap     int // milliseconds (default 500)
	maxGap     int // milliseconds (default 3000)
}

func NewSessionLifecycle() *SessionLifecycle {
	return &SessionLifecycle{
		minActive: 120,
		maxActive: 480,
		minGap:    500,
		maxGap:    3000,
	}
}

// NextActiveInterval returns how long the next "browse session" should last.
func (sl *SessionLifecycle) NextActiveInterval() int {
	return sl.minActive + rand.Intn(sl.maxActive-sl.minActive+1)
}

// NextGapDuration returns gap pause in milliseconds (weighted toward short).
func (sl *SessionLifecycle) NextGapDuration() int {
	// 70% under 1500ms
	if rand.Float64() < 0.70 {
		return sl.minGap + rand.Intn(1000)
	}
	return 1500 + rand.Intn(sl.maxGap-1500+1)
}

// MimicryEngine combines all DPI evasion components.
type MimicryEngine struct {
	Payload  *PayloadDistribution
	Session  *SessionLifecycle
	Ratio    *RatioController
}

func NewMimicryEngine() *MimicryEngine {
	return &MimicryEngine{
		Payload: NewPayloadDistribution(),
		Session: NewSessionLifecycle(),
		Ratio:   NewRatioController(2.5, 3.5),
	}
}
```

- [ ] **Step 4: Run tests**

Run: `cd shadowlink && go test ./skins/browser/ -v -run "TestPayload|TestRatio|TestChunk"`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add shadowlink/skins/browser/mimicry.go shadowlink/skins/browser/mimicry_test.go
git commit -m "feat(shadowlink): add Analytics Mimicry Engine (payload distribution, ratio controller, session lifecycle)"
```

---

### Task 6: Integrate MimicryEngine into transport layer

**Files:**
- Modify: `shadowlink/skins/browser/request.go:60-108` (multi-event), `shadowlink/skins/browser/request.go:174-188` (response inflation)
- Modify: `shadowlink/client/connmanager.go:159-171` (rotation interval)
- Modify: `shadowlink/skins/browser/shaping.go` (integrate mimicry)

- [ ] **Step 1: Update BuildDownloadResponse with inflation**

In `shadowlink/skins/browser/request.go`, modify `BuildDownloadResponse()` (lines 174-188) to add realistic JSON fields:

```go
func BuildDownloadResponse(encryptedChunk []byte, seqNum uint32) ([]byte, error) {
	result := downloadResult{
		ID:      fmt.Sprintf("evt_%d", seqNum),
		Payload: base64.StdEncoding.EncodeToString(encryptedChunk),
	}
	env := downloadEnvelope{
		Status:  "ok",
		Results: []downloadResult{result},
	}
	return json.Marshal(env)
}
```

Add inflation fields to the `downloadEnvelope` struct:

```go
type downloadEnvelope struct {
	Status        string           `json:"status"`
	Results       []downloadResult `json:"results"`
	ConfigVersion string           `json:"config_version,omitempty"`
	ExperimentID  string           `json:"experiment_id,omitempty"`
	Variant       string           `json:"variant,omitempty"`
	NextPoll      int              `json:"next_poll,omitempty"`
}
```

Create `BuildInflatedDownloadResponse`:

```go
func BuildInflatedDownloadResponse(encryptedChunk []byte, seqNum uint32) ([]byte, error) {
	result := downloadResult{
		ID:      fmt.Sprintf("evt_%d", seqNum),
		Payload: base64.StdEncoding.EncodeToString(encryptedChunk),
	}
	env := downloadEnvelope{
		Status:        "ok",
		Results:       []downloadResult{result},
		ConfigVersion: fmt.Sprintf("2026.%02d.%02d.%d", rand.Intn(12)+1, rand.Intn(28)+1, rand.Intn(10)),
		ExperimentID:  fmt.Sprintf("exp_%04x", rand.Intn(0xFFFF)),
		Variant:       []string{"control", "treatment_a", "treatment_b"}[rand.Intn(3)],
		NextPoll:      30 + rand.Intn(60),
	}
	return json.Marshal(env)
}
```

- [ ] **Step 2: Update connmanager rotation interval**

In `shadowlink/client/connmanager.go`, modify `ConnManagerConfig` defaults:
- Change `MinRotation` default from 5m to 2m
- Change `MaxRotation` default from 10m to 8m

In `startRotation()` (line 159-171), after `cm.rotate()` call, add gap pause:

```go
func (cm *ConnManager) startRotation() {
	go func() {
		for {
			interval := cm.minRotation + time.Duration(rand.Int63n(int64(cm.maxRotation-cm.minRotation)))
			select {
			case <-time.After(interval):
				// Gap pause before reconnecting (simulate navigation)
				gapMs := 500 + rand.Intn(2500)
				if rand.Float64() < 0.70 {
					gapMs = 500 + rand.Intn(1000) // 70% under 1.5s
				}
				time.Sleep(time.Duration(gapMs) * time.Millisecond)
				cm.rotate()
			case <-cm.stopCh:
				return
			}
		}
	}()
}
```

- [ ] **Step 3: Run all existing tests to check for regressions**

Run: `cd shadowlink && go test ./... -v -count=1`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add shadowlink/skins/browser/request.go shadowlink/client/connmanager.go shadowlink/skins/browser/shaping.go
git commit -m "feat(shadowlink): integrate mimicry engine — response inflation, 2-8min rotation with gap pause"
```

---

## Chunk 4: UDP ASSOCIATE

### Task 7: Add UDP relay on server side

**Files:**
- Create: `shadowlink/server/udp_relay.go`
- Create: `shadowlink/server/udp_relay_test.go`
- Modify: `shadowlink/core/chunk.go` (NewUDPDataChunk constructor)

- [ ] **Step 1: Add NewUDPDataChunk to chunk.go**

In `shadowlink/core/chunk.go`, after `NewKeepaliveChunk()`, add:

```go
// NewUDPDataChunk creates a UDP data chunk with stream ID and target address.
// Payload format: [StreamID(2)] + [AddrLen(2)] + [Addr(var)] + [Data]
func NewUDPDataChunk(sessID, seq uint32, streamID uint16, addr string, data []byte) *Chunk {
	addrBytes := []byte(addr)
	p := make([]byte, 2+2+len(addrBytes)+len(data))
	binary.BigEndian.PutUint16(p[0:2], streamID)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(addrBytes)))
	copy(p[4:4+len(addrBytes)], addrBytes)
	copy(p[4+len(addrBytes):], data)
	return &Chunk{SessionID: sessID, SeqNum: seq, Flags: FlagUDP, Payload: p}
}

// ParseUDPChunk extracts stream ID, target address, and data from a UDP chunk payload.
func ParseUDPChunk(payload []byte) (streamID uint16, addr string, data []byte, err error) {
	if len(payload) < 4 {
		return 0, "", nil, fmt.Errorf("UDP chunk too short: %d", len(payload))
	}
	streamID = binary.BigEndian.Uint16(payload[0:2])
	addrLen := binary.BigEndian.Uint16(payload[2:4])
	if len(payload) < 4+int(addrLen) {
		return 0, "", nil, fmt.Errorf("UDP chunk addr overflow: %d + %d > %d", 4, addrLen, len(payload))
	}
	addr = string(payload[4 : 4+addrLen])
	data = payload[4+addrLen:]
	return streamID, addr, data, nil
}
```

- [ ] **Step 2: Write test for UDP relay**

Create `shadowlink/server/udp_relay_test.go`:

```go
package server

import (
	"net"
	"testing"
	"time"
)

func TestUDPRelayBasic(t *testing.T) {
	relay := NewUDPRelay(60 * time.Second)
	defer relay.Close()

	// Start a local UDP echo server
	echoAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	echoConn, err := net.ListenUDP("udp", echoAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()

	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := echoConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echoConn.WriteToUDP(buf[:n], addr)
		}
	}()

	// Send data through relay
	target := echoConn.LocalAddr().String()
	responseCh := make(chan []byte, 1)

	relay.Send(1, target, []byte("hello udp"), func(data []byte) {
		responseCh <- append([]byte{}, data...)
	})

	select {
	case resp := <-responseCh:
		if string(resp) != "hello udp" {
			t.Fatalf("expected 'hello udp', got %q", resp)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for UDP response")
	}
}

func TestUDPRelayCleanup(t *testing.T) {
	relay := NewUDPRelay(100 * time.Millisecond)
	defer relay.Close()

	relay.Send(1, "127.0.0.1:9999", []byte("test"), func([]byte) {})

	if relay.FlowCount() != 1 {
		t.Fatalf("expected 1 flow, got %d", relay.FlowCount())
	}

	time.Sleep(200 * time.Millisecond)
	relay.Cleanup()

	if relay.FlowCount() != 0 {
		t.Fatalf("expected 0 flows after cleanup, got %d", relay.FlowCount())
	}
}
```

- [ ] **Step 3: Implement UDP relay**

Create `shadowlink/server/udp_relay.go`:

```go
package server

import (
	"net"
	"sync"
	"time"
)

type udpFlow struct {
	conn       *net.UDPConn
	lastActive time.Time
	onReceive  func(data []byte)
	done       chan struct{}
}

type UDPRelay struct {
	mu      sync.RWMutex
	flows   map[uint16]*udpFlow // streamID → flow
	timeout time.Duration
	closed  chan struct{}
}

func NewUDPRelay(timeout time.Duration) *UDPRelay {
	return &UDPRelay{
		flows:   make(map[uint16]*udpFlow),
		timeout: timeout,
		closed:  make(chan struct{}),
	}
}

func (r *UDPRelay) Send(streamID uint16, targetAddr string, data []byte, onReceive func([]byte)) error {
	r.mu.Lock()
	flow, exists := r.flows[streamID]
	if !exists {
		addr, err := net.ResolveUDPAddr("udp", targetAddr)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			r.mu.Unlock()
			return err
		}
		flow = &udpFlow{
			conn:       conn,
			lastActive: time.Now(),
			onReceive:  onReceive,
			done:       make(chan struct{}),
		}
		r.flows[streamID] = flow
		r.mu.Unlock()

		// Start receiver goroutine
		go r.readLoop(streamID, flow)
	} else {
		flow.lastActive = time.Now()
		flow.onReceive = onReceive
		r.mu.Unlock()
	}

	_, err := flow.conn.Write(data)
	return err
}

func (r *UDPRelay) readLoop(streamID uint16, flow *udpFlow) {
	buf := make([]byte, 65536)
	for {
		flow.conn.SetReadDeadline(time.Now().Add(r.timeout))
		n, err := flow.conn.Read(buf)
		if err != nil {
			return
		}
		flow.lastActive = time.Now()
		if flow.onReceive != nil {
			data := make([]byte, n)
			copy(data, buf[:n])
			flow.onReceive(data)
		}
	}
}

func (r *UDPRelay) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for id, flow := range r.flows {
		if now.Sub(flow.lastActive) > r.timeout {
			flow.conn.Close()
			delete(r.flows, id)
		}
	}
}

func (r *UDPRelay) FlowCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.flows)
}

func (r *UDPRelay) RemoveFlow(streamID uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if flow, ok := r.flows[streamID]; ok {
		flow.conn.Close()
		delete(r.flows, streamID)
	}
}

func (r *UDPRelay) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id, flow := range r.flows {
		flow.conn.Close()
		delete(r.flows, id)
	}
}
```

- [ ] **Step 4: Run tests**

Run: `cd shadowlink && go test ./server/ -v -run TestUDPRelay`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add shadowlink/core/chunk.go shadowlink/server/udp_relay.go shadowlink/server/udp_relay_test.go
git commit -m "feat(shadowlink): add UDP relay (NAT table + flow management) for UDP ASSOCIATE"
```

---

### Task 8: SOCKS5 UDP ASSOCIATE in client

**Files:**
- Modify: `shadowlink/cmd/shadowlink-client/main.go:189-213` (SOCKS5 cmd dispatch), add `handleUDPAssociate()`

- [ ] **Step 1: Modify SOCKS5 handler to dispatch UDP ASSOCIATE**

In `shadowlink/cmd/shadowlink-client/main.go`, in `handleSOCKS5WS()` (around line 343), change the cmd check from:

```go
if buf[1] != 0x01 {
    conn.Write([]byte{0x05, 0x07, ...})
    return
}
```

to:

```go
switch buf[1] {
case 0x01: // CONNECT — continue existing flow
case 0x03: // UDP ASSOCIATE
    handleUDPAssociateWS(ctx, conn, cl, wst, buf)
    return
default:
    conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
    return
}
```

Do the same in `handleSOCKS5()` (around line 210).

- [ ] **Step 2: Implement handleUDPAssociateWS**

Add after `handleSOCKS5WS()`:

```go
func handleUDPAssociateWS(ctx context.Context, conn net.Conn, cl *client.Client, wst *client.WebSocketTransport, socksReq []byte) {
	// Open local UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer udpConn.Close()

	// Reply with BND.ADDR:BND.PORT
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	reply := make([]byte, 10)
	reply[0] = 0x05 // version
	reply[1] = 0x00 // success
	reply[2] = 0x00 // reserved
	reply[3] = 0x01 // IPv4
	copy(reply[4:8], localAddr.IP.To4())
	reply[8] = byte(localAddr.Port >> 8)
	reply[9] = byte(localAddr.Port & 0xFF)
	conn.Write(reply)

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()

	session := cl.Session()
	streamID := cl.NextStreamID()

	// Track SOCKS5 client address for return path (set in send goroutine, read in recv goroutine)
	var lastClientAddr atomic.Pointer[net.UDPAddr]

	// Read UDP datagrams from SOCKS5 client, forward via ShadowLink
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx2.Done():
				return
			default:
			}
			udpConn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			if n < 10 {
				continue
			}
			// Parse SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR(var) + PORT(2) + DATA
			frag := buf[2]
			if frag != 0 {
				continue // fragmentation not supported
			}
			atyp := buf[3]
			var targetAddr string
			var dataOffset int
			switch atyp {
			case 0x01: // IPv4
				targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d", buf[4], buf[5], buf[6], buf[7],
					int(buf[8])<<8|int(buf[9]))
				dataOffset = 10
			case 0x03: // Domain
				domLen := int(buf[4])
				targetAddr = fmt.Sprintf("%s:%d", string(buf[5:5+domLen]),
					int(buf[5+domLen])<<8|int(buf[6+domLen]))
				dataOffset = 7 + domLen
			default:
				continue
			}

			data := buf[dataOffset:n]

			// Create UDP chunk and send via WS
			chunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, data)
			encrypted, err := session.EncryptChunk(chunk)
			if err != nil {
				continue
			}
			wst.WriteMessage(encrypted)

			// Store client address for return path (atomic for cross-goroutine access)
			lastClientAddr.Store(clientAddr)
		}
	}()

	// Register stream for incoming UDP responses from server
	incomingCh := cl.RegisterStream(streamID)

	// Return path: server → encrypted → decrypt → UDP back to SOCKS5 client
	go func() {
		for {
			select {
			case <-ctx2.Done():
				return
			case data := <-incomingCh:
				// data is already decrypted chunk payload (full FlagUDP payload)
				// Parse the address from the response (server echoes it in FlagUDP chunk)
				_, addr, udpData, err := core.ParseUDPChunk(data)
				if err != nil || len(udpData) == 0 {
					continue
				}
				// Build SOCKS5 UDP response header: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT + DATA
				var resp []byte
				resp = append(resp, 0, 0, 0) // RSV + FRAG
				resp = append(resp, 0x03)     // ATYP = domain
				host, portStr, _ := net.SplitHostPort(addr)
				resp = append(resp, byte(len(host)))
				resp = append(resp, []byte(host)...)
				port, _ := strconv.Atoi(portStr)
				resp = append(resp, byte(port>>8), byte(port&0xFF))
				resp = append(resp, udpData...)
				// Send back to the SOCKS5 client's actual address
				clientAddr := lastClientAddr.Load()
				if clientAddr != nil {
					udpConn.WriteToUDP(resp, clientAddr)
				}
			}
		}
	}()

	// Wait for TCP connection to close (signals end of UDP ASSOCIATE)
	tcpBuf := make([]byte, 1)
	conn.Read(tcpBuf) // blocks until TCP closes
}
```

- [ ] **Step 3: Update WS background reader to handle FlagUDP**

In `cmd/shadowlink-client/main.go`, in the background WS reader goroutine (around line 121-139), the reader currently does:
```go
chunk, _ := session.DecryptChunkSafe(data)
streamID, payload := core.ParseStreamID(chunk.Payload)
cl.RouteToStream(streamID, payload)
```

Add a check for FlagUDP before ParseStreamID:
```go
chunk, _ := session.DecryptChunkSafe(data)
if chunk.Flags == core.FlagUDP {
    // Route the full payload (includes addr info needed by UDP handler)
    streamID := binary.BigEndian.Uint16(chunk.Payload[0:2])
    cl.RouteToStream(streamID, chunk.Payload)
} else {
    streamID, payload := core.ParseStreamID(chunk.Payload)
    cl.RouteToStream(streamID, payload)
}
```

- [ ] **Step 4: Add FlagUDP handling on server side (BOTH HTTP and WebSocket paths)**

**HTTP path:** In `shadowlink/server/handler.go`, in `handleData()` method, add a case for FlagUDP in the switch on chunk.Flags:

```go
case core.FlagUDP:
    h.handleUDPData(w, session, chunk, tunnel)
```

**WebSocket path:** In `shadowlink/server/websocket.go`, in `handleWebSocket()` at the switch on `chunk.Flags` (line 127), add a case BEFORE the closing `}` (after `case core.FlagKeepalive:`):

```go
case core.FlagUDP:
    streamID, targetAddr, data, err := core.ParseUDPChunk(chunk.Payload)
    if err != nil {
        continue
    }
    if h.udpRelay != nil {
        h.udpRelay.Send(streamID, targetAddr, data, func(response []byte) {
            respChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, response)
            if enc, err := session.EncryptChunk(respChunk); err == nil {
                writeMsg(enc)
            }
        })
    }
```

This is critical because `handleUDPAssociateWS` on the client uses WebSocket transport — so the WS handler on the server is the primary code path for UDP.

Add the HTTP handler method:

```go
func (h *Handler) handleUDPData(w http.ResponseWriter, session *core.Session, chunk *core.Chunk, tunnel *Tunnel) {
    streamID, targetAddr, data, err := core.ParseUDPChunk(chunk.Payload)
    if err != nil {
        return
    }

    if h.udpRelay == nil {
        return
    }

    h.udpRelay.Send(streamID, targetAddr, data, func(response []byte) {
        // Send response back to client via the tunnel's outgoing channel
        respChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, response)
        encrypted, err := session.EncryptChunk(respChunk)
        if err != nil {
            return
        }
        tunnel.Outgoing <- encrypted
    })
}
```

Add `udpRelay *UDPRelay` field to Handler struct. Initialize in `NewHandler()`:

```go
h.udpRelay = NewUDPRelay(60 * time.Second)
```

- [ ] **Step 5: Run all tests**

Run: `cd shadowlink && go test ./... -v -count=1`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add shadowlink/cmd/shadowlink-client/main.go shadowlink/server/handler.go shadowlink/core/chunk.go
git commit -m "feat(shadowlink): add SOCKS5 UDP ASSOCIATE for system VPN UDP tunneling"
```

---

## Post-Implementation

### Task 9: Integration testing and deploy

- [ ] **Step 1: Run full test suite**

Run: `cd shadowlink && go test ./... -v -race -count=1`
Expected: ALL PASS, no race conditions

- [ ] **Step 2: Build binaries**

Run: `cd shadowlink && GOOS=linux GOARCH=amd64 go build -o shadowlink-server ./cmd/shadowlink-server/ && GOOS=windows GOARCH=amd64 go build -o shadowlink-client.exe ./cmd/shadowlink-client/`

- [ ] **Step 3: Run upload benchmark comparison**

Run: `cd shadowlink && go test ./core/ -bench "BenchmarkEncrypt" -benchmem -count=5`
Document: before/after ns/op, allocs/op

- [ ] **Step 4: Deploy to test server**

Use `cmd/sl-fixlimit/main.go` script to upload new binary to 150.241.86.160.
Start with `--mgmt-port 9444 --mgmt-key <key>`.

- [ ] **Step 5: Test upload speed**

Run speed test from Windows client, verify upload > 50 Mbit/s.

- [ ] **Step 6: Test device limits**

```bash
curl -X POST http://127.0.0.1:9444/manage/clients \
  -H "X-Management-Key: <key>" \
  -d '{"client_id": "u1:d1"}'

curl -X POST http://127.0.0.1:9444/manage/set-limit \
  -H "X-Management-Key: <key>" \
  -d '{"user_id": "u1", "max_devices": 2}'
```

Connect 2 devices — should work. Try 3rd — should get decoy.

- [ ] **Step 7: Test UDP (system VPN)**

Run `connect-system-vpn.bat`, verify:
- Blocked sites open
- DNS resolution works
- QUIC connections work (no fallback delay)
