# ShadowLink Phase 1: Browser Skin — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a working VPN tunnel protocol that disguises traffic as normal browser HTTP/1.1 API calls, bypasses TSPU DPI (including the 16 KB threshold), supports Direct and Cloudflare CDN modes with automatic switching.

**Architecture:** ShadowLink Phase 1 is a client-server protocol built in Go. The client opens multiple short-lived HTTP/1.1+TLS 1.3 connections (each <=12 KB) to the server, carrying encrypted VPN data inside JSON payloads. The server doubles as a real website (decoy). A Probe Engine auto-detects network conditions and switches between Direct and CDN mode.

**Tech Stack:** Go 1.22+, `crypto/tls` (TLS 1.3), `crypto/ecdh` (X25519), `crypto/aes` + `crypto/cipher` (AES-256-GCM), `golang.org/x/crypto/hkdf`, `golang.org/x/crypto/nacl/box`, `lukechampine.com/blake3`, `net/http` (HTTP/1.1 server/client)

**Spec:** `shadowlink/docs/specs/2026-03-28-shadowlink-protocol-design.md`

---

## File Structure (Phase 1 scope only)

```
shadowlink/
  go.mod                          -- module: github.com/nixavpn/shadowlink
  go.sum
  core/
    crypto.go                     -- KeyPair, ECDH, HKDF, NaCl Box encrypt/decrypt
    crypto_test.go
    chunk.go                      -- Unified Chunk Format: encode, decode, encrypt, decrypt
    chunk_test.go
    session.go                    -- Session state, sliding window, seq tracking
    session_test.go
    pool.go                       -- Adaptive connection pool manager
    pool_test.go
  server/
    server.go                     -- HTTP server, TLS, routing (auth vs decoy)
    server_test.go
    handler.go                    -- ShadowLink chunk handler (authenticated requests)
    decoy.go                      -- Decoy site static file handler
    config.go                     -- Server config struct + loading
    metrics.go                    -- Active clients, RAM, CPU gauges
  client/
    client.go                     -- Main client: connect, send/recv through pool
    client_test.go
    probe.go                      -- Probe Engine: classify network, select transport
    probe_test.go
    transport.go                  -- Transport interface + Direct implementation
    transport_cdn.go              -- CDN (Cloudflare) transport implementation
  skins/
    browser/
      request.go                  -- HTTP request/response building, JSON wrapping, base64
      request_test.go
      urls.go                     -- URL pool rotation
      shaping.go                  -- Behavior shaping: timing jitter, cover traffic
      shaping_test.go
  cmd/
    shadowlink-server/
      main.go                     -- Server entrypoint: flags, config, start
    shadowlink-client/
      main.go                     -- CLI client for testing: connect, proxy SOCKS5
  testutil/
    dpi_emulator.go               -- TCP proxy that emulates TSPU (16KB freeze, etc.)
    traffic_analyzer.go           -- Capture and analyze: entropy, sizes, timings
    integration_test.go           -- End-to-end tests using emulator
```

---

## Chunk 1: Foundation — Crypto + Chunks

### Task 1: Go module + dependencies

**Files:**
- Create: `shadowlink/go.mod`
- Create: `shadowlink/go.sum` (auto-generated)

- [ ] **Step 1: Initialize Go module**

```bash
cd shadowlink && go mod init github.com/nixavpn/shadowlink
```

- [ ] **Step 2: Add dependencies**

```bash
cd shadowlink && go get golang.org/x/crypto && go get lukechampine.com/blake3
```

- [ ] **Step 3: Verify**

```bash
cd shadowlink && go mod tidy && cat go.mod
```
Expected: module with `golang.org/x/crypto` and `lukechampine.com/blake3` listed.

- [ ] **Step 4: Commit**

```bash
git add shadowlink/go.mod shadowlink/go.sum
git commit -m "feat(shadowlink): initialize Go module with crypto dependencies"
```

---

### Task 2: Crypto primitives — key generation, ECDH, HKDF, NaCl Box

**Files:**
- Create: `shadowlink/core/crypto.go`
- Create: `shadowlink/core/crypto_test.go`

**What this file does:** All cryptographic operations for ShadowLink: X25519 key pairs, ECDH shared secret, HKDF key derivation (with proper IKM/salt/info as per spec section 3), NaCl Box for encrypting client_id in handshake (with random padding to prevent size leaks). No protocol logic here — just crypto building blocks.

- [ ] **Step 1: Write test for key pair generation**

```go
// crypto_test.go
func TestGenerateKeyPair(t *testing.T) {
    kp, err := GenerateKeyPair()
    require.NoError(t, err)
    assert.Len(t, kp.Public, 32)
    assert.Len(t, kp.Private, 32)
    assert.NotEqual(t, kp.Public, kp.Private)
}
```

- [ ] **Step 2: Run test — should fail (no implementation)**

```bash
cd shadowlink && go test ./core/ -run TestGenerateKeyPair -v
```
Expected: FAIL — `GenerateKeyPair` undefined.

- [ ] **Step 3: Implement KeyPair + GenerateKeyPair**

```go
// crypto.go
package core

import (
    "crypto/ecdh"
    "crypto/rand"
)

type KeyPair struct {
    Public  []byte
    Private []byte
    private *ecdh.PrivateKey
}

func GenerateKeyPair() (*KeyPair, error) {
    curve := ecdh.X25519()
    priv, err := curve.GenerateKey(rand.Reader)
    if err != nil {
        return nil, err
    }
    return &KeyPair{
        Public:  priv.PublicKey().Bytes(),
        Private: priv.Bytes(),
        private: priv,
    }, nil
}

func KeyPairFromPrivate(privBytes []byte) (*KeyPair, error) {
    curve := ecdh.X25519()
    priv, err := curve.NewPrivateKey(privBytes)
    if err != nil {
        return nil, err
    }
    return &KeyPair{
        Public:  priv.PublicKey().Bytes(),
        Private: priv.Bytes(),
        private: priv,
    }, nil
}
```

- [ ] **Step 4: Run test — should pass**

```bash
cd shadowlink && go test ./core/ -run TestGenerateKeyPair -v
```

- [ ] **Step 5: Write tests for ECDH + HKDF**

Test that two key pairs produce the same shared secret, and HKDF derives deterministic keys with proper domain separation (`"ShadowLink-v1" || client_id` as info).

```go
func TestECDHSharedSecret(t *testing.T) {
    client, _ := GenerateKeyPair()
    server, _ := GenerateKeyPair()
    s1, err := ComputeSharedSecret(client, server.Public)
    require.NoError(t, err)
    s2, err := ComputeSharedSecret(server, client.Public)
    require.NoError(t, err)
    assert.Equal(t, s1, s2)
}

func TestDeriveSessionKeys(t *testing.T) {
    shared := make([]byte, 32)
    rand.Read(shared)
    clientPub := make([]byte, 32)
    serverPub := make([]byte, 32)
    clientID := []byte("test-client-001")

    k1 := DeriveSessionKeys(shared, clientPub, serverPub, clientID)
    k2 := DeriveSessionKeys(shared, clientPub, serverPub, clientID)
    assert.Equal(t, k1.SendKey, k2.SendKey)   // deterministic
    assert.Equal(t, k1.RecvKey, k2.RecvKey)
    assert.NotEqual(t, k1.SendKey, k1.RecvKey) // different directions
    assert.Len(t, k1.SendKey, 32)              // AES-256
}
```

- [ ] **Step 6: Implement ECDH + HKDF**

```go
func ComputeSharedSecret(local *KeyPair, remotePub []byte) ([]byte, error) {
    curve := ecdh.X25519()
    remote, err := curve.NewPublicKey(remotePub)
    if err != nil {
        return nil, err
    }
    return local.private.ECDH(remote)
}

type SessionKeys struct {
    SendKey []byte // 32 bytes, AES-256
    RecvKey []byte // 32 bytes, AES-256
}

func DeriveSessionKeys(sharedSecret, clientPub, serverPub, clientID []byte) *SessionKeys {
    // Safe concat — never mutate input slices
    salt := make([]byte, 0, len(clientPub)+len(serverPub))
    salt = append(salt, clientPub...)
    salt = append(salt, serverPub...)
    info := make([]byte, 0, len("ShadowLink-v1")+len(clientID))
    info = append(info, []byte("ShadowLink-v1")...)
    info = append(info, clientID...)

    hkdfReader := hkdf.New(sha256.New, sharedSecret, salt, info)
    sendKey := make([]byte, 32)
    recvKey := make([]byte, 32)
    io.ReadFull(hkdfReader, sendKey)
    io.ReadFull(hkdfReader, recvKey)

    return &SessionKeys{SendKey: sendKey, RecvKey: recvKey}
}
```

- [ ] **Step 7: Run tests — should pass**

```bash
cd shadowlink && go test ./core/ -run "TestECDH|TestDerive" -v
```

- [ ] **Step 8: Write tests for NaCl Box (client_id encryption with random padding)**

```go
func TestNaclBoxEncryptDecrypt(t *testing.T) {
    sender, _ := GenerateKeyPair()
    receiver, _ := GenerateKeyPair()
    clientID := []byte("client-123")

    encrypted, err := EncryptClientID(clientID, receiver.Public, sender)
    require.NoError(t, err)

    decrypted, err := DecryptClientID(encrypted, sender.Public, receiver)
    require.NoError(t, err)
    assert.Equal(t, clientID, decrypted)
}

func TestNaclBoxVariesSize(t *testing.T) {
    sender, _ := GenerateKeyPair()
    receiver, _ := GenerateKeyPair()
    clientID := []byte("client-123")

    sizes := map[int]bool{}
    for i := 0; i < 20; i++ {
        enc, _ := EncryptClientID(clientID, receiver.Public, sender)
        sizes[len(enc)] = true
    }
    assert.Greater(t, len(sizes), 1, "random padding should vary ciphertext size")
}
```

- [ ] **Step 9: Implement NaCl Box with random padding**

```go
func EncryptClientID(clientID, receiverPub []byte, sender *KeyPair) ([]byte, error) {
    if len(clientID) > 255 {
        return nil, errors.New("client_id exceeds 255 bytes")
    }
    // Add 16-64 bytes random padding to vary ciphertext size (crypto/rand for unpredictability)
    var padLenBuf [1]byte
    rand.Read(padLenBuf[:])
    padLen := 16 + int(padLenBuf[0])%49 // 16..64, using crypto/rand
    padded := make([]byte, len(clientID)+1+padLen)
    padded[0] = byte(len(clientID))
    copy(padded[1:], clientID)
    rand.Read(padded[1+len(clientID):])

    var nonce [24]byte
    rand.Read(nonce[:])

    var pubKey, privKey [32]byte
    copy(pubKey[:], receiverPub)
    copy(privKey[:], sender.Private)

    encrypted := box.Seal(nonce[:], padded, &nonce, &pubKey, &privKey)
    return encrypted, nil
}

func DecryptClientID(encrypted, senderPub []byte, receiver *KeyPair) ([]byte, error) {
    if len(encrypted) < 24 {
        return nil, errors.New("ciphertext too short")
    }
    var nonce [24]byte
    copy(nonce[:], encrypted[:24])

    var pubKey, privKey [32]byte
    copy(pubKey[:], senderPub)
    copy(privKey[:], receiver.Private)

    decrypted, ok := box.Open(nil, encrypted[24:], &nonce, &pubKey, &privKey)
    if !ok {
        return nil, errors.New("decryption failed")
    }

    idLen := int(decrypted[0])
    if idLen > len(decrypted)-1 {
        return nil, errors.New("invalid padding")
    }
    return decrypted[1 : 1+idLen], nil
}
```

- [ ] **Step 10: Run all crypto tests**

```bash
cd shadowlink && go test ./core/ -v
```

- [ ] **Step 11: Commit**

```bash
git add shadowlink/core/crypto.go shadowlink/core/crypto_test.go
git commit -m "feat(shadowlink): crypto primitives — X25519, ECDH, HKDF, NaCl Box"
```

---

### Task 3: Unified Chunk Format — encode, decode, encrypt, decrypt

**Files:**
- Create: `shadowlink/core/chunk.go`
- Create: `shadowlink/core/chunk_test.go`

**What this file does:** The wire format per spec section 3: `sess_id(4B) + seq_num(4B) + flags(1B) + payload + GCM_tag(16B)`. Entire chunk encrypted with AES-256-GCM, sess_id in AAD. Nonce = `sess_id(4B) + seq_num(4B) + random(4B)`.

- [ ] **Step 1: Write test for chunk encode/decode roundtrip**

```go
func TestChunkRoundtrip(t *testing.T) {
    key := make([]byte, 32)
    rand.Read(key)

    chunk := &Chunk{
        SessionID: 42,
        SeqNum:    1,
        Flags:     FlagData,
        Payload:   []byte("hello shadowlink"),
    }

    encrypted, err := chunk.Encrypt(key)
    require.NoError(t, err)

    decoded, err := DecryptChunk(encrypted, key)
    require.NoError(t, err)
    assert.Equal(t, chunk.SessionID, decoded.SessionID)
    assert.Equal(t, chunk.SeqNum, decoded.SeqNum)
    assert.Equal(t, chunk.Flags, decoded.Flags)
    assert.Equal(t, chunk.Payload, decoded.Payload)
}

func TestChunkTamperedAAD(t *testing.T) {
    key := make([]byte, 32)
    rand.Read(key)
    chunk := &Chunk{SessionID: 1, SeqNum: 1, Flags: FlagData, Payload: []byte("data")}
    encrypted, _ := chunk.Encrypt(key)

    // Tamper with sess_id bytes (first 4 bytes of plaintext, but in AAD)
    // The nonce is first 12 bytes, so AAD is embedded differently
    // Flip a byte in the ciphertext
    encrypted[12] ^= 0xff
    _, err := DecryptChunk(encrypted, key)
    assert.Error(t, err, "tampered chunk must fail decryption")
}
```

- [ ] **Step 2: Run — should fail**

```bash
cd shadowlink && go test ./core/ -run TestChunk -v
```

- [ ] **Step 3: Implement Chunk type + Encrypt/Decrypt**

```go
// chunk.go
package core

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/binary"
    "errors"
)

const (
    FlagData      byte = 0x01
    FlagAck       byte = 0x02
    FlagPadding   byte = 0x03
    FlagKeepalive byte = 0x04
    FlagFin       byte = 0x05
    FlagControl   byte = 0x06

    NonceSize  = 12
    HeaderSize = 4 + 4 + 1 // sess_id + seq_num + flags
    TagSize    = 16
)

type Chunk struct {
    SessionID uint32
    SeqNum    uint32
    Flags     byte
    Payload   []byte
}

func (c *Chunk) Encrypt(key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    // Build plaintext: sess_id(4) + seq_num(4) + flags(1) + payload
    plaintext := make([]byte, HeaderSize+len(c.Payload))
    binary.BigEndian.PutUint32(plaintext[0:4], c.SessionID)
    binary.BigEndian.PutUint32(plaintext[4:8], c.SeqNum)
    plaintext[8] = c.Flags
    copy(plaintext[9:], c.Payload)

    // Nonce: sess_id(4) + seq_num(4) + random(4) = 12 bytes
    nonce := make([]byte, NonceSize)
    binary.BigEndian.PutUint32(nonce[0:4], c.SessionID)
    binary.BigEndian.PutUint32(nonce[4:8], c.SeqNum)
    rand.Read(nonce[8:12])

    // AAD = sess_id bytes (prevents cross-session replay)
    aad := nonce[0:4]

    ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

    // Output: nonce(12) + ciphertext_with_tag
    out := make([]byte, NonceSize+len(ciphertext))
    copy(out[:NonceSize], nonce)
    copy(out[NonceSize:], ciphertext)
    return out, nil
}

func DecryptChunk(data, key []byte) (*Chunk, error) {
    if len(data) < NonceSize+HeaderSize+TagSize {
        return nil, errors.New("chunk too short")
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := data[:NonceSize]
    ciphertext := data[NonceSize:]
    aad := nonce[0:4] // sess_id

    plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
    if err != nil {
        return nil, err
    }

    if len(plaintext) < HeaderSize {
        return nil, errors.New("plaintext too short")
    }

    return &Chunk{
        SessionID: binary.BigEndian.Uint32(plaintext[0:4]),
        SeqNum:    binary.BigEndian.Uint32(plaintext[4:8]),
        Flags:     plaintext[8],
        Payload:   plaintext[HeaderSize:],
    }, nil
}
```

- [ ] **Step 4: Run tests — should pass**

```bash
cd shadowlink && go test ./core/ -run TestChunk -v
```

- [ ] **Step 5: Add benchmark test**

```go
func BenchmarkChunkEncrypt(b *testing.B) {
    key := make([]byte, 32)
    rand.Read(key)
    chunk := &Chunk{SessionID: 1, SeqNum: 1, Flags: FlagData, Payload: make([]byte, 9000)}
    rand.Read(chunk.Payload)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        chunk.SeqNum = uint32(i)
        chunk.Encrypt(key)
    }
}
```

- [ ] **Step 6: Run benchmark**

```bash
cd shadowlink && go test ./core/ -bench=BenchmarkChunk -benchmem
```
Expected: >100K ops/sec on modern CPU (AES-NI).

- [ ] **Step 7: Commit**

```bash
git add shadowlink/core/chunk.go shadowlink/core/chunk_test.go
git commit -m "feat(shadowlink): unified chunk format — encrypt/decrypt with AES-256-GCM"
```

---

### Task 4: Session state — sliding window, seq tracking, timeout

**Files:**
- Create: `shadowlink/core/session.go`
- Create: `shadowlink/core/session_test.go`

**What this file does:** Server-side session management. Each client session tracks: session_id, encryption keys, seq_num counters (send/recv), a sliding window (size 256) for reordering chunks, creation time, last activity time. Sessions expire after 5 minutes of inactivity.

- [ ] **Step 1: Write tests for session creation and chunk acceptance**

```go
func TestSessionAcceptsInOrderChunks(t *testing.T) {
    s := NewSession(1, make([]byte, 32), make([]byte, 32))
    assert.True(t, s.AcceptSeqNum(0))
    assert.True(t, s.AcceptSeqNum(1))
    assert.True(t, s.AcceptSeqNum(2))
}

func TestSessionRejectsReplay(t *testing.T) {
    s := NewSession(1, make([]byte, 32), make([]byte, 32))
    s.AcceptSeqNum(5)
    assert.False(t, s.AcceptSeqNum(5), "replay must be rejected")
}

func TestSessionAcceptsOutOfOrder(t *testing.T) {
    s := NewSession(1, make([]byte, 32), make([]byte, 32))
    s.AcceptSeqNum(0)
    assert.True(t, s.AcceptSeqNum(3)) // skip 1,2
    assert.True(t, s.AcceptSeqNum(1)) // late arrival
    assert.True(t, s.AcceptSeqNum(2)) // late arrival
}

func TestSessionSlidingWindowLimit(t *testing.T) {
    s := NewSession(1, make([]byte, 32), make([]byte, 32))
    s.AcceptSeqNum(300)
    assert.False(t, s.AcceptSeqNum(0), "too old — outside window of 256")
}

func TestSessionExpiry(t *testing.T) {
    s := NewSession(1, make([]byte, 32), make([]byte, 32))
    s.lastActivity = time.Now().Add(-6 * time.Minute)
    assert.True(t, s.IsExpired(5*time.Minute))
}
```

- [ ] **Step 2: Run tests — fail**
- [ ] **Step 3: Implement Session + sliding window**

```go
// session.go
package core

import (
    "sync"
    "time"
)

const WindowSize = 256

type Session struct {
    ID           uint32
    SendKey      []byte
    RecvKey      []byte
    sendSeq      uint32
    recvHighest  uint32
    recvBitmap   [WindowSize / 64]uint64 // bitmap for sliding window
    lastActivity time.Time
    CreatedAt    time.Time
    mu           sync.Mutex
}

func NewSession(id uint32, sendKey, recvKey []byte) *Session {
    return &Session{
        ID:           id,
        SendKey:      sendKey,
        RecvKey:      recvKey,
        lastActivity: time.Now(),
        CreatedAt:    time.Now(),
    }
}

func (s *Session) NextSeqNum() uint32 {
    s.mu.Lock()
    defer s.mu.Unlock()
    seq := s.sendSeq
    s.sendSeq++
    return seq
}

func (s *Session) AcceptSeqNum(seq uint32) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.lastActivity = time.Now()

    if seq > s.recvHighest {
        // Advance window
        shift := seq - s.recvHighest
        if shift >= WindowSize {
            // Reset bitmap
            for i := range s.recvBitmap {
                s.recvBitmap[i] = 0
            }
        } else {
            s.shiftBitmap(shift)
        }
        s.recvHighest = seq
        s.setBit(0) // current position
        return true
    }

    // Check if within window
    diff := s.recvHighest - seq
    if diff >= WindowSize {
        return false // too old
    }

    // Check bitmap for replay
    if s.getBit(diff) {
        return false // already seen
    }
    s.setBit(diff)
    return true
}

func (s *Session) IsExpired(timeout time.Duration) bool {
    s.mu.Lock()
    defer s.mu.Unlock()
    return time.Since(s.lastActivity) > timeout
}

func (s *Session) shiftBitmap(n uint32) {
    if n == 0 {
        return
    }
    wordShift := n / 64
    bitShift := n % 64

    // Shift by whole words first
    if wordShift > 0 {
        for i := uint32(len(s.recvBitmap)) - 1; i < uint32(len(s.recvBitmap)); i-- {
            if i >= wordShift {
                s.recvBitmap[i] = s.recvBitmap[i-wordShift]
            } else {
                s.recvBitmap[i] = 0
            }
        }
    }

    // Then shift remaining bits within words
    if bitShift > 0 {
        for i := len(s.recvBitmap) - 1; i >= 0; i-- {
            s.recvBitmap[i] >>= bitShift
            if i > 0 {
                s.recvBitmap[i] |= s.recvBitmap[i-1] << (64 - bitShift)
            }
        }
    }
}

func (s *Session) setBit(pos uint32) {
    word := pos / 64
    bit := pos % 64
    if word < uint32(len(s.recvBitmap)) {
        s.recvBitmap[word] |= 1 << bit
    }
}

func (s *Session) getBit(pos uint32) bool {
    word := pos / 64
    bit := pos % 64
    if word >= uint32(len(s.recvBitmap)) {
        return false
    }
    return s.recvBitmap[word]&(1<<bit) != 0
}
```

- [ ] **Step 4: Run tests — should pass**

```bash
cd shadowlink && go test ./core/ -run TestSession -v
```

- [ ] **Step 5: Add SessionManager (stores sessions by ID, handles cleanup)**

```go
type SessionManager struct {
    sessions map[uint32]*Session
    mu       sync.RWMutex
    timeout  time.Duration
}

func NewSessionManager(timeout time.Duration) *SessionManager { ... }
func (sm *SessionManager) Create(sendKey, recvKey []byte) *Session { ... }
func (sm *SessionManager) Get(id uint32) (*Session, bool) { ... }
func (sm *SessionManager) Cleanup() int { ... }  // remove expired, return count
func (sm *SessionManager) Count() int { ... }
```

- [ ] **Step 6: Test SessionManager cleanup**
- [ ] **Step 7: Run all tests**

```bash
cd shadowlink && go test ./core/ -v -count=1
```

- [ ] **Step 8: Commit**

```bash
git add shadowlink/core/session.go shadowlink/core/session_test.go
git commit -m "feat(shadowlink): session management — sliding window, expiry, cleanup"
```

---

## Chunk 2: Browser Skin — HTTP Masquerade

### Task 5: HTTP request/response builder — JSON wrapping, base64, URL rotation

**Files:**
- Create: `shadowlink/skins/browser/request.go`
- Create: `shadowlink/skins/browser/request_test.go`
- Create: `shadowlink/skins/browser/urls.go`

**What this file does:** Wraps encrypted chunks into HTTP requests that look like a typical REST API. Payload is base64-encoded inside JSON. Session token disguised as JWT-like Bearer token. URL rotation from server-provided pool. Cover traffic generation (10% of requests are heartbeat-like JSON without base64 payload, per spec section 4).

- [ ] **Step 1: Write test for request building**

```go
func TestBuildUploadRequest(t *testing.T) {
    encryptedChunk := []byte("encrypted-data-here")
    sessionToken := []byte("session-token-32bytes-padded!!")
    seqNum := uint32(42)

    req, err := BuildUploadRequest("https://example.com", encryptedChunk, sessionToken, seqNum)
    require.NoError(t, err)
    assert.Equal(t, "POST", req.Method)
    assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
    assert.Contains(t, req.Header.Get("Authorization"), "Bearer ")
    assert.NotEmpty(t, req.Header.Get("X-Request-ID"))
    assert.Contains(t, req.Header.Get("User-Agent"), "Mozilla")
    assert.Equal(t, "close", req.Header.Get("Connection"))

    // Body should be valid JSON with base64 payload
    body, _ := io.ReadAll(req.Body)
    assert.True(t, json.Valid(body))
    assert.Contains(t, string(body), "data")
}

func TestParseDownloadResponse(t *testing.T) {
    jsonBody := `{"status":"ok","results":[{"id":"abc","payload":"aGVsbG8="}]}`
    payload, seqNum, err := ParseDownloadResponse([]byte(jsonBody))
    require.NoError(t, err)
    assert.NotEmpty(t, payload)
}
```

- [ ] **Step 2: Run — fail**
- [ ] **Step 3: Implement request builder**
- [ ] **Step 4: Run — pass**
- [ ] **Step 5: Write URL rotation tests**

```go
func TestURLPoolRotation(t *testing.T) {
    pool := NewURLPool()
    seen := map[string]bool{}
    for i := 0; i < 50; i++ {
        u := pool.NextUploadPath()
        seen[u] = true
    }
    assert.Greater(t, len(seen), 1, "should rotate between multiple URLs")
}
```

- [ ] **Step 6: Implement URL pool**
- [ ] **Step 7: Run all browser tests**

```bash
cd shadowlink && go test ./skins/browser/ -v
```

- [ ] **Step 8: Commit**

```bash
git add shadowlink/skins/browser/
git commit -m "feat(shadowlink): browser skin — HTTP request builder, JSON wrapping, URL rotation"
```

---

### Task 6: Behavior shaping — timing jitter, cover traffic

**Files:**
- Create: `shadowlink/skins/browser/shaping.go`
- Create: `shadowlink/skins/browser/shaping_test.go`

**What this file does:** Controls timing between requests (jitter, not fixed intervals), generates cover traffic (heartbeat-like JSON without VPN payload — 10% of requests), controls packet sizes to match bimodal HTTP distribution. Per spec section 4: Behavior Shaping Engine.

- [ ] **Step 1: Write test for timing jitter**

```go
func TestTimingJitterNotUniform(t *testing.T) {
    shaper := NewShaper(ShaperConfig{})
    delays := make([]time.Duration, 100)
    for i := range delays {
        delays[i] = shaper.NextDelay()
    }
    // Check not all the same
    unique := map[time.Duration]bool{}
    for _, d := range delays {
        unique[d] = true
    }
    assert.Greater(t, len(unique), 10, "delays should vary")
}

func TestCoverTrafficRatio(t *testing.T) {
    shaper := NewShaper(ShaperConfig{CoverTrafficRatio: 0.10})
    cover := 0
    total := 1000
    for i := 0; i < total; i++ {
        if shaper.ShouldSendCoverTraffic() {
            cover++
        }
    }
    // ~10% ± 5%
    assert.InDelta(t, 100, cover, 50)
}
```

- [ ] **Step 2: Run — fail**
- [ ] **Step 3: Implement Shaper**
- [ ] **Step 4: Run — pass**
- [ ] **Step 5: Commit**

```bash
git add shadowlink/skins/browser/shaping.go shadowlink/skins/browser/shaping_test.go
git commit -m "feat(shadowlink): behavior shaping — timing jitter, cover traffic"
```

---

### Task 4b: Handshake protocol — ClientHello/ServerHello

**Files:**
- Create: `shadowlink/core/handshake.go`
- Create: `shadowlink/core/handshake_test.go`

**What this file does:** Implements the 4-step handshake from spec section 3. ClientHello carries X25519 ephemeral pubkey + encrypted client_id (NaCl Box). ServerHello carries server ephemeral pubkey + encrypted session_token. In Browser Skin, these are embedded in the first HTTP request/response JSON bodies (not in TLS extensions for Phase 1 — TLS extension embedding is a Phase 1b optimization). Both sides derive SessionKeys via HKDF after exchange.

- [ ] **Step 1: Write test — full handshake roundtrip**

```go
func TestHandshakeRoundtrip(t *testing.T) {
    serverStatic, _ := GenerateKeyPair()
    clientID := []byte("test-client")

    // Client side
    clientHello, clientState, err := NewClientHello(clientID, serverStatic.Public)
    require.NoError(t, err)
    assert.NotEmpty(t, clientHello.EphemeralPub)
    assert.NotEmpty(t, clientHello.EncryptedClientID)

    // Server side
    serverHello, serverSession, err := HandleClientHello(clientHello, serverStatic)
    require.NoError(t, err)
    assert.NotEmpty(t, serverHello.EphemeralPub)
    assert.NotEmpty(t, serverHello.EncryptedSessionToken)
    assert.NotNil(t, serverSession)

    // Client completes
    clientSession, err := CompleteHandshake(clientState, serverHello)
    require.NoError(t, err)

    // Both sides should derive same keys
    assert.Equal(t, clientSession.SendKey, serverSession.RecvKey)
    assert.Equal(t, clientSession.RecvKey, serverSession.SendKey)
}

func TestHandshakeWrongServerKey(t *testing.T) {
    serverStatic, _ := GenerateKeyPair()
    wrongServer, _ := GenerateKeyPair()
    clientID := []byte("test-client")

    clientHello, _, _ := NewClientHello(clientID, wrongServer.Public)
    // Server with different key can't decrypt client_id
    _, _, err := HandleClientHello(clientHello, serverStatic)
    assert.Error(t, err)
}
```

- [ ] **Step 2: Run — fail**
- [ ] **Step 3: Implement ClientHello/ServerHello structs and functions**

```go
// handshake.go
type ClientHello struct {
    EphemeralPub      []byte // 32 bytes X25519
    EncryptedClientID []byte // NaCl Box encrypted
}

type ServerHello struct {
    EphemeralPub          []byte // 32 bytes X25519
    EncryptedSessionToken []byte // encrypted with derived key
    MaxConnsPerClient     uint8  // server-advertised limit
    ChunkSize             uint16 // server-advertised chunk size
}

type HandshakeClientState struct {
    ephemeral *KeyPair
    clientID  []byte
    serverPub []byte // server static public key
}

func NewClientHello(clientID, serverStaticPub []byte) (*ClientHello, *HandshakeClientState, error) { ... }
func HandleClientHello(hello *ClientHello, serverStatic *KeyPair) (*ServerHello, *Session, error) { ... }
func CompleteHandshake(state *HandshakeClientState, hello *ServerHello) (*Session, error) { ... }
```

- [ ] **Step 4: Run tests — pass**
- [ ] **Step 5: Commit**

```bash
git add shadowlink/core/handshake.go shadowlink/core/handshake_test.go
git commit -m "feat(shadowlink): handshake protocol — ClientHello/ServerHello with ECDH key exchange"
```

---

### Task 4c: Key rotation — in-band rekeying

**Files:**
- Modify: `shadowlink/core/session.go`
- Create: `shadowlink/core/rekey_test.go`

**What this file does:** Implements hourly key rotation per spec section 3. Client sends control chunk (flags=0x06) with new ephemeral pubkey. Server responds with its new pubkey. Both derive new keys. Old keys kept 10 seconds for in-flight chunks. Tested with "1 hour session" stability requirement.

- [ ] **Step 1: Write test for rekeying**

```go
func TestSessionRekey(t *testing.T) {
    s := NewSession(1, make([]byte, 32), make([]byte, 32))
    oldSendKey := make([]byte, 32)
    copy(oldSendKey, s.SendKey)

    newSendKey := make([]byte, 32)
    newRecvKey := make([]byte, 32)
    rand.Read(newSendKey)
    rand.Read(newRecvKey)

    s.Rekey(newSendKey, newRecvKey)
    assert.NotEqual(t, oldSendKey, s.SendKey)
    assert.Equal(t, newSendKey, s.SendKey)
    // Old key should still be accessible briefly
    assert.NotNil(t, s.OldRecvKey())
}

func TestSessionOldKeyExpiresAfter10Seconds(t *testing.T) {
    s := NewSession(1, make([]byte, 32), make([]byte, 32))
    s.Rekey(make([]byte, 32), make([]byte, 32))
    s.oldKeyExpiry = time.Now().Add(-11 * time.Second)
    assert.Nil(t, s.OldRecvKey(), "old key should be nil after 10s")
}
```

- [ ] **Step 2: Implement Rekey() and OldRecvKey() on Session**
- [ ] **Step 3: Add RekeyNeeded() check (returns true if session older than 1 hour since last rekey)**
- [ ] **Step 4: Run tests — pass**
- [ ] **Step 5: Commit**

```bash
git add shadowlink/core/session.go shadowlink/core/rekey_test.go
git commit -m "feat(shadowlink): key rotation — hourly rekeying with 10s old-key grace period"
```

---

## Chunk 2b: TLS Fingerprinting

### Task 6b: TLS fingerprint rotation — JA3/JA4 defense

**Files:**
- Create: `shadowlink/skins/browser/fingerprint.go`
- Create: `shadowlink/skins/browser/fingerprint_test.go`

**What this file does:** Customizes TLS ClientHello to match real browser fingerprints (Chrome, Safari, Firefox). Per spec section 4: GREASE extensions, cipher suite order matching Chrome, extension order shuffling, fingerprint rotation per connection. Uses Go `crypto/tls` with custom config — NOT uTLS (we control our own implementation).

- [ ] **Step 1: Write test — TLS config produces Chrome-like cipher suites**

```go
func TestChromeFingerprint(t *testing.T) {
    fp := NewFingerprint(ProfileChrome)
    tlsConfig := fp.TLSConfig("example.com")
    assert.Contains(t, tlsConfig.CipherSuites, tls.TLS_AES_128_GCM_SHA256)
    assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion)
    assert.NotEmpty(t, tlsConfig.ServerName)
}

func TestFingerprintRotation(t *testing.T) {
    pool := NewFingerprintPool()
    seen := map[string]bool{}
    for i := 0; i < 20; i++ {
        fp := pool.Next()
        seen[fp.Name()] = true
    }
    assert.Greater(t, len(seen), 1, "should rotate between profiles")
}
```

- [ ] **Step 2: Implement FingerprintPool with Chrome/Safari/Firefox profiles**

Each profile sets: CipherSuites order, CurvePreferences, supported TLS versions, ALPN protocols. Rotation is round-robin across profiles.

- [ ] **Step 3: Write test — each connection from pool gets different TLS config**
- [ ] **Step 4: Run tests — pass**
- [ ] **Step 5: Commit**

```bash
git add shadowlink/skins/browser/fingerprint.go shadowlink/skins/browser/fingerprint_test.go
git commit -m "feat(shadowlink): TLS fingerprint rotation — Chrome/Safari/Firefox profiles"
```

---

## Chunk 2c: Heartbeat + Freeze Recovery

### Task 6c: Heartbeat and freeze recovery

**Files:**
- Create: `shadowlink/client/heartbeat.go`
- Create: `shadowlink/client/heartbeat_test.go`

**What this file does:** Per spec section 4. Client sends keepalive chunks (flags=0x04) every 3-7 seconds (randomized jitter). If 3 consecutive heartbeats get no response, transport is considered dead → triggers fallback. Server responds to keepalive with ack.

- [ ] **Step 1: Write test — heartbeat interval has jitter**

```go
func TestHeartbeatJitter(t *testing.T) {
    hb := NewHeartbeat(HeartbeatConfig{MinInterval: 3 * time.Second, MaxInterval: 7 * time.Second})
    intervals := make([]time.Duration, 50)
    for i := range intervals {
        intervals[i] = hb.NextInterval()
    }
    unique := map[time.Duration]bool{}
    for _, d := range intervals {
        unique[d] = true
        assert.GreaterOrEqual(t, d, 3*time.Second)
        assert.LessOrEqual(t, d, 7*time.Second)
    }
    assert.Greater(t, len(unique), 3, "intervals should vary")
}

func TestHeartbeatDeadDetection(t *testing.T) {
    hb := NewHeartbeat(HeartbeatConfig{MaxMissed: 3})
    hb.RecordMiss()
    hb.RecordMiss()
    assert.False(t, hb.IsDead())
    hb.RecordMiss()
    assert.True(t, hb.IsDead())
}

func TestHeartbeatResetOnSuccess(t *testing.T) {
    hb := NewHeartbeat(HeartbeatConfig{MaxMissed: 3})
    hb.RecordMiss()
    hb.RecordMiss()
    hb.RecordSuccess()
    assert.False(t, hb.IsDead())
}
```

- [ ] **Step 2: Implement Heartbeat struct**
- [ ] **Step 3: Run tests — pass**
- [ ] **Step 4: Commit**

```bash
git add shadowlink/client/heartbeat.go shadowlink/client/heartbeat_test.go
git commit -m "feat(shadowlink): heartbeat with jitter + freeze detection"
```

---

## Chunk 3: Server

### Task 7: Server config + decoy site handler

**Files:**
- Create: `shadowlink/server/config.go`
- Create: `shadowlink/server/decoy.go`
- Create: `shadowlink/server/decoy_test.go`

**What this file does:** Server configuration (listen addr, TLS cert paths, static key, decoy site path, max clients, chunk size). Decoy handler serves static files for unauthenticated requests — this is the "real website" that TSPU active probes see.

- [ ] **Step 1: Write config struct**
- [ ] **Step 2: Write test for decoy handler**

```go
func TestDecoyHandlerServesHTML(t *testing.T) {
    tmpDir := t.TempDir()
    os.WriteFile(filepath.Join(tmpDir, "index.html"), []byte("<html>Hello</html>"), 0644)

    handler := NewDecoyHandler(tmpDir)
    req := httptest.NewRequest("GET", "/", nil)
    w := httptest.NewRecorder()
    handler.ServeHTTP(w, req)

    assert.Equal(t, 200, w.Code)
    assert.Contains(t, w.Body.String(), "Hello")
    assert.Contains(t, w.Header().Get("Content-Type"), "text/html")
}
```

- [ ] **Step 3: Implement**
- [ ] **Step 4: Run — pass**
- [ ] **Step 5: Commit**

---

### Task 8: ShadowLink chunk handler (authenticated requests)

**Files:**
- Create: `shadowlink/server/handler.go`
- Create: `shadowlink/server/handler_test.go`

**What this file does:** Handles authenticated ShadowLink requests: extracts encrypted chunk from JSON body, decrypts, validates session, processes data (or creates session on first contact), builds encrypted response chunk, wraps in JSON.

- [ ] **Step 1: Write test — unauthenticated request falls through to decoy**
- [ ] **Step 2: Write test — valid handshake creates session**
- [ ] **Step 3: Write test — valid data chunk is accepted and echoed**
- [ ] **Step 4: Implement handler with auth detection logic**
- [ ] **Step 5: Run tests**
- [ ] **Step 6: Commit**

---

### Task 9: Server binary + TLS

**Files:**
- Create: `shadowlink/cmd/shadowlink-server/main.go`
- Create: `shadowlink/server/server.go`

**What this file does:** Main server binary. Loads config, sets up TLS with Let's Encrypt cert (or self-signed for testing), routes: auth check → ShadowLink handler or decoy site. Periodic session cleanup. Graceful shutdown.

- [ ] **Step 1: Write server.go — Start/Stop, routing logic**
- [ ] **Step 2: Write main.go — CLI flags, config loading**
- [ ] **Step 3: Write server_test.go — integration: connect, handshake, transfer 1 chunk**
- [ ] **Step 4: Verify build**

```bash
cd shadowlink && go build ./cmd/shadowlink-server/
```

- [ ] **Step 5: Commit**

---

## Chunk 4: Client + Connection Pool

### Task 10: Connection pool manager

**Files:**
- Create: `shadowlink/core/pool.go`
- Create: `shadowlink/core/pool_test.go`

**What this file does:** Adaptive connection pool per spec section 5. Manages N concurrent HTTP/1.1+TLS connections to server. Each connection sends one request-response (one chunk), then closes. Preopen pipeline: 2 connections established ahead of time. Adapts pool size based on throughput.

- [ ] **Step 1: Write test — pool opens N connections**
- [ ] **Step 2: Write test — pool cycles connections (open, use, close, reopen)**
- [ ] **Step 3: Write test — preopen: next connection ready before needed**
- [ ] **Step 4: Implement pool**
- [ ] **Step 5: Run tests**
- [ ] **Step 6: Commit**

---

### Task 11: Direct transport

**Files:**
- Create: `shadowlink/client/transport.go`
- Create: `shadowlink/client/transport_cdn.go`
- Create: `shadowlink/client/transport_test.go`

**What this file does:** Transport interface with two implementations. Direct: HTTP/1.1+TLS 1.3 to server IP. CDN: same but target is Cloudflare domain (different TLS SNI, same JSON format). Both use connection pool from Task 10.

- [ ] **Step 1: Define Transport interface**

```go
type Transport interface {
    SendChunk(ctx context.Context, data []byte) ([]byte, error)
    Close() error
    Name() string
}
```

- [ ] **Step 2: Implement DirectTransport**
- [ ] **Step 3: Implement CDNTransport (differences: target URL, TLS config)**
- [ ] **Step 4: Test against test server from Task 9**
- [ ] **Step 5: Commit**

---

### Task 12: Client library — connect, handshake, tunnel

**Files:**
- Create: `shadowlink/client/client.go`
- Create: `shadowlink/client/client_test.go`

**What this file does:** Main client API. `Connect(serverAddr, serverPubKey, clientID)` performs handshake and returns a tunnel. Tunnel provides `Read()/Write()` implementing `io.ReadWriter`. Uses connection pool internally. Handles session token, seq_num counting, chunk encryption/decryption.

- [ ] **Step 1: Write test — client connects to server, sends data, receives data**
- [ ] **Step 2: Implement Client.Connect() — handshake flow**
- [ ] **Step 3: Implement tunnel Read/Write — chunk encrypt, send via pool, decrypt**
- [ ] **Step 4: Integration test with real server**

```bash
cd shadowlink && go test ./client/ -v -count=1
```

- [ ] **Step 5: Commit**

---

## Chunk 5: Probe Engine + CLI

### Task 13: Probe Engine

**Files:**
- Create: `shadowlink/client/probe.go`
- Create: `shadowlink/client/probe_test.go`

**What this file does:** Per spec section 8. Parallel probes (TCP to server, HTTPS to CF domain, HTTPS to ya.ru) with 3-second timeout. Classifies network as OPEN/DPI_BLOCK/WHITELIST/OFFLINE. Selects transport. Remembers last working transport for warm start.

- [ ] **Step 1: Write test — mock probes, verify classification logic**

```go
func TestClassifyOpen(t *testing.T) {
    result := Classify(ProbeResults{DirectOK: true, CDNOK: true, RuOK: true})
    assert.Equal(t, NetworkOpen, result)
}

func TestClassifyDPIBlock(t *testing.T) {
    result := Classify(ProbeResults{DirectOK: false, CDNOK: true, RuOK: true})
    assert.Equal(t, NetworkDPIBlock, result)
}

func TestClassifyWhitelist(t *testing.T) {
    result := Classify(ProbeResults{DirectOK: false, CDNOK: false, RuOK: true})
    assert.Equal(t, NetworkWhitelist, result)
}

func TestClassifyOffline(t *testing.T) {
    result := Classify(ProbeResults{DirectOK: false, CDNOK: false, RuOK: false})
    assert.Equal(t, NetworkOffline, result)
}
```

- [ ] **Step 2: Implement Classify**
- [ ] **Step 3: Implement ProbeEngine.Run() — parallel probes with timeout**
- [ ] **Step 4: Implement warm start (remember last transport)**
- [ ] **Step 5: Run tests**
- [ ] **Step 6: Commit**

---

### Task 14: CLI client (SOCKS5 proxy for testing)

**Files:**
- Create: `shadowlink/cmd/shadowlink-client/main.go`

**What this file does:** CLI tool for testing. Accepts server address, server public key, client ID. Runs Probe Engine, connects via best transport, opens local SOCKS5 proxy (default 127.0.0.1:1080). All traffic through SOCKS5 goes through ShadowLink tunnel.

- [ ] **Step 1: Write main.go with CLI flags**
- [ ] **Step 2: Integrate Probe Engine + Client + SOCKS5 listener**
- [ ] **Step 3: Build and test manually**

```bash
cd shadowlink && go build ./cmd/shadowlink-client/
# Terminal 1: start server
./shadowlink-server -listen :8443 -cert cert.pem -key key.pem -decoy ./decoy-site/
# Terminal 2: start client
./shadowlink-client -server 127.0.0.1:8443 -pubkey <server_pub> -socks 127.0.0.1:1080
# Terminal 3: test
curl --socks5 127.0.0.1:1080 https://ifconfig.me
```

- [ ] **Step 4: Commit**

---

## Chunk 6: DPI Emulator + Integration Tests

### Task 15: DPI Emulator

**Files:**
- Create: `shadowlink/testutil/dpi_emulator.go`

**What this file does:** TCP proxy that sits between client and server. Configurable behaviors: freeze connection after N bytes (emulate 16KB threshold), drop connections matching certain patterns, log all traffic for analysis. Used in automated tests.

- [ ] **Step 1: Implement TCPProxy with configurable byte limit**
- [ ] **Step 2: Test: proxy with 16KB limit → ShadowLink still works (multi-conn)**
- [ ] **Step 3: Test: proxy with 8KB limit → adaptive chunk_size kicks in**
- [ ] **Step 4: Commit**

---

### Task 16: Traffic analyzer

**Files:**
- Create: `shadowlink/testutil/traffic_analyzer.go`

**What this file does:** Captures traffic passing through DPI emulator. Analyzes: payload entropy (should be ~6 bits/byte for base64), packet size distribution (should be bimodal), timing patterns (should have jitter), upload/download ratio. Reports pass/fail against spec targets.

- [ ] **Step 1: Implement entropy calculator**
- [ ] **Step 2: Implement size distribution analyzer**
- [ ] **Step 3: Implement timing pattern analyzer**
- [ ] **Step 4: Commit**

---

### Task 17: End-to-end integration tests

**Files:**
- Create: `shadowlink/testutil/integration_test.go`

**What this file does:** Spins up server + client + DPI emulator in-process. Tests full flow: handshake → data transfer → reconnect → CDN fallback. Validates all spec test cases from section 10, Level 1 (T1.1-T1.10) and Level 2 (T2.1-T2.17).

- [ ] **Step 1: T1.1 — Handshake completes**
- [ ] **Step 2: T1.2 — Transfer 1 MB through tunnel (scaled down from 1 GB for CI)**
- [ ] **Step 3: T1.3 — Multi-conn chunks reassemble correctly**
- [ ] **Step 4: T1.5 — Kill connection → auto-recovery**
- [ ] **Step 5: T1.8 — Unauthenticated request → decoy site**
- [ ] **Step 6: T2.4 — 16 KB threshold emulation → ShadowLink continues**
- [ ] **Step 7: T2.14 — curl without auth → decoy**
- [ ] **Step 8: T2.10 — Entropy analysis of 30 seconds of traffic**

```bash
cd shadowlink && go test ./testutil/ -v -timeout 120s
```

- [ ] **Step 9: Commit**

---

## Chunk 7: Server Metrics + Resource Management

### Task 18: Server metrics and backpressure

**Files:**
- Create: `shadowlink/server/metrics.go`
- Modify: `shadowlink/server/server.go`

**What this file does:** Per spec section 9. Track active_clients, active_connections, memory_usage_bytes, cpu_usage_percent, chunks_per_second, bytes_relayed_total. Backpressure: if RAM >80% → reduce max_conns_per_client, if >90% → reject new connections.

- [ ] **Step 1: Implement Metrics struct with atomic counters**
- [ ] **Step 2: Implement RAM/CPU sampling goroutine**
- [ ] **Step 3: Implement backpressure logic in handler**
- [ ] **Step 4: Test: simulate high load, verify 503 rejection**
- [ ] **Step 5: Commit**

---

## Summary

| Chunk | Tasks | Scope |
|---|---|---|
| 1. Foundation | 1-4, 4b, 4c | Go module, crypto, chunks, sessions, handshake, key rotation |
| 2. Browser Skin | 5-6 | HTTP masquerade, JSON wrapping, shaping |
| 2b. TLS Fingerprint | 6b | JA3/JA4 fingerprint rotation (Chrome/Safari/Firefox) |
| 2c. Heartbeat | 6c | Heartbeat with jitter, freeze detection |
| 3. Server | 7-9 | Config, decoy, handler, TLS server binary |
| 4. Client + Pool | 10-12 | Connection pool, transports (Direct + CDN), client library |
| 5. Probe + CLI | 13-14 | Network detection, SOCKS5 CLI client |
| 6. Testing | 15-17 | DPI emulator, traffic analyzer, integration tests |
| 7. Metrics | 18 | Server metrics, backpressure |

**Total: 22 tasks, ~9 chunks.**

**Dependencies:**
- Task 1 (go.mod) → standalone
- Task 2 (crypto) → depends on Task 1
- Tasks 3, 4 (chunks, sessions) → depend on Task 2, parallel to each other
- Task 4b (handshake) → depends on Tasks 2, 3, 4
- Task 4c (key rotation) → depends on Task 4
- Tasks 5, 6 (browser skin) → depend on Task 3 (chunk format)
- Task 6b (fingerprint) → standalone (only needs Go crypto/tls)
- Task 6c (heartbeat) → depends on Task 3 (chunk flags)
- Tasks 7-9 (server) → depend on Tasks 3, 4, 4b
- Tasks 10-12 (client) → depend on Tasks 7-9 (need server to test against), 6b, 6c
- Tasks 13-14 (probe, CLI) → depend on Tasks 10-12
- Tasks 15-17 (testing) → depend on everything

**Critical path:** 1 → 2 → 3 → 4 → 4b → 8 → 9 → 10 → 11 → 12 → 17

**Parallelizable:** Tasks 3+4 (after Task 2), Tasks 5+6+6b+6c (after Task 3), Tasks 15+16 (after Task 9)
