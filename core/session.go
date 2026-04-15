package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// WindowSize is the anti-replay sliding window size.
// Per-stream WS mode: 80+ concurrent goroutines share one session, each
// incrementing seq_num atomically. Server receives seq_nums out-of-order
// across different WS connections (seq 5 on WS_A, seq 3 on WS_B, seq 8 on WS_C).
// 16384 gives ample room for 200+ concurrent streams with CDN latency jitter.
const WindowSize = 16384

// Session tracks state for one client connection.
type Session struct {
	ID      uint32
	SendKey []byte
	RecvKey []byte

	sendSeq     uint32
	recvHighest uint32
	recvBitmap  [WindowSize / 64]uint64
	CreatedAt   time.Time

	// Cached AES-GCM ciphers (zero-alloc encrypt/decrypt)
	sendGCM    cipher.AEAD
	recvGCM    cipher.AEAD
	oldRecvGCM cipher.AEAD // grace period during rekey
	sendNonce  uint64      // counter-based nonce

	// Key rotation
	oldRecvKey   []byte
	oldKeyExpiry time.Time
	lastRekey    time.Time

	lastActivity time.Time
	mu           sync.Mutex
}

// newGCM creates an AES-GCM cipher from a key.
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	return gcm, nil
}

// NewSession creates a new session with the given keys.
// Does NOT initialize cached GCM ciphers — use SessionManager.Create() for that.
func NewSession(id uint32, sendKey, recvKey []byte) *Session {
	now := time.Now()
	return &Session{
		ID:           id,
		SendKey:      sendKey,
		RecvKey:      recvKey,
		lastActivity: now,
		CreatedAt:    now,
		lastRekey:    now,
	}
}

// NextSeqNum returns the next sequence number for sending.
func (s *Session) NextSeqNum() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.sendSeq
	s.sendSeq++
	return seq
}

// AcceptSeqNum checks whether a received seq_num should be accepted.
// Returns false for replays and too-old packets.
func (s *Session) AcceptSeqNum(seq uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = time.Now()

	if seq > s.recvHighest {
		shift := seq - s.recvHighest
		if shift >= WindowSize {
			for i := range s.recvBitmap {
				s.recvBitmap[i] = 0
			}
		} else {
			s.shiftBitmap(shift)
		}
		s.recvHighest = seq
		s.setBit(0)
		return true
	}

	diff := s.recvHighest - seq
	if diff >= WindowSize {
		return false
	}

	if s.getBit(diff) {
		return false
	}
	s.setBit(diff)
	return true
}

// IsExpired returns true if the session has been inactive longer than timeout.
func (s *Session) IsExpired(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastActivity) > timeout
}

// isExpiredAndDestroy atomically checks expiry and destroys if expired (TOCTOU fix).
func (s *Session) isExpiredAndDestroy(timeout time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.lastActivity) <= timeout {
		return false
	}
	// Expired — zero keys while still holding lock
	ZeroBytes(s.SendKey)
	ZeroBytes(s.RecvKey)
	if s.oldRecvKey != nil {
		ZeroBytes(s.oldRecvKey)
		s.oldRecvKey = nil
	}
	s.sendGCM = nil
	s.recvGCM = nil
	s.oldRecvGCM = nil
	return true
}

// Rekey replaces session keys, keeping the old recv key/GCM for a grace period.
func (s *Session) Rekey(newSendKey, newRecvKey []byte) error {
	newSendGCM, err := newGCM(newSendKey)
	if err != nil {
		return fmt.Errorf("rekey sendGCM: %w", err)
	}
	newRecvGCM, err := newGCM(newRecvKey)
	if err != nil {
		return fmt.Errorf("rekey recvGCM: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.oldRecvKey = s.RecvKey // keep ref for grace period
	s.oldRecvGCM = s.recvGCM
	s.oldKeyExpiry = time.Now().Add(10 * time.Second)
	s.SendKey = newSendKey
	s.RecvKey = newRecvKey
	s.sendGCM = newSendGCM
	s.recvGCM = newRecvGCM
	s.sendNonce = 0
	s.lastRekey = time.Now()
	return nil
}

// OldRecvKey returns the previous recv key if still within the 10s grace period.
func (s *Session) OldRecvKey() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.oldRecvKey == nil {
		return nil
	}
	if time.Now().After(s.oldKeyExpiry) {
		ZeroBytes(s.oldRecvKey) // securely zero expired key material
		s.oldRecvKey = nil
		s.oldRecvGCM = nil
		return nil
	}
	return s.oldRecvKey
}

// RekeyNeeded returns true if more than 1 hour has passed since last rekey,
// OR if seq_num is approaching overflow (> 2^31). (Audit H5 fix)
func (s *Session) RekeyNeeded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastRekey) > time.Hour || s.sendSeq > 0x80000000
}

// Keys returns copies of SendKey and RecvKey under lock (prevents use-after-destroy).
func (s *Session) Keys() (sendKey, recvKey []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sk := make([]byte, len(s.SendKey))
	rk := make([]byte, len(s.RecvKey))
	copy(sk, s.SendKey)
	copy(rk, s.RecvKey)
	return sk, rk
}

// sessionEncryptCounter is a debug counter for client-side throughput stats.
// Set via SetEncryptCounter so core/ stays independent of client/.
var sessionEncryptCounter func()
var sessionDecryptCounter func()
var sessionDecryptFailCounter func()

// SetStatsCallbacks lets the client package hook atomic counters into the
// session's encrypt/decrypt hot paths without pulling client into core.
// All callbacks are optional — nil is a no-op.
func SetStatsCallbacks(onEncrypt, onDecrypt, onDecryptFail func()) {
	sessionEncryptCounter = onEncrypt
	sessionDecryptCounter = onDecrypt
	sessionDecryptFailCounter = onDecryptFail
}

// EncryptChunk encrypts a chunk safely using cached GCM if available.
func (s *Session) EncryptChunk(chunk *Chunk) ([]byte, error) {
	s.mu.Lock()
	gcm := s.sendGCM
	nonce := s.sendNonce
	if gcm != nil {
		s.sendNonce++
	}
	s.mu.Unlock()

	if sessionEncryptCounter != nil {
		sessionEncryptCounter()
	}

	if gcm != nil {
		return chunk.EncryptWith(gcm, nonce)
	}

	// Fallback for sessions created via NewSession (no cached GCM)
	s.mu.Lock()
	key := make([]byte, len(s.SendKey))
	copy(key, s.SendKey)
	s.mu.Unlock()
	return chunk.Encrypt(key)
}

// DecryptChunkSafe decrypts a chunk safely using cached GCM if available.
func (s *Session) DecryptChunkSafe(data []byte) (*Chunk, error) {
	if sessionDecryptCounter != nil {
		sessionDecryptCounter()
	}

	s.mu.Lock()
	gcm := s.recvGCM
	oldGCM := s.oldRecvGCM
	var oldKey []byte
	if s.oldRecvKey != nil && time.Now().Before(s.oldKeyExpiry) {
		oldKey = make([]byte, len(s.oldRecvKey))
		copy(oldKey, s.oldRecvKey)
	}
	var key []byte
	if gcm == nil {
		key = make([]byte, len(s.RecvKey))
		copy(key, s.RecvKey)
	}
	s.mu.Unlock()

	// Try cached GCM first
	if gcm != nil {
		chunk, err := DecryptWith(data, gcm)
		if err == nil {
			s.mu.Lock()
			s.lastActivity = time.Now()
			s.mu.Unlock()
			return chunk, nil
		}
		// Try old GCM (grace period)
		if oldGCM != nil {
			chunk, err = DecryptWith(data, oldGCM)
			if err == nil {
				s.mu.Lock()
				s.lastActivity = time.Now()
				s.mu.Unlock()
				return chunk, nil
			}
		}
		// Try old key-based fallback (grace period, sender may not have cached GCM)
		if oldKey != nil {
			chunk, err = DecryptChunk(data, oldKey)
			if err == nil {
				s.mu.Lock()
				s.lastActivity = time.Now()
				s.mu.Unlock()
				return chunk, nil
			}
		}
		if sessionDecryptFailCounter != nil {
			sessionDecryptFailCounter()
		}
		return nil, fmt.Errorf("decrypt failed with cached GCM")
	}

	// Fallback: no cached GCM (NewSession-created sessions)
	chunk, err := DecryptChunk(data, key)
	if err != nil && oldKey != nil {
		chunk, err = DecryptChunk(data, oldKey)
	}
	if err == nil {
		s.mu.Lock()
		s.lastActivity = time.Now()
		s.mu.Unlock()
	}
	return chunk, err
}

// LastActivity returns the time of the last accepted packet.
func (s *Session) LastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastActivity
}

// HIGH-6 fix: use int loop variables to avoid uint32 underflow wrap-around.
// The old code used uint32 loop variable which wraps at 0 → 0xFFFFFFFF,
// causing incorrect bitmap state after sequence number jumps of 64+.
func (s *Session) shiftBitmap(n uint32) {
	if n == 0 {
		return
	}
	ws := int(n / 64)
	bitShift := n % 64
	bitmapLen := len(s.recvBitmap)

	if ws > 0 {
		for i := bitmapLen - 1; i >= 0; i-- {
			if i >= ws {
				s.recvBitmap[i] = s.recvBitmap[i-ws]
			} else {
				s.recvBitmap[i] = 0
			}
		}
	}

	if bitShift > 0 {
		for i := bitmapLen - 1; i >= 0; i-- {
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

// SessionManager stores and manages active sessions.
type SessionManager struct {
	sessions map[uint32]*Session
	mu       sync.RWMutex
	timeout  time.Duration
	nextID   atomic.Uint32
}

// NewSessionManager creates a session manager with the given expiry timeout.
func NewSessionManager(timeout time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[uint32]*Session),
		timeout:  timeout,
	}
	// Start with random ID to prevent prediction
	var buf [4]byte
	rand.Read(buf[:])
	sm.nextID.Store(binary.BigEndian.Uint32(buf[:]))
	return sm
}

// Create creates a new session with the given keys and cached GCM ciphers.
// Session ID 0 is reserved as handshake sentinel for UDP protocol.
func (sm *SessionManager) Create(sendKey, recvKey []byte) (*Session, error) {
	sendGCM, err := newGCM(sendKey)
	if err != nil {
		return nil, fmt.Errorf("Create sendGCM: %w", err)
	}
	recvGCM, err := newGCM(recvKey)
	if err != nil {
		return nil, fmt.Errorf("Create recvGCM: %w", err)
	}

	id := sm.nextID.Add(1)
	if id == 0 {
		id = sm.nextID.Add(1) // skip 0
	}
	s := NewSession(id, sendKey, recvKey)
	s.sendGCM = sendGCM
	s.recvGCM = recvGCM

	sm.mu.Lock()
	sm.sessions[id] = s
	sm.mu.Unlock()
	return s, nil
}

// Get retrieves a session by ID.
func (sm *SessionManager) Get(id uint32) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	s, ok := sm.sessions[id]
	return s, ok
}

// Remove deletes a session, zeroing key material first. (Audit H3 fix)
func (sm *SessionManager) Remove(id uint32) {
	sm.mu.Lock()
	if s, ok := sm.sessions[id]; ok {
		s.Destroy()
		delete(sm.sessions, id)
	}
	sm.mu.Unlock()
}

// Destroy securely zeroes all key material in the session.
func (s *Session) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	ZeroBytes(s.SendKey)
	ZeroBytes(s.RecvKey)
	if s.oldRecvKey != nil {
		ZeroBytes(s.oldRecvKey)
		s.oldRecvKey = nil
	}
	s.sendGCM = nil
	s.recvGCM = nil
	s.oldRecvGCM = nil
}

// Cleanup removes expired sessions and returns the count removed.
// C1 fix: IsExpired+Destroy is atomic under session lock to prevent TOCTOU race.
func (sm *SessionManager) Cleanup() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	count := 0
	for id, s := range sm.sessions {
		if s.isExpiredAndDestroy(sm.timeout) {
			delete(sm.sessions, id)
			count++
		}
	}
	return count
}

// Count returns the number of active sessions.
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// ForEach iterates over all sessions. Callback returns true to stop early.
func (sm *SessionManager) ForEach(fn func(*Session) bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	for _, s := range sm.sessions {
		if fn(s) {
			return
		}
	}
}
