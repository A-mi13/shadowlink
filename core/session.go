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

// sendEpoch binds an AES-GCM cipher with its dedicated nonce counter so they always
// move together during rekey. This is required to lift the EncryptChunk lock from the
// hot path (A1-M2 fix): if the GCM and the counter were stored as separate atomics,
// a thread could load the OLD gcm but then Add(1) on the NEW counter (post-rekey),
// reusing a nonce that was already consumed under the OLD key. Pinning them together
// means every Encrypt observes a consistent (gcm, counter) pair.
type sendEpoch struct {
	gcm   cipher.AEAD
	nonce atomic.Uint64
}

// Session tracks state for one client connection.
type Session struct {
	ID      uint32
	SendKey []byte
	RecvKey []byte

	// ProtoVersion is the wire-format version pinned after handshake.
	// 0 = legacy (Bearer header), 1 = body-prefix (2026-04 migration).
	// Set once in performHandshake after ServerHello._v is validated, then
	// treated as read-only for the session lifetime.
	ProtoVersion uint8

	sendSeq     uint32
	recvHighest uint32
	recvBitmap  [WindowSize / 64]uint64
	CreatedAt   time.Time

	// AttachedAt is the unix nanosecond timestamp marking the session as
	// "handshake-complete and ready for use by the owning client". 0 means
	// "newborn — Create() returned but the handshake response was not yet
	// flushed (panic-window, validation reject path, internal error)".
	//
	// History:
	//   - Plan §C10 M2 (May 2026 audit) introduced this field tied to WS
	//     first-frame attach. Cleanup at 30s let orphan tunnels from
	//     client-side WS upgrade failures be reaped fast.
	//   - 2026-05-18 revision: set at handshake response flush instead.
	//     The old semantic raced with the WS-upgrade rate-limit gate: a
	//     rejected upgrade left AttachedAt=0 even though the client had
	//     received a valid handshake response and could legitimately retry
	//     the WS upgrade. CleanupNewbornOrphans would then evict it after
	//     30s, dropping the client mid-conversation. Production metrics
	//     showed 351 orphan_session_cleaned events in a 5-min test, ~all
	//     of which were this race rather than actual client abandons.
	//
	// CleanupNewbornOrphans now evicts only sessions that aborted between
	// Create() and the handshake response flush. Sessions that successfully
	// handshook but later went idle (legitimate client abandon, including
	// failed WS upgrade) fall under SessionManager.Cleanup's idle timeout.
	//
	// Atomic so the cleanup loop can read it without taking s.mu (the
	// handshake path stores it under no lock either; pure CAS-style publish).
	AttachedAt atomic.Int64

	// Cached AES-GCM ciphers (zero-alloc encrypt/decrypt).
	// A1-M2: sendEpoch is held in an atomic.Pointer so EncryptChunk can be lock-free.
	// recvGCM/oldRecvGCM remain under mu — their swap path (Rekey) is the only writer.
	sendEpochPtr atomic.Pointer[sendEpoch]
	recvGCM      cipher.AEAD
	oldRecvGCM   cipher.AEAD // grace period during rekey

	// Key rotation
	oldRecvKey   []byte
	oldKeyExpiry time.Time
	lastRekey    time.Time

	lastActivity time.Time
	mu           sync.Mutex

	// MimicrySession holds per-session sticky distribution state for the
	// browser skin (NextPollLambda etc.). nil for sessions that did not pass
	// through the server-side handshake init point (e.g. unit tests using
	// NewSession directly). Set once at handshake completion; read-only after.
	// See core/mimicry_session.go for the contract. T2.4 (Phase 3 Plan A).
	MimicrySession *MimicrySession
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
	s.sendEpochPtr.Store(nil)
	s.recvGCM = nil
	s.oldRecvGCM = nil
	return true
}

// Rekey replaces session keys, keeping the old recv key/GCM for a grace period.
// A1-M2: send-side rekey swaps the entire (gcm, nonce-counter) pair atomically by
// pointing sendEpochPtr at a fresh sendEpoch with counter=0. Concurrent EncryptChunk
// callers either observe the OLD epoch (with its OLD counter) or the NEW epoch
// (with counter starting from 0) — never a mixed pair.
func (s *Session) Rekey(newSendKey, newRecvKey []byte) error {
	newSendGCM, err := newGCM(newSendKey)
	if err != nil {
		return fmt.Errorf("rekey sendGCM: %w", err)
	}
	newRecvGCM, err := newGCM(newRecvKey)
	if err != nil {
		return fmt.Errorf("rekey recvGCM: %w", err)
	}

	newSendEpoch := &sendEpoch{gcm: newSendGCM}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.oldRecvKey = s.RecvKey // keep ref for grace period
	s.oldRecvGCM = s.recvGCM
	s.oldKeyExpiry = time.Now().Add(10 * time.Second)
	s.SendKey = newSendKey
	s.RecvKey = newRecvKey
	s.sendEpochPtr.Store(newSendEpoch)
	s.recvGCM = newRecvGCM
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
// OR if seq_num is approaching overflow.
// A1-M5 fix: bumped threshold from 0x80000000 (~2^31) to 0xFF000000 (~2^32 - 16M safety margin).
// At normal traffic rates the time-based 1h trigger fires far earlier; the seq-num gate is a
// last-resort overflow protection. The previous 2^31 threshold gave up half the address space
// unnecessarily on long-lived idle-but-active sessions.
func (s *Session) RekeyNeeded() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return time.Since(s.lastRekey) > time.Hour || s.sendSeq > 0xFF000000
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

// statsCallbacks holds the optional encrypt/decrypt counter hooks installed
// by the client package. Bundled into a single struct so SetStatsCallbacks
// can publish all three pointers atomically — the previous design (three
// plain package-globals) raced with hot-path EncryptChunk/DecryptChunkSafe
// reads when run under -race (May 2026 audit, T1 M6 / Plan §C11.2).
type statsCallbacks struct {
	onEncrypt     func()
	onDecrypt     func()
	onDecryptFail func()
}

// sessionStatsCallbacks holds the live callbacks pointer. Loaded on every
// hot-path encrypt/decrypt; stored atomically by SetStatsCallbacks. nil
// pointer ⇒ no callbacks installed (initial state, equivalent to the
// previous "all three globals are nil" state).
var sessionStatsCallbacks atomic.Pointer[statsCallbacks]

// SetStatsCallbacks lets the client package hook atomic counters into the
// session's encrypt/decrypt hot paths without pulling client into core.
// All callbacks are optional — nil-fields are skipped on the hot path. The
// three callbacks are published atomically as one *statsCallbacks struct so
// concurrent EncryptChunk/DecryptChunkSafe readers always observe a fully
// populated set, never a torn intermediate where one slot has been updated
// and another has not. May 2026 audit T1 M6 / Plan §C11.2.
//
// Lifecycle: caller is expected to invoke this once at process init (see
// client/stats.go:140 — the only production caller). Live re-binding is
// supported (idempotent atomic.Store), but tests that overwrite during a
// run must understand that previously-set callbacks are dropped wholesale.
func SetStatsCallbacks(onEncrypt, onDecrypt, onDecryptFail func()) {
	sessionStatsCallbacks.Store(&statsCallbacks{
		onEncrypt:     onEncrypt,
		onDecrypt:     onDecrypt,
		onDecryptFail: onDecryptFail,
	})
}

// EncryptChunk encrypts a chunk safely using cached GCM if available.
// A1-M2: hot path is lock-free. The (gcm, nonce-counter) pair is loaded as a single
// atomic pointer to a sendEpoch — under WS multiplex, ~80 concurrent goroutines no longer
// serialize on s.mu just to advance the counter. Rekey() re-points sendEpochPtr to a
// fresh epoch with counter=0; concurrent encrypters observe a consistent (gcm, counter)
// pair with no nonce reuse risk.
func (s *Session) EncryptChunk(chunk *Chunk) ([]byte, error) {
	if cbs := sessionStatsCallbacks.Load(); cbs != nil && cbs.onEncrypt != nil {
		cbs.onEncrypt()
	}

	if ep := s.sendEpochPtr.Load(); ep != nil {
		// Atomic increment, post-decrement to get pre-add value.
		nonce := ep.nonce.Add(1) - 1
		return chunk.EncryptWith(ep.gcm, nonce)
	}

	// Fallback for sessions created via NewSession (no cached GCM).
	// Used by client-side handshake completion (CompleteHandshakeWithVersion) and
	// by tests. Falls through to legacy chunk.Encrypt with a per-call random nonce.
	s.mu.Lock()
	key := make([]byte, len(s.SendKey))
	copy(key, s.SendKey)
	s.mu.Unlock()
	return chunk.Encrypt(key)
}

// DecryptChunkSafe decrypts a chunk safely using cached GCM if available.
func (s *Session) DecryptChunkSafe(data []byte) (*Chunk, error) {
	if cbs := sessionStatsCallbacks.Load(); cbs != nil && cbs.onDecrypt != nil {
		cbs.onDecrypt()
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
		if cbs := sessionStatsCallbacks.Load(); cbs != nil && cbs.onDecryptFail != nil {
			cbs.onDecryptFail()
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
//
// Final audit 2026-05-03 T1 P3 fix: `rand.Read` errors are no longer silently
// dropped. On extremely degraded hosts (initramfs before urandom seed, broken
// CSPRNG, container init без entropy) the previous implementation left
// `nextID = 0`, so the first session got ID = 1 — defeating the random seed
// added precisely to make session IDs unpredictable. Failing fast at boot
// is preferable to silently weakening the ID space at runtime; the panic is
// only reachable on systems where the OS CSPRNG itself is broken, which is
// unrecoverable for any cryptographic operation downstream.
func NewSessionManager(timeout time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[uint32]*Session),
		timeout:  timeout,
	}
	// Start with random ID to prevent prediction
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// CSPRNG failure at boot — fail fast rather than seed nextID with zero.
		// All downstream crypto (X25519 keygen, AES-GCM nonces, NaCl Box nonces)
		// would also fail, so booting in this state serves no purpose.
		panic(fmt.Sprintf("ShadowLink: crypto/rand.Read failed during SessionManager init: %v", err))
	}
	sm.nextID.Store(binary.BigEndian.Uint32(buf[:]))
	return sm
}

// Create creates a new session with the given keys and cached GCM ciphers.
// Session ID 0 is reserved as handshake sentinel for UDP protocol.
//
// Plan §C11.3 (May 2026 audit, T1 M3): MimicrySession is populated BEFORE
// the session is published into sm.sessions, so every concurrent reader of
// session.MimicrySession (e.g. server/handler.go::buildResponse via the WS
// download stream) observes the field via the same happens-before edge that
// publishes the session itself. Initializing post-publish (the previous
// design) worked on x86 TSO but lacked an explicit ordering guarantee.
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
	s.sendEpochPtr.Store(&sendEpoch{gcm: sendGCM})
	s.recvGCM = recvGCM
	// §C11.3: assign before publish to give readers a clean happens-before edge.
	s.MimicrySession = NewMimicrySession()

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
	s.sendEpochPtr.Store(nil)
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

// CleanupNewbornOrphans evicts sessions that completed the handshake but never
// had a transport attach within `maxAge`. Plan §C10 M2 (May 2026 audit) — the
// legacy idle timeout (5 min default) is too coarse to evict orphan tunnels
// created when a client fails between handshake POST OK and WS upgrade success.
//
// Returns the slice of evicted session IDs so the caller (server.Handler)
// can reap the matching tunnels. Uses now() injected by the caller so tests
// can mock without sleeping.
//
// Sessions whose AttachedAt is non-zero (transport currently attached or
// previously attached) are skipped — they fall under the regular Cleanup()
// idle-timeout policy.
//
// P2-3 fix (final audit 2026-05-03): the previous implementation held
// sm.mu.Lock() (write lock) for the entire scan + per-session zero work.
// Under handshake-abuse DoS that fast-fills the orphan pool, the write
// lock starves all concurrent handshake/data-path operations for the
// full sweep duration. Two-phase replacement:
//
//	Phase 1 — RLock the manager and collect the IDs of evictable
//	  sessions. Read-only iteration; concurrent Get/Count/ForEach
//	  proceed without blocking; concurrent Create/Remove (which take
//	  the write lock) wait only the duration of the read scan.
//
//	Phase 2 — for every collected ID, take the write lock, re-check
//	  eligibility (a session may have transitioned to attached
//	  between phases — AttachedAt is atomic; or may have been removed
//	  by another path), zero key material, delete, release. Each
//	  write-lock window is bounded by a single map lookup + the
//	  per-session mu.Lock under it.
//
// Memory ordering: AttachedAt.Load() (acquire on atomic.Int64) pairs
// with the Store inside authenticateFirstFrame (release semantics
// guaranteed by sync/atomic). Phase 2 re-reads AttachedAt under
// sm.mu.Lock(); a session that attaches between Phase 1 and Phase 2
// is correctly skipped because the Phase 2 atomic Load observes any
// happens-before-edged Store from the WS attach goroutine. CreatedAt
// is set once in NewSession before publication into sm.sessions, so
// the write-lock-protected publish of the *Session pointer (Create
// at sm.sessions[id]=s) is the synchronizing edge for CreatedAt.
func (sm *SessionManager) CleanupNewbornOrphans(now time.Time, maxAge time.Duration) []uint32 {
	// Phase 1: collect candidates under read lock only.
	type candidate struct {
		id        uint32
		createdAt time.Time
	}
	var candidates []candidate
	sm.mu.RLock()
	if len(sm.sessions) > 0 {
		candidates = make([]candidate, 0, len(sm.sessions))
		for id, s := range sm.sessions {
			if s.AttachedAt.Load() != 0 {
				continue
			}
			if now.Sub(s.CreatedAt) <= maxAge {
				continue
			}
			candidates = append(candidates, candidate{id: id, createdAt: s.CreatedAt})
		}
	}
	sm.mu.RUnlock()

	if len(candidates) == 0 {
		return nil
	}

	// Phase 2: per-candidate write-lock window. Re-validate eligibility
	// because a session may have attached or been removed between phases.
	evicted := make([]uint32, 0, len(candidates))
	for _, c := range candidates {
		sm.mu.Lock()
		s, ok := sm.sessions[c.id]
		if !ok {
			// Removed by another path (Cleanup, Remove, Destroy).
			sm.mu.Unlock()
			continue
		}
		// Re-check eligibility — atomic Load gives acquire ordering.
		if s.AttachedAt.Load() != 0 || now.Sub(s.CreatedAt) <= maxAge {
			sm.mu.Unlock()
			continue
		}
		// Zero key material under the session lock (mirrors Destroy).
		s.mu.Lock()
		ZeroBytes(s.SendKey)
		ZeroBytes(s.RecvKey)
		if s.oldRecvKey != nil {
			ZeroBytes(s.oldRecvKey)
			s.oldRecvKey = nil
		}
		s.sendEpochPtr.Store(nil)
		s.recvGCM = nil
		s.oldRecvGCM = nil
		s.mu.Unlock()
		delete(sm.sessions, c.id)
		sm.mu.Unlock()
		evicted = append(evicted, c.id)
	}
	return evicted
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
