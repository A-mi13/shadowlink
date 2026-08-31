package core

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
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

	// windowResets counts AcceptSeqNum full-window resets (seq jumps >=
	// WindowSize). L5 (2026-06-11) observability — a persistently growing value
	// signals pathological seq growth / a buggy duplicate-heavy peer. Atomic so
	// the exported reader is lock-free; the increment in AcceptSeqNum already
	// runs under s.mu.
	windowResets atomic.Uint64

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

	// DetachedAt is the unix nanosecond timestamp at which this session's WS
	// transport last DETACHED (the slot's reader goroutine exited — TSPU
	// age-cut close 1006, io_timeout, peer_eof, or our own teardown). 0 means
	// "no transport has detached since the last attach" (currently attached, or
	// never attached).
	//
	// Server ghost-sweep (2026-06-01 pool-capacity-dip-fix): a session whose
	// transport died externally lingers in the manager until the coarse idle
	// timeout, accumulating ghost sessions (active_clients=18 after the client
	// disconnected) that drift the server toward its rate limit. The WS session
	// teardown stamps DetachedAt; CleanupDetachedGhosts reclaims a session that
	// has stayed detached longer than a SHORT grace — gated so a session a
	// stream is migrating onto (Bug#9 orphan window) is never evicted mid-RESUME.
	//
	// Cleared back to 0 by authenticateFirstFrame on a successful re-attach (a
	// pool reconnect re-adopting the same session) so a healthy reconnect is not
	// mistaken for a ghost. Atomic for the same lock-free read/publish reason as
	// AttachedAt.
	DetachedAt atomic.Int64

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

	// destroyed latches to true the first time key material is zeroed, on ANY
	// of the four teardown paths (Destroy, isExpiredAndDestroy,
	// CleanupNewbornOrphans, the detached-grace sweep). Once set, the crypto
	// entry points fail closed.
	//
	// H-11 (раунд 18): ZeroBytes зануляет байты НА МЕСТЕ, не меняя длину, поэтому
	// после зануления SendKey — это 32 нулевых байта, а не nil.
	// aes.NewCipher(32 нуля) успешно создаёт шифр, так что без этого флага
	// EncryptChunk уходил в fallback-ветку и шифровал под ПУБЛИЧНО ИЗВЕСТНЫМ
	// нулевым ключом, а DecryptChunkSafe симметрично ПРИНИМАЛ такие кадры.
	// Флаг атомарный, а не под mu: EncryptChunk намеренно lock-free на горячем
	// пути (A1-M2), и добавлять туда мьютекс нельзя.
	destroyed atomic.Bool

	// MigrateNonce is a 16-byte crypto/rand nonce stamped at session creation.
	// It is the per-device binding discriminator for Bug #9 stream-migration
	// proof-of-ownership (§4.1, F2): the stream secret is
	// HMAC(serverPerClientKey, clientID‖globalStreamID‖MigrateNonce). A second
	// device of the same clientID cannot read this nonce (it travels only inside
	// the encrypted CONNECT reply of the originating session), so it cannot
	// forge a proof for a stream it does not own. MUST be crypto/rand — NEVER
	// derived from session.ID (sequential, guessable). Read-only after creation.
	MigrateNonce [16]byte
}

// ErrSessionDestroyed is returned by every crypto entry point once the session's
// key material has been zeroed. Callers MUST treat it as terminal for the
// session: the peer's keys are gone, so no retry can succeed. Fail closed —
// never fall back to the zeroed key material (H-11, раунд 18).
var ErrSessionDestroyed = errors.New("session destroyed: key material zeroed")

// IsDestroyed reports whether key material has been zeroed on any teardown path.
func (s *Session) IsDestroyed() bool {
	return s.destroyed.Load()
}

// zeroKeyMaterialLocked zeroes all key material and latches the destroyed flag.
// Caller MUST hold s.mu.
//
// H-11 (раунд 18): этот блок существовал в ЧЕТЫРЁХ скопированных экземплярах
// (Destroy, isExpiredAndDestroy, CleanupNewbornOrphans, detached-grace sweep).
// Дублирование и было причиной, по которой дефект расползся: фикс только в
// Destroy() оставил бы три пути, на которых сессия остаётся «рабочей» с нулевым
// ключом. Единая точка гарантирует, что флаг ставится всегда.
func (s *Session) zeroKeyMaterialLocked() {
	ZeroBytes(s.SendKey)
	ZeroBytes(s.RecvKey)
	if s.oldRecvKey != nil {
		ZeroBytes(s.oldRecvKey)
		s.oldRecvKey = nil
	}
	s.sendEpochPtr.Store(nil)
	s.recvGCM = nil
	s.oldRecvGCM = nil
	s.destroyed.Store(true)
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
	s := &Session{
		ID:           id,
		SendKey:      sendKey,
		RecvKey:      recvKey,
		lastActivity: now,
		CreatedAt:    now,
		lastRekey:    now,
	}
	// Bug #9 §4.1: per-session migration nonce from crypto/rand. A zero nonce
	// would only make migration proofs unverifiable (fail-closed), never insecure.
	_, _ = rand.Read(s.MigrateNonce[:])
	return s
}

// InitSendEpoch installs a counter-nonce sendEpoch on a session that was built
// via NewSession (client handshake completion) and therefore lacks the cached
// send GCM. Idempotent: if an epoch is already present (server Create path, or a
// prior InitSendEpoch), it is a no-op so the counter is NEVER reset — resetting
// would replay nonce 0 under the same key (AES-GCM catastrophic reuse).
//
// H-K1 (2026-06-11 audit): the client previously fell through EncryptChunk's
// random-nonce fallback (session.go fallback branch) for 100% of its uplink.
// A counter nonce removes all birthday-collision reliance. WIRE-COMPATIBLE: the
// peer decrypts via gcm.Open over whatever 12-byte nonce sits in the frame
// header (chunk.go DecryptWith/DecryptChunk), so the sender's nonce regime is
// invisible on the wire — no ServerHello._v bump, no two-client smoke required.
//
// MUST be called exactly once after CompleteHandshake, before the first
// EncryptChunk, on every client-side session (see client/ws_pool.go slot setup
// and client/client.go direct paths).
func (s *Session) InitSendEpoch() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// H-11: never resurrect a destroyed session — SendKey is all zeros, so
	// newGCM would happily build a cipher under a publicly known key.
	if s.destroyed.Load() {
		return ErrSessionDestroyed
	}
	if s.sendEpochPtr.Load() != nil {
		return nil // already cached (server Create, or idempotent re-call)
	}
	gcm, err := newGCM(s.SendKey)
	if err != nil {
		return fmt.Errorf("InitSendEpoch: %w", err)
	}
	s.sendEpochPtr.Store(&sendEpoch{gcm: gcm}) // nonce counter starts at 0
	return nil
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
			s.windowResets.Add(1) // L5 observability: pathological seq growth signal
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

// WindowResetCount returns how many times AcceptSeqNum performed a full-window
// reset (seq jump >= WindowSize). A persistently growing value signals
// pathological seq growth / a buggy duplicate-heavy peer (L5, 2026-06-11).
func (s *Session) WindowResetCount() uint64 { return s.windowResets.Load() }

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
	s.zeroKeyMaterialLocked()
	return true
}

// Rekey replaces session keys, keeping the old recv key/GCM for a grace period.
// A1-M2: send-side rekey swaps the entire (gcm, nonce-counter) pair atomically by
// pointing sendEpochPtr at a fresh sendEpoch with counter=0. Concurrent EncryptChunk
// callers either observe the OLD epoch (with its OLD counter) or the NEW epoch
// (with counter starting from 0) — never a mixed pair.
//
// ⚠ NOT WIRED IN PRODUCTION (verified 2026-08-31, integration review). Nothing
// outside tests calls this or RekeyNeeded; FlagControl on the server is a
// keepalive shim (server/handler.go:1629-1633) despite its "Control chunks
// handle rekeying" comment. So do not read this function as a live guarantee of
// intra-session forward secrecy.
//
// What actually rotates keys today is slot rotation: each WS pool slot runs its
// own handshake and gets its own Session, so keys change every MaxSlotAge
// (engine/engine.go:508, 75s by default) plus stagger. That covers forward
// secrecy but NOT the sendSeq overflow gate below, which is per-session and
// unchecked by anyone.
//
// Blocker before enabling (May-audit C13): session tokens are sealed with the
// server's RecvKey and are NOT re-issued on rekey, while
// findSessionByHint verifies the client token against the CURRENT key
// (server/handler.go:1837-1838). Rekeying without re-issuing the token breaks
// every subsequent WS upgrade for that session. Enabling this is a protocol
// change, not a one-line call. Guard: TestRekey_NotWiredInProduction.
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
	// H-11: a destroyed session must stay destroyed — Rekey would otherwise
	// install fresh working keys and put it back in service.
	if s.destroyed.Load() {
		return ErrSessionDestroyed
	}
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
//
// ⚠ Nobody calls this in production (see Rekey). The "1 hour" and the overflow
// gate describe a policy that is not enforced — treat this as the predicate a
// future scheduler would use, not as a property the running system has. The
// overflow side is currently safe only because slot rotation retires sessions
// long before sendSeq (uint32) gets near the threshold; core/chunk.go:117
// assumes "rekey at ~2^32 well before wrap", and that assumption rests on the
// timing constants, not on this function.
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
	// H-11: fail closed BEFORE any key use. Checked first so the destroyed
	// session can never reach the fallback branch below, which would otherwise
	// encrypt under the zeroed (all-zero, publicly known) SendKey.
	if s.destroyed.Load() {
		return nil, ErrSessionDestroyed
	}

	if cbs := sessionStatsCallbacks.Load(); cbs != nil && cbs.onEncrypt != nil {
		cbs.onEncrypt()
	}

	if ep := s.sendEpochPtr.Load(); ep != nil {
		// Atomic increment, post-decrement to get pre-add value.
		nonce := ep.nonce.Add(1) - 1
		return chunk.EncryptWith(ep.gcm, nonce)
	}

	// Fallback for sessions created via NewSession (no cached GCM).
	// Falls through to legacy chunk.Encrypt with a per-call random nonce.
	//
	// SECURITY (H-K1, 2026-06-11): after this audit a production client MUST call
	// Session.InitSendEpoch() right after CompleteHandshake (see client/ws_pool.go
	// slot setup and client/client.go direct paths). Reaching this branch in prod
	// means InitSendEpoch was skipped — uplink would silently degrade to the
	// random-nonce regime (birthday-collision reliance). This branch now remains
	// only for tests that build a Session via NewSession without InitSendEpoch and
	// that exercise the random-nonce path deliberately.
	s.mu.Lock()
	// H-11: re-check under the lock. A concurrent Destroy() may have latched the
	// flag after the check at the top of this function; this branch is the one
	// that would read the zeroed bytes, so it must not race with zeroing.
	if s.destroyed.Load() {
		s.mu.Unlock()
		return nil, ErrSessionDestroyed
	}
	key := make([]byte, len(s.SendKey))
	copy(key, s.SendKey)
	s.mu.Unlock()
	return chunk.Encrypt(key)
}

// DecryptChunkSafe decrypts a chunk safely using cached GCM if available.
func (s *Session) DecryptChunkSafe(data []byte) (*Chunk, error) {
	// H-11: fail closed. Without this a destroyed session ACCEPTED frames
	// encrypted under the all-zero key — it became a receiver for anyone who
	// knows the session was torn down.
	if s.destroyed.Load() {
		return nil, ErrSessionDestroyed
	}

	if cbs := sessionStatsCallbacks.Load(); cbs != nil && cbs.onDecrypt != nil {
		cbs.onDecrypt()
	}

	s.mu.Lock()
	// H-11: re-check under the lock — a concurrent teardown may have latched the
	// flag after the check above, and the branches below read key material.
	if s.destroyed.Load() {
		s.mu.Unlock()
		return nil, ErrSessionDestroyed
	}
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

// shiftBitmap продвигает окно вперёд на n позиций.
//
// Соглашение битмапа (см. setBit/getBit): бит с индексом d соответствует
// seq, отстающему от recvHighest на d, то есть бит 0 — самый свежий seq, а
// старшие биты — более старая история. Продвижение окна на n означает, что
// каждый ранее виденный seq становится старше на n → его бит уезжает в
// сторону СТАРШИХ индексов (влево), а освободившиеся младшие обнуляются.
//
// Раунд 18 / CRITICAL-1: здесь стоял сдвиг вправо (`>>=` и подмешивание из
// [i-1] влево), из-за чего история не сдвигалась, а стиралась — anti-replay
// не работал ни на одном пути. Регрессия закрыта тестами в
// session_replay_window_test.go.
//
// HIGH-6: индексы циклов — int, не uint32, иначе i-- на нуле уходит в
// 0xFFFFFFFF при прыжках seq на 64+.
func (s *Session) shiftBitmap(n uint32) {
	if n == 0 {
		return
	}
	ws := int(n / 64)
	bitShift := n % 64
	bitmapLen := len(s.recvBitmap)

	// Пословный сдвиг влево: слово i получает содержимое слова i-ws.
	// Идём от старших к младшим, чтобы не перезаписать источник до чтения.
	if ws > 0 {
		for i := bitmapLen - 1; i >= 0; i-- {
			if i >= ws {
				s.recvBitmap[i] = s.recvBitmap[i-ws]
			} else {
				s.recvBitmap[i] = 0
			}
		}
	}

	// Внутрисловный сдвиг влево с переносом старших бит предыдущего слова
	// в младшие биты следующего.
	if bitShift > 0 {
		for i := bitmapLen - 1; i >= 0; i-- {
			s.recvBitmap[i] <<= bitShift
			if i > 0 {
				s.recvBitmap[i] |= s.recvBitmap[i-1] >> (64 - bitShift)
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

// ReattachClearDetached atomically commits a WS re-attach against the
// ghost-sweep: it clears the session's DetachedAt stamp WHILE HOLDING sm.mu,
// the SAME lock CleanupDetachedGhosts' Phase 2 holds across its
// existence-check → DetachedAt-read → delete critical section. This serializes
// the attach-commit against the sweep-delete and closes the TOCTOU race
// (audit HIGH-4 / H-S3, 2026-06-11):
//
//   - If this clear runs first, the sweep's lock-held DetachedAt re-read sees 0
//     and skips the session.
//   - If the sweep's delete runs first, this lookup misses (ok==false) and the
//     caller MUST abort the attach (reset WSAttached, fall back to
//     fakeAckAndClose) — the client reconnects cleanly on a fresh session.
//
// Returns false iff the session is no longer in the manager (already swept):
// a bare atomic Store on Session.DetachedAt is NOT sufficient because the
// sweep's decision (map delete) and the attach's signal (DetachedAt / the
// WSAttached latch on the server Tunnel) live behind different locks — only a
// common lock makes them mutually exclusive.
func (sm *SessionManager) ReattachClearDetached(id uint32) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.sessions[id]
	if !ok {
		return false // swept between the WSAttached CAS-win and this commit
	}
	s.DetachedAt.Store(0)
	return true
}

// Destroy securely zeroes all key material and puts the session out of service:
// every subsequent EncryptChunk/DecryptChunkSafe/Rekey/InitSendEpoch returns
// ErrSessionDestroyed. Idempotent.
//
// H-11 (раунд 18): раньше Destroy только зануляло байты, а сессия оставалась
// «рабочей» — см. zeroKeyMaterialLocked и ErrSessionDestroyed.
func (s *Session) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zeroKeyMaterialLocked()
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
		s.zeroKeyMaterialLocked()
		s.mu.Unlock()
		delete(sm.sessions, c.id)
		sm.mu.Unlock()
		evicted = append(evicted, c.id)
	}
	return evicted
}

// CleanupDetachedGhosts reclaims sessions whose WS transport DETACHED (the
// slot's reader goroutine exited — TSPU age-cut, io_timeout, peer_eof) more
// than `grace` ago and which the caller-supplied gate confirms are safe to
// evict. It is the SERVER side of the 2026-06-01 pool-capacity-dip-fix: the
// client cannot FIN an age-cut session (dead transport, no on-wire session
// addressing — see docs/sl-capacity-dip-spec-review.md BLOCKER-1), so the
// server reclaims the ghost promptly instead of waiting for the coarse idle
// timeout (the source of active_clients=18 ghosts that drift toward rate-limit).
//
// Eligibility (a session is a sweepable ghost when ALL hold):
//   - AttachedAt != 0   — it actually completed a handshake + attach (a newborn
//     orphan is handled by CleanupNewbornOrphans, not here).
//   - DetachedAt != 0   — a transport detached since the last attach (0 means
//     currently attached, or a reconnect re-adopted it and cleared the stamp).
//   - now - DetachedAt > grace — past the short grace that lets a RESUME/MIGRATE
//     re-adopt the relay (the grace MUST be >= the Bug#9 orphan window).
//   - gate(id) == true  — the caller (server.Handler) confirms there is NO
//     active orphan relay still bound to this session AND no live transport
//     re-attached. This is the CRITICAL Bug#9-coexistence constraint: a session
//     a stream is migrating onto must survive until its grace expires.
//
// Two-phase (mirrors CleanupNewbornOrphans, P2-3): Phase 1 collects candidate
// IDs under RLock; Phase 2 re-validates each under the write lock (DetachedAt is
// atomic; the gate is re-consulted) before zeroing key material and deleting.
// The gate is called in BOTH phases — Phase 1 to cheaply skip the common case,
// Phase 2 under the write lock to close the migrate-onto race (a RESUME between
// phases re-attaches and clears DetachedAt, which Phase 2's re-read observes).
func (sm *SessionManager) CleanupDetachedGhosts(now time.Time, grace time.Duration, gate func(id uint32) bool) []uint32 {
	graceNs := grace.Nanoseconds()

	// Phase 1: collect candidates under read lock only.
	var candidates []uint32
	sm.mu.RLock()
	for id, s := range sm.sessions {
		if s.AttachedAt.Load() == 0 {
			continue // never attached — newborn-orphan path owns it
		}
		det := s.DetachedAt.Load()
		if det == 0 {
			continue // currently attached (or re-adopted)
		}
		if now.UnixNano()-det <= graceNs {
			continue // still within the short grace — let a RESUME re-adopt it
		}
		if gate != nil && !gate(id) {
			continue // an orphan relay / live transport still references it
		}
		candidates = append(candidates, id)
	}
	sm.mu.RUnlock()

	if len(candidates) == 0 {
		return nil
	}

	// Phase 2: per-candidate write-lock window, re-validate eligibility.
	evicted := make([]uint32, 0, len(candidates))
	for _, id := range candidates {
		// Re-consult the gate OUTSIDE the manager lock to avoid holding it across
		// the caller's registry/tunnel locks (lock-order safety).
		if gate != nil && !gate(id) {
			continue
		}
		sm.mu.Lock()
		s, ok := sm.sessions[id]
		if !ok {
			sm.mu.Unlock()
			continue
		}
		// A reconnect between phases re-attaches and clears DetachedAt (and may
		// have bumped AttachedAt) — re-read under the lock and skip if so.
		det := s.DetachedAt.Load()
		if s.AttachedAt.Load() == 0 || det == 0 || now.UnixNano()-det <= graceNs {
			sm.mu.Unlock()
			continue
		}
		// Zero key material under the session lock (mirrors Destroy).
		s.mu.Lock()
		s.zeroKeyMaterialLocked()
		s.mu.Unlock()
		delete(sm.sessions, id)
		sm.mu.Unlock()
		evicted = append(evicted, id)
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
