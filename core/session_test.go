package core

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSessionAcceptsInOrderChunks(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(0))
	assert.True(t, s.AcceptSeqNum(1))
	assert.True(t, s.AcceptSeqNum(2))
}

func TestSessionRejectsReplay(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(5))
	assert.False(t, s.AcceptSeqNum(5), "replay must be rejected")
}

func TestSessionAcceptsOutOfOrder(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(0))
	assert.True(t, s.AcceptSeqNum(3)) // skip 1,2
	assert.True(t, s.AcceptSeqNum(1)) // late arrival
	assert.True(t, s.AcceptSeqNum(2)) // late arrival
}

func TestSessionSlidingWindowLimit(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(WindowSize+100))
	assert.False(t, s.AcceptSeqNum(0), "too old — outside window")
}

// Раунд 18: прежняя версия этого теста утверждала, что seq=0 после
// продвижения на WindowSize-1 принимается повторно («still within window») —
// то есть закрепляла CRITICAL-1 как ожидаемое поведение. Корректная проверка
// края окна живёт в TestSlidingWindowEdge_ReplayAtEdgeRejected
// (session_replay_window_test.go).

func TestSessionLargeJump(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.True(t, s.AcceptSeqNum(0))
	high := uint32(WindowSize + 5000) // always larger than WindowSize
	assert.True(t, s.AcceptSeqNum(high))
	assert.False(t, s.AcceptSeqNum(0), "old seq after large jump")
	assert.True(t, s.AcceptSeqNum(high-1))            // within new window
	assert.True(t, s.AcceptSeqNum(high-WindowSize+1)) // exactly at edge
	assert.False(t, s.AcceptSeqNum(high-WindowSize), "just outside window")
}

func TestSessionExpiry(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.False(t, s.IsExpired(5*time.Minute))

	s.mu.Lock()
	s.lastActivity = time.Now().Add(-6 * time.Minute)
	s.mu.Unlock()
	assert.True(t, s.IsExpired(5*time.Minute))
}

func TestSessionNextSeqNum(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.Equal(t, uint32(0), s.NextSeqNum())
	assert.Equal(t, uint32(1), s.NextSeqNum())
	assert.Equal(t, uint32(2), s.NextSeqNum())
}

func TestSessionRekey(t *testing.T) {
	oldSend := make([]byte, 32)
	oldRecv := make([]byte, 32)
	oldSend[0] = 0x01
	oldRecv[0] = 0x02

	s := NewSession(1, oldSend, oldRecv)

	newSend := make([]byte, 32)
	newRecv := make([]byte, 32)
	newSend[0] = 0xAA
	newRecv[0] = 0xBB

	if err := s.Rekey(newSend, newRecv); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, byte(0xAA), s.SendKey[0])
	assert.Equal(t, byte(0xBB), s.RecvKey[0])
	// Old key should still be accessible
	old := s.OldRecvKey()
	require.NotNil(t, old)
	assert.Equal(t, byte(0x02), old[0])
}

func TestSessionOldKeyExpiresAfter10Seconds(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	if err := s.Rekey(make([]byte, 32), make([]byte, 32)); err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	s.oldKeyExpiry = time.Now().Add(-1 * time.Second)
	s.mu.Unlock()

	assert.Nil(t, s.OldRecvKey(), "old key should be nil after expiry")
}

func TestSessionRekeyNeeded(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	assert.False(t, s.RekeyNeeded())

	s.mu.Lock()
	s.lastRekey = time.Now().Add(-61 * time.Minute)
	s.mu.Unlock()
	assert.True(t, s.RekeyNeeded())
}

// SessionManager tests

func TestSessionManagerCreate(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	s1, err := sm.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := sm.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, s1.ID, s2.ID, "session IDs must be unique")
	assert.Equal(t, 2, sm.Count())
}

func TestSessionManagerGet(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	found, ok := sm.Get(s.ID)
	assert.True(t, ok)
	assert.Equal(t, s.ID, found.ID)

	_, ok = sm.Get(999999)
	assert.False(t, ok)
}

func TestSessionManagerRemove(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	sm.Remove(s.ID)
	assert.Equal(t, 0, sm.Count())
}

func TestSessionManagerCleanup(t *testing.T) {
	sm := NewSessionManager(1 * time.Second)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	s.mu.Lock()
	s.lastActivity = time.Now().Add(-2 * time.Second)
	s.mu.Unlock()

	removed := sm.Cleanup()
	assert.Equal(t, 1, removed)
	assert.Equal(t, 0, sm.Count())
}

func TestSessionManagerCleanupKeepsActive(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	_, err := sm.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	removed := sm.Cleanup()
	assert.Equal(t, 0, removed)
	assert.Equal(t, 1, sm.Count())
}

func TestSessionManagerRandomStartID(t *testing.T) {
	sm1 := NewSessionManager(5 * time.Minute)
	sm2 := NewSessionManager(5 * time.Minute)
	s1, err := sm1.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	s2, err := sm2.Create(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}

	// Very unlikely to collide with random start
	assert.NotEqual(t, s1.ID, s2.ID, "different managers should have different starting IDs")
}

// --- New tests for cached GCM ---

func TestSessionCachedEncryptDecrypt(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	sendKey := make([]byte, 32)
	sendKey[0] = 0xAA
	recvKey := make([]byte, 32)
	recvKey[0] = 0xBB

	s, err := sm.Create(sendKey, recvKey)
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt with cached GCM
	chunk := NewDataChunk(s.ID, 0, []byte("hello cached"))
	encrypted, err := s.EncryptChunk(chunk)
	require.NoError(t, err)

	// Decrypt with raw key (backward compat — proves EncryptWith output is DecryptChunk-compatible)
	decoded, err := DecryptChunk(encrypted, sendKey)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello cached"), decoded.Payload)
	assert.Equal(t, FlagData, decoded.Flags)
}

func TestSessionCachedRoundTrip(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)
	sendKey := make([]byte, 32)
	sendKey[0] = 0x11
	recvKey := make([]byte, 32)
	recvKey[0] = 0x22

	// Sender session
	sender, err := sm.Create(sendKey, recvKey)
	if err != nil {
		t.Fatal(err)
	}

	// Receiver session (reversed keys)
	receiver, err := sm.Create(recvKey, sendKey)
	if err != nil {
		t.Fatal(err)
	}

	// Sender encrypts
	chunk := NewDataChunk(sender.ID, 0, []byte("round trip data"))
	encrypted, err := sender.EncryptChunk(chunk)
	require.NoError(t, err)

	// Receiver decrypts via DecryptChunkSafe (uses cached recvGCM = sender's sendKey)
	decoded, err := receiver.DecryptChunkSafe(encrypted)
	require.NoError(t, err)
	assert.Equal(t, []byte("round trip data"), decoded.Payload)
}

func TestSessionCreateReturnsError(t *testing.T) {
	sm := NewSessionManager(5 * time.Minute)

	// Bad key length — should fail
	_, err := sm.Create([]byte("short"), []byte("short"))
	assert.Error(t, err, "bad key length should return error")
}

// TestSession_ProtoVersionPin verifies that the wire-format version field
// defaults to 0 (legacy) and can be pinned after handshake. D5 of Bearer→body-prefix
// migration.
func TestSession_ProtoVersionPin(t *testing.T) {
	s := NewSession(42, make([]byte, 32), make([]byte, 32))
	assert.Equal(t, uint8(0), s.ProtoVersion, "default proto version should be 0 (legacy)")

	s.ProtoVersion = 1
	assert.Equal(t, uint8(1), s.ProtoVersion, "proto version not pinnable")
}
