package client

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// ───────────────────────────────────────────────────────────────────────────
// Bug #9 Task 15 — client MIGRATE/RESUME send + ack-await + hysteresis +
// per-stream proof storage + StreamAck throttle (F3).
//
// These tests drive the migrate-send machinery in isolation. A fake target
// slot is wired into a minimal WSPoolTransport so sendMigrate can encrypt
// under that slot's session and enqueue to its control channel; the reader
// resolution path (slotReaderWithClient → resolveMigrateReply) is exercised
// directly by feeding a synthesized MIGRATE_OK/FAIL reply.
// ───────────────────────────────────────────────────────────────────────────

// captureSlotTransport is a wsSlotTransport that records control writes so a
// test can confirm sendMigrate enqueued a frame, and can be inspected for the
// MIGRATE/RESUME flag.
type captureSlotTransport struct {
	mu       sync.Mutex
	control  [][]byte
	tryCtrl  [][]byte
	writeErr error
}

func (c *captureSlotTransport) ReadMessage(timeout time.Duration) ([]byte, error) {
	// Block-ish: tests never read from this; return a slow timeout error.
	time.Sleep(timeout)
	return nil, &timeoutErr{}
}
func (c *captureSlotTransport) LastWriteUnixNano() int64 { return time.Now().UnixNano() }
func (c *captureSlotTransport) WriteMessage(data []byte) error {
	return c.writeErr
}
func (c *captureSlotTransport) WriteControlMessage(data []byte) error {
	c.mu.Lock()
	c.control = append(c.control, append([]byte(nil), data...))
	c.mu.Unlock()
	return c.writeErr
}
func (c *captureSlotTransport) TryWriteControlMessage(data []byte) bool {
	c.mu.Lock()
	c.tryCtrl = append(c.tryCtrl, append([]byte(nil), data...))
	c.mu.Unlock()
	return c.writeErr == nil
}
func (c *captureSlotTransport) Close() error { return nil }

func (c *captureSlotTransport) controlCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.control) + len(c.tryCtrl)
}

type timeoutErr struct{}

func (timeoutErr) Error() string { return "timeout" }
func (timeoutErr) Timeout() bool { return true }

// newMigrateTestPool builds a minimal pool with a single ready slot at the
// given index holding a fresh crypto session, plus a stream registered onto
// that slot. Returns the pool, the slot transport, and the session both ends
// share (so a test can encrypt a reply the way the server would).
func newMigrateTestPool(t *testing.T, streamID uint16, slotIdx int) (*WSPoolTransport, *captureSlotTransport, *core.Session) {
	t.Helper()
	// A session whose SendKey == RecvKey can decrypt what it itself encrypts —
	// EncryptChunk uses SendKey, DecryptChunkSafe uses RecvKey. This lets one
	// *core.Session object stand in for both ends of the in-test wire so a test
	// can synthesize a server reply the slot reader then decrypts.
	symKey := make([]byte, 32)
	for i := range symKey {
		symKey[i] = byte(i*7 + 3)
	}
	sess := core.NewSession(0xCAFE, symKey, symKey)

	p := &WSPoolTransport{
		poolSize: slotIdx + 2,
	}
	p.slots = make([]*poolSlot, slotIdx+2)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}
	tr := &captureSlotTransport{}
	slot := p.slots[slotIdx]
	slot.transport = tr
	slot.session = sess
	slot.state.Store(int32(slotReady))
	p.migrateEnabled.Store(true)
	// Arm migration capability the way connectSlot does after a negotiated
	// handshake (sets migrateCapable=true + clears the timeout streak).
	p.resetMigrateHysteresis()

	// Register the stream onto the slot.
	p.streamMap.Store(streamID, newStreamEntry(slotIdx))
	return p, tr, sess
}

// TestStreamProofStorage round-trips StoreStreamProof / StreamProof.
func TestStreamProofStorage(t *testing.T) {
	cl := &Client{}
	var proof [32]byte
	for i := range proof {
		proof[i] = byte(i + 1)
	}

	if _, ok := cl.StreamProof(7); ok {
		t.Fatal("StreamProof on unknown stream must return ok=false")
	}

	cl.StoreStreamProof(7, proof)
	got, ok := cl.StreamProof(7)
	if !ok {
		t.Fatal("StreamProof after store must return ok=true")
	}
	if got != proof {
		t.Fatalf("proof round-trip mismatch: got %x want %x", got, proof)
	}

	// Unregistering the stream must clear the stored proof (no leak).
	cl.UnregisterStream(7)
	if _, ok := cl.StreamProof(7); ok {
		t.Fatal("proof must be cleared after UnregisterStream")
	}
}

// TestSendMigrate_OKResolvesPending: sendMigrate registers a pending ack; a
// synthesized MIGRATE_OK delivered via resolveMigrateReply resolves it as a
// success carrying resumeDownSeq.
func TestSendMigrate_OKResolvesPending(t *testing.T) {
	const streamID = uint16(0x1234)
	const targetIdx = 1
	p, tr, sess := newMigrateTestPool(t, streamID, targetIdx)

	cl := &Client{}
	var proof [32]byte
	proof[0] = 0xAB
	cl.StoreStreamProof(streamID, proof)

	resCh := make(chan migrateResult, 1)
	go func() {
		resCh <- p.sendMigrate(cl, streamID, core.FlagMigrate, targetIdx)
	}()

	// Wait until the frame is enqueued AND the pending chan is registered.
	deadline := time.After(2 * time.Second)
	for {
		if tr.controlCount() > 0 {
			if _, ok := p.pendingMigrateAcks.Load(streamID); ok {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("sendMigrate did not enqueue + register pending in time")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	// Synthesize the server's MIGRATE_OK reply on the target slot's session.
	const resumeSeq = uint64(987)
	reply := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagMigrate,
		Payload:   core.BuildMigrateOK(streamID, resumeSeq),
	}
	enc, err := sess.EncryptChunk(reply)
	if err != nil {
		t.Fatalf("encrypt reply: %v", err)
	}
	p.handleMigrateReplyFrame(targetIdx, enc)

	select {
	case res := <-resCh:
		if res.kind != migrateResultOK {
			t.Fatalf("expected OK, got kind=%d", res.kind)
		}
		if res.resumeDownSeq != resumeSeq {
			t.Fatalf("resumeDownSeq=%d want %d", res.resumeDownSeq, resumeSeq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sendMigrate did not resolve on MIGRATE_OK")
	}

	// Pending entry must be removed (no leak).
	if _, ok := p.pendingMigrateAcks.Load(streamID); ok {
		t.Fatal("pending ack must be removed after resolve")
	}
}

// TestSendMigrate_TimeoutDegrades: no OK/FAIL within the (test-shortened) ack
// timeout → result=timeout and MigrateTimeout counter increments.
func TestSendMigrate_TimeoutDegrades(t *testing.T) {
	const streamID = uint16(0x55)
	const targetIdx = 1
	p, _, _ := newMigrateTestPool(t, streamID, targetIdx)

	// Shorten the ack timeout for this test via the injectable override.
	old := p.migrateAckTimeoutOverride
	p.migrateAckTimeoutOverride = 60 * time.Millisecond
	defer func() { p.migrateAckTimeoutOverride = old }()

	cl := &Client{}
	var proof [32]byte
	proof[0] = 0x99
	cl.StoreStreamProof(streamID, proof)
	before := Stats.MigrateTimeout.Load()

	res := p.sendMigrate(cl, streamID, core.FlagMigrate, targetIdx)
	if res.kind != migrateResultTimeout {
		t.Fatalf("expected timeout, got kind=%d", res.kind)
	}
	if Stats.MigrateTimeout.Load() != before+1 {
		t.Fatalf("MigrateTimeout not incremented: before=%d after=%d", before, Stats.MigrateTimeout.Load())
	}
	// No goroutine leak: pending chan removed on timeout.
	if _, ok := p.pendingMigrateAcks.Load(streamID); ok {
		t.Fatal("pending ack must be removed after timeout")
	}
}

// TestCapabilityHysteresis_DropsAfter3Timeouts: three consecutive timeouts flip
// migrateCapable false; a successful handshake-style reset restores it.
func TestCapabilityHysteresis_DropsAfter3Timeouts(t *testing.T) {
	const targetIdx = 1
	p, _, _ := newMigrateTestPool(t, 0x77, targetIdx)
	p.migrateAckTimeoutOverride = 30 * time.Millisecond

	if !p.MigrateCapable() {
		t.Fatal("migration-enabled pool must start MigrateCapable")
	}

	cl := &Client{}
	var proof [32]byte
	proof[0] = 0x42
	for i := 0; i < 2; i++ {
		// Register a fresh stream each iteration (sendMigrate keys pending by
		// streamID; a stale pending would collide).
		sid := uint16(0x100 + i)
		p.streamMap.Store(sid, newStreamEntry(targetIdx))
		cl.StoreStreamProof(sid, proof)
		p.sendMigrate(cl, sid, core.FlagMigrate, targetIdx)
		if !p.MigrateCapable() {
			t.Fatalf("after %d timeouts MigrateCapable must still be true", i+1)
		}
	}
	// Third consecutive timeout trips hysteresis.
	p.streamMap.Store(uint16(0x200), newStreamEntry(targetIdx))
	cl.StoreStreamProof(0x200, proof)
	p.sendMigrate(cl, 0x200, core.FlagMigrate, targetIdx)
	if p.MigrateCapable() {
		t.Fatal("3 consecutive timeouts must drop MigrateCapable to false")
	}

	// A successful handshake resets the counter and re-enables capability.
	p.resetMigrateHysteresis()
	if !p.MigrateCapable() {
		t.Fatal("resetMigrateHysteresis must restore MigrateCapable")
	}
}

// TestStreamAckThrottle: many acks within the throttle window coalesce into a
// single send; a forced flush bypasses the throttle.
func TestStreamAckThrottle(t *testing.T) {
	cl := &Client{}
	var sends atomic.Int32
	cl.streamAckSendForTest = func(streamID uint16, ackedDownSeq uint64) bool {
		sends.Add(1)
		return true
	}

	const streamID = uint16(9)
	// First ack always sends (no prior timestamp).
	cl.sendStreamAckThrottled(nil, streamID, 1, false)
	// Burst of acks within the throttle window must coalesce (no send).
	for i := 2; i <= 50; i++ {
		cl.sendStreamAckThrottled(nil, streamID, uint64(i), false)
	}
	if got := sends.Load(); got != 1 {
		t.Fatalf("burst within window must coalesce to the first send; got %d sends", got)
	}

	// A forced flush bypasses the throttle and sends immediately.
	cl.sendStreamAckThrottled(nil, streamID, 51, true)
	if got := sends.Load(); got != 2 {
		t.Fatalf("forced flush must send regardless of throttle; got %d sends", got)
	}

	// After the throttle interval elapses, a normal ack sends again.
	cl.forceStreamAckClockForTest(streamID, time.Now().Add(-2*streamAckThrottleInterval))
	cl.sendStreamAckThrottled(nil, streamID, 52, false)
	if got := sends.Load(); got != 3 {
		t.Fatalf("ack after throttle window must send; got %d sends", got)
	}
}
