package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// newMigratableEntry builds a relayEntry wired for the Task 11 handler tests:
// a bounded downBuffer/unackedTail, an active state, and an egress pipe whose
// server side the test writes into to drive the relay loop.
func newMigratableEntry(t *testing.T, egress net.Conn) *relayEntry {
	t.Helper()
	e := &relayEntry{
		originClientID: "client-A",
		globalStreamID: 42,
		tc:             egress,
		downBuffer:     newBoundedBuffer(1 << 20),
		unackedTail:    newBoundedBuffer(1 << 20),
		credit:         newStreamCredit(1 << 20),
	}
	e.state.Store(stActive)
	return e
}

// TestReassociate_MigrateOK_SwitchesBindingAndDrainsBuffer: entry has two
// frames buffered in downBuffer (seq 1,2) while no binding was active;
// reassociate to session B drains them onto B's writer in seq order, the
// binding now points at B, and the state is unchanged (Active). resumeDownSeq
// equals the highest seq assigned before the switch.
func TestReassociate_MigrateOK_SwitchesBindingAndDrainsBuffer(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	e := newMigratableEntry(t, egress)
	// Simulate two frames captured while there was no binding: counter advanced
	// to 2 and both frames sit in downBuffer.
	e.downSeqCounter.Store(2)
	e.perEntryMu.Lock()
	e.downBuffer.Push(pendingDownFrame{seq: 1, data: []byte("FRAME-1")})
	e.downBuffer.Push(pendingDownFrame{seq: 2, data: []byte("FRAME-2")})
	e.perEntryMu.Unlock()

	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()

	bnd := &binding{session: sessB, writer: sink.asWriter()}
	e.bound.Store(bnd)
	resumeSeq := e.reassociate(bnd, true /*migrateEnabled*/, false /*aDead*/, false /*originDeathTeardown*/)
	if resumeSeq != 2 {
		t.Fatalf("resumeDownSeq=%d, want 2", resumeSeq)
	}

	b := e.bound.Load()
	if b == nil || b.session != sessB {
		t.Fatal("binding was not switched to session B")
	}
	if e.state.Load() != stActive {
		t.Fatalf("state=%d, want stActive", e.state.Load())
	}

	// Two frames must arrive on B's writer, in seq order, decrypting under B.
	wantData := []string{"FRAME-1", "FRAME-2"}
	wantSeq := []uint64{1, 2}
	for i := 0; i < 2; i++ {
		frame := sink.waitFrame(t, time.Second)
		chunk, err := sessB.DecryptChunkSafe(frame)
		if err != nil {
			t.Fatalf("frame %d did not decrypt under B: %v", i, err)
		}
		sid, seq, data, perr := core.ParseStreamDataSeq(chunk.Payload)
		if perr != nil {
			t.Fatalf("frame %d parse: %v", i, perr)
		}
		if sid != 42 {
			t.Fatalf("frame %d streamID=%d, want 42", i, sid)
		}
		if seq != wantSeq[i] {
			t.Fatalf("frame %d seq=%d, want %d", i, seq, wantSeq[i])
		}
		if string(data) != wantData[i] {
			t.Fatalf("frame %d data=%q, want %q", i, data, wantData[i])
		}
	}

	// downBuffer must be empty after the drain.
	e.perEntryMu.Lock()
	left := e.downBuffer.byteLen()
	e.perEntryMu.Unlock()
	if left != 0 {
		t.Fatalf("downBuffer not drained: %d bytes left", left)
	}
}

// TestReassociate_DownSeqNotReset: reassociate MUST NOT touch downSeqCounter
// (NEW-3). The counter is monotonic across migrations.
func TestReassociate_DownSeqNotReset(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	e := newMigratableEntry(t, egress)
	e.downSeqCounter.Store(17)

	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()

	bnd := &binding{session: sessB, writer: sink.asWriter()}
	e.bound.Store(bnd)
	resumeSeq := e.reassociate(bnd, true, false, false)
	if resumeSeq != 17 {
		t.Fatalf("resumeDownSeq=%d, want 17", resumeSeq)
	}
	if got := e.downSeqCounter.Load(); got != 17 {
		t.Fatalf("downSeqCounter changed on reassociate: %d, want 17 (NEW-3 broken)", got)
	}
}

// TestResume_FromOrphaned_CASActive: an entry sitting in stOrphaned (slot A
// died, within grace) flips to stActive on a successful RESUME CAS.
func TestResume_FromOrphaned_CASActive(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	e := newMigratableEntry(t, egress)
	e.state.Store(stOrphaned)

	if !e.state.CompareAndSwap(stOrphaned, stActive) {
		t.Fatal("CAS stOrphaned->stActive failed on a freshly-orphaned entry")
	}
	if e.state.Load() != stActive {
		t.Fatalf("state=%d, want stActive", e.state.Load())
	}
}

// TestResume_GraceExpired_Fails: the grace timer already won the race and moved
// the entry to stClosing, so a late RESUME's CAS stOrphaned->stActive fails —
// the handler must reply grace_expired (modelled here by the CAS failing).
func TestResume_GraceExpired_Fails(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	e := newMigratableEntry(t, egress)
	e.state.Store(stClosing)

	if e.state.CompareAndSwap(stOrphaned, stActive) {
		t.Fatal("CAS stOrphaned->stActive unexpectedly succeeded on a closing entry")
	}
}

// TestGraceTimer_ClosesTCOnExpiry: an orphaned entry whose grace expires has
// its tc closed, is removed from the registry, and ends in stClosing.
func TestGraceTimer_ClosesTCOnExpiry(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()

	reg := newRelayRegistry()
	e := newMigratableEntry(t, egress)
	e.state.Store(stOrphaned)
	e.orphanedAt.Store(time.Now().UnixNano())
	reg.add("client-A", 42, e)

	// Short grace so the test is fast.
	reg.launchGraceTimer(e, 50*time.Millisecond, nil)

	// tc.Close races the test: detect closure by a Read returning an error
	// (net.Pipe Read unblocks with io.ErrClosedPipe once Close is called).
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := egress.Read(buf)
		readErr <- err
	}()

	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("egress read returned nil error — tc was not closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("grace timer did not close tc within 2s")
	}

	if got := e.state.Load(); got != stClosing {
		t.Fatalf("state=%d, want stClosing", got)
	}
	if _, ok := reg.find("client-A", 42); ok {
		t.Fatal("entry not removed from registry after grace expiry")
	}
	srvSide.Close()
}

// TestGraceTimer_ResumeWinsTimerNoop: if RESUME flips the entry back to active
// before the grace timer fires, the timer must be a no-op — it must NOT close
// tc (F8: a closing timer must never tear down a reassociated relay).
func TestGraceTimer_ResumeWinsTimerNoop(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	reg := newRelayRegistry()
	e := newMigratableEntry(t, egress)
	e.state.Store(stOrphaned)
	e.orphanedAt.Store(time.Now().UnixNano())
	reg.add("client-A", 42, e)

	reg.launchGraceTimer(e, 100*time.Millisecond, nil)

	// RESUME wins the race immediately.
	if !e.state.CompareAndSwap(stOrphaned, stActive) {
		t.Fatal("RESUME CAS failed before timer")
	}

	time.Sleep(250 * time.Millisecond) // let the timer fire and lose the CAS

	if got := e.state.Load(); got != stActive {
		t.Fatalf("state=%d after timer should-lose, want stActive", got)
	}
	// tc must still be open: a write should not hit a closed pipe error path.
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4)
		_, _ = srvSide.Read(buf) // drain so the write below can proceed
		close(done)
	}()
	if err := egress.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := egress.Write([]byte("PING")); err != nil {
		t.Fatalf("tc was closed by the losing timer (F8 violation): %v", err)
	}
	<-done
	if _, ok := reg.find("client-A", 42); !ok {
		t.Fatal("entry was removed by the losing timer (F8 violation)")
	}
}

// TestStreamAck_EvictsTail: onStreamAck(2) on an entry whose unackedTail holds
// seq 1,2,3 leaves only seq 3.
func TestStreamAck_EvictsTail(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	e := newMigratableEntry(t, egress)
	e.perEntryMu.Lock()
	e.unackedTail.Push(pendingDownFrame{seq: 1, data: []byte("a")})
	e.unackedTail.Push(pendingDownFrame{seq: 2, data: []byte("bb")})
	e.unackedTail.Push(pendingDownFrame{seq: 3, data: []byte("ccc")})
	e.perEntryMu.Unlock()

	e.onStreamAck(2)

	e.perEntryMu.Lock()
	remaining := e.unackedTail.tailFrames()
	e.perEntryMu.Unlock()
	if len(remaining) != 1 {
		t.Fatalf("unackedTail has %d frames, want 1", len(remaining))
	}
	if remaining[0].seq != 3 {
		t.Fatalf("remaining seq=%d, want 3", remaining[0].seq)
	}
}

// TestReassociate_ResendsUnackedTailWhenADead: when slot A is known-dead
// (aDead=true), reassociate resends the still-unacked tail onto B in seq
// order, in addition to draining downBuffer (NEW-1, §5.3).
func TestReassociate_ResendsUnackedTailWhenADead(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	e := newMigratableEntry(t, egress)
	e.downSeqCounter.Store(3)
	// Tail sent on A but not yet acked: seq 2,3.
	e.perEntryMu.Lock()
	e.unackedTail.Push(pendingDownFrame{seq: 2, data: []byte("TAIL-2")})
	e.unackedTail.Push(pendingDownFrame{seq: 3, data: []byte("TAIL-3")})
	e.perEntryMu.Unlock()

	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()

	bnd := &binding{session: sessB, writer: sink.asWriter()}
	e.bound.Store(bnd)
	e.reassociate(bnd, true, true /*aDead*/, false /*originDeathTeardown*/)

	want := []struct {
		seq  uint64
		data string
	}{{2, "TAIL-2"}, {3, "TAIL-3"}}
	for i, w := range want {
		frame := sink.waitFrame(t, time.Second)
		chunk, err := sessB.DecryptChunkSafe(frame)
		if err != nil {
			t.Fatalf("resend %d decrypt: %v", i, err)
		}
		_, seq, data, perr := core.ParseStreamDataSeq(chunk.Payload)
		if perr != nil {
			t.Fatalf("resend %d parse: %v", i, perr)
		}
		if seq != w.seq || string(data) != w.data {
			t.Fatalf("resend %d = (seq=%d,%q), want (seq=%d,%q)", i, seq, data, w.seq, w.data)
		}
	}
}

// drainOKReply pulls one reply frame from the writer sink, decrypts it under
// the given session, and parses it as a MIGRATE/RESUME reply.
func drainMigrateReply(t *testing.T, sink *testWriterSink, sess *core.Session) (ok bool, sid uint16, resumeSeq uint64, reason byte) {
	t.Helper()
	frame := sink.waitFrame(t, time.Second)
	chunk, err := sess.DecryptChunkSafe(frame)
	if err != nil {
		t.Fatalf("reply decrypt: %v", err)
	}
	if chunk.Flags != core.FlagMigrate && chunk.Flags != core.FlagResume {
		t.Fatalf("reply flag=0x%02x, want migrate/resume", chunk.Flags)
	}
	ok, sid, resumeSeq, reason, perr := core.ParseMigrateReply(chunk.Payload)
	if perr != nil {
		t.Fatalf("parse reply: %v", perr)
	}
	return ok, sid, resumeSeq, reason
}

// TestHandleMigrate_ValidProof_ReassociatesAndRepliesOK drives the full
// handler: a relay registered under (clientID, sid) with a known nonce, a valid
// HMAC proof computed from the server master key, MIGRATE → reassociates onto
// the new slot and replies MIGRATE_OK(resumeDownSeq).
func TestHandleMigrate_ValidProof_ReassociatesAndRepliesOK(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	const clientID = "client-A"
	const sid uint16 = 42
	var nonce [16]byte
	nonce[0], nonce[15] = 0xAB, 0xCD

	e := newMigratableEntry(t, egress)
	e.originSessionNonce = nonce
	e.downSeqCounter.Store(5)
	h.relayRegistry.add(clientID, sid, e)

	// Valid proof = HMAC(perClientKey, clientID‖sid‖nonce).
	perClientKey := core.DeriveServerPerClientKey(serverKey.Private, clientID)
	proof := core.ComputeStreamProof(perClientKey, clientID, sid, nonce)

	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()

	h.handleMigrateOrResume(core.FlagMigrate, core.BuildMigrateFrame(sid, proof),
		clientID, sessB, sink.asWriter(), true)

	ok, gotSid, resumeSeq, _ := drainMigrateReply(t, sink, sessB)
	if !ok {
		t.Fatal("expected MIGRATE_OK, got FAIL")
	}
	if gotSid != sid {
		t.Fatalf("reply sid=%d, want %d", gotSid, sid)
	}
	if resumeSeq != 5 {
		t.Fatalf("resumeDownSeq=%d, want 5", resumeSeq)
	}
	if b := e.bound.Load(); b == nil || b.session != sessB {
		t.Fatal("binding not switched to session B")
	}
	if h.metrics.MigrateOK.Load() != 1 {
		t.Fatalf("MigrateOK metric=%d, want 1", h.metrics.MigrateOK.Load())
	}
}

// TestHandleMigrate_BadProof_RepliesFail: a proof that does not verify → the
// handler replies MIGRATE_FAIL(bad_proof) and the binding is unchanged.
func TestHandleMigrate_BadProof_RepliesFail(t *testing.T) {
	h, _ := setupTestHandler(t)

	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	const clientID = "client-A"
	const sid uint16 = 7
	e := newMigratableEntry(t, egress)
	h.relayRegistry.add(clientID, sid, e)

	var bogus [32]byte
	bogus[0] = 0xFF

	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()

	h.handleMigrateOrResume(core.FlagMigrate, core.BuildMigrateFrame(sid, bogus),
		clientID, sessB, sink.asWriter(), true)

	ok, _, _, reason := drainMigrateReply(t, sink, sessB)
	if ok {
		t.Fatal("expected FAIL on bad proof")
	}
	if reason != core.MigrateReasonBadProof {
		t.Fatalf("reason=0x%02x, want bad_proof(0x%02x)", reason, core.MigrateReasonBadProof)
	}
	if e.bound.Load() != nil {
		t.Fatal("binding changed on bad-proof MIGRATE")
	}
	if h.metrics.MigrateFail.Load() != 1 {
		t.Fatalf("MigrateFail metric=%d, want 1", h.metrics.MigrateFail.Load())
	}
}

// TestHandleMigrate_NotFound_RepliesFail: no relay registered → not_found.
func TestHandleMigrate_NotFound_RepliesFail(t *testing.T) {
	h, _ := setupTestHandler(t)
	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()

	var proof [32]byte
	h.handleMigrateOrResume(core.FlagMigrate, core.BuildMigrateFrame(99, proof),
		"ghost", sessB, sink.asWriter(), true)

	ok, _, _, reason := drainMigrateReply(t, sink, sessB)
	if ok || reason != core.MigrateReasonNotFound {
		t.Fatalf("expected FAIL(not_found), got ok=%v reason=0x%02x", ok, reason)
	}
}

// TestHandleResume_GraceExpired_RepliesFail: the entry is already stClosing
// (grace timer won) → RESUME proof verifies but the CAS fails → grace_expired.
func TestHandleResume_GraceExpired_RepliesFail(t *testing.T) {
	h, serverKey := setupTestHandler(t)

	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	const clientID = "client-A"
	const sid uint16 = 3
	var nonce [16]byte
	nonce[3] = 0x77

	e := newMigratableEntry(t, egress)
	e.originSessionNonce = nonce
	e.state.Store(stClosing) // grace timer already won
	h.relayRegistry.add(clientID, sid, e)

	perClientKey := core.DeriveServerPerClientKey(serverKey.Private, clientID)
	proof := core.ComputeStreamProof(perClientKey, clientID, sid, nonce)

	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()

	h.handleMigrateOrResume(core.FlagResume, core.BuildMigrateFrame(sid, proof),
		clientID, sessB, sink.asWriter(), true)

	ok, _, _, reason := drainMigrateReply(t, sink, sessB)
	if ok || reason != core.MigrateReasonGraceExpired {
		t.Fatalf("expected FAIL(grace_expired), got ok=%v reason=0x%02x", ok, reason)
	}
}

// TestEntriesForSession_FiltersByBinding: entriesForSession returns only relays
// whose current binding points at the queried session.
func TestEntriesForSession_FiltersByBinding(t *testing.T) {
	reg := newRelayRegistry()
	sessA := newSelfSession(t)
	sessB := newSelfSession(t)

	eA := &relayEntry{originClientID: "c", globalStreamID: 1, downBuffer: newBoundedBuffer(1 << 10), unackedTail: newBoundedBuffer(1 << 10)}
	eA.bound.Store(&binding{session: sessA})
	eB := &relayEntry{originClientID: "c", globalStreamID: 2, downBuffer: newBoundedBuffer(1 << 10), unackedTail: newBoundedBuffer(1 << 10)}
	eB.bound.Store(&binding{session: sessB})
	reg.add("c", 1, eA)
	reg.add("c", 2, eB)

	got := reg.entriesForSession("c", sessA)
	if len(got) != 1 || got[0] != eA {
		t.Fatalf("entriesForSession returned %d entries, want exactly eA", len(got))
	}
}

// TestRelayLoop_BufferFull_NoSeqGap is the acceptance test for the critical
// requirement (quality review of Task 10): when there is no binding and the
// downBuffer is full, the relay loop MUST NOT advance downSeqCounter for a
// frame it cannot store, MUST NOT lose any frame, and MUST NOT create a gap in
// the seq sequence. The loop blocks (TCP backpressure) until reassociate drains
// the buffer; then every byte written into the egress arrives on B with a
// strictly-monotonic, gapless seq.
func TestRelayLoop_BufferFull_NoSeqGap(t *testing.T) {
	srvSide, egress := net.Pipe()
	defer srvSide.Close()
	defer egress.Close()

	// Tiny downBuffer: holds at most a few small frames before it is full.
	e := &relayEntry{
		originClientID: "client-A",
		globalStreamID: 9,
		tc:             egress,
		downBuffer:     newBoundedBuffer(24), // ~3 frames of 8 bytes
		unackedTail:    newBoundedBuffer(1 << 20),
		credit:         newStreamCredit(1 << 20),
	}
	e.state.Store(stActive)
	// No binding yet — every frame goes to downBuffer until reassociate.

	closeCh := make(chan struct{})
	defer close(closeCh)
	go e.relayLoop(true, closeCh)

	// Writer goroutine: push many fixed-size frames into the egress. With no
	// binding and a tiny buffer, the loop must block on backpressure rather
	// than dropping frames or skipping seqs.
	const nFrames = 20
	const frameSize = 8
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		payload := make([]byte, frameSize)
		for i := 0; i < nFrames; i++ {
			payload[0] = byte(i) // tag each frame so we can verify order
			if _, err := srvSide.Write(payload); err != nil {
				return
			}
		}
	}()

	// Give the writer time to fill the buffer and block on backpressure.
	time.Sleep(150 * time.Millisecond)

	// Now reassociate to B, draining whatever was buffered, and keep draining
	// by repeatedly reassociating is unnecessary — once bound, the loop sends
	// directly. We attach B once; subsequent frames flow straight to B.
	sessB := newSelfSession(t)
	sink := newTestWriterSink()
	defer sink.close()
	bnd := &binding{session: sessB, writer: sink.asWriter()}
	e.bound.Store(bnd)
	e.reassociate(bnd, true, false, false)

	// Collect all frames; verify strictly monotonic, gapless seq starting at 1,
	// and that the tag bytes arrive in write order (no loss, no reorder).
	var lastSeq uint64
	var lastTag int = -1
	collected := 0
	deadline := time.After(5 * time.Second)
	for collected < nFrames {
		select {
		case frame := <-sink.sink.frames:
			chunk, err := sessB.DecryptChunkSafe(frame)
			if err != nil {
				t.Fatalf("frame %d decrypt: %v", collected, err)
			}
			_, seq, data, perr := core.ParseStreamDataSeq(chunk.Payload)
			if perr != nil {
				t.Fatalf("frame %d parse: %v", collected, perr)
			}
			if seq != lastSeq+1 {
				t.Fatalf("seq gap: got seq=%d after %d (gap or non-monotonic)", seq, lastSeq)
			}
			lastSeq = seq
			tag := int(data[0])
			if tag != lastTag+1 {
				t.Fatalf("frame out of order or lost: got tag=%d after %d", tag, lastTag)
			}
			lastTag = tag
			collected++
		case <-deadline:
			t.Fatalf("only collected %d/%d frames — frames lost under backpressure", collected, nFrames)
		}
	}
	if lastSeq != nFrames {
		t.Fatalf("final seq=%d, want %d (gapless 1..N)", lastSeq, nFrames)
	}
}
