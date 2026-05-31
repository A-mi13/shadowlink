package client

import (
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// migrate_send.go — Bug #9 Task 15 client send-side of stream migration.
//
// sendMigrate transmits a MIGRATE (preemptive, §5.3) or RESUME (reactive, §5.5)
// control frame for a stream onto a TARGET slot (the slot the stream is moving
// TO) and awaits the server's MIGRATE_OK/FAIL reply. The reply rides the new
// slot's downlink and is decrypted by slotReaderWithClient, which hands the
// payload to resolveMigrateReplyPayload, resolving the pending chan.
//
// Concurrency contract (no leak / no double-resolve):
//   - sendMigrate registers exactly one buffered(1) chan per streamID under
//     pendingMigrateAcks before enqueuing the frame.
//   - On EITHER a reply OR the timeout, the chan is removed from the map via
//     LoadAndDelete; the removing path is the SOLE winner. A reply that loses
//     the race finds nothing to resolve (LoadAndDelete miss → dropped). A
//     timeout that loses the race (reply already removed + sent) reads the chan
//     it still holds non-blockingly. The chan is buffered so the resolver never
//     blocks even if sendMigrate already returned on timeout.

// migrateAckTimeoutEffective returns the ack-await window, honoring a test
// override.
func (p *WSPoolTransport) migrateAckTimeoutEffective() time.Duration {
	if p.migrateAckTimeoutOverride > 0 {
		return p.migrateAckTimeoutOverride
	}
	return migrateAckTimeout
}

// MigrateCapable reports whether the pool may currently attempt stream
// migration: the wire format was negotiated (migrateEnabled) AND the hysteresis
// has not disabled it. Lock-free.
func (p *WSPoolTransport) MigrateCapable() bool {
	return p.migrateEnabled.Load() && p.migrateCapable.Load()
}

// resetMigrateHysteresis re-arms migration capability and clears the
// consecutive-timeout counter. Called from connectSlot when a slot negotiates
// migration (a fresh, acking server invalidates any prior "stopped acking"
// verdict). Idempotent.
func (p *WSPoolTransport) resetMigrateHysteresis() {
	p.consecutiveMigrateTimeouts.Store(0)
	p.migrateCapable.Store(true)
}

// noteMigrateTimeout records a timeout against the hysteresis. On the
// threshold-th consecutive timeout it drops migrateCapable and bumps the
// dropped counter exactly once (the CAS-free path is fine: only the goroutine
// crossing the threshold sets false, and resetMigrateHysteresis is the only
// re-enabler — a benign double-store of false is idempotent).
func (p *WSPoolTransport) noteMigrateTimeout() {
	n := p.consecutiveMigrateTimeouts.Add(1)
	if n == migrateHysteresisThreshold && p.migrateCapable.Load() {
		p.migrateCapable.Store(false)
		Stats.MigrateCapabilityDropped.Add(1)
	}
}

// noteMigrateAck records a successful (OK) reply, clearing the consecutive
// timeout streak. A FAIL is NOT a timeout — the server replied — so it also
// clears the streak (the channel is alive). Only silence (timeout) erodes
// capability.
func (p *WSPoolTransport) noteMigrateAck() {
	p.consecutiveMigrateTimeouts.Store(0)
}

// slotForMigrate returns the target slot's session + a non-blocking control
// enqueue closure, or ok=false if the slot is unusable. The frame is encrypted
// under the TARGET slot's session (the stream is moving onto it, so the server
// decrypts the MIGRATE on that slot's reader-loop binding).
func (p *WSPoolTransport) slotForMigrate(targetIdx int) (sess *core.Session, enqueue func([]byte) bool, ok bool) {
	if targetIdx < 0 || targetIdx >= len(p.slots) {
		return nil, nil, false
	}
	slot := p.slots[targetIdx]
	if slot == nil || slot.transport == nil || slot.session == nil {
		return nil, nil, false
	}
	if st := slot.getState(); st != slotReady && st != slotDraining {
		return nil, nil, false
	}
	tr := slot.transport
	enqueue = func(data []byte) bool {
		// Prefer the non-blocking control path so a backed-up writer can't stall
		// the migration goroutine; fall back to the blocking control write when
		// the transport doesn't expose a try-variant.
		if tw, ok := tr.(interface{ TryWriteControlMessage(data []byte) bool }); ok {
			return tw.TryWriteControlMessage(data)
		}
		return tr.WriteControlMessage(data) == nil
	}
	return slot.session, enqueue, true
}

// sendMigrate sends a MIGRATE (kind=core.FlagMigrate) or RESUME
// (kind=core.FlagResume) for streamID onto targetIdx and blocks until the
// server replies or the ack window elapses. It is safe to call from a watchdog
// goroutine (Task 16/17). Returns the outcome; the caller decides whether to
// flip the stream's slot binding (on OK) or hard-break it (on FAIL/timeout).
func (p *WSPoolTransport) sendMigrate(cl *Client, streamID uint16, kind byte, targetIdx int) migrateResult {
	// Proof is mandatory — without it the server's constant-time verify fails
	// closed (a zero proof never matches). Skip the wire round-trip entirely.
	proof, ok := cl.StreamProof(streamID)
	if !ok {
		return migrateResult{kind: migrateResultNoSend}
	}

	sess, enqueue, ok := p.slotForMigrate(targetIdx)
	if !ok {
		return migrateResult{kind: migrateResultNoSend}
	}

	chunk := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     kind,
		Payload:   core.BuildMigrateFrame(streamID, proof),
	}
	enc, err := sess.EncryptChunk(chunk)
	if err != nil {
		return migrateResult{kind: migrateResultNoSend}
	}

	// Register the pending chan BEFORE enqueuing so a fast reply can't arrive
	// before we are listening. Buffered(1) so resolveMigrateReply never blocks.
	replyCh := make(chan migrateResult, 1)
	// One in-flight MIGRATE per stream: if a stale entry exists (shouldn't under
	// the single-watchdog caller contract), the new chan replaces it and the old
	// awaiter falls through to its own timeout.
	p.pendingMigrateAcks.Store(streamID, replyCh)

	if !enqueue(enc) {
		// Could not enqueue — tear down the pending registration so it doesn't
		// linger until a stray reply or never resolves.
		p.pendingMigrateAcks.CompareAndDelete(streamID, replyCh)
		return migrateResult{kind: migrateResultNoSend}
	}

	Stats.MigrateAttempt.Add(1)

	timer := time.NewTimer(p.migrateAckTimeoutEffective())
	defer timer.Stop()

	select {
	case res := <-replyCh:
		// resolveMigrateReply already removed the map entry (it owns the delete).
		switch res.kind {
		case migrateResultOK:
			Stats.MigrateOK.Add(1)
			p.noteMigrateAck()
		case migrateResultFail:
			Stats.MigrateFail.Add(1)
			p.noteMigrateAck() // server replied → channel healthy, streak cleared
		}
		return res
	case <-timer.C:
		// Timeout wins the race iff it removes the entry. If a reply slipped in
		// first, LoadAndDelete here misses and we drain the buffered chan.
		if _, loaded := p.pendingMigrateAcks.LoadAndDelete(streamID); !loaded {
			select {
			case res := <-replyCh:
				switch res.kind {
				case migrateResultOK:
					Stats.MigrateOK.Add(1)
					p.noteMigrateAck()
				case migrateResultFail:
					Stats.MigrateFail.Add(1)
					p.noteMigrateAck()
				}
				return res
			default:
				// Reply removed the entry but hasn't sent yet — treat as timeout;
				// the late send lands in the buffered chan and is GC'd with it.
			}
		}
		Stats.MigrateTimeout.Add(1)
		p.noteMigrateTimeout()
		return migrateResult{kind: migrateResultTimeout}
	}
}

// migrateBarrierPollInterval is the poll cadence of the uplink barrier's
// bounded wait loop. Short enough that a freed barrier resumes uplink with
// negligible added latency; long enough not to busy-spin.
const migrateBarrierPollInterval = 2 * time.Millisecond

// WaitStreamMigrateBarrier implements the §5.3 uplink barrier: while streamID's
// entry is migrating (a MIGRATE/RESUME is in flight), the SOCKS5 uplink
// goroutine must NOT write to the OLD slot — uplink bytes that race ahead of the
// MIGRATE would land on the aging slot after the server has already re-homed the
// stream, de-syncing the per-stream sequence. This call blocks until the flag
// clears (the binding now points at the new slot, so the next StreamWrite routes
// there) OR a bounded timeout (migrateAckTimeout) elapses.
//
// Bounded BY DESIGN: a stuck migration (server never acks → sendMigrate times
// out → flag cleared by migrateStream's defer) clears the flag within
// migrateAckTimeout anyway, but the barrier caps its own wait independently so a
// lost flag-clear (future bug) can never wedge the uplink goroutine forever. On
// timeout the write proceeds against whatever slot the binding currently names —
// graceful degradation, identical to the pre-Task-17 behavior (no barrier).
//
// Fast path (the overwhelming common case — no migration in flight): a single
// streamMap.Load + atomic Bool Load, then return. No allocation, no timer.
func (p *WSPoolTransport) WaitStreamMigrateBarrier(streamID uint16) {
	// Cheap pre-check: only migration-negotiated pools ever set the flag.
	if !p.migrateEnabled.Load() {
		return
	}
	v, ok := p.streamMap.Load(streamID)
	if !ok {
		return
	}
	e, ok := v.(*streamEntry)
	if !ok || !e.migrating.Load() {
		return // fast path: not migrating
	}

	deadline := time.Now().Add(p.migrateAckTimeoutEffective())
	for e.migrating.Load() {
		if time.Now().After(deadline) {
			return // bounded — never block past the ack window
		}
		time.Sleep(migrateBarrierPollInterval)
		// Re-resolve the entry: a successful rebind replaces it with a fresh
		// (migrating=false) entry, so the loaded `e` is stale after a move
		// completes. Reload so we observe the new entry's cleared flag.
		v, ok = p.streamMap.Load(streamID)
		if !ok {
			return // stream gone (slot death broke it) — stop waiting
		}
		if ne, ok := v.(*streamEntry); ok {
			e = ne
		}
	}
}

// sendMigrateOrHook routes through the test hook when one is installed, else
// performs the real sendMigrate wire round-trip. Both the preemptive watchdog
// (migrateStream) and the reactive slot-death path (resumeStreamOnDeath) call
// through here so a single hook intercepts every migration send in tests.
func (p *WSPoolTransport) sendMigrateOrHook(streamID uint16, kind byte, targetIdx int) migrateResult {
	if p.migrateSendHook != nil {
		return p.migrateSendHook(streamID, kind, targetIdx)
	}
	return p.sendMigrate(p.client, streamID, kind, targetIdx)
}

// resolveMigrateReplyPayload parses a MIGRATE/RESUME reply payload and resolves
// the pending ack for its streamID. Splitting decrypt (handleMigrateReplyFrame)
// from parse keeps the resolve path unit-testable with a raw payload.
func (p *WSPoolTransport) resolveMigrateReplyPayload(payload []byte) {
	okStatus, sid, resumeSeq, reason, perr := core.ParseMigrateReply(payload)
	if perr != nil {
		return // malformed reply — drop
	}
	v, loaded := p.pendingMigrateAcks.LoadAndDelete(sid)
	if !loaded {
		return // no awaiter (timed out or never sent) — drop
	}
	ch, ok := v.(chan migrateResult)
	if !ok {
		return
	}
	res := migrateResult{}
	if okStatus {
		res.kind = migrateResultOK
		res.resumeDownSeq = resumeSeq
	} else {
		res.kind = migrateResultFail
		res.reason = reason
	}
	// Buffered(1) chan — never blocks. A second reply for the same sid can't
	// reach here because LoadAndDelete already removed the entry.
	ch <- res
}
