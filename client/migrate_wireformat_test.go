package client

import (
	"log/slog"
	"testing"

	"github.com/nixavpn/shadowlink/core"
)

// migrate_wireformat_test.go — audit 2026-06-11 H-C2 / H-C3.
//
// H-C2: an unparseable FlagData frame on a migration slot must NOT be silently
// dropped (a dropped already-decrypted downlink frame punches a hole in the TCP
// byte-stream → app-side corruption, the Bug#8 class). It must bump a counter
// AND deterministically tear the stream so the app gets EOF and retries.
//
// H-C3: the seq-tagged downlink decode shape must follow the SLOT's own
// migration negotiation (slot.migrateNegotiated), not the pool-wide
// migrateEnabled flag. A slot whose session negotiated the flat (legacy) wire
// format must keep flat-decoding its frames even after another slot flips the
// pool-wide bit true.

// newWireFmtTestPool builds a minimal pool with a real Client whose stream
// channels are wired, suitable for driving routeDownlinkFlagData directly.
func newWireFmtTestPool(t *testing.T, size int) (*WSPoolTransport, *Client) {
	t.Helper()
	cl := &Client{}
	cl.streamChans = make(map[uint16]chan []byte)
	cl.streamFramesChans = make(map[uint16]chan StreamFrame)
	cl.streamProof = make(map[uint16][32]byte)
	p := &WSPoolTransport{
		poolSize: size,
		client:   cl,
		log:      slog.Default(),
	}
	p.slots = make([]*poolSlot, size)
	for i := range p.slots {
		p.slots[i] = &poolSlot{index: i}
	}
	return p, cl
}

// registerStreamChans wires both the legacy (RouteToStream) and the seq
// (RouteToStreamSeq) channels for a streamID so the test can observe which path
// a frame took and whether the stream got closed.
func registerStreamChans(cl *Client, streamID uint16) (legacy chan []byte, seq chan StreamFrame) {
	legacy = make(chan []byte, 4)
	seq = make(chan StreamFrame, 4)
	cl.streamMu.Lock()
	cl.streamChans[streamID] = legacy
	cl.streamFramesChans[streamID] = seq
	cl.streamMu.Unlock()
	return legacy, seq
}

// chansClosed reports whether BOTH stream channels for streamID were removed
// from the client maps (handleStreamClose deletes + closes them).
func chansClosed(cl *Client, streamID uint16) bool {
	cl.streamMu.Lock()
	defer cl.streamMu.Unlock()
	_, hasLegacy := cl.streamChans[streamID]
	_, hasSeq := cl.streamFramesChans[streamID]
	return !hasLegacy && !hasSeq
}

// H-C2: an unparseable FlagData frame on a migration-negotiated slot must bump
// MigrationFrameUnparseable AND tear the stream (deterministic EOF), NOT drop.
func TestRouteDownlinkFlagData_UnparseableSeqFrame_TearsStreamAndCounts(t *testing.T) {
	p, cl := newWireFmtTestPool(t, 2)
	slot := p.slotAt(0)
	slot.migrateNegotiated.Store(true) // this slot negotiated the seq wire format

	const streamID uint16 = 7
	registerStreamChans(cl, streamID)

	before := Stats.MigrationFrameUnparseable.Load()

	// A FlagData frame whose payload is [streamID(2)] + 3 bytes of body. The
	// body is not a control string, and the total payload (5 bytes) is < 10 so
	// ParseStreamDataSeq returns perr != nil. Pre-fix: silent drop.
	payload := []byte{0x00, 0x07, 'x', 'y', 'z'}
	chunk := &core.Chunk{Flags: core.FlagData, Payload: payload}

	p.routeDownlinkFlagData(cl, slot, streamID, chunk)

	if got := Stats.MigrationFrameUnparseable.Load(); got != before+1 {
		t.Fatalf("MigrationFrameUnparseable = %d, want %d", got, before+1)
	}
	if !chansClosed(cl, streamID) {
		t.Fatalf("stream %d was not torn down on unparseable frame (silent drop regression)", streamID)
	}
}

// H-C2 negative: a well-formed seq frame on a migration slot routes via the seq
// path and does NOT bump the unparseable counter or close the stream.
func TestRouteDownlinkFlagData_ValidSeqFrame_RoutesSeq(t *testing.T) {
	p, cl := newWireFmtTestPool(t, 2)
	slot := p.slotAt(0)
	slot.migrateNegotiated.Store(true)

	const streamID uint16 = 9
	_, seqCh := registerStreamChans(cl, streamID)

	before := Stats.MigrationFrameUnparseable.Load()

	// [streamID(2)][downSeq=5(8)][data "hello"] — a valid seq-tagged data frame.
	chunk := core.NewStreamDataChunkSeq(0, 0, streamID, 5, []byte("hello"))

	p.routeDownlinkFlagData(cl, slot, streamID, chunk)

	if got := Stats.MigrationFrameUnparseable.Load(); got != before {
		t.Fatalf("MigrationFrameUnparseable bumped on a valid seq frame: %d -> %d", before, got)
	}
	select {
	case fr := <-seqCh:
		if fr.Seq != 5 || string(fr.Data) != "hello" {
			t.Fatalf("seq frame mis-routed: seq=%d data=%q", fr.Seq, fr.Data)
		}
	default:
		t.Fatalf("valid seq frame did not route to the seq channel")
	}
	if chansClosed(cl, streamID) {
		t.Fatalf("stream %d was torn down on a valid frame", streamID)
	}
}

// H-C3: slot 0's session negotiated the FLAT (legacy) wire format. After slot 1
// flips the pool-wide migrateEnabled bit true, slot 0's reader MUST keep
// flat-decoding its frames (follow the slot's own negotiation), not switch to
// seq-decode. A flat frame routed as seq would mis-parse the 8-byte downSeq out
// of real payload → H-C2 drop or mis-route.
func TestRouteDownlinkFlagData_FlatSlot_StaysFlat_AfterPoolFlip(t *testing.T) {
	p, cl := newWireFmtTestPool(t, 2)

	// Slot 1 negotiated migration and flips the pool-wide flag (as connectSlot
	// does). Slot 0 did NOT negotiate it — its session still speaks flat.
	p.slotAt(1).migrateNegotiated.Store(true)
	p.migrateEnabled.Store(true) // pool-wide flag is now true

	slot0 := p.slotAt(0)
	if slot0.migrateNegotiated.Load() {
		t.Fatal("precondition: slot 0 must not be migration-negotiated")
	}

	const streamID uint16 = 3
	legacyCh, seqCh := registerStreamChans(cl, streamID)

	before := Stats.MigrationFrameUnparseable.Load()

	// A flat FlagData frame: [streamID(2)][data "PONG"]. On the seq path the
	// 8 bytes after streamID would be mis-read as downSeq. On the correct flat
	// path it routes the data verbatim to the legacy channel.
	payload := []byte{0x00, 0x03, 'P', 'O', 'N', 'G'}
	chunk := &core.Chunk{Flags: core.FlagData, Payload: payload}

	p.routeDownlinkFlagData(cl, slot0, streamID, chunk)

	if got := Stats.MigrationFrameUnparseable.Load(); got != before {
		t.Fatalf("flat frame on a flat slot bumped unparseable counter: %d -> %d (desync: slot decoded as seq)", before, got)
	}
	if chansClosed(cl, streamID) {
		t.Fatalf("flat frame on a flat slot tore the stream (seq mis-decode regression)")
	}
	select {
	case data := <-legacyCh:
		if string(data) != "PONG" {
			t.Fatalf("flat frame mis-routed: data=%q want PONG", data)
		}
	default:
		t.Fatalf("flat frame did not route to the legacy channel (slot followed pool flag, not its own negotiation)")
	}
	select {
	case fr := <-seqCh:
		t.Fatalf("flat frame leaked onto the seq channel: %+v", fr)
	default:
	}
}
