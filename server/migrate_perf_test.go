package server

import (
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// migrate_perf_test.go — Bug #9 Task 21, Part 2 (perf acceptance). After a
// preemptive migration, every stream that moved onto the SAME target slot now
// runs its downlink through that slot's single *core.Session. enqueueDownFrame
// (relay_registry.go) calls session.NextSeqNum() on EVERY frame, and NextSeqNum
// takes the session's sync.Mutex (core/session.go:141-147). So N relays all
// bound to one session B serialize their per-frame seq advance on ONE mutex —
// a contention point that does not exist while streams are spread across N
// sessions (the "baseline").
//
// These benchmarks quantify that contention, and TestSessionMuContention_*
// turns it into a regression GATE: the all-on-one throughput must stay within a
// documented fraction of the spread baseline. If it ever falls below the
// threshold the §8 mitigation note in the spec (shard the downlink seq off the
// session mutex, e.g. a per-relay atomic downSeq already exists — the SESSION
// seq could likewise move to an atomic) must be revisited.
//
// We exercise the REAL hot path: enqueueDownFrame → NextSeqNum + EncryptChunk +
// writer.Enqueue, with a drain-only writer so the channel never blocks and the
// measured cost is the seq-mutex + crypto, not I/O.

// benchSession builds a self-encrypting session with a cached GCM send-epoch
// (so EncryptChunk uses the atomic-nonce fast path and the ONLY shared mutex on
// the hot path is the NextSeqNum send-seq lock — exactly the contention under
// test). Mirrors newSelfSession but takes testing.TB so benchmarks can use it.
func benchSession(tb testing.TB) *core.Session {
	tb.Helper()
	sm := core.NewSessionManager(5 * time.Minute)
	key := make([]byte, 32)
	key[0] = 0x5A
	key[7] = 0xC3
	sess, err := sm.Create(key, key)
	if err != nil {
		tb.Fatalf("create session: %v", err)
	}
	return sess
}

// drainWriter is a WSConnWriter that discards every frame immediately so the
// async writer's outbound channel never backs up — isolating the measurement to
// the seq-mutex + encrypt cost rather than socket I/O.
type drainWriter struct{}

func (drainWriter) WriteMessage(_ int, _ []byte) error  { return nil }
func (drainWriter) SetWriteDeadline(_ time.Time) error  { return nil }

// newBenchRelay builds a migratable relayEntry bound to sess with a generous
// credit/buffer so neither throttles the benchmark. The egress tc is left nil —
// the benchmark drives enqueueDownFrame directly (the downlink encrypt+enqueue
// path), which is where the session-mutex contention lives; tc.Read is not on
// that path.
func newBenchRelay(tb testing.TB, streamID uint16, sess *core.Session, w *core.WSAsyncWriter) *relayEntry {
	e := &relayEntry{
		globalStreamID: streamID,
		downBuffer:     newBoundedBuffer(1 << 20),
		unackedTail:    newBoundedBuffer(1 << 20),
		credit:         newStreamCredit(1 << 30),
	}
	e.state.Store(stActive)
	e.bound.Store(&binding{session: sess, writer: w})
	return e
}

// contentionRig is a pre-built set of N relays (all-on-one OR spread) plus the
// writers it owns. Setup (session + async-writer construction, which is what
// dominated the earlier naive benchmark) is done ONCE in newContentionRig and
// kept OUT of the timed push so the measurement isolates the per-frame
// enqueueDownFrame cost — i.e. the NextSeqNum mutex contention under test, not
// 256 session-creations per iteration.
type contentionRig struct {
	relays  []*relayEntry
	writers []*core.WSAsyncWriter // all writers to Close on teardown
}

func newContentionRig(tb testing.TB, n int, allOnOne bool) *contentionRig {
	rig := &contentionRig{relays: make([]*relayEntry, n)}
	var sharedSess *core.Session
	var sharedWriter *core.WSAsyncWriter
	if allOnOne {
		sharedSess = benchSession(tb)
		sharedWriter = core.NewWSAsyncWriter(drainWriter{}, 1<<16)
		go func() { _ = sharedWriter.Run() }()
		rig.writers = append(rig.writers, sharedWriter)
	}
	for i := 0; i < n; i++ {
		if allOnOne {
			rig.relays[i] = newBenchRelay(tb, uint16(i+1), sharedSess, sharedWriter)
		} else {
			s := benchSession(tb)
			w := core.NewWSAsyncWriter(drainWriter{}, 1<<16)
			go func() { _ = w.Run() }()
			rig.writers = append(rig.writers, w)
			rig.relays[i] = newBenchRelay(tb, uint16(i+1), s, w)
		}
	}
	return rig
}

func (rig *contentionRig) close() {
	for _, w := range rig.writers {
		w.Close()
	}
}

// push concurrently drives every relay to enqueue framesPerRelay frames of
// frameSize bytes through the production enqueueDownFrame path. Returns when all
// relays are done. This is the region the contention gate times.
func (rig *contentionRig) push(framesPerRelay, frameSize int) {
	frame := pendingDownFrame{seq: 1, data: make([]byte, frameSize)}
	var wg sync.WaitGroup
	wg.Add(len(rig.relays))
	for _, e := range rig.relays {
		go func(e *relayEntry) {
			defer wg.Done()
			b := e.bound.Load()
			for j := 0; j < framesPerRelay; j++ {
				// enqueueDownFrame is the production hot path: NextSeqNum (mutex)
				// + EncryptChunk (atomic nonce) + writer.Enqueue (channel).
				e.enqueueDownFrame(b, true /*migrateEnabled*/, frame)
			}
		}(e)
	}
	wg.Wait()
}

// runContention builds a rig and pushes — used by the benchmarks (which WANT the
// setup cost folded into b.N so allocs/op is reported honestly per full run).
func runContention(tb testing.TB, n, framesPerRelay, frameSize int, allOnOne bool) {
	rig := newContentionRig(tb, n, allOnOne)
	defer rig.close()
	rig.push(framesPerRelay, frameSize)
}

// BenchmarkRelayContention_AllOnOneSlot: N relays all migrated onto ONE session
// B — every frame contends the same NextSeqNum mutex. This is the worst case a
// migration storm can produce (all of one aging slot's streams move to the same
// youngest slot).
func BenchmarkRelayContention_AllOnOneSlot(b *testing.B) {
	const (
		n         = 256
		frameSize = 4096
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runContention(b, n, 32, frameSize, true)
	}
}

// BenchmarkRelayContention_SpreadBaseline: N relays on N distinct sessions — no
// shared mutex. The throughput delta vs AllOnOneSlot is the cost the migration-
// collapse contention imposes.
func BenchmarkRelayContention_SpreadBaseline(b *testing.B) {
	const (
		n         = 256
		frameSize = 4096
	)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		runContention(b, n, 32, frameSize, false)
	}
}

// TestSessionMuContention_NoThroughputCliff is the regression GATE. With N=256
// relays each pushing a fixed number of frames, it measures wall-clock for the
// all-on-one case and the spread baseline and asserts the all-on-one throughput
// stays at or above a documented fraction of the baseline.
//
// THRESHOLD — documented, not tuned to pass:
//
//	NextSeqNum holds the mutex for a handful of instructions (read+increment a
//	uint32). EncryptChunk is OUTSIDE that lock (atomic-nonce GCM fast path), so
//	the serialized critical section is tiny relative to the per-frame encrypt +
//	channel-send work. We therefore expect the all-on-one case to retain the
//	bulk of baseline throughput. We gate at 25% of baseline: a regression that
//	moved real work (e.g. the encrypt) under the session mutex, or reintroduced
//	a coarse per-session lock around the whole enqueue, would collapse far below
//	25% and trip this gate → revisit the §8 mitigation (move the session send-seq
//	to an atomic, as the per-relay downSeq already is). The generous margin keeps
//	the gate noise-robust on shared CI while still catching an order-of-magnitude
//	contention regression.
//
// If this test fails, DO NOT relax the threshold — investigate whether new work
// crept under core.Session.mu, and add the §8 atomic-seq mitigation note to the
// spec.
func TestSessionMuContention_NoThroughputCliff(t *testing.T) {
	if testing.Short() {
		t.Skip("contention timing test skipped in -short")
	}
	const (
		n              = 256
		framesPerRelay = 64
		frameSize      = 4096
		ratioFloor     = 0.25 // all-on-one must be >= 25% of spread throughput
	)

	// Build both rigs ONCE — session/writer construction (which dominates a naive
	// per-iteration build) is excluded from the timed region so the measurement
	// isolates the per-frame enqueueDownFrame cost (the NextSeqNum mutex under
	// test), not 256 session-creations.
	spreadRig := newContentionRig(t, n, false)
	defer spreadRig.close()
	allOneRig := newContentionRig(t, n, true)
	defer allOneRig.close()

	// Warm up allocator / GC once so the first measured run isn't skewed.
	spreadRig.push(8, frameSize)
	allOneRig.push(8, frameSize)

	// Take the best of a few runs to reduce CI-scheduler noise (min wall-clock
	// is the least-perturbed sample of the underlying cost).
	best := func(rig *contentionRig) time.Duration {
		bestD := time.Hour
		for i := 0; i < 5; i++ {
			start := time.Now()
			rig.push(framesPerRelay, frameSize)
			if d := time.Since(start); d < bestD {
				bestD = d
			}
		}
		return bestD
	}

	spread := best(spreadRig)
	allOne := best(allOneRig)

	totalFrames := float64(n * framesPerRelay)
	spreadTput := totalFrames / spread.Seconds()
	allOneTput := totalFrames / allOne.Seconds()
	ratio := allOneTput / spreadTput

	t.Logf("session-mu contention: spread=%.0f frames/s, all-on-one=%.0f frames/s, ratio=%.3f (floor=%.2f) [spread=%s allOne=%s]",
		spreadTput, allOneTput, ratio, ratioFloor, spread, allOne)

	if ratio < ratioFloor {
		t.Fatalf("all-on-one throughput collapsed to %.1f%% of baseline (floor %.0f%%) — "+
			"the session NextSeqNum mutex (or new work under core.Session.mu) is a throughput cliff; "+
			"revisit §8 mitigation (move session send-seq to an atomic like the per-relay downSeq)",
			ratio*100, ratioFloor*100)
	}
}
