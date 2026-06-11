package client

import (
	"context"
	"sync"
	"testing"
	"time"
)

// genProbeTransport records the slot's generation value observed at the
// moment Close() is called. The M4 fix requires legacyRotateOneSlot to bump
// generation BEFORE tearing the transport down, so genAtClose must already be
// past the pre-rotation value.
type genProbeTransport struct {
	slot       *poolSlot
	genAtClose uint64
	closed     bool
}

func (g *genProbeTransport) ReadMessage(_ time.Duration) ([]byte, error) { return nil, nil }
func (g *genProbeTransport) LastWriteUnixNano() int64                    { return 0 }
func (g *genProbeTransport) WriteMessage(_ []byte) error                 { return nil }
func (g *genProbeTransport) WriteControlMessage(_ []byte) error          { return nil }
func (g *genProbeTransport) Close() error {
	g.closed = true
	g.genAtClose = g.slot.generation.Load()
	return nil
}

// TestLegacyRotateOneSlot_BumpsGenerationBeforeClose is the M4 regression
// (audit 2026-06-11): the legacy (non-graceful) rotation path must advance
// slot.generation before transport.Close, mirroring the graceful tearDown and
// tryForceEvictIdleSlot. Without it, the old reader blocked in ReadMessage
// gets a closed-conn error, shouldExitReader returns false (gen unchanged),
// and it calls handleSlotDeath(deathCauseNatural) — a false meltdown signal
// for a rotation we initiated.
func TestLegacyRotateOneSlot_BumpsGenerationBeforeClose(t *testing.T) {
	cl := &Client{
		streamChans: make(map[uint16]chan []byte),
		transport:   failingHandshakeTransport{}, // reconnect handshake fails fast, no panic
		serverPub:   make([]byte, 32),
		clientID:    []byte("test-client-id"),
	}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:          1,
		ServerAddr:    "127.0.0.1:1", // unreachable — reconnect handshake fails, harmless
		GracefulDrain: false,         // legacy path
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // stop the post-reconnect reconnectLoop goroutine after the test
	p.ctx = ctx
	p.client = cl

	slot := &poolSlot{index: 0}
	slot.setState(slotReady)
	slot.streams.Store(0) // idle → legacy drain loop hits goto reconnect on first 500ms tick
	probe := &genProbeTransport{slot: slot}
	slot.transport = probe
	p.storeSlot(0, slot)

	genBefore := slot.generation.Load()
	// legacyRotateOneSlot: streams==0 → first ticker tick (~500ms) jumps to
	// reconnect, bumps generation, Close()s the probe, then connectSlot fails
	// (unreachable addr) and spawns reconnectLoop (canceled by defer above).
	p.legacyRotateOneSlot(0)

	if !probe.closed {
		t.Fatal("transport.Close was not called by legacyRotateOneSlot")
	}
	if probe.genAtClose <= genBefore {
		t.Errorf("generation at Close = %d, want > %d (bump must precede Close)",
			probe.genAtClose, genBefore)
	}
}

// TestSlotAt_ReturnsCellUnderLock verifies the centralized single-cell
// accessor returns the installed pointer and a nil for empty/out-of-range
// cells without panicking. The behavioral guarantee is trivial; the real
// payoff is that slotAt takes reserveMu so a concurrent writer cannot tear
// the read (see TestSlotsAccess_NoRaceUnderConcurrentLifecycle, which the
// Linux -race detector validates).
func TestSlotAt_ReturnsCellUnderLock(t *testing.T) {
	p := &WSPoolTransport{slots: make([]*poolSlot, 4)}
	s := &poolSlot{index: 2}
	p.storeSlot(2, s)

	if got := p.slotAt(2); got != s {
		t.Fatalf("slotAt(2) = %v, want %v", got, s)
	}
	if got := p.slotAt(0); got != nil {
		t.Fatalf("slotAt(0) = %v, want nil (empty cell)", got)
	}
	// Out-of-range must be safe (return nil, no panic).
	if got := p.slotAt(-1); got != nil {
		t.Fatalf("slotAt(-1) = %v, want nil", got)
	}
	if got := p.slotAt(99); got != nil {
		t.Fatalf("slotAt(99) = %v, want nil", got)
	}
}

// TestStoreSlot_NilsAndInstalls verifies storeSlot installs and clears
// cells under the lock, mirroring connectSlot's install and
// handleSlotDeath's teardown nil-write.
func TestStoreSlot_NilsAndInstalls(t *testing.T) {
	p := &WSPoolTransport{slots: make([]*poolSlot, 2)}
	s := &poolSlot{index: 0}
	p.storeSlot(0, s)
	if p.slotAt(0) != s {
		t.Fatal("storeSlot did not install pointer")
	}
	p.storeSlot(0, nil)
	if p.slotAt(0) != nil {
		t.Fatal("storeSlot(nil) did not clear cell")
	}
	// Out-of-range store must be a no-op (no panic).
	p.storeSlot(5, s)
}

// TestSlotsAccess_NoRaceUnderConcurrentLifecycle stress-exercises the
// centralized accessors against concurrent installs/teardowns. On amd64
// without -race this just confirms no panic/corruption; the decisive check
// is `go test -race` on Linux/CI, where any unguarded p.slots[idx] read by a
// reader path would fire the detector. Kept here so the concurrency contract
// is encoded next to the helpers and runs in CI -race.
func TestSlotsAccess_NoRaceUnderConcurrentLifecycle(t *testing.T) {
	const cells = 8
	p := &WSPoolTransport{slots: make([]*poolSlot, cells)}
	for i := 0; i < cells; i++ {
		s := &poolSlot{index: i}
		s.setState(slotReady)
		p.storeSlot(i, s)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: emulate connectSlot install + handleSlotDeath teardown,
	// the two real reserveMu writers, racing each cell.
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				idx := seed % cells
				ns := &poolSlot{index: idx}
				ns.setState(slotReady)
				p.storeSlot(idx, ns) // install
				p.storeSlot(idx, nil) // teardown
				seed++
			}
		}(w)
	}

	// Readers: emulate the single-cell read paths (slotReaderWithClient,
	// WriteMessageForStream, slotForMigrate) and the iteration paths
	// (readyCapacity, WriteMessage) — all now via the centralized helpers.
	for r := 0; r < 6; r++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if s := p.slotAt(seed % cells); s != nil {
					_ = s.getState()
				}
				_ = p.readyCapacity()
				for _, s := range p.snapshotSlots() {
					if s != nil {
						_ = s.getState()
					}
				}
				seed++
			}
		}(r)
	}

	// Brief stress window; CI -race makes even a short window decisive.
	for i := 0; i < 2000; i++ {
		_ = p.slotAt(i % cells)
	}
	close(stop)
	wg.Wait()
}
