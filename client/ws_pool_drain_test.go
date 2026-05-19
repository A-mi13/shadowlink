package client

import (
	"testing"
	"time"
)

// TestCountNonReadySlots_IgnoresEmptyReserve verifies that nil cells in
// the reserve range (i >= poolSize) do NOT inflate the non-ready count.
// This guards the storm brake against permanent activation after slice
// expansion to 2*poolSize.
func TestCountNonReadySlots_IgnoresEmptyReserve(t *testing.T) {
	p := &WSPoolTransport{poolSize: 4}
	p.slots = make([]*poolSlot, 8) // 4 primary + 4 reserve, all nil

	// All 4 primary are nil → all count as non-ready (capacity = 0)
	if got := p.countNonReadySlots(); got != 4 {
		t.Errorf("countNonReadySlots with all-nil primary = %d, want 4", got)
	}

	// Fill 4 primary as ready
	for i := range 4 {
		p.slots[i] = &poolSlot{}
		p.slots[i].setState(slotReady)
	}
	// Reserve still all nil
	if got := p.countNonReadySlots(); got != 0 {
		t.Errorf("countNonReadySlots with 4 primary ready + 4 nil reserve = %d, want 0 (reserve nil = empty, not non-ready)", got)
	}

	// One primary draining, 3 ready, reserve still nil
	p.slots[0].setState(slotDraining)
	if got := p.countNonReadySlots(); got != 1 {
		t.Errorf("countNonReadySlots with 1 draining primary = %d, want 1", got)
	}

	// Add a reserve slot in slotConnecting state — this is the parallel
	// drain replacement for primary[0] (which is slotDraining). Per the
	// countNonReadySlots design (parallel-replacement exception), this
	// reserve cell is NOT counted as non-ready because its matching
	// primary is in slotDraining: capacity is being maintained, not
	// lost. The non-ready count therefore stays at 1 (the primary
	// draining itself).
	p.slots[4] = &poolSlot{}
	p.slots[4].setState(slotConnecting)
	if got := p.countNonReadySlots(); got != 1 {
		t.Errorf("countNonReadySlots with 1 draining primary + 1 connecting reserve (parallel replacement) = %d, want 1 (reserve connecting paired with draining primary is exempted)", got)
	}

	// Sanity: a reserve slotConnecting WITHOUT a matching primary
	// slotDraining IS counted (it's a genuine non-ready cell, not a
	// parallel replacement). Use slot 5 (reserve) paired with primary[1]
	// which is in slotReady.
	p.slots[5] = &poolSlot{}
	p.slots[5].setState(slotConnecting)
	if got := p.countNonReadySlots(); got != 2 {
		t.Errorf("countNonReadySlots with 1 draining primary + 1 paired-parallel reserve + 1 standalone reserve connecting = %d, want 2 (standalone reserve connecting counts)", got)
	}
}

// countingTransport is a minimal stub satisfying wsSlotTransport for
// write-routing tests. It records how many data / control writes it
// received so the test can assert which slot's transport was hit.
type countingTransport struct {
	writes        int
	controlWrites int
}

func (c *countingTransport) WriteMessage(data []byte) error {
	c.writes++
	return nil
}
func (c *countingTransport) WriteControlMessage(data []byte) error {
	c.controlWrites++
	return nil
}
func (c *countingTransport) ReadMessage(timeout time.Duration) ([]byte, error) {
	return nil, nil
}
func (c *countingTransport) Close() error            { return nil }
func (c *countingTransport) LastWriteUnixNano() int64 { return 0 }

// TestWriteMessageForStream_AcceptsDraining verifies that a stream
// assigned to a slot that has transitioned to slotDraining continues
// to write through that slot's transport (not a random ready fallback).
// Critical for crypto correctness — the draining slot's session is
// still the one the server expects for this stream.
func TestWriteMessageForStream_AcceptsDraining(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{
		Size:       2,
		ServerAddr: "127.0.0.1:0",
	})

	stubDraining := &countingTransport{}
	p.slots[0] = &poolSlot{transport: stubDraining}
	p.slots[0].setState(slotDraining)

	stubReady := &countingTransport{}
	p.slots[1] = &poolSlot{transport: stubReady}
	p.slots[1].setState(slotReady)

	p.streamMap.Store(uint16(42), 0)

	if err := p.WriteMessageForStream(42, []byte("hello")); err != nil {
		t.Fatalf("WriteMessageForStream returned err: %v", err)
	}
	if stubDraining.writes != 1 {
		t.Errorf("draining slot transport got %d writes, want 1", stubDraining.writes)
	}
	if stubReady.writes != 0 {
		t.Errorf("ready slot got %d writes, want 0 (must not fall back)", stubReady.writes)
	}
}

// TestWriteControlMessageForStream_AcceptsDraining mirrors the data-path
// test for the control-frame path.
func TestWriteControlMessageForStream_AcceptsDraining(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 2, ServerAddr: "127.0.0.1:0"})

	stubDraining := &countingTransport{}
	p.slots[0] = &poolSlot{transport: stubDraining}
	p.slots[0].setState(slotDraining)
	stubReady := &countingTransport{}
	p.slots[1] = &poolSlot{transport: stubReady}
	p.slots[1].setState(slotReady)
	p.streamMap.Store(uint16(43), 0)

	if err := p.WriteControlMessageForStream(43, []byte("ctrl")); err != nil {
		t.Fatalf("WriteControlMessageForStream returned err: %v", err)
	}
	if stubDraining.controlWrites != 1 {
		t.Errorf("draining slot got %d control writes, want 1", stubDraining.controlWrites)
	}
	if stubReady.controlWrites != 0 {
		t.Errorf("ready slot got %d control writes, want 0", stubReady.controlWrites)
	}
}
