package client

import (
	"testing"
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
