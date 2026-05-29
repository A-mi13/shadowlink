package client

import "testing"

func TestEffectiveStickyMaxSlots(t *testing.T) {
	cases := []struct {
		name       string
		poolSize   int
		cfgMax     int
		wantResult int
	}{
		{"auto half of 6", 6, 0, 3},
		{"auto half of 8", 8, 0, 4},
		{"auto poolSize 2 → min 1", 2, 0, 1},
		{"auto odd 5 → 2", 5, 0, 2},
		{"explicit 1", 6, 1, 1},
		{"explicit cap above half", 6, 5, 5},
		{"negative → disabled (0)", 6, -1, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &WSPoolTransport{poolSize: tc.poolSize, stickyMaxSlots: tc.cfgMax}
			if got := p.effectiveStickyMaxSlots(); got != tc.wantResult {
				t.Errorf("poolSize=%d cfgMax=%d: got %d, want %d",
					tc.poolSize, tc.cfgMax, got, tc.wantResult)
			}
		})
	}
}

func TestStickyMarkReleaseIdempotent(t *testing.T) {
	p := &WSPoolTransport{poolSize: 6, stickyMaxSlots: 0}
	slot := &poolSlot{index: 0}

	p.markSticky(slot)
	p.markSticky(slot) // idempotent via CAS
	if got := p.stickyDrainCount.Load(); got != 1 {
		t.Fatalf("after 2× markSticky: count=%d, want 1", got)
	}
	if !slot.isSticky.Load() {
		t.Fatal("isSticky should be true after markSticky")
	}

	p.releaseSticky(slot)
	p.releaseSticky(slot) // idempotent via Swap
	if got := p.stickyDrainCount.Load(); got != 0 {
		t.Fatalf("after 2× releaseSticky: count=%d, want 0", got)
	}
	if slot.isSticky.Load() {
		t.Fatal("isSticky should be false after releaseSticky")
	}
}

func TestStickyQuotaAvailable(t *testing.T) {
	newReadyPool := func(size, cfgMax int) *WSPoolTransport {
		p := &WSPoolTransport{poolSize: size, stickyMaxSlots: cfgMax}
		p.slots = make([]*poolSlot, 2*size)
		for i := 0; i < size; i++ {
			s := &poolSlot{index: i}
			s.state.Store(int32(slotReady))
			p.slots[i] = s
		}
		return p
	}

	t.Run("already sticky → always allowed", func(t *testing.T) {
		p := newReadyPool(6, 0)
		s := &poolSlot{index: 0}
		s.isSticky.Store(true)
		if !p.stickyQuotaAvailable(s) {
			t.Fatal("already-sticky slot must always be allowed to extend")
		}
	})
	t.Run("under cap + healthy capacity → allowed", func(t *testing.T) {
		p := newReadyPool(6, 0)
		s := &poolSlot{index: 0}
		if !p.stickyQuotaAvailable(s) {
			t.Fatal("fresh slot under cap with healthy capacity should be allowed")
		}
	})
	t.Run("at static cap → denied", func(t *testing.T) {
		p := newReadyPool(6, 0)
		p.stickyDrainCount.Store(3)
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("at static cap, new sticky must be denied")
		}
	})
	t.Run("capacity at floor → denied", func(t *testing.T) {
		p := newReadyPool(6, 0)
		for i := 0; i < 6; i++ {
			p.slots[i].state.Store(int32(slotDraining))
		}
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("at/below capacity floor, new sticky must be denied")
		}
	})
	t.Run("disabled cap (cfgMax<0) → denied", func(t *testing.T) {
		p := newReadyPool(6, -1)
		s := &poolSlot{index: 0}
		if p.stickyQuotaAvailable(s) {
			t.Fatal("cfgMax<0 disables sticky → denied")
		}
	})
}
