package client

import (
	"testing"
	"time"
)

// Bug #9 (2026-05-31): a quiet long-lived stream (user waiting 5+ min for an
// AI-agent reply, almost no bytes) left its slot silent long enough for the РФ
// TSPU / a stateful middlebox to cut the direct-mode bare-origin TCP
// (close 1006, last_write_age_ms=10000-15000 in the field log). The slot's
// streams are force-closed in handleSlotDeath and do NOT migrate, so the
// session dies unrecoverably.
//
// Root cause: keepalive base was 20s → JitteredIntervalLogNormal truncates to
// [base/2, base*2] = [10s, 40s], routinely exceeding the ~10-15s cut window.
//
// These tests pin the invariant: the worst-case keepalive silence window
// (base*2) must stay at or under the middlebox silent-cut threshold.

// middleboxSilentCutFloor объявлена в ws_pool.go рядом с keepaliveSpreadMax,
// которую она ограничивает. Здесь её быть не должно: пока константа жила в
// _test.go, сторожа сравнивали продовую величину с тестовой, то есть менять
// порог в проде было негде.

// TestKeepalive_DefaultBaseUnderMiddleboxCut is the RED test for Bug #9:
// with the default config the keepalive max silence window (base*2 from the
// log-normal truncation) must be <= the middlebox silent-cut floor. Under the
// pre-fix 20s base this asserts 40s <= 10s and fails.
func TestKeepalive_DefaultBaseUnderMiddleboxCut(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 6, ServerAddr: "127.0.0.1:0"})

	if p.keepaliveBase <= 0 {
		t.Fatalf("keepaliveBase not initialized: %v", p.keepaliveBase)
	}
	maxGap := p.keepaliveBase * 2 // JitteredIntervalLogNormal truncates to [base/2, base*2]
	if maxGap > middleboxSilentCutFloor {
		t.Fatalf("keepalive max silence window = %v (base=%v) exceeds middlebox silent-cut floor %v — "+
			"a quiet slot can be reaped before the next keepalive (Bug #9)",
			maxGap, p.keepaliveBase, middleboxSilentCutFloor)
	}
}

// TestKeepalive_SampledDelaysNeverExceedMaxGap drives the actual sampler
// (nextKeepaliveDelay) many times and confirms NO draw exceeds base*2 — i.e.
// the truncation rail the invariant relies on actually holds for this pool's
// configured base. Guards against a future refactor that swaps the sampler for
// one without the [base/2, base*2] truncation.
func TestKeepalive_SampledDelaysNeverExceedMaxGap(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 4, ServerAddr: "127.0.0.1:0"})

	maxGap := p.keepaliveBase * 2
	minGap := p.keepaliveBase / 2
	const draws = 20000
	for i := 0; i < draws; i++ {
		d := p.nextKeepaliveDelay()
		if d > maxGap {
			t.Fatalf("draw %d = %v exceeds max gap %v (base=%v)", i, d, maxGap, p.keepaliveBase)
		}
		if d < minGap {
			t.Fatalf("draw %d = %v below min gap %v (base=%v)", i, d, minGap, p.keepaliveBase)
		}
	}
	// Sanity: with the 5s default, every draw must also clear the cut floor.
	if maxGap > middleboxSilentCutFloor {
		t.Fatalf("default base %v gives max gap %v > cut floor %v", p.keepaliveBase, maxGap, middleboxSilentCutFloor)
	}
}

// TestKeepalive_EnvOverrideHonored confirms a caller-supplied KeepaliveInterval
// (the SHADOWLINK_KEEPALIVE_INTERVAL field-tuning path) is honored, and that a
// zero/negative value falls back to the safe default rather than producing a
// zero-interval busy loop.
func TestKeepalive_EnvOverrideHonored(t *testing.T) {
	cl := &Client{streamChans: make(map[uint16]chan []byte)}

	custom := 3 * time.Second
	p := NewWSPoolTransport(cl, WSPoolConfig{Size: 2, ServerAddr: "127.0.0.1:0", KeepaliveInterval: custom})
	if p.keepaliveBase != custom {
		t.Fatalf("KeepaliveInterval override not honored: got %v want %v", p.keepaliveBase, custom)
	}

	// Zero → default (not a zero-interval busy loop).
	pz := NewWSPoolTransport(cl, WSPoolConfig{Size: 2, ServerAddr: "127.0.0.1:0", KeepaliveInterval: 0})
	if pz.keepaliveBase != keepaliveDefaultBase {
		t.Fatalf("zero KeepaliveInterval should default to %v, got %v", keepaliveDefaultBase, pz.keepaliveBase)
	}

	// Negative → default too.
	pn := NewWSPoolTransport(cl, WSPoolConfig{Size: 2, ServerAddr: "127.0.0.1:0", KeepaliveInterval: -1})
	if pn.keepaliveBase != keepaliveDefaultBase {
		t.Fatalf("negative KeepaliveInterval should default to %v, got %v", keepaliveDefaultBase, pn.keepaliveBase)
	}
}
