package server

import (
	"net"
	"testing"
	"time"
)

// Task 12 (Bug#9, F5/F6/F13): orphan DoS caps + FD budget + idle-only eviction.
//
// Semantics established by these tests (and matched by admitOrphan):
//   - admitOrphan(clientID, e) is the admission gate the WS-death cleanup calls
//     BEFORE it decides to HOLD an orphaned relay's egress conn open through the
//     grace window. The entry is already present in the registry (the relay was
//     registered at CONNECT) — admitOrphan therefore answers "may THIS client
//     hold ONE MORE orphaned relay?", counting the relays already in the map.
//   - With perClient=2 and 2 relays present, the cap is reached: the gate first
//     tries to make room by evicting an IDLE orphan; if none is idle it rejects.
//   - FD budget of 0 always rejects (no headroom to hold a conn open).
//   - Eviction NEVER touches an stActive entry, and among idle orphans picks the
//     least-recently-used (oldest lastDownlink) first.

func TestOrphanAdmit_RejectsWhenPerClientFull(t *testing.T) {
	r := newRelayRegistry()
	r.setLimits(2 /*perClient*/, 100 /*total*/, 100 /*fdBudget*/)
	// 2 orphaned, both recent (not idle) → 3rd reject (nothing to evict).
	for i := uint16(0); i < 2; i++ {
		e := &relayEntry{originClientID: "c1", globalStreamID: i}
		e.state.Store(stOrphaned)
		e.lastDownlinkNs.Store(time.Now().UnixNano()) // recent → not idle
		r.add("c1", i, e)
		if !r.admitOrphan("c1", e) {
			t.Fatalf("admit %d should pass", i)
		}
	}
	e3 := &relayEntry{originClientID: "c1", globalStreamID: 99}
	e3.state.Store(stOrphaned)
	r.add("c1", 99, e3)
	if r.admitOrphan("c1", e3) {
		t.Fatal("per-client full with all-recent → must reject")
	}
}

func TestOrphanAdmit_EvictsIdleWhenPerClientFull(t *testing.T) {
	r := newRelayRegistry()
	r.setLimits(2, 100, 100)
	// 2 orphaned, ONE idle (old lastDownlink) → on 3rd admit the idle one is
	// evicted and the new admit succeeds.
	old := &relayEntry{originClientID: "c1", globalStreamID: 1, tc: discardConn()}
	old.state.Store(stOrphaned)
	old.holdsFD = true
	old.lastDownlinkNs.Store(time.Now().Add(-5 * time.Second).UnixNano()) // idle
	r.add("c1", 1, old)
	r.admitOrphan("c1", old)

	recent := &relayEntry{originClientID: "c1", globalStreamID: 2}
	recent.state.Store(stOrphaned)
	recent.holdsFD = true
	recent.lastDownlinkNs.Store(time.Now().UnixNano())
	r.add("c1", 2, recent)
	r.admitOrphan("c1", recent)

	// per-client full (2); new → evictIdleOrphan removes old (idle), admit passes.
	e3 := &relayEntry{originClientID: "c1", globalStreamID: 3}
	e3.state.Store(stOrphaned)
	r.add("c1", 3, e3)
	if !r.admitOrphan("c1", e3) {
		t.Fatal("idle orphan should have been evicted to make room")
	}
	if _, ok := r.find("c1", 1); ok {
		t.Fatal("idle orphan (stream 1) should have been evicted")
	}
}

func TestOrphanAdmit_FDBudgetReject(t *testing.T) {
	r := newRelayRegistry()
	r.setLimits(100, 100, 0 /*fdBudget=0 → always reject*/)
	if r.admitOrphan("c1", &relayEntry{}) {
		t.Fatal("zero FD budget must reject orphan hold")
	}
}

func TestEviction_SkipsActiveMigrating(t *testing.T) {
	r := newRelayRegistry()
	r.setLimits(10, 10, 10)
	active := &relayEntry{originClientID: "c1", globalStreamID: 1, tc: discardConn()}
	active.state.Store(stActive) // active — must NOT be evicted
	active.lastDownlinkNs.Store(time.Now().Add(-10 * time.Second).UnixNano())
	r.add("c1", 1, active)
	r.evictIdleOrphan("c1")
	if _, ok := r.find("c1", 1); !ok {
		t.Fatal("active entry must NOT be evicted")
	}
}

func TestEviction_PicksIdleOrphanedLRU(t *testing.T) {
	r := newRelayRegistry()
	r.setLimits(10, 10, 10)
	older := &relayEntry{originClientID: "c1", globalStreamID: 1, tc: discardConn()}
	older.state.Store(stOrphaned)
	older.lastDownlinkNs.Store(time.Now().Add(-10 * time.Second).UnixNano())
	newer := &relayEntry{originClientID: "c1", globalStreamID: 2, tc: discardConn()}
	newer.state.Store(stOrphaned)
	newer.lastDownlinkNs.Store(time.Now().Add(-3 * time.Second).UnixNano())
	r.add("c1", 1, older)
	r.add("c1", 2, newer)
	r.evictIdleOrphan("c1")
	if _, ok := r.find("c1", 1); ok {
		t.Fatal("oldest idle orphan (stream 1) should be evicted first")
	}
	if _, ok := r.find("c1", 2); !ok {
		t.Fatal("newer idle orphan should survive single eviction")
	}
}

// discardConn returns a net.Conn whose Close is a no-op-ish (one end of
// net.Pipe with the peer already closed) so evictIdleOrphan can call tc.Close()
// without a real socket.
func discardConn() net.Conn {
	a, b := net.Pipe()
	_ = b.Close()
	return a
}
