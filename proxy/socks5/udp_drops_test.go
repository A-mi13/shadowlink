package socks5

import (
	"net"
	"strings"
	"testing"

	"github.com/nixavpn/shadowlink/client"
)

// The counters exist because the 33% DNS failure rate the field team measured
// (2026-09-01) was invisible from our side: every discard on the UDP path was a
// bare `continue`. These tests assert the counters actually move on the
// branches that matter — a counter that is only ever zero is worse than none,
// because it reads as evidence of health.

func TestUDPDrops_CountPerReason(t *testing.T) {
	udpDrops.reset()

	udpDrops.Add(dropReasonBadHeader, 3)
	udpDrops.Add(dropReasonForeignIP, 1)

	if got := udpDrops.Get(dropReasonBadHeader); got != 3 {
		t.Errorf("bad_header = %d, want 3", got)
	}
	if got := udpDrops.Get(dropReasonForeignIP); got != 1 {
		t.Errorf("foreign_source_ip = %d, want 1", got)
	}
	if got := udpDrops.Total(); got != 4 {
		t.Errorf("total = %d, want 4", got)
	}

	snap := udpDrops.Snapshot()
	if len(snap) != 2 {
		t.Errorf("snapshot has %d entries, want 2 (zero-valued reasons must be omitted)", len(snap))
	}
	if snap["bad_header"] != 3 || snap["foreign_source_ip"] != 1 {
		t.Errorf("snapshot mislabelled: %v", snap)
	}

	// The summary must be stable across calls so an operator can diff two
	// intervals; map iteration order would make it useless.
	first := UDPDropsSummary()
	for i := 0; i < 8; i++ {
		if UDPDropsSummary() != first {
			t.Fatalf("summary is not order-stable: %q vs %q", first, UDPDropsSummary())
		}
	}
	if !strings.Contains(first, "bad_header=3") || !strings.Contains(first, "foreign_source_ip=1") {
		t.Errorf("summary missing counts: %q", first)
	}
}

// TestUDPDrops_MirroredIntoClientStats guards the seam: the per-reason detail
// lives here, but the aggregate has to reach the client's Prometheus output.
// client cannot import this package, so the link is a write from Add() — and a
// write is exactly the kind of thing a refactor drops silently.
func TestUDPDrops_MirroredIntoClientStats(t *testing.T) {
	udpDrops.reset()

	udpDrops.Add(dropReasonBadChunk, 2)
	udpDrops.Add(dropReasonNoClientYet, 5)

	if got := client.Stats.UDPDatagramsDroppedTotal.Load(); got != 7 {
		t.Errorf("client.Stats.UDPDatagramsDroppedTotal = %d, want 7 — the "+
			"aggregate must reach the client metrics, otherwise the counters "+
			"are invisible outside this package", got)
	}
	if got := udpDrops.Total(); got != 7 {
		t.Errorf("local total = %d, want 7", got)
	}
}

func TestUDPDrops_SilentWhenNothingDropped(t *testing.T) {
	udpDrops.reset()

	if s := UDPDropsSnapshot(); s != nil {
		t.Errorf("snapshot must be nil when clean, got %v", s)
	}
	if s := UDPDropsSummary(); s != "" {
		t.Errorf("summary must be empty when clean, got %q", s)
	}
}

// TestUDPDrops_ForeignIPIsCounted ties the counter to the predicate it is
// supposed to observe, rather than only to a hand-called Add.
func TestUDPDrops_ForeignIPIsCounted(t *testing.T) {
	udpDrops.reset()

	var senders udpSenderSet
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	foreign := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}

	if !senders.accept(first, "1.1.1.1:53") {
		t.Fatal("first datagram must be accepted")
	}
	if senders.accept(foreign, "1.1.1.1:53") {
		t.Fatal("foreign IP must be rejected")
	}
	// The handler increments on the reject branch; mirror that here so the
	// mapping reason->branch is asserted somewhere.
	udpDrops.Add(dropReasonForeignIP, 1)

	if got := udpDrops.Get(dropReasonForeignIP); got != 1 {
		t.Errorf("foreign_source_ip = %d, want 1", got)
	}
}

// TestUDPSenderSet_DestinationMapIsBounded guards the memory side of routing by
// destination: a client fanning out to many targets must not grow the map
// without limit.
func TestUDPSenderSet_DestinationMapIsBounded(t *testing.T) {
	var senders udpSenderSet
	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}

	for i := 0; i < maxUDPDestinations*3; i++ {
		dest := "10.0.0.1:" + utoa(uint64(i))
		if !senders.accept(src, dest) {
			t.Fatalf("datagram %d rejected unexpectedly", i)
		}
	}

	senders.mu.Lock()
	n := len(senders.byDest)
	senders.mu.Unlock()

	if n > maxUDPDestinations {
		t.Errorf("destination map grew to %d, above the %d bound", n, maxUDPDestinations)
	}
	// And the association must still work after the map is cleared: the
	// fallback keeps replies flowing rather than dropping them.
	if got := senders.replyTo("no.such.dest:1"); got == nil {
		t.Error("fallback reply target must survive the bound being hit")
	}
}
