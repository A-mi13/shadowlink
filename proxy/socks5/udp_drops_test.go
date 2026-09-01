package socks5

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
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

// TestUDPDrops_ForeignIPPredicate pins the predicate itself: same IP on another
// port is accepted (the multiplexing client we fixed for), a different IP is
// not (H4). It deliberately asserts NOTHING about counters — see the test below
// for why that separation matters.
func TestUDPDrops_ForeignIPPredicate(t *testing.T) {
	var senders udpSenderSet
	first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	foreign := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 9), Port: 5000}

	if !senders.accept(first, "1.1.1.1:53") {
		t.Fatal("first datagram must be accepted")
	}
	if senders.accept(foreign, "1.1.1.1:53") {
		t.Fatal("foreign IP must be rejected")
	}
}

// TestUDPDrops_HandlerLabelsBranchesCorrectly drives the REAL handler and
// asserts which counter moved.
//
// The previous version of this guard called udpDrops.Add(dropReasonForeignIP, 1)
// by hand right after exercising the predicate, and its comment claimed that
// this "ties the counter to the predicate rather than only to a hand-called
// Add" — while doing exactly the hand-called Add it disclaimed. Verified
// 2026-09-01 by mislabelling BOTH handler call-sites (dropReasonForeignIP ->
// dropReasonShort): every counter test still passed. A guard that stays green
// while the thing it names is broken is worse than no guard, because the
// operator then reads `udp_drop_reasons` as if the labels were checked.
//
// Labels are the whole product here: the counters exist so a field report can
// name the failing branch without a debugger, and a mislabelled counter sends
// the next investigation to the wrong half of the code.
func TestUDPDrops_HandlerLabelsBranchesCorrectly(t *testing.T) {
	stub := newMultiportStub(0xD00D)

	key := make([]byte, 32)
	cl := client.NewTestClientWithSession(core.NewSession(0xFEED, key, key))

	port, stop := startAssociation(t, cl, stub)
	defer stop()

	relayAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer sock.Close()

	// Each case drives one uplink branch of the handler and names the counter
	// that must move. Counting the delta rather than the absolute value keeps
	// this independent of other tests sharing the process-wide counters.
	cases := []struct {
		name     string
		datagram []byte
		reason   udpDropReason
	}{
		// Below the 4-byte SOCKS5 UDP header minimum.
		{"short", []byte{0x00, 0x00}, dropReasonShort},
		// FRAG != 0: fragmentation is not supported, so the header is refused.
		{"bad_header", []byte{0x00, 0x00, 0x01, 0x01, 1, 1, 1, 1, 0x00, 0x35}, dropReasonBadHeader},
		// Well-formed header addressed to 1.1.1.1:53 but carrying no payload.
		{"empty_payload", []byte{0x00, 0x00, 0x00, 0x01, 1, 1, 1, 1, 0x00, 0x35}, dropReasonEmptyPayload},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := udpDrops.Get(tc.reason)
			if _, err := sock.WriteToUDP(tc.datagram, relayAddr); err != nil {
				t.Fatalf("write: %v", err)
			}
			// The handler drops silently by design, so there is no reply to
			// wait on; poll the counter instead of sleeping a fixed interval.
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if udpDrops.Get(tc.reason) > before {
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			t.Errorf("%s: counter %q did not move (still %d) — the handler "+
				"either dropped this datagram under a different label or did "+
				"not drop it at all; either way udp_drop_reasons would point "+
				"a field investigation at the wrong branch",
				tc.name, udpDropNames[tc.reason], before)
		})
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
