package socks5

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPinClientAddr_FirstWins(t *testing.T) {
	var pinned atomic.Pointer[net.UDPAddr]
	a := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	b := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 6000}

	// Первый источник — принимается и фиксируется.
	if !acceptUDPClient(&pinned, a) {
		t.Fatal("first datagram must be accepted")
	}
	// Тот же IP (другой порт) — принимается.
	a2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5001}
	if !acceptUDPClient(&pinned, a2) {
		t.Fatal("same-IP datagram must be accepted")
	}
	// Другой IP — отвергается, pinned не меняется.
	if acceptUDPClient(&pinned, b) {
		t.Fatal("foreign-IP datagram must be rejected (H4)")
	}
	if got := pinned.Load(); got == nil || !got.IP.Equal(a.IP) {
		t.Fatalf("pinned addr drifted: %v", got)
	}
}

func TestUDPAssociationIdle(t *testing.T) {
	var last atomic.Int64
	now := time.Now()
	last.Store(now.UnixNano())

	idle := 100 * time.Millisecond
	if udpAssociationIdleExpired(&last, now, idle) {
		t.Fatal("must not be expired immediately")
	}
	if !udpAssociationIdleExpired(&last, now.Add(200*time.Millisecond), idle) {
		t.Fatal("must be expired after idle window")
	}
}
