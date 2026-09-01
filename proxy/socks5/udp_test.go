package socks5

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestPinClientAddr_FirstWins(t *testing.T) {
	var senders udpSenderSet
	a := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	b := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 6000}

	// Первый источник — принимается и фиксирует IP.
	if !senders.accept(a, "1.1.1.1:53") {
		t.Fatal("first datagram must be accepted")
	}
	// Тот же IP (другой порт) — принимается.
	a2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5001}
	if !senders.accept(a2, "8.8.8.8:53") {
		t.Fatal("same-IP datagram must be accepted")
	}
	// Другой IP — отвергается, привязка IP не меняется.
	if senders.accept(b, "1.1.1.1:53") {
		t.Fatal("foreign-IP datagram must be rejected (H4)")
	}
	if got := senders.pinnedIP.Load(); got == nil || !got.Equal(a.IP) {
		t.Fatalf("pinned IP drifted: %v", got)
	}

	// И — то, чего старый пин не умел: ответ идёт отправителю, задавшему
	// вопрос, а не первому, кто заговорил.
	if got := senders.replyTo("8.8.8.8:53"); got == nil || got.Port != a2.Port {
		t.Fatalf("reply for 8.8.8.8 must go to the socket that asked (port %d), got %v",
			a2.Port, got)
	}
	if got := senders.replyTo("1.1.1.1:53"); got == nil || got.Port != a.Port {
		t.Fatalf("reply for 1.1.1.1 must go to port %d, got %v", a.Port, got)
	}
	// Отвергнутый источник не должен был подменить цель ответа.
	if got := senders.replyTo("1.1.1.1:53"); got != nil && got.IP.Equal(b.IP) {
		t.Fatal("a rejected foreign sender must not become a reply target")
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
