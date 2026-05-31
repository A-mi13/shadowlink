package socks5

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// udpAddr builds a *net.UDPAddr for tests.
func udpAddr(ip string, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}

// TestStreamPacketConn_WriteToSendsChunk — WriteTo must encode an outbound UDP
// chunk (target addr + data) and hand it to the send func. The first WriteTo
// starts the stream.
func TestStreamPacketConn_WriteToSendsChunk(t *testing.T) {
	sent := make(chan struct {
		addr string
		data []byte
	}, 4)

	incoming := make(chan []byte, 4)
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	pc := newStreamPacketConn(dst, incoming, func(targetAddr string, data []byte) error {
		sent <- struct {
			addr string
			data []byte
		}{targetAddr, append([]byte(nil), data...)}
		return nil
	}, func() {})
	defer pc.Close()

	payload := []byte("\x00\x00DNSQUERY")
	if _, err := pc.WriteTo(payload, udpAddr("8.8.8.8", 53)); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	select {
	case s := <-sent:
		if s.addr != "8.8.8.8:53" {
			t.Errorf("target addr: got %q want 8.8.8.8:53", s.addr)
		}
		if string(s.data) != string(payload) {
			t.Errorf("data: got %q want %q", s.data, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteTo did not invoke send func")
	}
}

// TestStreamPacketConn_ReadFromReturnsDstAddr is the HIGH-2 contract: tun2socks
// wraps the PacketConn in symmetricNATPacketConn which DROPS any datagram whose
// from-addr != the dial dst. So ReadFrom MUST return from == metadata.dst,
// regardless of the addr embedded in the server's UDP chunk.
func TestStreamPacketConn_ReadFromReturnsDstAddr(t *testing.T) {
	incoming := make(chan []byte, 4)
	dst := netip.MustParseAddrPort("8.8.8.8:53")
	pc := newStreamPacketConn(dst, incoming, func(string, []byte) error { return nil }, func() {})
	defer pc.Close()

	// Server pushes a UDP chunk whose embedded addr is a DIFFERENT source
	// (e.g. anycast reply / multi-homed). incomingCh carries the FULL payload
	// WITH the 2-byte StreamID prefix (FlagUDP demux contract).
	chunk := core.NewUDPDataChunk(1, 1, 42, "8.8.4.4:53", []byte("DNSREPLY"))
	incoming <- chunk.Payload

	buf := make([]byte, 1500)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != "DNSREPLY" {
		t.Errorf("data: got %q want DNSREPLY", buf[:n])
	}
	// CRITICAL: from must equal the dial dst (8.8.8.8:53), NOT the chunk's
	// embedded 8.8.4.4:53 — else symmetricNATPacketConn drops it.
	if from.String() != "8.8.8.8:53" {
		t.Fatalf("ReadFrom from: got %q want 8.8.8.8:53 (HIGH-2: symmetric NAT would drop)", from.String())
	}
}

// TestStreamPacketConn_CloseInvokesCleanup is the HIGH-3 lifecycle contract:
// Close must run the cleanup (UnregisterStream + FIN) exactly once, or stream
// slots leak under DNS bursts (many short-lived 5-tuples).
func TestStreamPacketConn_CloseInvokesCleanup(t *testing.T) {
	cleanups := make(chan struct{}, 4)
	incoming := make(chan []byte)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	pc := newStreamPacketConn(dst, incoming, func(string, []byte) error { return nil }, func() {
		cleanups <- struct{}{}
	})

	_ = pc.Close()
	_ = pc.Close() // idempotent — must NOT clean up twice

	select {
	case <-cleanups:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not invoke cleanup (stream slot would leak)")
	}
	select {
	case <-cleanups:
		t.Fatal("cleanup invoked more than once (double FIN/unregister)")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestStreamPacketConn_ReadFromUnblocksOnClose — a ReadFrom blocked waiting for
// inbound datagrams must return when the conn is closed (tun2socks udpTimeout /
// engine shutdown), else the drain goroutine leaks.
func TestStreamPacketConn_ReadFromUnblocksOnClose(t *testing.T) {
	incoming := make(chan []byte)
	dst := netip.MustParseAddrPort("1.1.1.1:53")
	pc := newStreamPacketConn(dst, incoming, func(string, []byte) error { return nil }, func() {})

	done := make(chan error, 1)
	go func() {
		_, _, err := pc.ReadFrom(make([]byte, 1500))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	pc.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ReadFrom after Close must return error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ReadFrom did not unblock on Close")
	}
}
