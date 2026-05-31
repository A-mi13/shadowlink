package socks5

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

// metaFor builds a tun2socks Metadata for an IP:port destination (packet-level —
// always a concrete IP, never a hostname).
func metaFor(ip string, port uint16) *M.Metadata {
	return &M.Metadata{Network: M.TCP, DstIP: netip.MustParseAddr(ip), DstPort: port}
}

// TestInProcessDialer_DialContextReturnsConn — the core contract: DialContext
// returns a usable net.Conn (the app end of a memConn) and starts the relay on
// the long-lived engine context, NOT the 5s dial ctx (review HIGH-5).
func TestInProcessDialer_DialContextReturnsConn(t *testing.T) {
	engineCtx, engineCancel := context.WithCancel(context.Background())
	defer engineCancel()

	var gotRelayCtx context.Context
	var gotDst string
	relayStarted := make(chan struct{})
	var once sync.Once

	d := &inProcessDialer{
		engineCtx: engineCtx,
		srv:       &Server{}, // connectSem nil → AcquireConnect no-op
		runRelay: func(ctx context.Context, conn net.Conn, destAddr string) {
			gotRelayCtx = ctx
			gotDst = destAddr
			once.Do(func() { close(relayStarted) })
			// emulate relay: read until closed so the conn isn't leaked
			io_copy_discard(conn)
		},
	}

	// 5s dial ctx, like tun2socks passes.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()

	conn, err := d.DialContext(dialCtx, metaFor("142.250.1.1", 443))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext returned nil conn")
	}
	defer conn.Close()

	select {
	case <-relayStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not start")
	}

	if gotDst != "142.250.1.1:443" {
		t.Errorf("dst: got %q want 142.250.1.1:443", gotDst)
	}

	// HIGH-5: relay ctx must be derived from engineCtx, not the 5s dialCtx.
	// Cancel dialCtx — relay ctx must remain alive.
	dialCancel()
	time.Sleep(50 * time.Millisecond)
	if gotRelayCtx.Err() != nil {
		t.Fatal("relay ctx was cancelled by dial ctx — HIGH-5 violation (streams would die at 5s)")
	}
	// Cancelling engineCtx MUST propagate to relay ctx.
	engineCancel()
	time.Sleep(50 * time.Millisecond)
	if gotRelayCtx.Err() == nil {
		t.Fatal("relay ctx not derived from engineCtx (engine shutdown wouldn't stop relays)")
	}
}

// TestInProcessDialer_NoRouterDecide — BLOCKER-1: the dialer must NOT run
// router.Decide. Routing is the BypassDialer's job (IP-trie); metadata carries
// only an IP so hostname rules are meaningless here. We assert the dialer has no
// router field/dependency by constructing it without one and dialing successfully.
func TestInProcessDialer_NoRouterDecide(t *testing.T) {
	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &inProcessDialer{
		engineCtx: engineCtx,
		srv:       &Server{},
		runRelay:  func(ctx context.Context, conn net.Conn, destAddr string) { io_copy_discard(conn) },
	}
	conn, err := d.DialContext(context.Background(), metaFor("8.8.8.8", 443))
	if err != nil {
		t.Fatalf("DialContext must not require a router: %v", err)
	}
	conn.Close()
}

// TestInProcessDialer_DataFlowsToRelay — bytes written on the app side reach the
// relay's conn (proving the memConn is wired correctly between the two).
func TestInProcessDialer_DataFlowsToRelay(t *testing.T) {
	engineCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	received := make(chan []byte, 1)
	d := &inProcessDialer{
		engineCtx: engineCtx,
		srv:       &Server{},
		runRelay: func(ctx context.Context, conn net.Conn, destAddr string) {
			buf := make([]byte, 64)
			n, _ := conn.Read(buf)
			received <- buf[:n]
		},
	}

	conn, err := d.DialContext(context.Background(), metaFor("1.1.1.1", 443))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	want := []byte("GET / HTTP/1.1")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	select {
	case got := <-received:
		if string(got) != string(want) {
			t.Fatalf("relay got %q want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("data did not flow from app conn to relay")
	}
}

// io_copy_discard drains a conn until closed (test helper to avoid leaking the
// relay goroutine's conn).
func io_copy_discard(c net.Conn) {
	buf := make([]byte, 4096)
	for {
		if _, err := c.Read(buf); err != nil {
			return
		}
	}
}
