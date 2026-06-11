package socks5

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// captureConn is a minimal net.Conn that records everything written to it and
// returns EOF on Read so DirectDial's relay (if ever reached) unblocks fast.
type captureConn struct {
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *captureConn) Read(b []byte) (int, error) { return 0, net.ErrClosed }
func (c *captureConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.written.Write(b)
}
func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return dummyAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return dummyAddr{} }
func (c *captureConn) SetDeadline(t time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(t time.Time) error { return nil }
func (c *captureConn) firstReply() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "0.0.0.0:0" }

func replyEquals(got, want []byte) bool {
	return len(got) >= len(want) && bytes.Equal(got[:len(want)], want)
}

// withMockResolver swaps lookupIPFunc for the duration of fn.
func withMockResolver(t *testing.T, fn func() ([]net.IP, error), body func()) {
	t.Helper()
	orig := lookupIPFunc
	lookupIPFunc = func(_ context.Context, _ string) ([]net.IP, error) { return fn() }
	defer func() { lookupIPFunc = orig }()
	body()
}

// SEC-H3: a host whose DNS resolves to a private/loopback/link-local IP must
// be rejected with ReplyNotAllowed (SSRF / DNS-rebind defense).
func TestDirectDial_RejectsResolvedPrivateIP(t *testing.T) {
	cases := map[string]net.IP{
		"loopback":       net.ParseIP("127.0.0.1"),
		"rfc1918":        net.ParseIP("192.168.1.1"),
		"link-local":     net.ParseIP("169.254.169.254"), // cloud metadata
		"ipv6-ula":       net.ParseIP("fc00::1"),
		"ipv6-loopback":  net.ParseIP("::1"),
		"ipv6-linklocal": net.ParseIP("fe80::1"),
	}
	for name, ip := range cases {
		t.Run(name, func(t *testing.T) {
			conn := &captureConn{}
			withMockResolver(t, func() ([]net.IP, error) { return []net.IP{ip}, nil }, func() {
				DirectDial(conn, "evil.example.com:80")
			})
			if !replyEquals(conn.firstReply(), ReplyNotAllowed) {
				t.Fatalf("expected ReplyNotAllowed for resolved %v, got % x", ip, conn.firstReply())
			}
		})
	}
}

// SEC-H3: mixed resolution (one public, one private) must still be rejected —
// ANY private IP in the set is a rebind hazard.
func TestDirectDial_RejectsMixedPublicPrivate(t *testing.T) {
	conn := &captureConn{}
	withMockResolver(t, func() ([]net.IP, error) {
		return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("10.0.0.5")}, nil
	}, func() {
		DirectDial(conn, "rebind.example.com:443")
	})
	if !replyEquals(conn.firstReply(), ReplyNotAllowed) {
		t.Fatalf("expected ReplyNotAllowed for mixed public/private, got % x", conn.firstReply())
	}
}

// SEC-H3: lookup error must FAIL CLOSED — the old code silently skipped the
// SSRF check on lookup error. We must not dial; expect ReplyHostUnreachable.
func TestDirectDial_FailsClosedOnLookupError(t *testing.T) {
	conn := &captureConn{}
	withMockResolver(t, func() ([]net.IP, error) {
		return nil, errors.New("dns timeout")
	}, func() {
		DirectDial(conn, "broken.example.com:80")
	})
	if !replyEquals(conn.firstReply(), ReplyHostUnreachable) {
		t.Fatalf("expected ReplyHostUnreachable on lookup error, got % x", conn.firstReply())
	}
}

// SEC-H3: empty resolution must also fail closed (no IPs to validate/dial).
func TestDirectDial_FailsClosedOnEmptyLookup(t *testing.T) {
	conn := &captureConn{}
	withMockResolver(t, func() ([]net.IP, error) {
		return []net.IP{}, nil
	}, func() {
		DirectDial(conn, "empty.example.com:80")
	})
	if !replyEquals(conn.firstReply(), ReplyHostUnreachable) {
		t.Fatalf("expected ReplyHostUnreachable on empty lookup, got % x", conn.firstReply())
	}
}

// SEC-H3: a bare private IP literal (no DNS) must be rejected without any
// resolution.
func TestDirectDial_RejectsPrivateIPLiteral(t *testing.T) {
	conn := &captureConn{}
	resolverCalled := false
	withMockResolver(t, func() ([]net.IP, error) {
		resolverCalled = true
		return []net.IP{net.ParseIP("8.8.8.8")}, nil
	}, func() {
		DirectDial(conn, "169.254.169.254:80")
	})
	if resolverCalled {
		t.Fatal("resolver must not be called for an IP literal")
	}
	if !replyEquals(conn.firstReply(), ReplyNotAllowed) {
		t.Fatalf("expected ReplyNotAllowed for private IP literal, got % x", conn.firstReply())
	}
}

// SEC-H3: malformed destAddr (no port) must be rejected, not panic.
func TestDirectDial_RejectsMalformedAddr(t *testing.T) {
	conn := &captureConn{}
	DirectDial(conn, "no-port-here")
	if !replyEquals(conn.firstReply(), ReplyHostUnreachable) {
		t.Fatalf("expected ReplyHostUnreachable for malformed addr, got % x", conn.firstReply())
	}
}
