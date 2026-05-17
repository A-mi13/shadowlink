package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// selfSignedTLS returns a TLS listener on localhost with a self-signed cert
// valid for "example.test" — the ServerName the uTLS handshake will present.
func selfSignedTLS(t *testing.T) (net.Listener, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().String()
}

// TestSplitTransportUTLSDialYieldsUTLSConn verifies the DialTLSContext produced
// by buildUTLSDialTLS actually wraps the connection in utls.UConn (i.e. the
// handshake goes through refraction-networking/utls, not crypto/tls). This is
// the whole point of P0.5: split_transport must NOT leak the Go stdlib JA3.
func TestSplitTransportUTLSDialYieldsUTLSConn(t *testing.T) {
	ln, addr := selfSignedTLS(t)

	// Server-side: accept one connection, echo "ok" after handshake. The
	// handshake itself proves our ClientHello was valid from the peer's
	// perspective; the utls type check proves it came from uTLS, not stdlib.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Force handshake so an unresponsive client is visible as error, not
		// a hang on first Read.
		if tc, ok := conn.(*tls.Conn); ok {
			_ = tc.Handshake()
		}
		_, _ = conn.Write([]byte("ok"))
	}()

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	fp := browser.NewFingerprint(browser.ProfileChrome)
	dialTLS := buildUTLSDialTLS("", "example.test", fp, dialer, true, "http/1.1")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialTLS(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("uTLS dial failed: %v", err)
	}
	defer conn.Close()

	if _, ok := conn.(*utls.UConn); !ok {
		t.Fatalf("expected *utls.UConn, got %T — stdlib crypto/tls must not be used", conn)
	}

	// Sanity: the wrapped connection actually carries data after handshake.
	buf := make([]byte, 8)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadAtLeast(conn, buf, 2)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("expected 'ok' from server, got %q (err=%v)", buf[:n], err)
	}
}

// TestSplitTransportUTLSDialPinsCFIP verifies that when cfIP is set, the
// dial actually goes to that IP even though the TLS ServerName stays as the
// domain. Regression guard: the pinning logic used to live in a separate
// DialContext closure, now it's folded into the uTLS dialer.
func TestSplitTransportUTLSDialPinsCFIP(t *testing.T) {
	ln, addr := selfSignedTLS(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tc, ok := conn.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}()
		}
	}()

	dialer := &net.Dialer{Timeout: 3 * time.Second}
	fp := browser.NewFingerprint(browser.ProfileChrome)

	// cfIP set to the loopback address the server listens on; serverAddr
	// arg uses a domain that obviously does not resolve. If pinning works
	// the dial still reaches the local server.
	dialTLS := buildUTLSDialTLS(host, "example.test", fp, dialer, true, "http/1.1")

	// "bogus.invalid" would fail DNS normally; we never resolve it because
	// the uTLS dialer swaps the host for cfIP.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialTLS(ctx, "tcp", net.JoinHostPort("bogus.invalid", port))
	if err != nil {
		t.Fatalf("cfIP-pinned dial failed: %v", err)
	}
	conn.Close()
}
