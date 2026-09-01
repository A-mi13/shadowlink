package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"
)

// UDP ASSOCIATE check, driven from MULTIPLE source ports on purpose.
//
// The 2026-09-01 field defect was invisible to every hand check we had: a
// one-socket probe scored 8/8 while sing-box scored 33 %, because the relay
// pinned the first datagram's port and answered everything there. For a single
// socket the pin and the real sender coincide, so the bug cannot manifest.
//
// A probe that uses one socket therefore measures nothing about the class of
// failure that actually reached the field. This one resolves several names over
// one association, each from its own socket, and reports per-socket results.
//
// Measured signature of the defect, reproduced 2026-09-01 against the original
// code (full-address pin, first sender wins): this check reports exactly
// **1/4** — the first socket is the one the pin points at, so it is answered
// and the remaining three time out. That single success is the whole reason a
// hand check scored 8/8.
//
// Note what this means for the drop counters added alongside the fix: they stay
// **silent** on this defect. `no_client_yet` fires only when no sender was ever
// recorded, and here one was — merely the wrong one; the reply goes to a closed
// loopback port, which does not fail the write, so `unroutable_reply` does not
// move either. "Answered somebody, just not the asker" is not a discard on any
// branch. This probe, not a metric, is what catches it.

// udpCheckDomains are resolved through the tunnel, one per source socket.
var udpCheckDomains = []string{
	"example.com",
	"cloudflare.com",
	"google.com",
	"wikipedia.org",
}

// runUDPCheck opens one UDP ASSOCIATE and sends a DNS query for each domain
// from a DIFFERENT local socket, mirroring how a multiplexing client behaves.
func runUDPCheck(proxy, user, pass, resolver string) error {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	d := &net.Dialer{Timeout: 10 * time.Second}
	ctrl, relay, err := socks5UDPAssociate(ctx, d, proxy, user, pass)
	if err != nil {
		return fmt.Errorf("UDP ASSOCIATE: %w", err)
	}
	defer ctrl.Close()

	fmt.Printf("[probe] UDP relay at %s, resolver %s, %d sockets\n",
		relay, resolver, len(udpCheckDomains))

	type result struct {
		domain string
		port   int
		err    error
	}
	results := make([]result, 0, len(udpCheckDomains))

	for _, domain := range udpCheckDomains {
		// A fresh socket per query — this is the whole point of the check.
		sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return fmt.Errorf("listen udp: %w", err)
		}
		local := sock.LocalAddr().(*net.UDPAddr).Port

		err = udpResolveOnce(sock, relay, resolver, domain)
		results = append(results, result{domain: domain, port: local, err: err})
		sock.Close()
	}

	ok := 0
	for _, r := range results {
		if r.err == nil {
			ok++
			fmt.Printf("[probe]   %-16s from :%-5d OK\n", r.domain, r.port)
		} else {
			fmt.Printf("[probe]   %-16s from :%-5d FAIL: %v\n", r.domain, r.port, r.err)
		}
	}

	if ok != len(results) {
		// Name the likely cause: a first-socket-only success is the exact
		// signature of the reply-pinning defect, and saying so saves the next
		// person the investigation.
		hint := ""
		if ok == 1 && results[0].err == nil {
			hint = " — only the FIRST socket got a reply, which is the signature " +
				"of replies being pinned to the first datagram's port"
		}
		return fmt.Errorf("%d/%d UDP queries succeeded%s", ok, len(results), hint)
	}
	fmt.Printf("[probe] UDP OK — %d/%d across %d distinct source ports\n",
		ok, len(results), len(results))
	return nil
}

// udpResolveOnce sends one DNS A query through the relay and waits for a reply.
func udpResolveOnce(sock *net.UDPConn, relay *net.UDPAddr, resolver, domain string) error {
	query, wantID := buildDNSQuery(domain)

	host, portStr, err := net.SplitHostPort(resolver)
	if err != nil {
		return fmt.Errorf("resolver %q: %w", resolver, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("resolver must be an IPv4 literal, got %q", host)
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// SOCKS5 UDP request: [RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2)] + data
	dgram := make([]byte, 0, 10+len(query))
	dgram = append(dgram, 0, 0, 0, 0x01)
	dgram = append(dgram, ip.To4()...)
	dgram = append(dgram, byte(port>>8), byte(port))
	dgram = append(dgram, query...)

	if _, err := sock.WriteToUDP(dgram, relay); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	sock.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := sock.ReadFromUDP(buf)
	if err != nil {
		return fmt.Errorf("no reply: %w", err)
	}
	if n < 10 {
		return fmt.Errorf("short reply (%d bytes)", n)
	}
	// Skip the SOCKS5 UDP header; only ATYP=1 is expected from our own request.
	off := 10
	if buf[3] == 0x03 {
		off = 5 + int(buf[4]) + 2
	} else if buf[3] == 0x04 {
		off = 22
	}
	if n < off+4 {
		return fmt.Errorf("reply truncated at DNS header")
	}
	gotID := binary.BigEndian.Uint16(buf[off : off+2])
	if gotID != wantID {
		return fmt.Errorf("DNS id mismatch: got %#04x want %#04x — a reply "+
			"delivered to the wrong socket looks exactly like this", gotID, wantID)
	}
	ancount := binary.BigEndian.Uint16(buf[off+6 : off+8])
	if ancount == 0 {
		return fmt.Errorf("no answers")
	}
	return nil
}

// buildDNSQuery returns a minimal A query and the transaction ID to match.
func buildDNSQuery(domain string) ([]byte, uint16) {
	id := uint16(rand.Intn(0xfffe) + 1)
	msg := make([]byte, 12, 32+len(domain))
	binary.BigEndian.PutUint16(msg[0:2], id)
	msg[2] = 0x01 // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)

	for _, label := range strings.Split(domain, ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)
	msg = append(msg, 0x00, 0x01) // QTYPE=A
	msg = append(msg, 0x00, 0x01) // QCLASS=IN
	return msg, id
}

// socks5UDPAssociate performs the SOCKS5 handshake and UDP ASSOCIATE, returning
// the control connection (which must stay open for the association's lifetime)
// and the relay address to send datagrams to.
func socks5UDPAssociate(ctx context.Context, d *net.Dialer, proxyAddr, user, pass string) (net.Conn, *net.UDPAddr, error) {
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if dl, has := ctx.Deadline(); has {
		conn.SetDeadline(dl)
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		return nil, nil, err
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return nil, nil, err
	}
	if greeting[0] != 0x05 || greeting[1] != 0x02 {
		return nil, nil, fmt.Errorf("proxy refused user/pass auth: %v", greeting)
	}

	auth := []byte{0x01, byte(len(user))}
	auth = append(auth, user...)
	auth = append(auth, byte(len(pass)))
	auth = append(auth, pass...)
	if _, err := conn.Write(auth); err != nil {
		return nil, nil, err
	}
	var authReply [2]byte
	if _, err := io.ReadFull(conn, authReply[:]); err != nil {
		return nil, nil, err
	}
	if authReply[1] != 0x00 {
		return nil, nil, fmt.Errorf("auth rejected: %v", authReply)
	}

	// UDP ASSOCIATE with DST 0.0.0.0:0 — what a client that does not yet know
	// its own source port sends, and what sing-box sends.
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		return nil, nil, err
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, nil, err
	}
	if head[1] != 0x00 {
		return nil, nil, fmt.Errorf("UDP ASSOCIATE refused, REP=0x%02x", head[1])
	}

	var bndIP net.IP
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, nil, err
		}
		bndIP = net.IP(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return nil, nil, err
		}
		bndIP = net.IP(b)
	default:
		return nil, nil, fmt.Errorf("unexpected BND.ATYP 0x%02x", head[3])
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return nil, nil, err
	}

	// The relay binds on loopback; if BND.ADDR is unspecified, fall back to the
	// proxy's own host rather than sending to 0.0.0.0.
	if bndIP.IsUnspecified() {
		host, _, _ := net.SplitHostPort(proxyAddr)
		bndIP = net.ParseIP(host)
	}

	conn.SetDeadline(time.Time{}) // the association lives as long as this conn
	ok = true
	return conn, &net.UDPAddr{IP: bndIP, Port: int(binary.BigEndian.Uint16(portBuf[:]))}, nil
}
