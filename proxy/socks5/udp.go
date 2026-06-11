package socks5

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/client"
	"github.com/nixavpn/shadowlink/core"
)

// udpMinReadySlots is the minimum number of ready WS-pool slots required
// before HandleUDPAssociateWS will accept a UDP ASSOCIATE request. C12 F6
// (May audit, 2026-05-01): under degraded pool a UDP relay socket bound
// against a slot that never recovers can permanently hang the SOCKS5
// client; fail-fast with a SOCKS5 0x03 (network unreachable) reply lets
// the client retry or fall back to TCP without waiting on a dead transport.
//
// Threshold of 2 ensures we have at least one redundant slot — a single
// ready slot is fragile because losing it produces exactly the cascade we
// are guarding against. The handler does NOT block waiting for slots to
// recover; "fail-fast" is plan-literal.
//
// Single-WS transports do not implement client.PoolReadiness and are
// treated as always-ready (gate skipped) so non-pooled deployments are
// not penalised.
const udpMinReadySlots = 2

// udpAssociationIdle is the inactivity window after which a UDP ASSOCIATE is
// torn down regardless of the control-TCP state (M6, 2026-06-11). The 120s
// value matches the existing per-read deadline; the watchdog converts that
// per-read timeout into a hard association-level teardown so a half-closed
// control TCP can no longer leak the listener + 3 goroutines forever.
const udpAssociationIdle = 120 * time.Second

// acceptUDPClient implements RFC1928 client pinning (H4, 2026-06-11): the first
// datagram source IP is pinned for the lifetime of the UDP association; later
// datagrams from a DIFFERENT IP are rejected so a foreign localhost process
// cannot smuggle traffic through (or steal responses from) someone else's
// stream. Same-IP datagrams (any port) are accepted. Returns true if the
// datagram should be relayed.
func acceptUDPClient(pinned *atomic.Pointer[net.UDPAddr], src *net.UDPAddr) bool {
	if pinned.CompareAndSwap(nil, src) {
		return true // first datagram — pin and accept
	}
	cur := pinned.Load()
	if cur == nil {
		return false // lost the CAS race and pin cleared — reject defensively
	}
	return cur.IP.Equal(src.IP)
}

// udpAssociationIdleExpired reports whether the association has been idle longer
// than the given window (M6, 2026-06-11). last holds the most recent activity
// timestamp in UnixNano.
func udpAssociationIdleExpired(last *atomic.Int64, now time.Time, idle time.Duration) bool {
	return now.UnixNano()-last.Load() > idle.Nanoseconds()
}

// HandleUDPAssociateWS handles SOCKS5 UDP ASSOCIATE over WebSocket transport.
// Opens a local UDP listener, relays datagrams through the encrypted WS tunnel.
// conn is NOT closed by this function (caller handles it via defer).
func HandleUDPAssociateWS(ctx context.Context, conn net.Conn, cl *client.Client, wst client.StreamTransport, router *client.Router) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in HandleUDPAssociateWS", "error", r)
		}
	}()

	// C12 F6: pool readiness gate. If the underlying transport is a pool and
	// it reports fewer than udpMinReadySlots ready slots, refuse the UDP
	// ASSOCIATE with a 0x03 (network unreachable) reply. Plan-literal
	// fail-fast — no retry, no wait. Transports that are not pools (single
	// WS) skip this branch and proceed unchanged.
	if pr, ok := wst.(client.PoolReadiness); ok {
		if ready := pr.ReadyCount(); ready < udpMinReadySlots {
			slog.Warn("SOCKS5 UDP ASSOCIATE rejected — pool starved",
				"ready", ready,
				"minRequired", udpMinReadySlots,
			)
			conn.Write(ReplyNetUnreachable)
			return
		}
	}

	// Open local UDP listener on loopback
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		conn.Write(ReplyGeneralFailure)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		conn.Write(ReplyGeneralFailure)
		return
	}
	defer udpConn.Close()

	// Get bound address for SOCKS5 reply
	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip4 := boundAddr.IP.To4()
	if ip4 == nil {
		ip4 = []byte{127, 0, 0, 1}
	}

	// Reply: success with BND.ADDR = local UDP address
	reply := []byte{0x05, 0x00, 0x00, 0x01,
		ip4[0], ip4[1], ip4[2], ip4[3],
		byte(boundAddr.Port >> 8), byte(boundAddr.Port & 0xff)}
	conn.Write(reply)

	client.Trace("SOCKS5 UDP ASSOCIATE (WS)", "udp_addr", boundAddr.String())

	// Allocate stream for this UDP association
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded for UDP", "error", regErr)
		return
	}
	defer cl.UnregisterStream(streamID)

	session := cl.Session()
	if session == nil {
		return
	}

	// Track last client address for sending responses back
	var lastClientAddr atomic.Pointer[net.UDPAddr]
	// M6: association-level activity timestamp (UnixNano) for the idle watchdog.
	var lastUDPActivity atomic.Int64
	lastUDPActivity.Store(time.Now().UnixNano())

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	// Goroutine 1 (send): Read UDP datagrams from SOCKS5 client -> encrypt -> send via WS
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue // too short for SOCKS5 UDP header
			}

			// H4: pin to the first client IP; reject datagrams from any other IP.
			if !acceptUDPClient(&lastClientAddr, clientAddr) {
				continue
			}
			lastUDPActivity.Store(time.Now().UnixNano())

			targetAddr, dataOffset, ok := ParseSOCKS5UDPHeader(buf, n)
			if !ok {
				continue
			}
			data := buf[dataOffset:n]
			if len(data) == 0 {
				continue
			}

			// Create UDP chunk and send via WS
			chunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, data)
			enc, err := session.EncryptChunk(chunk)
			if err != nil {
				return
			}
			if err := wst.WriteMessage(enc); err != nil {
				return
			}
		}
	}()

	// Goroutine 2 (receive): Read from stream channel -> parse UDP response -> send to SOCKS5 client
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case payload, ok := <-incomingCh:
				if !ok || payload == nil {
					return // HIGH-2 fix: channel closed by ResetStreams
				}
				// payload is full UDP chunk payload: [StreamID(2)][AddrLen(2)][Addr][Data]
				_, addr, data, err := core.ParseUDPChunk(payload)
				if err != nil || len(data) == 0 {
					continue
				}

				// Build SOCKS5 UDP response header
				udpResp := BuildSOCKS5UDPHeader(addr, data)
				if udpResp == nil {
					continue
				}

				ca := lastClientAddr.Load()
				if ca != nil {
					udpConn.WriteToUDP(udpResp, ca)
					lastUDPActivity.Store(time.Now().UnixNano())
				}
			case <-ctx2.Done():
				return
			}
		}
	}()

	// Goroutine 3 (M6 idle watchdog): tear down the association if it goes idle
	// past udpAssociationIdle even when the control TCP is half-closed/hung —
	// closing udpConn unblocks ReadFromUDP and cancel() (via defer) stops the rest.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		ticker := time.NewTicker(udpAssociationIdle / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-ticker.C:
				if udpAssociationIdleExpired(&lastUDPActivity, time.Now(), udpAssociationIdle) {
					udpConn.Close() // unblock ReadFromUDP; cancel via defer
					return
				}
			}
		}
	}()

	// Main: wait for TCP connection to close (signals end of UDP ASSOCIATE per RFC 1928)
	waitBuf := make([]byte, 1)
	conn.Read(waitBuf) // blocks until TCP closes
	cancel()
	udpConn.Close() // unblock ReadFromUDP
	wg.Wait()
}

// HandleUDPAssociate handles SOCKS5 UDP ASSOCIATE over poll-based (HTTP) transport.
// Same logic as HandleUDPAssociateWS but uses poll-based sending.
func HandleUDPAssociate(ctx context.Context, conn net.Conn, cl *client.Client, router *client.Router) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("panic recovered in HandleUDPAssociate", "error", r)
		}
	}()

	// Open local UDP listener on loopback
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		conn.Write(ReplyGeneralFailure)
		return
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		conn.Write(ReplyGeneralFailure)
		return
	}
	defer udpConn.Close()

	boundAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip4 := boundAddr.IP.To4()
	if ip4 == nil {
		ip4 = []byte{127, 0, 0, 1}
	}

	reply := []byte{0x05, 0x00, 0x00, 0x01,
		ip4[0], ip4[1], ip4[2], ip4[3],
		byte(boundAddr.Port >> 8), byte(boundAddr.Port & 0xff)}
	conn.Write(reply)

	slog.Debug("SOCKS5 UDP ASSOCIATE (poll)", "udp_addr", boundAddr.String())

	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded for UDP poll", "error", regErr)
		return
	}
	defer cl.UnregisterStream(streamID)

	session := cl.Session()
	if session == nil {
		return
	}

	var lastClientAddr atomic.Pointer[net.UDPAddr]
	// M6: association-level activity timestamp (UnixNano) for the idle watchdog.
	var lastUDPActivity atomic.Int64
	lastUDPActivity.Store(time.Now().UnixNano())

	ctx2, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup

	// Send: UDP client -> encrypt -> HTTP poll
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, 65535)
		for {
			udpConn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < 4 {
				continue
			}
			// H4: pin to the first client IP; reject datagrams from any other IP.
			if !acceptUDPClient(&lastClientAddr, clientAddr) {
				continue
			}
			lastUDPActivity.Store(time.Now().UnixNano())

			targetAddr, dataOffset, ok := ParseSOCKS5UDPHeader(buf, n)
			if !ok {
				continue
			}
			data := buf[dataOffset:n]
			if len(data) == 0 {
				continue
			}

			// Send via HTTP poll transport
			udpChunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, data)
			encrypted, err := session.EncryptChunk(udpChunk)
			if err != nil {
				return
			}

			token := cl.SessionToken()
			if _, err := cl.SendChunkRaw(ctx2, encrypted, token, udpChunk.SeqNum); err != nil {
				return
			}
		}
	}()

	// Receive: incoming channel -> parse -> send to SOCKS5 client
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case payload, ok := <-incomingCh:
				if !ok || payload == nil {
					return // HIGH-2 fix: channel closed by ResetStreams
				}
				_, addr, data, err := core.ParseUDPChunk(payload)
				if err != nil || len(data) == 0 {
					continue
				}
				udpResp := BuildSOCKS5UDPHeader(addr, data)
				if udpResp == nil {
					continue
				}
				ca := lastClientAddr.Load()
				if ca != nil {
					udpConn.WriteToUDP(udpResp, ca)
					lastUDPActivity.Store(time.Now().UnixNano())
				}
			case <-ctx2.Done():
				return
			}
		}
	}()

	// Poll loop for receiving UDP responses in poll mode
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		pollTicker := time.NewTicker(20 * time.Millisecond)
		defer pollTicker.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-pollTicker.C:
			}
			client.Stats.UdpPolls.Add(1)
			cl.PollStreams(ctx2)
		}
	}()

	// M6 idle watchdog: tear down the association if idle past udpAssociationIdle
	// even when the control TCP is half-closed/hung. Closing udpConn unblocks
	// ReadFromUDP; cancel() (via defer) stops the send/receive/poll goroutines.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer cancel()
		ticker := time.NewTicker(udpAssociationIdle / 4)
		defer ticker.Stop()
		for {
			select {
			case <-ctx2.Done():
				return
			case <-ticker.C:
				if udpAssociationIdleExpired(&lastUDPActivity, time.Now(), udpAssociationIdle) {
					udpConn.Close()
					return
				}
			}
		}
	}()

	waitBuf := make([]byte, 1)
	conn.Read(waitBuf)
	cancel()
	udpConn.Close()
	wg.Wait()
}
