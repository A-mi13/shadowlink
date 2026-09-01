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

// maxUDPDestinations bounds the destination->sender map of one association.
// Reached only by a client fanning out to more than this many targets over a
// single ASSOCIATE; the map is then cleared rather than grown, degrading to the
// last-sender fallback instead of leaking memory. Sized well above the handful
// of resolvers and peers a real client uses concurrently.
const maxUDPDestinations = 512

// udpSenderSet implements RFC1928 client pinning (H4, 2026-06-11) while keeping
// the reply path correct for clients that multiplex several UDP flows over one
// association from DIFFERENT source ports.
//
// The IP half is the security boundary and is unchanged: the first datagram's
// source IP is pinned for the association's lifetime, and datagrams from any
// other IP are rejected so a foreign local process cannot smuggle traffic
// through — or steal responses from — someone else's stream.
//
// The port half used to be a defect. The old code pinned the first datagram's
// full address and sent EVERY response back to it, while accepting uplink from
// any port of the pinned IP. A client using one socket per in-flight query —
// sing-box does exactly this — had all replies after the first delivered to the
// wrong port, where nothing was listening.
//
// Field measurement 2026-09-01 (NixaVPN client team): DNS over the tunnel
// resolved 8/8 driven by a single-socket probe but 33% (242/485) driven by
// sing-box. A single-socket client cannot observe the defect at all, because
// for it the pin and the real sender coincide — which is why manual acceptance
// passed and the integration did not.
//
// The reply target is therefore the sender of the most recent datagram rather
// than a fixed pin. Guard: TestUDPAssociateWS_RepliesToSenderPortNotFirstPort.
// Responses are routed by DESTINATION rather than to whoever spoke last: the
// downlink chunk carries the address the answer came from (core.ParseUDPChunk),
// so a datagram sent to 1.1.1.1:53 by socket A and one sent to 8.8.8.8:53 by
// socket B are told apart even when they interleave. "Last sender wins" would
// have passed the two-socket test while still misdelivering under concurrency,
// which is the same class of defect one layer down.
//
// lastAddr remains as the fallback for a response whose source matches no
// recorded destination — NAT rewrites and anycast make that possible — and for
// the degenerate case of a server answering from an address we never wrote to.
type udpSenderSet struct {
	pinnedIP atomic.Pointer[net.IP]      // security boundary: first source IP
	lastAddr atomic.Pointer[net.UDPAddr] // fallback reply target: most recent sender

	mu     sync.Mutex
	byDest map[string]*net.UDPAddr // destination "host:port" -> the socket that asked
}

// accept reports whether a datagram from src should be relayed. dest is the
// SOCKS5 target the datagram is addressed to; it is recorded so the response
// can be returned to this exact sender.
func (s *udpSenderSet) accept(src *net.UDPAddr, dest string) bool {
	if src == nil {
		return false
	}
	ip := append(net.IP(nil), src.IP...)
	addr := &net.UDPAddr{IP: ip, Port: src.Port, Zone: src.Zone}

	if !s.pinnedIP.CompareAndSwap(nil, &ip) {
		cur := s.pinnedIP.Load()
		if cur == nil {
			return false // lost the CAS race and the pin cleared — reject defensively
		}
		if !cur.Equal(src.IP) {
			return false
		}
	}

	s.lastAddr.Store(addr)
	if dest != "" {
		s.mu.Lock()
		if s.byDest == nil {
			s.byDest = make(map[string]*net.UDPAddr, 4)
		}
		// Bounded: a client that talks to an unbounded number of destinations
		// through one association must not grow this map without limit.
		if len(s.byDest) >= maxUDPDestinations {
			clear(s.byDest)
		}
		s.byDest[dest] = addr
		s.mu.Unlock()
	}
	return true
}

// replyTo returns the address a response from src must be delivered to, or nil
// if no datagram has arrived yet (the relay cannot know where the client
// listens until it speaks first).
func (s *udpSenderSet) replyTo(src string) *net.UDPAddr {
	if src != "" {
		s.mu.Lock()
		addr := s.byDest[src]
		s.mu.Unlock()
		if addr != nil {
			return addr
		}
	}
	return s.lastAddr.Load()
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

	// The success reply is deliberately NOT sent yet. It used to go out here,
	// before the stream was registered and its session resolved, so a client
	// could be told the association was up while the relay was already dead —
	// it then blocked until its own timeout instead of failing over, inflating
	// the failure rate the field team measured on 2026-09-01. Everything that
	// can fail now happens first; the reply is written once the relay is
	// genuinely usable. Guard: TestUDPAssociateWS_NoSuccessReplyWithoutSession.
	client.Trace("SOCKS5 UDP ASSOCIATE (WS)", "udp_addr", boundAddr.String())

	// Allocate stream for this UDP association
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded for UDP", "error", regErr)
		conn.Write(ReplyGeneralFailure)
		return
	}
	defer cl.UnregisterStream(streamID)

	// Bind the stream to a slot BEFORE resolving its session: SessionForStream
	// looks the stream up in the pool's streamMap and returns nil until then
	// (client/ws_pool.go:4367). Assignment also makes the slot account this
	// stream, without which the drain path sees an empty slot and tears it down
	// mid-association (client/ws_pool_drain.go:1256).
	if pa, ok := wst.(client.PoolAware); ok {
		pa.AssignStream(streamID)
		defer pa.ReleaseStream(streamID)
	}

	// Field defect 2026-08-31 (iOS/macOS integration): this used to be
	// cl.Session() — the global handshake session, which no pooled WS
	// connection is authenticated against. The server resolves a session once
	// at upgrade (server/websocket.go:159) and decrypts every later frame with
	// that slot's session only, so a frame sealed with the global session fails
	// AES-GCM and is dropped by `continue` (server/websocket.go:917-919) with
	// no log line and no metric. Symptom: UDP hangs until the tunnel drops
	// while TCP over the same pool works. Guard:
	// TestUDPAssociateWS_SealsWithSlotSessionNotGlobal.
	if client.StreamSession(wst, cl, streamID) == nil {
		slog.Warn("UDP ASSOCIATE: no session for stream", "stream_id", streamID)
		conn.Write(ReplyGeneralFailure)
		return
	}

	// The relay is usable from here on: tell the client where to send.
	reply := []byte{0x05, 0x00, 0x00, 0x01,
		ip4[0], ip4[1], ip4[2], ip4[3],
		byte(boundAddr.Port >> 8), byte(boundAddr.Port & 0xff)}
	conn.Write(reply)

	// Senders sharing this association, and where each expects its replies.
	var senders udpSenderSet
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
				udpDrops.Add(dropReasonShort, 1)
				continue // too short for SOCKS5 UDP header
			}

			// Parse before accept(): the destination is what lets the response
			// find this exact sender among several sharing the association.
			targetAddr, dataOffset, ok := ParseSOCKS5UDPHeader(buf, n)
			if !ok {
				udpDrops.Add(dropReasonBadHeader, 1)
				continue
			}

			// H4: pin to the first client IP; reject datagrams from any other IP.
			if !senders.accept(clientAddr, targetAddr) {
				udpDrops.Add(dropReasonForeignIP, 1)
				continue
			}
			lastUDPActivity.Store(time.Now().UnixNano())

			data := buf[dataOffset:n]
			if len(data) == 0 {
				udpDrops.Add(dropReasonEmptyPayload, 1)
				continue
			}

			// Resolve the session per datagram, not once outside the loop: the
			// stream can be migrated to another slot mid-association (aging
			// watchdog, emergency evict, RESUME-on-death), and each slot has
			// its own keys. A captured session would keep sealing frames for a
			// slot the stream no longer lives on.
			session := client.StreamSession(wst, cl, streamID)
			if session == nil {
				return
			}
			chunk := core.NewUDPDataChunk(session.ID, session.NextSeqNum(), streamID, targetAddr, data)
			enc, err := session.EncryptChunk(chunk)
			if err != nil {
				return
			}
			// StreamWrite routes to the slot that owns this stream's session;
			// WriteMessage would pick any ready slot and the server there
			// cannot decrypt the frame.
			if err := client.StreamWrite(wst, streamID, enc); err != nil {
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
					udpDrops.Add(dropReasonBadChunk, 1)
					continue
				}

				// Build SOCKS5 UDP response header
				udpResp := BuildSOCKS5UDPHeader(addr, data)
				if udpResp == nil {
					udpDrops.Add(dropReasonBadChunk, 1)
					continue
				}

				// Route by the address the answer came from, so a client
				// multiplexing several flows over this association gets each
				// reply on the socket that asked for it.
				ca := senders.replyTo(addr)
				if ca == nil {
					udpDrops.Add(dropReasonNoClientYet, 1)
					continue
				}
				if _, err := udpConn.WriteToUDP(udpResp, ca); err != nil {
					udpDrops.Add(dropReasonUnroutableReply, 1)
					continue
				}
				lastUDPActivity.Store(time.Now().UnixNano())
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

	// Main: wait for the control TCP to CLOSE, which is what ends a UDP
	// ASSOCIATE per RFC 1928 — not merely to carry a byte. This used to be a
	// single unchecked conn.Read, so any traffic on the control channel (a
	// keepalive byte, a client probing liveness) tore the relay down instantly.
	// Guard: TestUDPAssociateWS_SurvivesControlChannelTraffic.
	waitForControlClose(conn, ctx2)
	cancel()
	udpConn.Close() // unblock ReadFromUDP
	wg.Wait()
}

// waitForControlClose blocks until the control connection is closed by the peer
// or the association is cancelled. Bytes arriving on the control channel are
// discarded: RFC 1928 gives them no meaning after the reply, and treating them
// as a teardown signal breaks clients that keep the channel warm.
func waitForControlClose(conn net.Conn, ctx context.Context) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		for {
			if _, err := conn.Read(buf); err != nil {
				return // EOF or reset: the association is over
			}
			// Data on the control channel is not a teardown signal — keep waiting.
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		// The relay died first (idle watchdog, transport failure). Unblock the
		// reader so this goroutine cannot outlive the association.
		conn.SetReadDeadline(time.Now())
	}
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

	slog.Debug("SOCKS5 UDP ASSOCIATE (poll)", "udp_addr", boundAddr.String())

	// As in the WS path, the success reply waits until the relay is actually
	// usable — a client told "up" over a dead relay blocks until its own
	// timeout instead of failing over.
	streamID := cl.NextStreamID()
	incomingCh, regErr := cl.RegisterStream(streamID)
	if regErr != nil {
		slog.Warn("stream limit exceeded for UDP poll", "error", regErr)
		conn.Write(ReplyGeneralFailure)
		return
	}
	defer cl.UnregisterStream(streamID)

	session := cl.Session()
	if session == nil {
		conn.Write(ReplyGeneralFailure)
		return
	}

	reply := []byte{0x05, 0x00, 0x00, 0x01,
		ip4[0], ip4[1], ip4[2], ip4[3],
		byte(boundAddr.Port >> 8), byte(boundAddr.Port & 0xff)}
	conn.Write(reply)

	// Senders sharing this association, and where each expects its replies.
	// Same reasoning as the WS path: this branch is reachable in production
	// (plain SOCKS5 without websocket, the startup fallback, and
	// NIXAVPN_FORCE_PER_STREAM_WS), so it carries the same fix rather than
	// being left as the one place a multiplexing client still breaks.
	var senders udpSenderSet
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
				udpDrops.Add(dropReasonShort, 1)
				continue
			}

			targetAddr, dataOffset, ok := ParseSOCKS5UDPHeader(buf, n)
			if !ok {
				udpDrops.Add(dropReasonBadHeader, 1)
				continue
			}

			// H4: pin to the first client IP; reject datagrams from any other IP.
			if !senders.accept(clientAddr, targetAddr) {
				udpDrops.Add(dropReasonForeignIP, 1)
				continue
			}
			lastUDPActivity.Store(time.Now().UnixNano())

			data := buf[dataOffset:n]
			if len(data) == 0 {
				udpDrops.Add(dropReasonEmptyPayload, 1)
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
					udpDrops.Add(dropReasonBadChunk, 1)
					continue
				}
				udpResp := BuildSOCKS5UDPHeader(addr, data)
				if udpResp == nil {
					udpDrops.Add(dropReasonBadChunk, 1)
					continue
				}
				ca := senders.replyTo(addr)
				if ca == nil {
					udpDrops.Add(dropReasonNoClientYet, 1)
					continue
				}
				if _, err := udpConn.WriteToUDP(udpResp, ca); err != nil {
					udpDrops.Add(dropReasonUnroutableReply, 1)
				} else {
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

	// Wait for CLOSE, not for a byte — see waitForControlClose.
	waitForControlClose(conn, ctx2)
	cancel()
	udpConn.Close()
	wg.Wait()
}
