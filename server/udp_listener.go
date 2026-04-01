package server

import (
	"encoding/binary"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// UDPListener handles TURN-relayed encrypted chunks over UDP.
// Protocol: each datagram = [session_id(4 bytes)] + [encrypted_chunk].
// session_id=0 is the handshake sentinel.
type UDPListener struct {
	conn    *net.UDPConn
	handler *Handler
	config  Config
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// Track peer addresses for proactive data push
	peers   map[uint32]*net.UDPAddr // session_id → last known UDP address
	peersMu sync.RWMutex
}

// NewUDPListener creates a UDP listener sharing the handler with HTTP.
func NewUDPListener(handler *Handler, config Config) *UDPListener {
	return &UDPListener{
		handler: handler,
		config:  config,
		stopCh:  make(chan struct{}),
		peers:   make(map[uint32]*net.UDPAddr),
	}
}

// Start begins listening on the given UDP address.
func (u *UDPListener) Start(addr string) (string, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return "", err
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return "", err
	}
	u.conn = conn

	u.wg.Add(1)
	go u.readLoop()

	actualAddr := conn.LocalAddr().String()
	slog.Info("UDP listener started", "addr", actualAddr)
	return actualAddr, nil
}

// Stop closes the UDP listener.
func (u *UDPListener) Stop() error {
	close(u.stopCh)
	if u.conn != nil {
		u.conn.Close()
	}
	u.wg.Wait()
	return nil
}

func (u *UDPListener) readLoop() {
	defer u.wg.Done()
	buf := make([]byte, 2048)
	for {
		select {
		case <-u.stopCh:
			return
		default:
		}

		u.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := u.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-u.stopCh:
				return
			default:
				slog.Debug("UDP read error")
				continue
			}
		}
		if n < 5 { // minimum: 4 bytes session_id + 1 byte data
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		go u.handleDatagram(data, remoteAddr)
	}
}

func (u *UDPListener) handleDatagram(data []byte, remoteAddr *net.UDPAddr) {
	sessionID := binary.BigEndian.Uint32(data[:4])
	payload := data[4:]

	if sessionID == 0 {
		u.handleUDPHandshake(payload, remoteAddr)
		return
	}

	u.handleUDPData(sessionID, payload, remoteAddr)
}

func (u *UDPListener) handleUDPHandshake(payload []byte, remoteAddr *net.UDPAddr) {
	if len(payload) < 33 {
		return
	}

	// Rate limit UDP handshakes (M1 fix: prevent computational DoS)
	if !u.handler.rateLimiter.Allow(remoteAddr.IP.String()) {
		return
	}

	clientHello := &core.ClientHello{
		EphemeralPub:      payload[:32],
		EncryptedClientID: payload[32:],
	}

	serverHello, session, clientID, err := core.HandleClientHello(
		clientHello,
		u.handler.serverKey,
		uint8(u.config.MaxConnsPerClient),
		uint16(min(u.config.ChunkSize, 1100)), // smaller chunks for UDP
		u.handler.sessions,
	)
	if err != nil {
		return // silent fail — looks like random UDP noise
	}

	if !u.handler.clientAuth.IsAuthorized(string(clientID)) {
		u.handler.sessions.Remove(session.ID)
		return
	}

	// CRIT-2 fix: check per-user device limit
	if !u.handler.clientAuth.CheckDeviceLimit(string(clientID)) {
		u.handler.sessions.Remove(session.ID)
		return
	}

	// Create tunnel (CRIT-3 + HIGH-2 fix: initialize done channel and set ClientID)
	tunnel := &Tunnel{
		SessionID: session.ID,
		ClientID:  string(clientID),
		Incoming:  make(chan []byte, 64),
		Outgoing:  make(chan []byte, 64),
		done:      make(chan struct{}),
	}
	u.handler.tunnelsMu.Lock()
	u.handler.tunnels[session.ID] = tunnel
	u.handler.tunnelsMu.Unlock()

	// CRIT-2 fix: track session for device limit enforcement
	u.handler.clientAuth.OnSessionCreated(string(clientID), session.ID)

	u.handler.metrics.HandshakesTotal.Add(1)
	u.handler.metrics.ActiveClients.Add(1)

	// Store peer address
	u.peersMu.Lock()
	u.peers[session.ID] = remoteAddr
	u.peersMu.Unlock()

	// Build response: [session_id(4)] + [ServerHello JSON]
	respPayload := encodeServerHello(serverHello)
	resp := make([]byte, 4+len(respPayload))
	binary.BigEndian.PutUint32(resp[:4], session.ID)
	copy(resp[4:], respPayload)

	u.conn.WriteToUDP(resp, remoteAddr)
	slog.Info("UDP session created")
}

func (u *UDPListener) handleUDPData(sessionID uint32, encryptedChunk []byte, remoteAddr *net.UDPAddr) {
	session, ok := u.handler.sessions.Get(sessionID)
	if !ok {
		return
	}

	// Update peer address
	u.peersMu.Lock()
	u.peers[sessionID] = remoteAddr
	u.peersMu.Unlock()

	// Decrypt (CRIT-1 fix: use safe wrapper that copies keys under lock)
	chunk, err := session.DecryptChunkSafe(encryptedChunk)
	if err != nil {
		return
	}

	if !session.AcceptSeqNum(chunk.SeqNum) {
		return
	}

	u.handler.metrics.ChunksReceived.Add(1)

	// Process by flag
	var responsePayload []byte
	switch chunk.Flags {
	case core.FlagData:
		u.handler.tunnelsMu.RLock()
		tunnel, ok := u.handler.tunnels[sessionID]
		u.handler.tunnelsMu.RUnlock()
		if ok && len(chunk.Payload) > 0 {
			// HIGH-7 fix: read tunnel.connected/targetConn under lock
			tunnel.mu.Lock()
			connected := tunnel.connected
			tc := tunnel.targetConn
			tunnel.mu.Unlock()
			if connected && tc != nil {
				tc.Write(chunk.Payload)
			} else {
				select {
				case tunnel.Incoming <- chunk.Payload:
				default:
				}
			}
		}
		// Check for outgoing data
		if ok {
			waitMs := 20 + rand.IntN(50)
			// Fix: replace time.After with NewTimer to prevent timer leak
			timer := time.NewTimer(time.Duration(waitMs) * time.Millisecond)
			select {
			case data := <-tunnel.Outgoing:
				timer.Stop()
				responsePayload = data
			case <-timer.C:
			}
		}

	case core.FlagPadding:
		// Cover traffic — just ACK

	case core.FlagKeepalive:
		// Will send ACK below

	case core.FlagConnect:
		// TODO: handle CONNECT over UDP
		return

	case core.FlagFin:
		u.handler.handleFin(session)
		u.peersMu.Lock()
		delete(u.peers, sessionID)
		u.peersMu.Unlock()
		return
	}

	// Build encrypted response
	respChunk := &core.Chunk{
		SessionID: session.ID,
		SeqNum:    session.NextSeqNum(),
		Flags:     core.FlagData,
		Payload:   responsePayload,
	}
	if chunk.Flags == core.FlagKeepalive {
		respChunk.Flags = core.FlagAck
	}

	// CRIT-1 fix: use safe wrapper that copies keys under lock
	encrypted, err := session.EncryptChunk(respChunk)
	if err != nil {
		return
	}

	u.handler.metrics.ChunksSent.Add(1)

	// Send: [session_id(4)] + [encrypted]
	resp := make([]byte, 4+len(encrypted))
	binary.BigEndian.PutUint32(resp[:4], session.ID)
	copy(resp[4:], encrypted)

	u.conn.WriteToUDP(resp, remoteAddr)
}
