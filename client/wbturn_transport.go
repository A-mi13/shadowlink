package client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/call"
	"github.com/nixavpn/shadowlink/skins/call/wbcreds"
)

// WBTurnTransport implements Transport over WB Stream TURN relay.
// Uses Wildberries video conferencing TURN servers as relay — no VK account needed.
// Data: Client → WB TURN server (whitelisted IP) → ShadowLink server (UDP).
type WBTurnTransport struct {
	turnClient *call.TURNClient
	sessionID  uint32
	mu         sync.Mutex
	closed     bool
}

// NewWBTurnTransport fetches TURN credentials from WB Stream API,
// connects to a WB TURN server, and prepares relay to ShadowLink server.
func NewWBTurnTransport(serverUDPAddr string) (*WBTurnTransport, error) {
	slog.Info("wbturn: fetching TURN credentials from WB Stream...")
	creds, err := wbcreds.GetTURNCredentials()
	if err != nil {
		return nil, fmt.Errorf("wbturn credentials: %w", err)
	}
	slog.Info("wbturn: got credentials", "count", len(creds))

	// Try each TURN server until one works
	var lastErr error
	for _, cred := range creds {
		if cred.URL == "" || cred.Username == "" {
			continue
		}

		// Parse TURN URL: "turn:host:port?transport=udp" → "host:port"
		turnAddr := parseTURNURL(cred.URL)
		if turnAddr == "" {
			continue
		}

		slog.Info("wbturn: trying TURN server", "addr", turnAddr)
		tc, err := call.NewTURNClient(call.TURNConfig{
			TURNServer: turnAddr,
			Username:   cred.Username,
			Password:   cred.Password,
			PeerAddr:   serverUDPAddr,
		})
		if err != nil {
			lastErr = err
			slog.Debug("wbturn: TURN failed", "addr", turnAddr, "error", err)
			continue
		}

		slog.Info("wbturn: relay allocated", "relay", tc.RelayAddr().String(), "turn", turnAddr)
		return &WBTurnTransport{turnClient: tc}, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all WB TURN servers failed, last error: %w", lastErr)
	}
	return nil, errors.New("no usable WB TURN servers found")
}

func (t *WBTurnTransport) Name() string { return "wb_turn" }

// SendHandshake sends ClientHello via WB TURN relay.
// Format: [0x00000000] + [ephPub + encClientID].
func (t *WBTurnTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	payload := make([]byte, 0, len(hello.EphemeralPub)+len(hello.EncryptedClientID))
	payload = append(payload, hello.EphemeralPub...)
	payload = append(payload, hello.EncryptedClientID...)

	// session_id=0 = handshake sentinel
	datagram := make([]byte, 4+len(payload))
	copy(datagram[4:], payload)

	if err := t.turnClient.Send(datagram); err != nil {
		return nil, fmt.Errorf("wbturn send handshake: %w", err)
	}

	resp, err := t.turnClient.Receive(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("wbturn receive handshake: %w", err)
	}
	if len(resp) < 5 {
		return nil, errors.New("wbturn: handshake response too short")
	}

	// Parse session_id from response prefix
	sid := binary.BigEndian.Uint32(resp[:4])
	t.mu.Lock()
	t.sessionID = sid
	t.mu.Unlock()

	// Wrap raw ServerHello JSON in downloadEnvelope for Client.Connect() parsing
	serverHelloJSON := resp[4:]
	env, _ := json.Marshal(map[string]any{
		"status": "ok",
		"results": []map[string]any{
			{
				"id":      "00000000",
				"payload": base64.RawURLEncoding.EncodeToString(serverHelloJSON),
			},
		},
	})
	return env, nil
}

// SendChunk sends an encrypted chunk via WB TURN relay.
// Format: [session_id(4)] + [chunk].
func (t *WBTurnTransport) SendChunk(ctx context.Context, encryptedChunk []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	t.mu.Lock()
	sid := t.sessionID
	t.mu.Unlock()

	datagram := make([]byte, 4+len(encryptedChunk))
	binary.BigEndian.PutUint32(datagram[:4], sid)
	copy(datagram[4:], encryptedChunk)

	if err := t.turnClient.Send(datagram); err != nil {
		return nil, fmt.Errorf("wbturn send: %w", err)
	}

	resp, err := t.turnClient.Receive(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("wbturn receive: %w", err)
	}
	if len(resp) < 5 {
		return nil, errors.New("wbturn: response too short")
	}

	// Strip session_id prefix, return encrypted chunk
	return resp[4:], nil
}

func (t *WBTurnTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.turnClient.Close()
}

// parseTURNURL extracts "host:port" from TURN URL format.
// Examples: "turn:host:3478?transport=udp" → "host:3478"
//           "turn:host:3478" → "host:3478"
//           "turns:host:5349" → "host:5349"
func parseTURNURL(rawURL string) string {
	// Strip scheme
	addr := rawURL
	for _, prefix := range []string{"turns:", "turn:"} {
		if len(addr) > len(prefix) && addr[:len(prefix)] == prefix {
			addr = addr[len(prefix):]
			break
		}
	}
	// Strip query params
	for i, c := range addr {
		if c == '?' {
			addr = addr[:i]
			break
		}
	}
	if addr == "" {
		return ""
	}
	return addr
}
