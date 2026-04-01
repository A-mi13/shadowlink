package client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/call"
)

// CallSkinTransport implements Transport over TURN relay (Phase 2 whitelist bypass).
// Data: Client → TURN server (whitelisted IP) → ShadowLink server (UDP:56000).
type CallSkinTransport struct {
	turnClient *call.TURNClient
	sessionID  uint32 // set after handshake for datagram framing
	mu         sync.Mutex
	closed     bool
}

// CallSkinConfig holds TURN relay configuration.
type CallSkinConfig struct {
	TURNServer    string // TURN "host:port"
	TURNUsername  string
	TURNPassword  string
	ServerUDPAddr string // ShadowLink server UDP "host:port"
}

// NewCallSkinTransport creates a transport over TURN relay.
func NewCallSkinTransport(config CallSkinConfig) (*CallSkinTransport, error) {
	tc, err := call.NewTURNClient(call.TURNConfig{
		TURNServer: config.TURNServer,
		Username:   config.TURNUsername,
		Password:   config.TURNPassword,
		PeerAddr:   config.ServerUDPAddr,
	})
	if err != nil {
		return nil, fmt.Errorf("TURN client: %w", err)
	}
	return &CallSkinTransport{turnClient: tc}, nil
}

func (t *CallSkinTransport) Name() string { return "call_skin" }

// SendHandshake sends ClientHello via TURN UDP. Format: [0x00000000] + [ephPub + encClientID].
func (t *CallSkinTransport) SendHandshake(ctx context.Context, hello *core.ClientHello) ([]byte, error) {
	payload := make([]byte, 0, len(hello.EphemeralPub)+len(hello.EncryptedClientID))
	payload = append(payload, hello.EphemeralPub...)
	payload = append(payload, hello.EncryptedClientID...)

	// session_id=0 = handshake sentinel
	datagram := make([]byte, 4+len(payload))
	copy(datagram[4:], payload)

	if err := t.turnClient.Send(datagram); err != nil {
		return nil, fmt.Errorf("TURN send: %w", err)
	}

	resp, err := t.turnClient.Receive(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("TURN receive: %w", err)
	}
	if len(resp) < 5 {
		return nil, errors.New("response too short")
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

// SendChunk sends an encrypted chunk via TURN. Format: [session_id(4)] + [chunk].
func (t *CallSkinTransport) SendChunk(ctx context.Context, encryptedChunk []byte, sessionToken []byte, seqNum uint32) ([]byte, error) {
	t.mu.Lock()
	sid := t.sessionID
	t.mu.Unlock()

	datagram := make([]byte, 4+len(encryptedChunk))
	binary.BigEndian.PutUint32(datagram[:4], sid)
	copy(datagram[4:], encryptedChunk)

	if err := t.turnClient.Send(datagram); err != nil {
		return nil, fmt.Errorf("TURN send: %w", err)
	}

	resp, err := t.turnClient.Receive(10 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("TURN receive: %w", err)
	}
	if len(resp) < 5 {
		return nil, errors.New("response too short")
	}

	// Strip session_id prefix, return encrypted chunk
	return resp[4:], nil
}

func (t *CallSkinTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.turnClient.Close()
}
