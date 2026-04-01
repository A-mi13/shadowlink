package call

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

// TURNConfig holds the TURN server connection parameters.
type TURNConfig struct {
	TURNServer string // "host:port" of TURN server
	Username   string // TURN credentials
	Password   string // TURN credentials
	PeerAddr   string // ShadowLink server UDP "host:port"
	Realm      string // TURN realm (optional)
}

// TURNClient wraps pion/turn to provide a simple send/receive interface.
type TURNClient struct {
	conn      net.PacketConn // local UDP socket
	client    *turn.Client   // pion TURN client
	relayConn net.PacketConn // TURN-allocated relay connection
	peerAddr  net.Addr       // ShadowLink server UDP address

	mu     sync.Mutex
	closed bool
}

// NewTURNClient connects to a TURN server, allocates a relay, and creates
// a permission for the ShadowLink server's UDP address.
func NewTURNClient(config TURNConfig) (*TURNClient, error) {
	if config.TURNServer == "" {
		return nil, errors.New("TURN server address required")
	}
	if config.PeerAddr == "" {
		return nil, errors.New("peer address required")
	}

	// Resolve peer address
	peerUDP, err := net.ResolveUDPAddr("udp4", config.PeerAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve peer addr: %w", err)
	}

	// Local UDP socket
	conn, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	// Create TURN client
	logFactory := logging.NewDefaultLoggerFactory()
	logFactory.DefaultLogLevel = logging.LogLevelError // suppress verbose logs

	turnCfg := &turn.ClientConfig{
		STUNServerAddr: config.TURNServer,
		TURNServerAddr: config.TURNServer,
		Conn:           conn,
		Username:       config.Username,
		Password:       config.Password,
		Realm:          config.Realm,
		LoggerFactory:  logFactory,
	}

	client, err := turn.NewClient(turnCfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("create TURN client: %w", err)
	}

	// Listen for TURN messages
	if err := client.Listen(); err != nil {
		client.Close()
		conn.Close()
		return nil, fmt.Errorf("TURN listen: %w", err)
	}

	// Allocate relay address
	relayConn, err := client.Allocate()
	if err != nil {
		client.Close()
		conn.Close()
		return nil, fmt.Errorf("TURN allocate: %w", err)
	}

	return &TURNClient{
		conn:      conn,
		client:    client,
		relayConn: relayConn,
		peerAddr:  peerUDP,
	}, nil
}

// Send sends data through the TURN relay to the peer (ShadowLink server).
func (t *TURNClient) Send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("TURN client closed")
	}
	_, err := t.relayConn.WriteTo(data, t.peerAddr)
	return err
}

// Receive reads data from the TURN relay (response from ShadowLink server).
func (t *TURNClient) Receive(timeout time.Duration) ([]byte, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("TURN client closed")
	}
	rc := t.relayConn
	t.mu.Unlock()

	buf := make([]byte, 2048)
	rc.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := rc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

// RelayAddr returns the TURN-allocated relay address.
func (t *TURNClient) RelayAddr() net.Addr {
	if t.relayConn == nil {
		return nil
	}
	return t.relayConn.LocalAddr()
}

// Close releases the TURN allocation and closes connections.
func (t *TURNClient) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	if t.relayConn != nil {
		t.relayConn.Close()
	}
	if t.client != nil {
		t.client.Close()
	}
	if t.conn != nil {
		t.conn.Close()
	}
	return nil
}
