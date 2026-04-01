package testutil

import (
	"net"
	"strconv"

	"github.com/pion/logging"
	"github.com/pion/turn/v4"
)

// TestTURNServer is an embedded TURN server for integration tests.
type TestTURNServer struct {
	server *turn.Server
	addr   string
}

// NewTestTURNServer starts a TURN server on the given address with static credentials.
// Use "127.0.0.1:0" for random port.
func NewTestTURNServer(listenAddr, username, password string) (*TestTURNServer, error) {
	udpListener, err := net.ListenPacket("udp4", listenAddr)
	if err != nil {
		return nil, err
	}

	logFactory := logging.NewDefaultLoggerFactory()
	logFactory.DefaultLogLevel = logging.LogLevelError

	server, err := turn.NewServer(turn.ServerConfig{
		Realm: "shadowlink-test",
		AuthHandler: func(username2, realm string, srcAddr net.Addr) ([]byte, bool) {
			if username2 == username {
				return turn.GenerateAuthKey(username, realm, password), true
			}
			return nil, false
		},
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: net.ParseIP("127.0.0.1"),
					Address:      "0.0.0.0",
				},
			},
		},
		LoggerFactory: logFactory,
	})
	if err != nil {
		udpListener.Close()
		return nil, err
	}

	// Get actual address
	addr := udpListener.LocalAddr().(*net.UDPAddr)

	return &TestTURNServer{
		server: server,
		addr:   "127.0.0.1:" + strconv.Itoa(addr.Port),
	}, nil
}

// Addr returns the TURN server address "host:port".
func (t *TestTURNServer) Addr() string {
	return t.addr
}

// Close stops the TURN server.
func (t *TestTURNServer) Close() error {
	if t.server != nil {
		return t.server.Close()
	}
	return nil
}
