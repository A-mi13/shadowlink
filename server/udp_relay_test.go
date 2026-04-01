package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startUDPEchoServer starts a UDP server that echoes back whatever it receives.
// Returns the address and a cleanup function.
func startUDPEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-done:
				return
			default:
			}
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				continue
			}
			conn.WriteTo(buf[:n], addr)
		}
	}()

	return conn.LocalAddr().String(), func() {
		close(done)
		conn.Close()
	}
}

func TestUDPRelayBasic(t *testing.T) {
	echoAddr, cleanup := startUDPEchoServer(t)
	defer cleanup()

	relay := NewUDPRelay(5 * time.Second)
	defer relay.Close()

	var mu sync.Mutex
	var received []byte
	gotData := make(chan struct{}, 1)

	onReceive := func(data []byte) {
		mu.Lock()
		received = append(received, data...)
		mu.Unlock()
		select {
		case gotData <- struct{}{}:
		default:
		}
	}

	// Send data through relay
	err := relay.Send(1, echoAddr, []byte("hello udp"), onReceive)
	require.NoError(t, err)

	// Wait for echo response
	select {
	case <-gotData:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for UDP echo response")
	}

	mu.Lock()
	assert.Equal(t, []byte("hello udp"), received)
	mu.Unlock()

	assert.Equal(t, 1, relay.FlowCount())
}

func TestUDPRelayMultipleStreams(t *testing.T) {
	echoAddr, cleanup := startUDPEchoServer(t)
	defer cleanup()

	relay := NewUDPRelay(5 * time.Second)
	defer relay.Close()

	var mu1, mu2 sync.Mutex
	var received1, received2 []byte
	got1 := make(chan struct{}, 1)
	got2 := make(chan struct{}, 1)

	err := relay.Send(1, echoAddr, []byte("stream1"), func(data []byte) {
		mu1.Lock()
		received1 = append(received1, data...)
		mu1.Unlock()
		select {
		case got1 <- struct{}{}:
		default:
		}
	})
	require.NoError(t, err)

	err = relay.Send(2, echoAddr, []byte("stream2"), func(data []byte) {
		mu2.Lock()
		received2 = append(received2, data...)
		mu2.Unlock()
		select {
		case got2 <- struct{}{}:
		default:
		}
	})
	require.NoError(t, err)

	// Wait for both
	for _, ch := range []chan struct{}{got1, got2} {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for UDP echo response")
		}
	}

	mu1.Lock()
	assert.Equal(t, []byte("stream1"), received1)
	mu1.Unlock()

	mu2.Lock()
	assert.Equal(t, []byte("stream2"), received2)
	mu2.Unlock()

	assert.Equal(t, 2, relay.FlowCount())
}

func TestUDPRelayReuseFlow(t *testing.T) {
	echoAddr, cleanup := startUDPEchoServer(t)
	defer cleanup()

	relay := NewUDPRelay(5 * time.Second)
	defer relay.Close()

	gotData := make(chan []byte, 10)

	onReceive := func(data []byte) {
		cp := make([]byte, len(data))
		copy(cp, data)
		gotData <- cp
	}

	// Send twice on same stream — should reuse the same flow
	err := relay.Send(1, echoAddr, []byte("first"), onReceive)
	require.NoError(t, err)

	select {
	case d := <-gotData:
		assert.Equal(t, []byte("first"), d)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	err = relay.Send(1, echoAddr, []byte("second"), onReceive)
	require.NoError(t, err)

	select {
	case d := <-gotData:
		assert.Equal(t, []byte("second"), d)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}

	// Still only 1 flow
	assert.Equal(t, 1, relay.FlowCount())
}

func TestUDPRelayCleanup(t *testing.T) {
	echoAddr, cleanup := startUDPEchoServer(t)
	defer cleanup()

	relay := NewUDPRelay(100 * time.Millisecond)
	defer relay.Close()

	err := relay.Send(1, echoAddr, []byte("hello"), func(data []byte) {})
	require.NoError(t, err)
	assert.Equal(t, 1, relay.FlowCount())

	// Wait for flow to expire
	time.Sleep(200 * time.Millisecond)

	relay.Cleanup()
	assert.Equal(t, 0, relay.FlowCount())
}

func TestUDPRelayRemoveFlow(t *testing.T) {
	echoAddr, cleanup := startUDPEchoServer(t)
	defer cleanup()

	relay := NewUDPRelay(5 * time.Second)
	defer relay.Close()

	err := relay.Send(1, echoAddr, []byte("hello"), func(data []byte) {})
	require.NoError(t, err)
	err = relay.Send(2, echoAddr, []byte("world"), func(data []byte) {})
	require.NoError(t, err)
	assert.Equal(t, 2, relay.FlowCount())

	relay.RemoveFlow(1)
	assert.Equal(t, 1, relay.FlowCount())

	relay.RemoveFlow(2)
	assert.Equal(t, 0, relay.FlowCount())
}

func TestUDPRelayClose(t *testing.T) {
	echoAddr, cleanup := startUDPEchoServer(t)
	defer cleanup()

	relay := NewUDPRelay(5 * time.Second)

	err := relay.Send(1, echoAddr, []byte("a"), func(data []byte) {})
	require.NoError(t, err)
	err = relay.Send(2, echoAddr, []byte("b"), func(data []byte) {})
	require.NoError(t, err)
	assert.Equal(t, 2, relay.FlowCount())

	relay.Close()
	assert.Equal(t, 0, relay.FlowCount())
}
