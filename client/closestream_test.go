package client

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestCloseStreamWithSlowTransport(t *testing.T) {
	_, receiver := testSessionPair(t)

	cl := &Client{}
	cl.session = receiver
	cl.RegisterStream(1) //nolint:errcheck

	slow := &slowTransport{delay: 5 * time.Second}

	start := time.Now()
	cl.CloseStream(1, slow)
	elapsed := time.Since(start)

	if elapsed < 2*time.Second || elapsed > 4*time.Second {
		t.Errorf("CloseStream took %v, expected ~3s timeout", elapsed)
	}
}

func TestCloseStreamWithFailingTransport(t *testing.T) {
	_, receiver := testSessionPair(t)

	cl := &Client{}
	cl.session = receiver
	cl.RegisterStream(1) //nolint:errcheck

	failing := &failTransport{}

	start := time.Now()
	cl.CloseStream(1, failing)
	elapsed := time.Since(start)

	if elapsed > 1*time.Second {
		t.Errorf("CloseStream with failing transport took too long: %v", elapsed)
	}
}

type slowTransport struct {
	delay time.Duration
}

func (s *slowTransport) WriteMessage(data []byte) error {
	time.Sleep(s.delay)
	return nil
}
func (s *slowTransport) StartReader(ctx context.Context, cl *Client) error { return nil }
func (s *slowTransport) Close() error                                      { return nil }

type failTransport struct{}

func (f *failTransport) WriteMessage(data []byte) error {
	return fmt.Errorf("transport closed")
}
func (f *failTransport) StartReader(ctx context.Context, cl *Client) error { return nil }
func (f *failTransport) Close() error                                      { return nil }
