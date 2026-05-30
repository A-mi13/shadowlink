package client

import (
	"context"
	"testing"
)

// fakeTryControl implements TryControlPoolAware for the helper test.
type fakeTryControl struct {
	tried   bool
	allowed bool
}

func (f *fakeTryControl) TryWriteControlMessageForStream(streamID uint16, data []byte) bool {
	f.tried = true
	return f.allowed
}

// fakeTryControl must also satisfy StreamTransport for TryStreamWriteControl's
// type switch (it takes a StreamTransport). Add no-op StreamTransport methods.
func (f *fakeTryControl) WriteMessage(data []byte) error                   { return nil }
func (f *fakeTryControl) StartReader(ctx context.Context, cl *Client) error { return nil }
func (f *fakeTryControl) Close() error                                     { return nil }

func TestTryStreamWriteControl_UsesPoolPath(t *testing.T) {
	f := &fakeTryControl{allowed: true}
	if !TryStreamWriteControl(f, 5, []byte("x")) {
		t.Fatal("expected true when pool path accepts")
	}
	if !f.tried {
		t.Fatal("pool TryWriteControlMessageForStream not called")
	}
}

func TestTryStreamWriteControl_FalseWhenChannelFull(t *testing.T) {
	f := &fakeTryControl{allowed: false}
	if TryStreamWriteControl(f, 5, []byte("x")) {
		t.Fatal("expected false when pool path rejects")
	}
	if !f.tried {
		t.Fatal("pool TryWriteControlMessageForStream should still be called")
	}
}

func TestTryStreamWriteControl_FalseWhenNotSupported(t *testing.T) {
	var notSupported StreamTransport = &nopStreamTransport{}
	if TryStreamWriteControl(notSupported, 1, []byte("x")) {
		t.Fatal("expected false for transport without TryControlPoolAware")
	}
}

// nopStreamTransport implements StreamTransport only (no TryControlPoolAware).
type nopStreamTransport struct{}

func (nopStreamTransport) WriteMessage(data []byte) error                   { return nil }
func (nopStreamTransport) StartReader(ctx context.Context, cl *Client) error { return nil }
func (nopStreamTransport) Close() error                                     { return nil }

func TestOnStreamConsumed_AccumulatesPendingDelta(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 1 << 20
	c.streamFlow = map[uint16]*streamFlowState{}
	c.streamFlow[7] = &streamFlowState{window: 1 << 20}

	c.OnStreamConsumed(7, 1000)
	c.OnStreamConsumed(7, 2000)

	if got := c.streamFlow[7].pendingDelta.Load(); got != 3000 {
		t.Fatalf("pendingDelta = %d, want 3000", got)
	}
}

func TestOnStreamConsumed_NoopWhenDisabled(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = false
	c.streamFlow = map[uint16]*streamFlowState{7: {window: 1 << 20}}
	c.OnStreamConsumed(7, 5000)
	if got := c.streamFlow[7].pendingDelta.Load(); got != 0 {
		t.Fatalf("pendingDelta = %d, want 0 (disabled)", got)
	}
}

func TestOnStreamConsumed_UnknownStreamSafe(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.streamFlow = map[uint16]*streamFlowState{}
	c.OnStreamConsumed(999, 100) // no panic, no-op
}
