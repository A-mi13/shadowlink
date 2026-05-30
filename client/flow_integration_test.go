package client

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFlowControl_NoDropsUnderFastDownload reproduces the Bug #8 scenario:
// a server pushing frames faster than the app consumes them. With flow control
// the server respects the credit window, so RouteToStream never overflows and
// no bytes are dropped.
func TestFlowControl_NoDropsUnderFastDownload(t *testing.T) {
	const window = 64 * 1024
	const total = 4 * 1024 * 1024 // 4 MiB download
	const frame = 4096

	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = window
	c.streamFlow = map[uint16]*streamFlowState{}
	ch, err := c.RegisterStream(1)
	if err != nil {
		t.Fatal(err)
	}
	c.streamFlow[1] = &streamFlowState{window: window}

	// server-side credit mirror
	var mu sync.Mutex
	credit := int64(window)

	// client credit sender feeds WINDOW_UPDATE back to the server mirror
	c.flowSendForTest = func(_ uint16, delta uint32) bool {
		mu.Lock()
		credit += int64(delta)
		mu.Unlock()
		return true
	}

	baseline := Stats.StreamBufferOverflowsTotal.Load()

	// slow consumer: drains ch and credits consumption
	consumed := 0
	consumerDone := make(chan struct{})
	go func() {
		defer close(consumerDone)
		for consumed < total {
			select {
			case data := <-ch:
				time.Sleep(time.Millisecond) // slow app
				consumed += len(data)
				c.OnStreamConsumed(1, len(data))
			case <-time.After(5 * time.Second):
				return
			}
		}
	}()

	// credit sender ticking
	stop := make(chan struct{})
	go func() {
		tk := time.NewTicker(2 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tk.C:
				c.creditSenderTick(0.5)
			}
		}
	}()

	// server: send frames only while credit available
	sent := 0
	for sent < total {
		mu.Lock()
		has := credit > 0
		mu.Unlock()
		if !has {
			time.Sleep(time.Millisecond)
			continue
		}
		c.RouteToStream(1, make([]byte, frame))
		mu.Lock()
		credit -= frame
		mu.Unlock()
		sent += frame
	}

	<-consumerDone
	close(stop)

	drops := Stats.StreamBufferOverflowsTotal.Load() - baseline
	if drops != 0 {
		t.Fatalf("flow control should yield 0 drops, got %d", drops)
	}
	if consumed < total {
		t.Fatalf("consumed %d < total %d (stalled)", consumed, total)
	}
}

// TestFlowControl_NoHeadOfLineBlocking proves per-stream isolation: one stuck
// stream (channel fills, no consumer) must not block a live stream from
// receiving its data. RouteToStream uses a non-blocking send on stream 1's
// channel (drops on overflow) and an independent channel for stream 2.
func TestFlowControl_NoHeadOfLineBlocking(t *testing.T) {
	c := &Client{}
	c.flowControlEnabled = true
	c.flowWindow = 32 * 1024
	c.streamFlow = map[uint16]*streamFlowState{}

	chStuck, err := c.RegisterStream(1)
	if err != nil {
		t.Fatal(err)
	}
	chLive, err := c.RegisterStream(2)
	if err != nil {
		t.Fatal(err)
	}
	c.streamFlow[1] = &streamFlowState{window: 32 * 1024}
	c.streamFlow[2] = &streamFlowState{window: 32 * 1024}

	_ = chStuck // never drained → its channel fills; must NOT block stream 2

	// stream 2 has an active consumer
	var got2 atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for got2.Load() < 100*1024 {
			select {
			case d := <-chLive:
				got2.Add(int64(len(d)))
			case <-time.After(2 * time.Second):
				return
			}
		}
	}()

	// fill stream 1 channel beyond cap (no consumer) — drops on stream 1 only,
	// must not stop stream 2
	for i := 0; i < 600; i++ {
		c.RouteToStream(1, make([]byte, 1024))
	}
	// stream 2 keeps flowing while stream 1 is stuck/overflowing
	for got2.Load() < 100*1024 {
		c.RouteToStream(2, make([]byte, 1024))
	}
	<-done
	if got2.Load() < 100*1024 {
		t.Fatalf("stream 2 starved by stuck stream 1: got %d, want >=100KiB", got2.Load())
	}
}
