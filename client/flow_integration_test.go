package client

import (
	"sync"
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
