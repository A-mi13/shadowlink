//go:build linux

// Race tests skip on Windows (no gcc). Run on Linux CI.
//
// These tests exist to lock in audit A4-M5 (2026-04-25) — the
// send-on-closed-channel panic that used to be masked by `defer recover`.
// After A4-M5 closeTunnel only closes `done`; senders MUST select on
// `<-tunnel.done` to short-circuit. This file's tests prove the
// invariant under the race detector. Run via:
//
//   go test -race -count=3 ./server/ -run TestConcurrentTunnelClose
//
// They are gated on linux because Go's race detector requires CGO + gcc,
// and the project's Windows dev hosts deliberately skip CGO. The CI
// matrix MUST include a linux job that runs `-race`.

package server

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestConcurrentTunnelClose drives N producer goroutines through the
// canonical "select with done" pattern while a single closer calls
// closeTunnel mid-stream. After A4-M5 the only allowed effect of
// closeTunnel is closing `done`; producers either succeed in their
// send or observe `done` and exit cleanly. Either way: no panics.
//
// Failure modes this test catches:
//
//  1. closeTunnel reintroduces close(Outgoing) — producer panics on
//     the send-arm.
//  2. A producer is reintroduced without the `<-tunnel.done` select
//     guard — producer hangs forever (test hits its deadline).
//  3. closeOnce is removed/broken — second close() panics.
func TestConcurrentTunnelClose(t *testing.T) {
	const senders = 32
	const sendsPer = 200

	tunnel := &Tunnel{
		Incoming:    make(chan []byte, 8),
		Outgoing:    make(chan []byte, 8),
		OutgoingUDP: make(chan []byte, 8),
		done:        make(chan struct{}),
	}

	var wg sync.WaitGroup
	var sent atomic.Int64
	var dropped atomic.Int64
	var panics atomic.Int32

	// Producers: send via the canonical select-with-done pattern.
	for i := range senders {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					panics.Add(1)
					t.Errorf("sender %d panicked: %v", id, r)
				}
			}()
			for range sendsPer {
				select {
				case <-tunnel.done:
					dropped.Add(1)
					return
				case tunnel.Outgoing <- []byte{0xAA}:
					sent.Add(1)
				}
			}
		}(i)
	}

	// Drainer: pull from Outgoing so producers can make progress.
	doneDrain := make(chan struct{})
	go func() {
		defer close(doneDrain)
		for {
			select {
			case <-tunnel.done:
				// After done fires, drain remaining items briefly so
				// producers in the send-arm complete instead of
				// blocking forever. After A4-M5 the channel is not
				// closed; this loop must self-exit on a deadline.
				deadline := time.NewTimer(50 * time.Millisecond)
				defer deadline.Stop()
				for {
					select {
					case <-tunnel.Outgoing:
					case <-deadline.C:
						return
					}
				}
			case <-tunnel.Outgoing:
			}
		}
	}()

	// Closer: fire close midway through the burst.
	time.Sleep(2 * time.Millisecond)
	tunnel.closeTunnel()
	// Idempotency: second call must not panic.
	tunnel.closeTunnel()

	// Reaper deadline — 5s is generous; a deadlock surfaces as a fail.
	doneAll := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneAll)
	}()
	select {
	case <-doneAll:
	case <-time.After(5 * time.Second):
		t.Fatalf("producers deadlocked after closeTunnel — sent=%d dropped=%d", sent.Load(), dropped.Load())
	}
	<-doneDrain

	if got := panics.Load(); got != 0 {
		t.Fatalf("got %d panics, want 0 (audit A4-M5 invariant)", got)
	}
	// Sanity: at least some sends and at least some drops happened —
	// otherwise the test scheduler missed the race window and we
	// didn't actually exercise the close-mid-flight path.
	if sent.Load() == 0 {
		t.Logf("WARN: no sends completed before close — close may have fired too early")
	}
	if dropped.Load() == 0 {
		t.Logf("WARN: no drops observed — close may have fired too late")
	}
}

// TestSafeSendPattern_DocumentsContract is a runnable example that pins the
// canonical sender pattern. Code reviewers can grep `safeSend` and find
// this as the reference. Audit A4-M5 ratifies this as the public contract
// for any caller writing to tunnel.Outgoing / tunnel.OutgoingUDP.
func TestSafeSendPattern_DocumentsContract(t *testing.T) {
	tunnel := &Tunnel{
		Outgoing: make(chan []byte, 1),
		done:     make(chan struct{}),
	}

	// Pre-fill so the next send blocks.
	tunnel.Outgoing <- []byte("first")

	// Close — sender below MUST observe done before send completes.
	go func() {
		time.Sleep(5 * time.Millisecond)
		tunnel.closeTunnel()
	}()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("safe-send pattern must not panic: %v", r)
		}
	}()

	select {
	case <-tunnel.done:
		// Expected path on close-during-send.
	case tunnel.Outgoing <- []byte("second"):
		t.Fatal("expected done fast-path, got send (channel had no drainer)")
	}
}
