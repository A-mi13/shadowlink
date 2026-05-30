package server

import (
	"testing"
	"time"
)

func TestStreamCredit_WaitUnblocksOnAdd(t *testing.T) {
	c := newStreamCredit(0) // start with zero credit
	done := make(chan int64, 1)
	doneCh := make(chan struct{})
	go func() { done <- c.waitForCredit(doneCh) }()

	select {
	case <-done:
		t.Fatal("waitForCredit returned with zero credit")
	case <-time.After(50 * time.Millisecond):
	}

	c.add(500, 1<<20)
	select {
	case got := <-done:
		if got != 500 {
			t.Fatalf("waitForCredit = %d, want 500", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waitForCredit did not unblock after add")
	}
}

func TestStreamCredit_CloseUnblocks(t *testing.T) {
	c := newStreamCredit(0)
	done := make(chan int64, 1)
	go func() { done <- c.waitForCredit(make(chan struct{})) }()
	time.Sleep(20 * time.Millisecond)
	c.close()
	select {
	case got := <-done:
		if got > 0 {
			t.Fatalf("waitForCredit after close = %d, want <=0", got)
		}
	case <-time.After(time.Second):
		t.Fatal("close did not unblock waiter")
	}
}

func TestStreamCredit_ConsumeAndClamp(t *testing.T) {
	c := newStreamCredit(1000)
	c.consume(400)
	if got := c.snapshot(); got != 600 {
		t.Fatalf("after consume available = %d, want 600", got)
	}
	c.add(100000, 1000) // window=1000 → clamp at 2*window=2000
	if got := c.snapshot(); got > 2000 {
		t.Fatalf("available = %d, exceeds clamp 2000", got)
	}
}

func TestStreamCredit_WaitReturnsWhenDoneClosed(t *testing.T) {
	c := newStreamCredit(0)
	doneCh := make(chan struct{})
	res := make(chan int64, 1)
	go func() { res <- c.waitForCredit(doneCh) }()
	time.Sleep(20 * time.Millisecond)
	close(doneCh)
	c.wake() // done-watcher wakes the cond
	select {
	case got := <-res:
		if got > 0 {
			t.Fatalf("got %d, want <=0 on done", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiter not woken on done")
	}
}
