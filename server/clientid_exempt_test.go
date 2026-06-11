package server

import (
	"testing"
	"time"
)

func TestExemption_MarkSeenAndAllow(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 60, time.Minute, 0)
	cid := []byte("clientid-aaaaaaaa")
	if e.IsExempt(cid) {
		t.Fatal("fresh clientID should not be exempt")
	}
	e.MarkSeen(cid)
	if !e.IsExempt(cid) {
		t.Fatal("after MarkSeen should be exempt")
	}
}

func TestExemption_TTLExpiry(t *testing.T) {
	e := NewClientIDExemption(100, 50*time.Millisecond, 60, time.Minute, 0)
	cid := []byte("ttl-test-clientid")
	e.MarkSeen(cid)
	time.Sleep(100 * time.Millisecond)
	if e.IsExempt(cid) {
		t.Fatal("after TTL expiry should not be exempt")
	}
}

func TestExemption_SoftLimit(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 3, time.Minute, 0)
	cid := []byte("softlimit-cid")
	e.MarkSeen(cid)
	for i := range 3 {
		if !e.AllowExempted(cid) {
			t.Fatalf("hit %d should allow", i)
		}
	}
	if e.AllowExempted(cid) {
		t.Fatal("4th hit (above softLimit=3) should reject")
	}
}

func TestExemption_LRUEviction(t *testing.T) {
	e := NewClientIDExemption(2, 1*time.Hour, 60, time.Minute, 0)
	a, b, c := []byte("aa"), []byte("bb"), []byte("cc")
	e.MarkSeen(a)
	e.MarkSeen(b)
	e.MarkSeen(c)
	if e.IsExempt(a) {
		t.Fatal("a should be evicted (LRU cap=2)")
	}
}

func TestExemption_SoftLimitDisabled(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 0, time.Minute, 0)
	cid := []byte("nocap-cid")
	e.MarkSeen(cid)
	for i := range 100 {
		if !e.AllowExempted(cid) {
			t.Fatalf("hit %d should allow when softLimit=0 (unlimited)", i)
		}
	}
}

func TestExemption_SoftWindowReset(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 1, 50*time.Millisecond, 0)
	cid := []byte("win-reset-cid")
	e.MarkSeen(cid)
	if !e.AllowExempted(cid) {
		t.Fatal("first hit should allow")
	}
	if e.AllowExempted(cid) {
		t.Fatal("second hit should be blocked (softLimit=1)")
	}
	time.Sleep(60 * time.Millisecond)
	if !e.AllowExempted(cid) {
		t.Fatal("after softWindow elapse, should allow again")
	}
}

func TestExemption_ByteCapAllowsGenerously(t *testing.T) {
	// 1 MiB/s cap; a single 64 KiB chunk is well under → allowed.
	e := NewClientIDExemption(100, time.Hour, 60, time.Minute, 1<<20)
	cid := []byte("u1:d1")
	if !e.AllowExemptedBytes(cid, 64*1024) {
		t.Fatal("64 KiB under 1 MiB/s cap must be allowed")
	}
}

func TestExemption_ByteCapTrips(t *testing.T) {
	// Tiny 1 KiB/s cap; first big chunk drains it, second within the same second rejected.
	e := NewClientIDExemption(100, time.Hour, 60, time.Minute, 1024)
	cid := []byte("u1:d1")
	if !e.AllowExemptedBytes(cid, 1024) {
		t.Fatal("first 1 KiB fills the budget, must be allowed")
	}
	if e.AllowExemptedBytes(cid, 1024) {
		t.Fatal("second 1 KiB within the same second must be rejected (cap tripped)")
	}
}

func TestExemption_ByteCapUnlimitedWhenZero(t *testing.T) {
	e := NewClientIDExemption(100, time.Hour, 60, time.Minute, 0)
	cid := []byte("u1:d1")
	for i := 0; i < 1000; i++ {
		if !e.AllowExemptedBytes(cid, 10*1024*1024) {
			t.Fatal("zero cap = unlimited, must always allow")
		}
	}
}

func TestExemption_ByteCapRefills(t *testing.T) {
	e := NewClientIDExemption(100, time.Hour, 60, time.Minute, 1024)
	cid := []byte("u1:d1")
	e.AllowExemptedBytes(cid, 1024) // drain
	if e.AllowExemptedBytes(cid, 1) {
		t.Fatal("immediately drained")
	}
	time.Sleep(1100 * time.Millisecond) // ~1 sec → ~1 KiB refill
	if !e.AllowExemptedBytes(cid, 512) {
		t.Fatal("after ~1s the byte budget should refill")
	}
}
