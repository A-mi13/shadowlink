package server

import (
	"testing"
	"time"
)

func TestExemption_MarkSeenAndAllow(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 60, time.Minute)
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
	e := NewClientIDExemption(100, 50*time.Millisecond, 60, time.Minute)
	cid := []byte("ttl-test-clientid")
	e.MarkSeen(cid)
	time.Sleep(100 * time.Millisecond)
	if e.IsExempt(cid) {
		t.Fatal("after TTL expiry should not be exempt")
	}
}

func TestExemption_SoftLimit(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 3, time.Minute)
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
	e := NewClientIDExemption(2, 1*time.Hour, 60, time.Minute)
	a, b, c := []byte("aa"), []byte("bb"), []byte("cc")
	e.MarkSeen(a)
	e.MarkSeen(b)
	e.MarkSeen(c)
	if e.IsExempt(a) {
		t.Fatal("a should be evicted (LRU cap=2)")
	}
}

func TestExemption_SoftLimitDisabled(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 0, time.Minute)
	cid := []byte("nocap-cid")
	e.MarkSeen(cid)
	for i := range 100 {
		if !e.AllowExempted(cid) {
			t.Fatalf("hit %d should allow when softLimit=0 (unlimited)", i)
		}
	}
}

func TestExemption_SoftWindowReset(t *testing.T) {
	e := NewClientIDExemption(100, 1*time.Hour, 1, 50*time.Millisecond)
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
