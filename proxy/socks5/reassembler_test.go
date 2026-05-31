package socks5

import "testing"

func TestReassembler_InOrder(t *testing.T) {
	r := newReassembler(1 << 20)
	out, st := r.push(1, []byte("a"))
	if st != reasmOK || len(out) != 1 || string(out[0]) != "a" {
		t.Fatalf("seq1: st=%v out=%v", st, out)
	}
	out, st = r.push(2, []byte("b"))
	if st != reasmOK || len(out) != 1 || string(out[0]) != "b" {
		t.Fatalf("seq2: st=%v out=%v", st, out)
	}
}

func TestReassembler_OutOfOrderBuffersThenFlushes(t *testing.T) {
	r := newReassembler(1 << 20)
	if out, st := r.push(3, []byte("c")); st != reasmOK || len(out) != 0 {
		t.Fatalf("seq3 early: st=%v out=%v (want buffered, no flush)", st, out)
	}
	if out, _ := r.push(2, []byte("b")); len(out) != 0 {
		t.Fatalf("seq2 still gapped at 1: out=%v", out)
	}
	out, st := r.push(1, []byte("a"))
	if st != reasmOK || len(out) != 3 ||
		string(out[0]) != "a" || string(out[1]) != "b" || string(out[2]) != "c" {
		t.Fatalf("flush after gap closed: st=%v out=%v", st, out)
	}
}

func TestReassembler_DedupsBelowExpected(t *testing.T) {
	r := newReassembler(1 << 20)
	r.push(1, []byte("a"))
	if out, st := r.push(1, []byte("a")); st != reasmDup || len(out) != 0 {
		t.Fatalf("dup seq1: st=%v out=%v", st, out)
	}
}

func TestReassembler_OverflowBySize(t *testing.T) {
	r := newReassembler(4)
	r.push(2, []byte("xx"))
	if _, st := r.push(3, []byte("yyy")); st != reasmOverflow {
		t.Fatalf("expected reasmOverflow, got %v", st)
	}
}

func TestReassembler_HasGap(t *testing.T) {
	r := newReassembler(1 << 20)
	r.push(2, []byte("b"))
	if !r.hasGap() {
		t.Fatal("hasGap should be true with pending past expected")
	}
	r.push(1, []byte("a"))
	if r.hasGap() {
		t.Fatal("hasGap should be false after gap closed")
	}
}
