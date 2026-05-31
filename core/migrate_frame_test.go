package core

import (
	"bytes"
	"testing"
)

func TestBuildParseMigrateFrame_RoundTrip(t *testing.T) {
	var proof [32]byte
	for i := range proof {
		proof[i] = byte(i + 1)
	}
	p := BuildMigrateFrame(0xBEEF, proof)
	if len(p) != 34 {
		t.Fatalf("migrate frame len = %d, want 34", len(p))
	}
	gotID, gotProof, err := ParseMigrateFrame(p)
	if err != nil {
		t.Fatalf("ParseMigrateFrame: %v", err)
	}
	if gotID != 0xBEEF {
		t.Errorf("streamID = %#x, want 0xBEEF", gotID)
	}
	if !bytes.Equal(gotProof[:], proof[:]) {
		t.Errorf("proof mismatch")
	}
}

func TestParseMigrateFrame_TooShort(t *testing.T) {
	if _, _, err := ParseMigrateFrame(make([]byte, 33)); err == nil {
		t.Fatal("expected error on 33-byte frame")
	}
}

func TestBuildParseStreamAckFrame_RoundTrip(t *testing.T) {
	p := BuildStreamAckFrame(0x1234, 0xDEADBEEFCAFE)
	if len(p) != 10 {
		t.Fatalf("ack frame len = %d, want 10", len(p))
	}
	id, seq, err := ParseStreamAckFrame(p)
	if err != nil {
		t.Fatalf("ParseStreamAckFrame: %v", err)
	}
	if id != 0x1234 || seq != 0xDEADBEEFCAFE {
		t.Errorf("got id=%#x seq=%#x", id, seq)
	}
}

func TestParseStreamAckFrame_TooShort(t *testing.T) {
	if _, _, err := ParseStreamAckFrame(make([]byte, 9)); err == nil {
		t.Fatal("expected error on 9-byte frame")
	}
}

func TestNewControlFlagValues(t *testing.T) {
	if FlagMigrate != 0x0B || FlagResume != 0x0C || FlagStreamAck != 0x0D {
		t.Fatalf("flag values drifted: migrate=%#x resume=%#x ack=%#x",
			FlagMigrate, FlagResume, FlagStreamAck)
	}
}
