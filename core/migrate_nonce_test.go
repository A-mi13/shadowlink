package core

import (
	"bytes"
	"testing"
)

func TestNewSession_MigrateNonce_NonZero(t *testing.T) {
	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	var zero [16]byte
	if bytes.Equal(s.MigrateNonce[:], zero[:]) {
		t.Fatal("MigrateNonce is all-zero — must be seeded from crypto/rand")
	}
}

func TestNewSession_MigrateNonce_DistinctPerSession(t *testing.T) {
	a := NewSession(1, make([]byte, 32), make([]byte, 32))
	b := NewSession(2, make([]byte, 32), make([]byte, 32))
	if bytes.Equal(a.MigrateNonce[:], b.MigrateNonce[:]) {
		t.Fatal("two sessions share a MigrateNonce — must be independent random")
	}
}

func TestNewSession_MigrateNonce_NotDerivedFromID(t *testing.T) {
	s := NewSession(0x01020304, make([]byte, 32), make([]byte, 32))
	if s.MigrateNonce[0] == 0x01 && s.MigrateNonce[1] == 0x02 &&
		s.MigrateNonce[2] == 0x03 && s.MigrateNonce[3] == 0x04 {
		t.Fatal("MigrateNonce appears derived from session.ID")
	}
}
