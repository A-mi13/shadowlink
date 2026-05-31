package core

import "testing"

func TestDeriveServerPerClientKey_Deterministic(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	k1 := DeriveServerPerClientKey(master, "client-A")
	k2 := DeriveServerPerClientKey(master, "client-A")
	if len(k1) != 32 {
		t.Fatalf("perClientKey len = %d, want 32", len(k1))
	}
	if string(k1) != string(k2) {
		t.Fatal("HKDF not deterministic for same clientID")
	}
	kB := DeriveServerPerClientKey(master, "client-B")
	if string(k1) == string(kB) {
		t.Fatal("different clientIDs must yield different keys")
	}
}

func TestStreamProof_ValidVerifies(t *testing.T) {
	master := make([]byte, 32)
	key := DeriveServerPerClientKey(master, "client-A")
	var nonce [16]byte
	nonce[0] = 0x42
	proof := ComputeStreamProof(key, "client-A", 0xABCD, nonce)
	if !VerifyStreamProof(proof, key, "client-A", 0xABCD, nonce) {
		t.Fatal("valid proof did not verify")
	}
}

func TestStreamProof_WrongStreamIDFails(t *testing.T) {
	master := make([]byte, 32)
	key := DeriveServerPerClientKey(master, "client-A")
	var nonce [16]byte
	proof := ComputeStreamProof(key, "client-A", 0xABCD, nonce)
	if VerifyStreamProof(proof, key, "client-A", 0x0001, nonce) {
		t.Fatal("proof verified for the wrong streamID")
	}
}

func TestStreamProof_ForeignClientFails(t *testing.T) {
	master := make([]byte, 32)
	keyA := DeriveServerPerClientKey(master, "client-A")
	keyB := DeriveServerPerClientKey(master, "client-B")
	var nonce [16]byte
	proof := ComputeStreamProof(keyA, "client-A", 0xABCD, nonce)
	if VerifyStreamProof(proof, keyB, "client-B", 0xABCD, nonce) {
		t.Fatal("foreign clientID forged a proof")
	}
}

func TestStreamProof_ForeignNonceFails(t *testing.T) {
	master := make([]byte, 32)
	key := DeriveServerPerClientKey(master, "client-A")
	var nonceA, nonceB [16]byte
	nonceA[0] = 0x01
	nonceB[0] = 0x02
	proof := ComputeStreamProof(key, "client-A", 0xABCD, nonceA)
	if VerifyStreamProof(proof, key, "client-A", 0xABCD, nonceB) {
		t.Fatal("proof verified under a different session_nonce (second-device/replay)")
	}
}
