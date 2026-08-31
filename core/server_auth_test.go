package core

import (
	"testing"
	"time"
)

// What authenticates the ShadowLink server, stated as executable fact.
//
// Background (2026-08-31 review): client/transport.go justified
// InsecureSkipVerify on the full-direct path with "ShadowLink pins the server's
// X25519 public key at the protocol layer". No such pin exists —
// HandshakeClientState.ServerPub is stored and never compared, and nothing
// signs or MACs ServerHello. The real guarantee is authentication-by-key-
// agreement: only the holder of the static private key can decrypt clientID,
// and clientID is mixed into the session-key HKDF, so only it can seal a
// session token the client can open.
//
// These tests pin that mechanism so the justification cannot quietly become
// false again: if someone changes the KDF inputs or the token check, one of
// them fails.

// TestServerAuth_MITMWithoutStaticKeyCannotCompleteHandshake is the property the
// InsecureSkipVerify comment depends on: an attacker who terminates TLS (which
// he can, since certificates are not validated) but does not hold the server's
// static private key cannot complete the handshake.
func TestServerAuth_MITMWithoutStaticKeyCannotCompleteHandshake(t *testing.T) {
	realServer, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	mitm, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("mitm keypair: %v", err)
	}

	clientID := []byte("user_1234567890x")

	// Client addresses the REAL server's static key.
	hello, _, err := NewClientHello(clientID, realServer.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}

	// The MITM intercepts and answers with its own static key. It cannot read
	// clientID, so it cannot reach the same HKDF info.
	sm := NewSessionManager(time.Minute)
	if _, _, _, err := HandleClientHelloWithVersion(hello, mitm, 4, 12288, sm, 1); err == nil {
		t.Fatal("MITM without the static private key decrypted clientID — " +
			"server authentication rests on exactly this failing")
	}
}

// TestServerAuth_WrongClientIDBreaksTokenCheck isolates the second half: even if
// an attacker somehow answered the handshake, the client's token check is what
// detects it. A server that derives keys with a different clientID produces a
// token the client cannot open.
func TestServerAuth_WrongClientIDBreaksTokenCheck(t *testing.T) {
	server, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	clientID := []byte("user_1234567890x")
	hello, state, err := NewClientHello(clientID, server.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}

	sm := NewSessionManager(time.Minute)
	sh, _, _, err := HandleClientHelloWithVersion(hello, server, 4, 12288, sm, 1)
	if err != nil {
		t.Fatalf("HandleClientHello: %v", err)
	}

	// Sanity: the honest path completes.
	if _, err := CompleteHandshakeWithVersion(state, sh, 1); err != nil {
		t.Fatalf("honest handshake failed: %v", err)
	}

	// Now the client believes it has a different identity. Keys diverge, so the
	// token no longer opens — this is the check that stands in for certificate
	// validation.
	tampered := &HandshakeClientState{
		Ephemeral: state.Ephemeral,
		ClientID:  []byte("user_9999999999y"),
		ServerPub: state.ServerPub,
	}
	if _, err := CompleteHandshakeWithVersion(tampered, sh, 1); err == nil {
		t.Error("session token opened with the wrong clientID — the client would " +
			"accept a server that never proved knowledge of clientID")
	}
}

// TestServerAuth_ServerPubIsNotComparedAnywhere documents the absence that the
// old comment got wrong. It is a documentation test: it asserts that the handshake
// completes while ServerPub in the client state is garbage, proving the field is
// not a pin. If a real pin is ever added, this test SHOULD fail — and the fix is
// to update the InsecureSkipVerify comment, not to delete the test.
func TestServerAuth_ServerPubIsNotComparedAnywhere(t *testing.T) {
	server, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}

	clientID := []byte("user_1234567890x")
	hello, state, err := NewClientHello(clientID, server.Public)
	if err != nil {
		t.Fatalf("NewClientHello: %v", err)
	}

	sm := NewSessionManager(time.Minute)
	sh, _, _, err := HandleClientHelloWithVersion(hello, server, 4, 12288, sm, 1)
	if err != nil {
		t.Fatalf("HandleClientHello: %v", err)
	}

	// Corrupt the stored "pin" — the ClientHello was already sealed to the real
	// key, so only the post-hoc comparison could notice, and there is none.
	state.ServerPub = make([]byte, 32)

	if _, err := CompleteHandshakeWithVersion(state, sh, 1); err != nil {
		t.Fatalf("handshake failed with a zeroed ServerPub (%v) — if this is now "+
			"a real pin, update the InsecureSkipVerify justification in "+
			"client/transport.go, which currently says there is none", err)
	}
}
