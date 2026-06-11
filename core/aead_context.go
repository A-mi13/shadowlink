package core

// AEAD associated-data context (M2, 2026-06-11). Binds each chunk to its
// DIRECTION and protocol version so a chunk can never be reflected across the
// send/recv boundary even if a future bug shares a key across directions (the
// test suite uses symmetric NewSession(id,key,key) keys — without AAD that would
// open a reflection channel). AAD is NOT transmitted (no wire growth); it is
// recomputed identically by sender and receiver. Mismatch → gcm.Open fails.
//
// GATED — DEFAULT OFF: AAD is only emitted when the session negotiated
// protoVersion >= 2. v0/v1 sessions pass nil AAD (backwards compat). The
// production wire is v1, so this code is dormant until a protoVersion bump.
// Enabling requires a lockstep client+server upgrade AND a two-client smoke test
// (decrypt_fails=0, streams survive) before default-on — the standard crypto-
// compatibility rule. This file ships the constructor + the AAD-aware Seal/Open
// helpers only; wiring buildAEAD into Session.EncryptChunk/DecryptChunkSafe
// (which needs an explicit per-session role→direction mapping) is a separate
// task done together with the protoVersion>=2 negotiation and the canary.

const (
	aeadDirClientToServer byte = 0x01 // chunk authored by client (uplink)
	aeadDirServerToClient byte = 0x02 // chunk authored by server (downlink)
)

// buildAEAD returns the associated data for a chunk, or nil when AAD is disabled
// for this protoVersion (v0/v1). Layout: [dir(1)][protoVersion(1)]. nil AAD is
// byte-identical to the legacy gcm.Open(..., nil) contract, so a v0/v1 frame is
// wire/AEAD-context unchanged.
func buildAEAD(protoVersion uint8, dir byte) []byte {
	if protoVersion < 2 {
		return nil // legacy: no AAD, preserves wire/AEAD-context compat
	}
	return []byte{dir, protoVersion}
}
