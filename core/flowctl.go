package core

import "encoding/binary"

// flowctl.go — in-band capability negotiation marker for per-stream flow
// control (Bug #8). The marker rides inside the ENCRYPTED Chunk.Payload of the
// first keepalive (client → server) and the FlagAck reply (server → client),
// so it never appears in cleartext and adds no DPI signal. Flow control is an
// optional feature layered over the v1 session — NOT a new crypto version, so
// DeriveSessionKeys is untouched (no downgrade-via-keys risk).

// flowCtlMagic prefixes a window-advertisement payload. Layout:
//
//	["FLOWCTL"(7)] + [window(4 BE)]  = 11 bytes
var flowCtlMagic = []byte("FLOWCTL")

const flowCtlMarkerLen = 7 + 4

// BuildFlowCtlMarker builds the 11-byte capability+window advertisement that
// goes inside the encrypted keepalive/ack chunk payload.
func BuildFlowCtlMarker(window uint32) []byte {
	p := make([]byte, flowCtlMarkerLen)
	copy(p[:7], flowCtlMagic)
	binary.BigEndian.PutUint32(p[7:11], window)
	return p
}

// ParseFlowCtlMarker reports whether payload begins with the FLOWCTL marker and
// returns the advertised window. ok=false for any non-marker payload (nil,
// short, or wrong magic) — callers treat that as "peer does not support flow
// control".
func ParseFlowCtlMarker(payload []byte) (window uint32, ok bool) {
	if len(payload) < flowCtlMarkerLen {
		return 0, false
	}
	for i := 0; i < 7; i++ {
		if payload[i] != flowCtlMagic[i] {
			return 0, false
		}
	}
	return binary.BigEndian.Uint32(payload[7:11]), true
}
