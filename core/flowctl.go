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

const flowCtlMarkerLenV2 = 7 + 4 + 1 // magic(7) + window(4 BE) + capFlags(1)

// Capability flag bits in the optional 12th byte of the FLOWCTL marker.
const flowCapMigrate byte = 0x01 // peer supports Bug #9 stream migration (§3.5)

// BuildFlowCtlMarkerV2 builds the 12-byte capability+window advertisement:
//
//	["FLOWCTL"(7)] + [window(4 BE)] + [capFlags(1)]
//
// The extra byte is invisible to an old peer's ParseFlowCtlMarker (it reads
// only the first 11 bytes). §3.5.
func BuildFlowCtlMarkerV2(window uint32, migrate bool) []byte {
	p := make([]byte, flowCtlMarkerLenV2)
	copy(p[:7], flowCtlMagic)
	binary.BigEndian.PutUint32(p[7:11], window)
	if migrate {
		p[11] |= flowCapMigrate
	}
	return p
}

// ParseFlowCtlMarkerV2 reports window + migrate-capability. A legacy 11-byte
// marker parses with migrate=false (backwards compat). ok=false for any
// non-marker payload.
func ParseFlowCtlMarkerV2(payload []byte) (window uint32, migrate bool, ok bool) {
	if len(payload) < flowCtlMarkerLen { // 11 — magic + window minimum
		return 0, false, false
	}
	for i := 0; i < 7; i++ {
		if payload[i] != flowCtlMagic[i] {
			return 0, false, false
		}
	}
	window = binary.BigEndian.Uint32(payload[7:11])
	if len(payload) >= flowCtlMarkerLenV2 {
		migrate = payload[11]&flowCapMigrate != 0
	}
	return window, migrate, true
}
