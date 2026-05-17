package client

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// isGREASE matches utls' GREASE convention: high byte equals low byte AND
// low nibble is 0xa (e.g. 0x0a0a, 0x1a1a, 0x2a2a, ...). GREASE values are
// drawn from a per-connection random seed by utls so they would defeat the
// fixture if hashed verbatim. We collapse all GREASE codepoints to the
// canonical placeholder 0x0a0a before hashing.
func isGREASE(v uint16) bool {
	return ((v >> 8) == v&0xff) && (v&0xf) == 0xa
}

// normalizeGREASE returns 0x0a0a for any GREASE codepoint and v unchanged
// otherwise. Hash inputs flow through this so the JA4 fixture stays stable
// across runs (utls re-rolls the GREASE seed every UClient).
func normalizeGREASE(v uint16) uint16 {
	if isGREASE(v) {
		return 0x0a0a
	}
	return v
}

// computeJA4 produces a deterministic byte-level fingerprint over a stable
// subset of `utls.PubClientHelloMsg` fields. It is NOT the official FoxIO JA4
// algorithm — `PubClientHelloMsg` does not expose the full Extensions slice in
// wire order, only the parsed, decoded fields, so a true JA4 would require
// re-walking the raw ClientHello bytes. Instead we hash the fields that are
// most semantically meaningful for PQ regression detection (key shares,
// supported groups, supported versions, ALPN, signature algorithms, cipher
// suites). A change in any of these flips the hash; the test in utls_pq_test.go
// uses the hash as a regression canary against the fixture in
// testdata/ja4/chrome_133_pq.txt.
//
// GREASE handling: utls draws fresh GREASE codepoints from a per-connection
// random seed (see `greaseSeed`), which would scramble the hash on every
// run. All GREASE-shaped uint16s are collapsed to 0x0a0a before hashing so
// the fingerprint reflects the structure (positions where GREASE appears,
// number of GREASE entries) without being sensitive to which specific
// GREASE codepoint was rolled. Same for GREASE key-share entries: we hash
// the slot but normalize the curve id and ignore the random Data bytes.
//
// The serialization is canonical (length-prefixed big-endian; field-tagged so
// adding a new field later cannot accidentally collide with the old hash) so
// the same hello produces the same hash across machines, Go versions, and
// successive runs of the same test.
//
// Output is hex-encoded SHA-256, lowercase, single line, no trailing newline —
// the fixture must match exactly.
func computeJA4(hello *utls.PubClientHelloMsg) string {
	if hello == nil {
		return ""
	}

	h := sha256.New()
	tmp := make([]byte, 4)

	writeTag := func(tag string) {
		h.Write([]byte("|" + tag + "|"))
	}
	writeU16 := func(v uint16) {
		binary.BigEndian.PutUint16(tmp[:2], v)
		h.Write(tmp[:2])
	}
	writeU16SliceNorm := func(xs []uint16) {
		binary.BigEndian.PutUint32(tmp[:4], uint32(len(xs)))
		h.Write(tmp[:4])
		for _, x := range xs {
			writeU16(normalizeGREASE(x))
		}
	}
	writeBytesPrefixed := func(b []byte) {
		binary.BigEndian.PutUint32(tmp[:4], uint32(len(b)))
		h.Write(tmp[:4])
		h.Write(b)
	}

	writeTag("vers")
	writeU16(hello.Vers)

	writeTag("ciphers")
	writeU16SliceNorm(hello.CipherSuites)

	writeTag("supported_versions")
	writeU16SliceNorm(hello.SupportedVersions)

	writeTag("supported_curves")
	curves := make([]uint16, len(hello.SupportedCurves))
	for i, c := range hello.SupportedCurves {
		curves[i] = uint16(c)
	}
	writeU16SliceNorm(curves)

	writeTag("key_shares")
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(hello.KeyShares)))
	h.Write(tmp[:4])
	for _, ks := range hello.KeyShares {
		group := normalizeGREASE(uint16(ks.Group))
		writeU16(group)
		// Don't hash Data: ephemeral keys (and GREASE keyshare blobs) are
		// drawn from crypto/rand per handshake and would scramble the hash.
		// We do NOT even hash len(Data) — the GREASE keyshare data length
		// is also random per utls run (the grease seed picks the size),
		// which would defeat the fixture.
	}

	writeTag("alpn")
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(hello.AlpnProtocols)))
	h.Write(tmp[:4])
	for _, p := range hello.AlpnProtocols {
		writeBytesPrefixed([]byte(p))
	}

	writeTag("sig_algs")
	sigs := make([]uint16, len(hello.SupportedSignatureAlgorithms))
	for i, s := range hello.SupportedSignatureAlgorithms {
		sigs[i] = uint16(s)
	}
	writeU16SliceNorm(sigs)

	writeTag("psk_modes")
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(hello.PskModes)))
	h.Write(tmp[:4])
	h.Write(hello.PskModes)

	writeTag("supported_points")
	binary.BigEndian.PutUint32(tmp[:4], uint32(len(hello.SupportedPoints)))
	h.Write(tmp[:4])
	h.Write(hello.SupportedPoints)

	return hex.EncodeToString(h.Sum(nil))
}

// buildPQClientHelloForCapture creates an *utls.UConn over a net.Pipe, applies
// the PQ spec, and runs BuildHandshakeState so HandshakeState.Hello.Raw and
// the parsed PubClientHelloMsg are populated. The pipe peer is closed
// immediately because we never actually want to perform a Handshake — we
// only need the marshaled ClientHello bytes.
//
// Returns the parsed hello and the raw ClientHello bytes on the wire.
func buildPQClientHelloForCapture() (*utls.PubClientHelloMsg, []byte, error) {
	clientConn, serverConn := net.Pipe()
	// Drain & close the server side asynchronously so any pending writes
	// from utls don't deadlock if the impl pushes bytes during build.
	go func() {
		_, _ = io.Copy(io.Discard, serverConn)
	}()
	// Defensive deadline so a misbehaving impl doesn't hang the test.
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))

	cfg := &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"http/1.1"},
	}
	uconn := utls.UClient(clientConn, cfg, utls.HelloCustom)

	spec, err := pqClientHelloSpec()
	if err != nil {
		clientConn.Close()
		serverConn.Close()
		return nil, nil, fmt.Errorf("pq spec: %w", err)
	}
	if err := uconn.ApplyPreset(&spec); err != nil {
		clientConn.Close()
		serverConn.Close()
		return nil, nil, fmt.Errorf("apply preset: %w", err)
	}
	if err := uconn.BuildHandshakeState(); err != nil {
		clientConn.Close()
		serverConn.Close()
		return nil, nil, fmt.Errorf("build handshake state: %w", err)
	}

	hello := uconn.HandshakeState.Hello
	raw := append([]byte(nil), hello.Raw...)

	clientConn.Close()
	serverConn.Close()
	return hello, raw, nil
}

// containsCurveID returns true if the big-endian uint16 needle appears
// anywhere in haystack as a contiguous byte pair. Used to assert the
// X25519MLKEM768 (0x11ec) marker is present in the ClientHello bytes.
//
// Note: this scan checks every byte position (i, i+1) — not extension-frame
// aligned. A truly strict aligned check would have to parse the ClientHello
// extension list. The byte-pair scan is sufficient for the regression check
// here: if the marker is anywhere in the bytes the spec is at least
// attempting to advertise MLKEM. The previous implementation used
// strings.Contains over a string-converted byte slice which had identical
// semantics for binary needles but was misleadingly named for text data.
func containsCurveID(haystack []byte, needle uint16) bool {
	for i := 0; i+1 < len(haystack); i++ {
		if haystack[i] == byte(needle>>8) && haystack[i+1] == byte(needle) {
			return true
		}
	}
	return false
}
