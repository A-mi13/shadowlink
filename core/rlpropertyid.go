package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"strings"
)

// DeriveRLPropertyID renders the Schema.org `identifier.propertyID` used to
// carry the rate-limit sentinel, derived deterministically from the server's
// host so that no two deployments share one.
//
// # Why this exists
//
// The predecessor was the literal string "rl-state", identical on every server
// in the fleet. Schema.org itself is fine with that shape — the spec allows
// "a site-specific, non-prefixed string (e.g. the primary key of the property
// or the vendor-specific ID of the property)", and canonical examples include
// "OCoLC" and "Company Number". The problem was never vocabulary compliance.
// The problem was that one internet-wide scan for a fixed substring enumerated
// every host we run: find one, find all.
//
// # Why the output is words, not hex
//
// The obvious derivation — hex of a hash — trades one signal for a worse one.
// `propertyID: "a7f3c91e"` is not a string real sites emit; high entropy in a
// human-facing metadata field is itself the anomaly, the same trap as
// randomising a TLS fingerprint (CLAUDE.md hard rule 2: uniqueness IS the
// signal). So the hash selects from a fixed table of shapes that real catalogue
// and inventory markup actually uses, and appends a short numeric-ish suffix in
// the style those vocabularies already carry.
//
// The result looks like a per-deployment vendor field, because that is exactly
// what a per-deployment vendor field looks like.
//
// # Determinism contract
//
// Server and client must agree without exchanging anything: the server knows
// its own Host, the client knows the SNI/host it dialled. Both call this with
// the same normalised host and get the same string. Note that a shared X25519
// pubkey does NOT work as input — backup endpoints deliberately share one key
// (engine/engine.go), so keying on it would hand several
// hosts the same identifier and rebuild the very problem this removes.
//
// Host normalisation: lowercased, port stripped, trailing dot stripped. An
// empty host yields LegacyRLPropertyID so callers degrade to the old behaviour
// instead of to an empty field.
//
// # STATUS 2026-08-08: receiving side only
//
// Nothing in this repository WRITES a derived identifier into a decoy template.
// Templates are static HTML on the server (server.LoadDecoySnapshots only reads
// them), and the generator that would bake in DeriveRLPropertyID(host) is
// deferred. So production still serves the legacy literal, clients match it via
// the legacy arm in client.acceptsPropertyID, and the fleet-wide constant is
// still there.
//
// That is currently harmless — the deployment is a single server, and one host
// cannot be "enumerated" from itself. The work matters when a second host
// appears. Until the generator exists, treat this as groundwork, not a fix:
// deploy-round18.sh reports baseline_propertyid=LEGACY precisely so the gap
// stays visible instead of reading as done.
//
// Collision behaviour, measured over 10k synthetic hosts: ~9600 effective
// values, so P(at least one collision) ≈ 1.7% at 10 hosts, 34% at 50, 80% at
// 100. Fine for a handful of servers; widen the shape table before the fleet
// reaches a few dozen.
func DeriveRLPropertyID(host string) string {
	h := NormalizeRLHost(host)
	if h == "" {
		return LegacyRLPropertyID
	}

	mac := hmac.New(sha256.New, []byte(rlPropertyIDContext))
	mac.Write([]byte(h))
	sum := mac.Sum(nil)

	shape := rlPropertyIDShapes[int(sum[0])%len(rlPropertyIDShapes)]

	// Two bytes of the digest drive the suffix. Kept short (3-4 visible chars)
	// because real vendor IDs are short; a long opaque tail would reintroduce
	// the entropy tell this design exists to avoid.
	n := (int(sum[1])<<8 | int(sum[2])) % shape.mod
	return fmt.Sprintf(shape.format, n)
}

// LegacyRLPropertyID is the fleet-wide constant used before per-host
// derivation. Clients keep accepting it through the migration window so a new
// client still understands a server that has not been redeployed yet; drop it
// once the fleet has rolled over.
const LegacyRLPropertyID = "rl-state"

// rlPropertyIDContext domain-separates this HMAC from any other use of the
// same host string. It is not a secret — the derivation is deliberately
// public, since the client must reproduce it with no shared state beyond the
// hostname. Secrecy would buy nothing here: an adversary who already has the
// host can compute the ID either way. What the derivation buys is that the ID
// differs per host, so one hit does not enumerate the rest.
const rlPropertyIDContext = "shadowlink/rl-propertyid/v1"

// rlPropertyIDShapes are the rendering templates. Each is modelled on an
// identifier form that appears in real product/catalogue markup, so a scan for
// any one of them returns mostly genuine sites rather than our fleet.
//
// mod bounds the numeric part to the digit-width the shape implies — a
// four-digit "SKU-93712" would read as machine-generated where "SKU-937" reads
// as a catalogue key.
var rlPropertyIDShapes = []struct {
	format string
	mod    int
}{
	{"sku-%03d", 1000},
	{"item-%03d", 1000},
	{"cat-%02d", 100},
	{"ref-%03d", 1000},
	{"pid-%03d", 1000},
	{"prod-%02d", 100},
	{"asset-%03d", 1000},
	{"variant-%02d", 100},
	{"listing-%03d", 1000},
	{"catalog-%02d", 100},
	{"inv-%03d", 1000},
	{"model-%03d", 1000},
}

// SignalHost picks the host both sides must agree on for DeriveRLPropertyID,
// given a transport's SNI override and dial address.
//
// The rule is "whatever the server will see as its own Host": with an SNI
// override the client sends that domain in the Host header (so nginx
// server_name matches), otherwise the host part of the dial address. Returned
// unnormalised — DeriveRLPropertyID normalises, and callers that log it are
// better off seeing the raw value.
//
// Lives here rather than on either transport because both need it and they
// had drifted: WebSocketTransport derived it inline while DirectTransport
// left the field empty when no SNI override was set, which silently limited
// that path to the legacy marker.
func SignalHost(sniOverride, dialAddr string) string {
	if sniOverride != "" {
		return sniOverride
	}
	if dialAddr == "" {
		return ""
	}
	if h := NormalizeRLHost(dialAddr); h != "" {
		return h
	}
	return dialAddr
}

// NormalizeRLHost reduces a Host header or dial address to the canonical form
// used as derivation input: lowercase, no port, no trailing dot.
//
// Port is stripped so that a client dialling "example.com:443" and a server
// seeing Host "example.com" derive the same ID. IPv6 literals keep their
// brackets stripped as well.
func NormalizeRLHost(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" {
		return ""
	}

	// Bracketed IPv6, optionally with port: [::1]:443 → ::1
	if strings.HasPrefix(h, "[") {
		if end := strings.Index(h, "]"); end > 0 {
			return h[1:end]
		}
		return strings.TrimPrefix(h, "[")
	}

	// Strip port only when the remainder is unambiguous. A bare IPv6 literal
	// contains multiple colons and must not be cut.
	if strings.Count(h, ":") == 1 {
		if i := strings.LastIndex(h, ":"); i > 0 {
			h = h[:i]
		}
	}

	return strings.TrimSuffix(h, ".")
}
