package client

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/nixavpn/shadowlink/core"
)

// DetectionContext carries everything carriers need to inspect a response.
type DetectionContext struct {
	Response *http.Response
	BodyHead []byte // first ≤4KB of response body (caller's responsibility to limit)
	// Path identifies the transport path that produced this response.
	// Used by RateLimitDetector to increment per-path counters (Phase 2, 2026-05-14).
	// Accepted values: "handshake" (POST path), "ws_upgrade" (WS Dial path).
	// Empty string → no per-path counters incremented (aggregate-only mode, back-compat).
	Path string

	// Host is the server host this response came from (SNI host, or dial
	// address). BodyMarkerCarrier derives the expected Schema.org propertyID
	// from it — the marker is per-host by design, so without this the carrier
	// can only recognise the legacy fleet-wide literal.
	//
	// Empty is safe: the carrier still accepts core.LegacyRLPropertyID, which
	// is what a not-yet-redeployed server emits.
	Host string
}

// RateLimitCarrier — single carrier that may extract a signal from response.
type RateLimitCarrier interface {
	Name() string
	Detect(ctx *DetectionContext) *RateLimitSignal
}

// === BodyMarkerCarrier — primary, CDN-safe ===

type BodyMarkerCarrier struct{}

func (BodyMarkerCarrier) Name() string { return "body" }

var jsonLDRe = regexp.MustCompile(`<script[^>]*type="application/ld\+json"[^>]*>(\{[^<]+\})</script>`)

// acceptsPropertyID reports whether id is the marker this client should read
// for the given host.
//
// Two are accepted during the migration window (2026-08-08):
//
//   - core.DeriveRLPropertyID(host) — the per-host identifier. Servers used to
//     embed the literal "rl-state" on every host, so one internet-wide scan
//     for that substring enumerated the whole fleet. Deriving from the host
//     removes that: find one, you have found one.
//   - core.LegacyRLPropertyID — what a server that has not been redeployed
//     yet still emits. A new client must keep understanding it, or upgrading
//     the client ahead of the servers silently kills the rate-limit channel
//     and the pool degrades into blind exponential backoff.
//
// Drop the legacy arm once the fleet has rolled over.
func acceptsPropertyID(id, host string) bool {
	if id == "" {
		return false
	}
	if id == core.LegacyRLPropertyID {
		return true
	}
	return host != "" && id == core.DeriveRLPropertyID(host)
}

func (BodyMarkerCarrier) Detect(ctx *DetectionContext) *RateLimitSignal {
	head := ctx.BodyHead
	if len(head) > 4096 {
		head = head[:4096]
	}

	matches := jsonLDRe.FindAllSubmatch(head, -1)
	for _, match := range matches {
		var payload struct {
			Identifier *struct {
				AtType     string `json:"@type"`
				PropertyID string `json:"propertyID"`
				Value      string `json:"value"`
			} `json:"identifier"`
		}
		if err := json.Unmarshal(match[1], &payload); err != nil {
			continue
		}
		if payload.Identifier == nil {
			continue
		}
		if payload.Identifier.AtType != "PropertyValue" {
			continue
		}
		if !acceptsPropertyID(payload.Identifier.PropertyID, ctx.Host) {
			continue
		}

		sig := parseRLStateValue(payload.Identifier.Value)
		if sig == nil {
			continue // baseline, not a real signal
		}
		return sig
	}
	return nil
}

// === HeaderCarrier — back-compat, supports both formats ===

type HeaderCarrier struct{}

func (HeaderCarrier) Name() string {
	return "header" // overridden per-format in Detect via Signal.Carrier
}

func (HeaderCarrier) Detect(ctx *DetectionContext) *RateLimitSignal {
	if ctx.Response == nil {
		return nil
	}
	v := ctx.Response.Header.Get("X-SL-RL")
	if v == "" {
		return nil
	}

	// Determine format by presence of "v1;" prefix (new) vs comma separator (legacy).
	if strings.Contains(v, ";") && strings.HasPrefix(v, "v") {
		if sig := parseRLStateValue(v); sig != nil {
			sig.Carrier = "header_v1"
			return sig
		}
	}
	// Try legacy comma format
	if sig := parseRLStateLegacyHeader(v); sig != nil {
		sig.Carrier = "header_legacy"
		return sig
	}
	return nil
}

// compile-time check: both carrier types implement RateLimitCarrier.
var _ RateLimitCarrier = BodyMarkerCarrier{}
var _ RateLimitCarrier = HeaderCarrier{}
