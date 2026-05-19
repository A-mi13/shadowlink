package server

import (
	"slices"
	"strings"
)

// wsURLPool is the whitelist of URL paths on which WebSocket upgrade is
// accepted. Requests to other paths fall through to the decoy site.
//
// Why a pool (not a single path): a generic WS endpoint reachable on a single
// fixed path (e.g. /ws) is a strong DPI fingerprint — an active prober can
// separate ShadowLink hosts from real analytics SaaS in a handful of probes
// (CRIT-4 in 2026-04-25 audit). Real analytics / realtime SaaS endpoints are
// scattered across paths shaped like /socket.io, /api/v2/realtime, /collect,
// etc. We mirror that shape.
//
// The set below is hardcoded on BOTH client and server (see
// shadowlink/client/ws_paths.go for the mirrored list). Adding a path
// requires deploying the server FIRST so older clients that hash to the new
// path don't hit a 404-decoy. Removing a path requires retiring the client
// release that picks it before the server stops accepting it.
//
// All paths here intentionally look like real-world realtime / analytics
// endpoints. None of them spell "shadowlink", "vpn", "tunnel", or anything
// project-specific. Equally important: none of them is just "/ws" — that
// single string is the fingerprint we are removing.
var wsURLPool = []string{
	"/socket.io/",                           // Socket.IO default mount (Mixpanel, Intercom, many SaaS)
	"/socket.io/?EIO=4&transport=websocket", // Socket.IO v4 polling-then-upgrade explicit form
	"/api/v2/realtime",                      // generic v2 analytics realtime channel
	"/api/v1/socket",                        // v1 socket endpoint (PostHog-shape)
	"/api/v2/collect/stream",                // analytics collect-stream (GA4-ish)
	"/realtime/v1/connect",                  // realtime gateway connect
	"/live/v1/events",                       // Pusher / Ably-shape live events stream
	"/api/v2/notifications/stream",          // notifications stream (Slack/Linear-shape)
	"/_ws/sync",                             // generic sync channel
	"/cable",                                // ActionCable (Rails) default — extremely common across the web
}

// legacyAcceptedWSPaths — retired from the active wsURLPool (Wave 2.1,
// 2026-05-17) but still accepted by IsAllowedWSPath for backward compatibility
// with already-installed clients that hashed one of these paths at install
// time. Every WS upgrade landing on a legacy path increments
// Metrics.WSPathLegacyHits to inform a data-driven cutoff decision: when the
// rate falls below 0.01/s sustained for two weeks the entries here can be
// safely removed from the whitelist (MINOR-V2-6).
//
// Removed paths:
//   - /_next/webpack-hmr — Next.js HMR endpoint, dev-only on real deployments.
//   - /track/realtime    — Mixpanel-specific public tracking endpoint shape.
var legacyAcceptedWSPaths = map[string]struct{}{
	"/_next/webpack-hmr": {},
	"/track/realtime":    {},
}

// IsAllowedWSPath reports whether path is in the WebSocket URL whitelist.
// Comparison is exact and case-sensitive; query strings / trailing slashes
// do NOT match (callers should compare r.URL.Path, not r.RequestURI).
//
// Note: pool entries that themselves contain "?" (the Socket.IO polling-then-
// upgrade form) are matched on the full RequestURI form via a separate path
// — for those we accept either the path-only prefix ("/socket.io/") or the
// fully-qualified URI. The handler routes on r.URL.Path; query-string-bearing
// pool entries serve as documentation for the client side and reduce to the
// underlying path for matching.
func IsAllowedWSPath(path string) bool {
	if slices.Contains(wsURLPool, path) {
		return true
	}
	// Accept the canonical path of any pool entry that carries a query string
	// component. The pool stores both forms for symmetry with the client URL
	// builder, but Go's r.URL.Path drops the query string before this check.
	for _, p := range wsURLPool {
		if i := strings.IndexByte(p, '?'); i > 0 && p[:i] == path {
			return true
		}
	}
	// Backward-compat: retired entries from the active pool (Wave 2.1,
	// 2026-05-17) are still accepted here so already-installed clients keep
	// connecting. The WS upgrade dispatcher ticks Metrics.WSPathLegacyHits
	// on these hits — when the rate decays below the cutoff threshold the
	// entries here can be dropped.
	if _, ok := legacyAcceptedWSPaths[path]; ok {
		return true
	}
	return false
}

// AllWSPaths returns a copy of the WebSocket URL pool. Test / client
// bootstrap helper; callers may mutate the returned slice safely.
func AllWSPaths() []string {
	out := make([]string, len(wsURLPool))
	copy(out, wsURLPool)
	return out
}
