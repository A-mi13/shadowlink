package client

import "math/rand/v2"

// wsURLPool MIRRORS shadowlink/server/urls.go:wsURLPool exactly. The two lists
// are kept in lockstep at compile time — there is no over-the-wire delivery of
// the pool because that itself would be a fingerprint (a fixed initial GET that
// returns a list of paths). The deploy ordering rule lives in the server file.
//
// Why mirror instead of import: the production client must NOT depend on
// shadowlink/server (layering — client is a public-facing binary; server is
// a service). Tests are allowed to import server and they assert that the two
// lists are byte-identical (see ws_paths_test.go::TestWSURLPool_MirrorsServer).
//
// Pool members are ordinary realtime / analytics URL shapes — Socket.IO,
// PostHog-style, Pusher/Ably-style, Rails ActionCable, Next.js HMR, generic
// /api/v2/realtime variants. None of them spell "shadowlink", "vpn", or
// "tunnel". Equally important: the literal "/ws" is intentionally absent —
// that's the fingerprint CRIT-4 calls out.
var wsURLPool = []string{
	"/socket.io/",
	"/socket.io/?EIO=4&transport=websocket",
	"/api/v2/realtime",
	"/api/v1/socket",
	"/api/v2/collect/stream",
	"/realtime/v1/connect",
	"/_next/webpack-hmr",
	"/track/realtime",
	"/live/v1/events",
	"/api/v2/notifications/stream",
	"/_ws/sync",
	"/cable",
}

// pickWSPath returns a random path from the pool. It is called once per
// UpgradeToWS, which means every WebSocket dial — including reconnects from the
// WS pool to the same server — picks an independent path. That is the
// anti-correlation property the CRIT-4 fix needs: a passive observer cannot
// pin down "this client always opens WS at /api/v2/realtime" because the
// next reconnect is equally likely to land on /cable or /socket.io/.
//
// math/rand/v2 has its own concurrency-safe global state — no extra
// synchronization is needed.
func pickWSPath() string {
	return wsURLPool[rand.IntN(len(wsURLPool))]
}

// allWSPaths returns a copy of the pool. Test / debug helper.
func allWSPaths() []string {
	out := make([]string, len(wsURLPool))
	copy(out, wsURLPool)
	return out
}
