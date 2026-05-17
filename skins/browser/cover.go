package browser

// defaultCoverPaths is the path pool used by WarmupRequests
// (`client/ws_transport.go::WarmupRequests`). The endpoints intentionally
// look like SDK telemetry + feature-flag fetches a real SPA would emit
// before opening a long-lived WebSocket — this seeds the pre-upgrade
// burst that mimics legitimate browser cold-start.
//
// Originally this pool was shared with the cover-GET scheduler that fired
// periodic GETs alongside the active WS session. The scheduler was retired
// 2026-05-02 (F3 wire/transport DPI followup) — the periodic 30-50%
// GET-vs-POST cadence it produced was itself a passive-FFT signal and the
// peer tools we benchmark against (Reality / Hysteria2 / TrustTunnel) ship
// with no cover GETs and operate cleanly inside Russia. WarmupRequests is
// not part of that retirement; it produces a one-shot burst (1-4 GETs)
// before the WS upgrade, not a periodic interleave.
//
// Pool entries are Mixpanel-aligned per may-audit C1 (2026-05-02):
//   - `/sdk-config.json`     — config endpoint
//   - `/api/v2/sdk/version`  — SDK version probe
//   - `/tag.js`              — tag-manager script
//   - `/pixel.gif`           — pixel beacon
//   - `/decide`              — feature-flag / config lookup
//   - `/lib.min.js`          — JS SDK bundle
//
// Pool size is pinned at 6 by `TestDefaultCoverPaths_PoolSize`; downstream
// callers (warmup count clamp, etc.) assume k=6.
var defaultCoverPaths = []string{
	"/sdk-config.json",
	"/api/v2/sdk/version",
	"/tag.js",
	"/pixel.gif",
	"/decide",
	"/lib.min.js",
}

// DefaultCoverPaths exposes a defensive copy of the warmup path pool to
// call sites in package client (e.g. WarmupRequests). Callers are free to
// shuffle the returned slice without affecting the package-internal copy.
func DefaultCoverPaths() []string {
	out := make([]string, len(defaultCoverPaths))
	copy(out, defaultCoverPaths)
	return out
}
