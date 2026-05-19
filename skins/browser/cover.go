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
// Pool entries are a mix of Mixpanel-aligned SDK endpoints (may-audit C1,
// 2026-05-02) and static page assets (Wave 2.4, 2026-05-17 — multi-resource
// decoy mimicry). A real SPA cold-start emits both shapes before opening a
// long-lived socket, so the warmup burst draws from both classes:
//
// SDK / telemetry (Mixpanel-aligned):
//   - `/sdk-config.json`     — config endpoint
//   - `/api/v2/sdk/version`  — SDK version probe
//   - `/tag.js`              — tag-manager script
//   - `/pixel.gif`           — pixel beacon
//   - `/decide`              — feature-flag / config lookup
//   - `/lib.min.js`          — JS SDK bundle
//
// Static page assets (Wave 2.4):
//   - `/assets/main.css`     — stylesheet
//   - `/assets/app.js`       — page JS bundle
//   - `/assets/hero.webp`    — hero image
//   - `/favicon.ico`         — favicon
//
// Pool size is pinned at 10 by `TestDefaultCoverPaths_PoolSize`. The
// `chooseWarmupCount` clamp (`client/ws_transport.go`) caps the burst at
// `min(4, len(pool))` — so the cap stays at 4 regardless of pool growth.
// Growing the pool widens the prefix-permutation space sampled by
// `WarmupRequests`, strengthening order-entropy without changing the
// burst-length distribution observed on the wire.
var defaultCoverPaths = []string{
	"/sdk-config.json",
	"/api/v2/sdk/version",
	"/tag.js",
	"/pixel.gif",
	"/decide",
	"/lib.min.js",
	"/assets/main.css",
	"/assets/app.js",
	"/assets/hero.webp",
	"/favicon.ico",
}

// DefaultCoverPaths exposes a defensive copy of the warmup path pool to
// call sites in package client (e.g. WarmupRequests). Callers are free to
// shuffle the returned slice without affecting the package-internal copy.
func DefaultCoverPaths() []string {
	out := make([]string, len(defaultCoverPaths))
	copy(out, defaultCoverPaths)
	return out
}

// CoverPathsPool returns a defensive copy of defaultCoverPaths +
// dynamicCoverPaths combined. dynamicCoverPaths is generated from an HTML
// snapshot of the decoy origin via tools/extract_cover_paths (the result
// lives in cover_paths_gen.go). Merging the two widens the prefix space
// the WarmupRequests burst draws from, blending hand-curated SDK/asset
// shapes with paths the real decoy origin actually references — closer to
// NaiveProxy-style preamble where the warmup looks indistinguishable from
// a real browser cold-start against that origin.
//
// Returned slice is safe to shuffle without affecting either underlying
// pool.
func CoverPathsPool() []string {
	combined := make([]string, 0, len(defaultCoverPaths)+len(dynamicCoverPaths))
	combined = append(combined, defaultCoverPaths...)
	combined = append(combined, dynamicCoverPaths...)
	return combined
}
