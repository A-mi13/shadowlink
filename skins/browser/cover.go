package browser

// defaultCoverPaths is the path pool used by WarmupRequests
// (`client/ws_transport.go::WarmupRequests`). The endpoints intentionally
// look like the config + feature-flag fetches a real SPA would emit against
// its own backend before opening a long-lived WebSocket — this seeds the
// pre-upgrade burst that mimics legitimate browser cold-start.
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
// Pool entries are a mix of first-party application endpoints and static page
// assets (Wave 2.4, 2026-05-17 — multi-resource decoy mimicry). A real SPA
// cold-start emits both shapes before opening a long-lived socket, so the
// warmup burst draws from both classes:
//
// First-party application endpoints:
//   - `/api/v2/config`       — client bootstrap config
//   - `/api/v2/session`      — session/identity probe
//   - `/api/v2/flags`        — feature-flag lookup
//   - `/api/v2/telemetry`    — telemetry ingest
//
// Static page assets (Wave 2.4):
//   - `/assets/main.css`     — stylesheet
//   - `/assets/app.js`       — page JS bundle
//   - `/assets/vendor.js`    — vendor bundle
//   - `/assets/hero.webp`    — hero image
//   - `/assets/logo.svg`     — logo
//   - `/favicon.ico`         — favicon
//
// Third-party SDK endpoints removed 2026-08-08: `/decide`, `/lib.min.js`,
// `/tag.js`, `/pixel.gif` and `/sdk-config.json` are PostHog/Mixpanel-shaped
// paths. A browser fetches those from the SDK vendor's own origin, never from
// the site's domain — and `BuildTrackingPayload` sends Origin/Referer of our
// own baseURL (`request.go`), so a same-origin request to a vendor path had no
// real-world counterpart. The analytics-vendor persona is retired (2026-04-28
// pivot: TSPU does not parse encrypted bodies); the legend is now a
// self-contained SPA talking to its own backend, which same-origin traffic
// actually matches.
//
// Pool size is pinned at 10 by `TestDefaultCoverPaths_PoolSize`. The
// `chooseWarmupCount` clamp (`client/ws_transport.go`) caps the burst at
// `min(4, len(pool))` — so the cap stays at 4 regardless of pool growth.
// Growing the pool widens the prefix-permutation space sampled by
// `WarmupRequests`, strengthening order-entropy without changing the
// burst-length distribution observed on the wire.
var defaultCoverPaths = []string{
	"/api/v2/config",
	"/api/v2/session",
	"/api/v2/flags",
	"/api/v2/telemetry",
	"/assets/main.css",
	"/assets/app.js",
	"/assets/vendor.js",
	"/assets/hero.webp",
	"/assets/logo.svg",
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
