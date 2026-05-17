# Live Decoy (T1.3) — `/blog/*` habr reverse-proxy

Serverside-only feature, shipped 2026-04-23. Adds `/blog/*` and `/_cdn/*`
paths to the ShadowLink decoy. Unauthenticated GET requests under those
prefixes are reverse-proxied to habr.com and its CDN, with an HTML rewriter
swapping branding, internal links, and asset hosts so responses appear to
come from `datacanvases.com` only.

## Enabling

YAML config `live_blog`:

```yaml
live_blog:
  enabled: true
  upstream: https://habr.com
  cdn_upstream: https://dr.habracdn.net
  cache_ttl: 1h
  cache_max_entries: 500
  cache_stale_grace: 24h
  upstream_rps: 1.0
  upstream_burst: 5
  upstream_timeout: 10s
  max_body_bytes: 2097152
  cdn_max_body_bytes: 16777216
  canary_article_id: "723128"
  canary_interval: 15m
  target_brand: DataCanvases
  target_logo_path: /assets/logo.svg
  target_title_suffix: " — DataCanvases Research"
```

CLI overrides: `-live-blog-enabled`, `-live-blog-upstream`, `-live-blog-cache-ttl`.

Default (feature flag off): zero behavioral change — Handler dispatch skips
the live-blog branch entirely.

## Metrics

Exposed via `/metrics?format=prom`:

- `decoy_live_blog_requests_total`
- `decoy_live_blog_cache_hits_total`, `decoy_live_blog_cache_misses_total`
- `decoy_live_blog_upstream_ok_total`, `decoy_live_blog_upstream_err_total`
- `decoy_live_blog_upstream_rate_limited_total`
- `decoy_live_blog_stale_served_total`
- `decoy_live_blog_fallback_spa_total`
- `decoy_live_blog_rewrite_panic_total`
- `decoy_live_blog_rewrite_drift_total`
- `decoy_live_blog_canary_ok_total`
- `decoy_live_blog_canary_fetch_fail_total`
- `decoy_live_blog_cdn_hits_total`, `decoy_live_blog_cdn_errors_total`

## Alertmanager rules (ops)

```
- alert: LiveBlogCanaryDrift
  expr: increase(decoy_live_blog_rewrite_drift_total[30m]) > 0
  for: 30m
  labels: {severity: warning}

- alert: LiveBlogCanaryStuck
  expr: increase(decoy_live_blog_canary_ok_total[1h]) == 0
  for: 1h
  labels: {severity: critical}

- alert: LiveBlogUpstreamErrorRateHigh
  expr: rate(decoy_live_blog_upstream_err_total[5m])
        / rate(decoy_live_blog_requests_total[5m]) > 0.5
  for: 15m
  labels: {severity: warning}
```

## Canary watchdog

A background goroutine fetches the canary article every `canary_interval`
(default 15 min), runs it through the rewriter, and checks 5 invariants:

- I1 body > 20 KB
- I2 target brand substring present
- I3 no source-brand tokens in visible text
- I4 no `/ru/articles/` or `habr.com` hrefs remaining
- I5 no `habracdn.net` substring

Failure increments `decoy_live_blog_rewrite_drift_total` and logs warn. 3
consecutive failures log error (alertmanager-visible).

If the canary article is removed from habr, the canary switches to
fetch-fail mode. Ops response: change `canary_article_id` in YAML and
`systemctl restart shadowlink`.

## Rollback procedures

1. **Fastest** — set `live_blog.enabled: false`, `systemctl restart shadowlink`. ~5s.
2. **Binary rollback** — restore previous binary from `/opt/shadowlink/releases/`, restart.
3. **Full revert** — revert commits, rebuild, redeploy.

The feature is additive on the decoy side. Disabling it restores the exact
pre-T1.3 decoy behavior: the static metricshub SPA is served for all
non-VPN paths. VPN code paths are never touched by T1.3.

## Known limitations

- habr ToS likely forbids rebranded reverse-proxy. Accepted risk; if habr
  cease-and-desists, change `upstream` to a different site (medium.com,
  dev.to, substack.com).
- Rewriter regex coverage is imperfect. Brand leaks inside inline JSON-LD
  schemas or `<script>` bodies pass through — acceptable because most tools
  don't render those visibly.
- Habr HTML markup changes can break the rewriter silently. The canary
  catches this class of regression within 15 minutes.
- Concurrent misses on the same key trigger parallel upstream fetches up to
  the burst limit (5). Single-flight coalescing is a V2 optimization.

## File map

- `shadowlink/server/live_blog.go` — `LiveBlogHandler`
- `shadowlink/server/live_blog_canary.go` — `CanaryWatchdog`
- `shadowlink/server/html_rewriter.go` — `HTMLRewriter`
- `shadowlink/server/config.go` — `LiveBlogConfig`
- `shadowlink/server/metrics.go` — `DecoyLiveBlog*` counters
- `shadowlink/server/handler.go` — dispatch hook + canary lifecycle wiring
- `shadowlink/testdata/habr/habr_article_synthetic.html` — rewriter fixture

Spec: `docs/superpowers/specs/2026-04-23-t13-live-decoy-design.md`.
Plan: `docs/superpowers/plans/2026-04-23-t13-live-decoy.md`.
