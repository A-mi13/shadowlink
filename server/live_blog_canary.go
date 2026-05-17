package server

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"time"
)

// canaryInvariantResult records which invariants failed on a single canary
// run. ok() is true iff all five passed.
type canaryInvariantResult struct {
	I1SizeFailed       bool // body < 20 KB
	I2BrandMissing     bool // BrandTo substring absent
	I3SourceBrandLeak  bool // any BrandFromTokens present in visible text
	I4InternalLinkLeak bool // href="/ru/articles/..." or href="*habr.com/..." still there
	I5CDNLeak          bool // habracdn.net string present
}

func (r canaryInvariantResult) ok() bool {
	return !r.I1SizeFailed && !r.I2BrandMissing && !r.I3SourceBrandLeak &&
		!r.I4InternalLinkLeak && !r.I5CDNLeak
}

var (
	canaryArticleHrefRe = regexp.MustCompile(`href="[^"]*(?:/ru/articles/|//[^"]*habr\.com/)`)
	canaryHTMLTagRe     = regexp.MustCompile(`(?s)<[^>]+>`)
)

const canaryMinBodyBytes = 20 * 1024

// checkCanaryInvariants runs the 5 invariants on a rewriter output. Called by
// the watchdog loop; pure function, cheap to unit-test.
func checkCanaryInvariants(body []byte, brandTo string, brandFromTokens []string) canaryInvariantResult {
	var r canaryInvariantResult

	if len(body) < canaryMinBodyBytes {
		r.I1SizeFailed = true
	}
	if !bytes.Contains(body, []byte(brandTo)) {
		r.I2BrandMissing = true
	}

	// Visible-text brand check: strip tags first so we don't false-positive
	// on habr references inside code blocks / inline scripts.
	visible := canaryHTMLTagRe.ReplaceAll(body, []byte(" "))
	for _, from := range brandFromTokens {
		if from == "" {
			continue
		}
		if bytes.Contains(visible, []byte(from)) {
			r.I3SourceBrandLeak = true
			break
		}
	}

	if canaryArticleHrefRe.Match(body) {
		r.I4InternalLinkLeak = true
	}
	if bytes.Contains(body, []byte("habracdn.net")) {
		r.I5CDNLeak = true
	}
	return r
}

// canaryTracker counts consecutive failures. record(false) increments the
// consecutive-fail counter and returns true when the counter reaches 3 or
// more. record(true) clears the counter.
type canaryTracker struct {
	consecutiveFails int
}

func (t *canaryTracker) record(ok bool) (errorLevel bool) {
	if ok {
		t.consecutiveFails = 0
		return false
	}
	t.consecutiveFails++
	return t.consecutiveFails >= 3
}

// runCanaryLoop is the long-running watchdog goroutine. It blocks until ctx
// cancels. Called from NewHandler when LiveBlog.Enabled is true.
func runCanaryLoop(ctx context.Context, h *LiveBlogHandler) {
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("live_blog: canary panic", "err", rec)
		}
	}()

	// Wait 30s before first fetch so server startup cost doesn't overlap
	// with a habr fetch.
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	ticker := time.NewTicker(h.cfg.CanaryInterval)
	defer ticker.Stop()

	tracker := &canaryTracker{}
	for {
		runCanaryOnce(ctx, h, tracker)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runCanaryOnce fetches the canary article, runs it through the rewriter,
// checks invariants, and updates metrics. Kept package-private so tests can
// exercise it.
//
// Финальный аудит 2026-05-03 P2 (T3 строка 105): ctx плюмбится в slog.Log
// для drift-warning. На handler'е slog.Default() сейчас не использует ctx,
// но плумбинг закрывает defensive lint и даёт hooks'у в будущем
// (ctx-aware handler'у — например, OTel) корректную shutdown-aware
// атрибуцию событий.
func runCanaryOnce(ctx context.Context, h *LiveBlogHandler, tracker *canaryTracker) {
	body, _, status, err := h.fetchUpstreamArticle(h.cfg.CanaryArticleID)
	if err != nil || status != 200 {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogCanaryFetchFail.Add(1)
		}
		slog.Warn("live_blog: canary fetch failed",
			"article_id", h.cfg.CanaryArticleID, "status", status, "err", err)
		return
	}

	out, rerr := h.rewriter.Rewrite(bytes.NewReader(body))
	if rerr != nil {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogRewritePanic.Add(1)
		}
		slog.Warn("live_blog: canary rewrite error", "err", rerr)
		return
	}

	brandFrom := []string{"Хабр", "Habr", "habrahabr"}
	result := checkCanaryInvariants(out, h.cfg.TargetBrand, brandFrom)

	if result.ok() {
		if h.metrics != nil {
			h.metrics.DecoyLiveBlogCanaryOK.Add(1)
			h.metrics.DecoyLiveBlogCanaryLastHealthyUnix.Store(time.Now().Unix())
		}
		tracker.record(true)
		return
	}

	if h.metrics != nil {
		h.metrics.DecoyLiveBlogRewriteDrift.Add(1)
	}
	level := slog.LevelWarn
	if tracker.record(false) {
		level = slog.LevelError
	}
	slog.Log(ctx, level, "live_blog: canary drift detected",
		"article_id", h.cfg.CanaryArticleID,
		"I1_size", result.I1SizeFailed,
		"I2_brand_missing", result.I2BrandMissing,
		"I3_source_brand_leak", result.I3SourceBrandLeak,
		"I4_internal_link_leak", result.I4InternalLinkLeak,
		"I5_cdn_leak", result.I5CDNLeak,
		"consecutive_fails", tracker.consecutiveFails,
	)
}
