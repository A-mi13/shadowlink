// Package client — slog log level helpers.
//
// LevelTrace adds an extra granularity below slog.LevelDebug for per-chunk
// per-stream spam (downlink data, WS CONNECT_OK, SOCKS5 CONNECT, etc.).
// In normal debugging (-log=debug) those messages stay hidden. -log=trace
// surfaces them for deep-dive forensics.
package client

import (
	"context"
	"log/slog"
)

// LevelTrace is below slog.LevelDebug (-4). slog has no built-in level
// below Debug; we pick -8 to leave room for intermediate values if needed.
const LevelTrace slog.Level = -8

// Trace logs at LevelTrace through the default slog logger. Per-chunk
// per-stream call sites should use this instead of slog.Debug — the
// default Debug bucket is already crowded with one-per-event diagnostics
// (slot reconnects, keepalives, auth) that we want visible at -log=debug.
func Trace(msg string, args ...any) {
	slog.Default().Log(context.Background(), LevelTrace, msg, args...)
}
