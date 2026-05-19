package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/nixavpn/shadowlink/client"
)

// logSpec captures parsed log configuration from CLI flags.
type logSpec struct {
	level   slog.Level
	file    string // empty = stderr only
	tagName string // for slog "level" key replacement (TRACE)
}

// parseLogLevel maps -log= values to slog.Level. Defaults to Info on unknown.
func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "quiet", "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err":
		return slog.LevelError, nil
	case "debug":
		return slog.LevelDebug, nil
	case "trace":
		return client.LevelTrace, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %q (use: quiet|info|debug|trace)", s)
	}
}

// renameTraceLevelAttr rewrites the slog "level" attribute from "DEBUG-4" to
// "TRACE" when the record level matches client.LevelTrace. Without this,
// trace lines print as "level=DEBUG-4" which is ugly and grep-unfriendly.
func renameTraceLevelAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key != slog.LevelKey {
		return a
	}
	if lvl, ok := a.Value.Any().(slog.Level); ok && lvl == client.LevelTrace {
		return slog.Attr{Key: slog.LevelKey, Value: slog.StringValue("TRACE")}
	}
	return a
}

// configureLogging wires slog.Default to write at the requested level, with
// optional tee to a file. Returns a closer to defer in main.
func configureLogging(spec logSpec) (io.Closer, error) {
	var sinks []io.Writer
	sinks = append(sinks, os.Stderr)

	var fileCloser io.Closer
	if spec.file != "" {
		f, err := os.OpenFile(spec.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, fmt.Errorf("open log file %q: %w", spec.file, err)
		}
		sinks = append(sinks, f)
		fileCloser = f
	}

	var out io.Writer
	if len(sinks) == 1 {
		out = sinks[0]
	} else {
		out = &syncMultiWriter{writers: sinks}
	}

	handler := slog.NewTextHandler(out, &slog.HandlerOptions{
		Level:       spec.level,
		ReplaceAttr: renameTraceLevelAttr,
	})
	slog.SetDefault(slog.New(handler))

	return closerFunc(func() error {
		if fileCloser != nil {
			return fileCloser.Close()
		}
		return nil
	}), nil
}

// syncMultiWriter writes to all sinks serially under a mutex. We need the
// mutex because slog's text handler emits multiple Write calls per record
// when the line wraps; without serialization, concurrent records would
// interleave bytes between stderr and the file.
type syncMultiWriter struct {
	mu      sync.Mutex
	writers []io.Writer
}

func (w *syncMultiWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.writers {
		if _, err := s.Write(p); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
