package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// flow_max_window is the server-side ceiling on the per-stream flow-control
// window, and the effective window is min(client, server). Until 2026-08-31 it
// was reachable only through the -flow-max-window CLI flag, while production
// runs `ExecStart=... -config config.yaml` with no flags
// (install-server.sh:752) — and main.go overwrote whatever YAML had set,
// unconditionally. Net effect: the ceiling was pinned at 1 MiB, no config
// change could move it, and a client raising SHADOWLINK_FLOW_WINDOW above 1 MiB
// silently got nothing. That trap produced an invalid throughput measurement in
// the integration review (28.3 vs 27.4 Mbit/s read as "the window is not the
// limiter", having compared 1 MiB with 1 MiB).

func TestApplyTo_FlowMaxWindow(t *testing.T) {
	t.Run("set from YAML", func(t *testing.T) {
		v := 4 * 1024 * 1024
		fc := &FileConfig{FlowMaxWindow: &v}
		cfg := DefaultConfig()

		fc.ApplyTo(&cfg)

		assert.Equal(t, uint64(4*1024*1024), cfg.FlowMaxWindow)
	})

	t.Run("absent key leaves the field untouched", func(t *testing.T) {
		fc := &FileConfig{}
		cfg := DefaultConfig()
		cfg.FlowMaxWindow = 1234 // as a flag layer would have set it

		fc.ApplyTo(&cfg)

		assert.Equal(t, uint64(1234), cfg.FlowMaxWindow,
			"an absent flow_max_window must not reset the value")
	})

	t.Run("explicit zero disables flow control", func(t *testing.T) {
		zero := 0
		fc := &FileConfig{FlowMaxWindow: &zero}
		cfg := DefaultConfig()
		cfg.FlowMaxWindow = 1 << 20

		fc.ApplyTo(&cfg)

		assert.Equal(t, uint64(0), cfg.FlowMaxWindow,
			"flow_max_window: 0 is a legal way to turn flow control off")
	})
}

func TestLoadConfigFile_FlowMaxWindowValidation(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		p := filepath.Join(dir, "config.yaml")
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}

	t.Run("accepts a sane value", func(t *testing.T) {
		fc, err := LoadConfigFile(write(t, "flow_max_window: 4194304\n"))
		require.NoError(t, err)
		require.NotNil(t, fc.FlowMaxWindow)
		assert.Equal(t, 4194304, *fc.FlowMaxWindow)
	})

	t.Run("accepts zero", func(t *testing.T) {
		fc, err := LoadConfigFile(write(t, "flow_max_window: 0\n"))
		require.NoError(t, err)
		require.NotNil(t, fc.FlowMaxWindow)
		assert.Equal(t, 0, *fc.FlowMaxWindow)
	})

	t.Run("rejects negative", func(t *testing.T) {
		_, err := LoadConfigFile(write(t, "flow_max_window: -1\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "flow_max_window")
	})

	t.Run("rejects a window too small for one chunk", func(t *testing.T) {
		_, err := LoadConfigFile(write(t, "flow_max_window: 1024\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "65536")
	})

	t.Run("rejects above the client clamp", func(t *testing.T) {
		// The client clamps its own advertised window at 6 MiB
		// (client/stream_flow.go maxFlowWindow) because window/minChunk must fit
		// the 512-frame per-stream incomingCh. A larger server ceiling could
		// never be reached and would mislead whoever set it.
		_, err := LoadConfigFile(write(t, "flow_max_window: 8388608\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "6291456")
	})
}

// The CLI layer must not overwrite a YAML-provided value. Asserted against the
// source: cmd/shadowlink-server has no test package, and the precedence lives in
// a straight-line main() that a unit test cannot call.
func TestFlowMaxWindow_YAMLIsNotOverwritten(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "cmd", "shadowlink-server", "main.go"))
	require.NoError(t, err, "read main.go")
	src := string(raw)

	const assign = "config.FlowMaxWindow = uint64(*flowMaxWindow)"
	const guard = `if explicitly["flow-max-window"] || !flowWindowFromYAML {`

	idx := strings.Index(src, assign)
	require.GreaterOrEqual(t, idx, 0,
		"the flag no longer feeds config.FlowMaxWindow at all — re-point this guard")

	// The assignment is only safe inside the precedence guard. Look at the text
	// immediately before it rather than matching the line alone, because the line
	// itself is identical in the correct and the defective version — the whole
	// bug was the absence of the surrounding condition.
	preceding := src[:idx]
	lastGuard := strings.LastIndex(preceding, guard)
	assert.GreaterOrEqual(t, lastGuard, 0,
		"config.FlowMaxWindow is assigned without the flag-vs-YAML guard — that "+
			"makes flow_max_window in config.yaml unreachable in the deployed shape "+
			"(ExecStart uses -config with no flags, install-server.sh:752)")
	if lastGuard >= 0 {
		// Nothing but whitespace/comments may sit between guard and assignment,
		// or the guard governs some other statement.
		between := preceding[lastGuard+len(guard):]
		for _, line := range strings.Split(between, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			assert.Fail(t, "unexpected statement between the guard and the "+
				"assignment: %q — the guard may no longer cover it", trimmed)
		}
	}

	assert.Contains(t, src, "flowWindowFromYAML = fc.FlowMaxWindow != nil",
		"nothing records whether YAML set flow_max_window; a YAML 0 (disable) "+
			"would be indistinguishable from an absent key")
}
