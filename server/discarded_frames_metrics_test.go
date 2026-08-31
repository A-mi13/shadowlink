package server

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The WS relay loop drops undecryptable and replayed frames with a bare
// `continue` and no log line, on purpose: logging them would let an attacker
// fill the disk. The counters are the only observability that remains, and
// their absence had a real cost — pooled UDP sealed frames with the wrong
// session, the server discarded every one, and nothing on our side showed it
// (found by an integrator in the field, 2026-08-31).
//
// So these tests check the counters actually reach an operator: the field, the
// JSON snapshot, and the Prometheus text.

func TestDiscardedFrameMetrics_ReachSnapshotAndProm(t *testing.T) {
	m := NewMetrics()

	m.WSFramesUndecryptable.Add(7)
	m.WSFramesReplayed.Add(3)

	snap := m.Snapshot()
	require.Equal(t, uint64(7), snap.WSFramesUndecryptable,
		"undecryptable count missing from the JSON snapshot")
	require.Equal(t, uint64(3), snap.WSFramesReplayed,
		"replayed count missing from the JSON snapshot")

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	m.ServeHTTP(w, r)

	require.Equal(t, 200, w.Code)
	body := w.Body.String()

	expected := []string{
		`shadowlink_ws_frames_discarded_total{reason="undecryptable"} 7`,
		`shadowlink_ws_frames_discarded_total{reason="replayed"} 3`,
	}
	for _, line := range expected {
		assert.True(t, strings.Contains(body, line),
			"prom output missing line %q\nbody:\n%s", line, body)
	}
}

// A fresh server must report zero, not omit the series: an operator alerting on
// "undecryptable > 0" needs the metric present from the start, or the alert
// silently never evaluates.
func TestDiscardedFrameMetrics_PresentAtZero(t *testing.T) {
	m := NewMetrics()

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	m.ServeHTTP(w, r)

	body := w.Body.String()
	for _, line := range []string{
		`shadowlink_ws_frames_discarded_total{reason="undecryptable"} 0`,
		`shadowlink_ws_frames_discarded_total{reason="replayed"} 0`,
	} {
		assert.True(t, strings.Contains(body, line),
			"zero-valued series must still be emitted, missing %q", line)
	}
}

// The guard that ties the counters to the code path they exist for: the two
// silent `continue` branches in the WS relay loop must each increment one.
// Checked against the source because the drop is unobservable by construction —
// no log, no response, no error return.
func TestWSRelayLoop_CountsSilentDrops(t *testing.T) {
	raw, err := os.ReadFile("websocket.go")
	require.NoError(t, err, "read websocket.go")
	src := string(raw)

	// Locate the relay-loop decrypt and seq-window checks and require a counter
	// next to each. Anchors are the exact expressions in the loop.
	for _, anchor := range []struct {
		check   string
		counter string
	}{
		{"chunk, err := session.DecryptChunkSafe(data)", "WSFramesUndecryptable"},
		{"if !session.AcceptSeqNum(chunk.SeqNum) {", "WSFramesReplayed"},
	} {
		idx := strings.Index(src, anchor.check)
		if idx < 0 {
			t.Fatalf("anchor %q no longer present in websocket.go — the relay "+
				"loop was restructured; re-point this guard", anchor.check)
		}
		// Look at the block that follows: the counter must appear before the
		// next `switch` (i.e. still inside the drop handling).
		window := src[idx:]
		if end := strings.Index(window, "switch chunk.Flags"); end > 0 {
			window = window[:end]
		}
		assert.True(t, strings.Contains(window, anchor.counter),
			"the silent-drop branch after %q does not increment %s — the drop "+
				"would be invisible again", anchor.check, anchor.counter)
	}
}
