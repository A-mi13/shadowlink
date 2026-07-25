package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeSentinelTestSnap builds a DecoySnapshot from a minimal HTML with the
// Schema.org baseline embedded. Uses t.TempDir() for file I/O so LoadDecoySnapshots
// validates the invariants the same way production startup does.
func makeSentinelTestSnap(t *testing.T, key string) (*DecoySnapshot, map[string]*DecoySnapshot) {
	t.Helper()
	baseline := MakeBaselineValue()
	html := makeDecoyHTML(baseline) // reuse helper from decoy_snapshots_test.go

	dir := t.TempDir()
	relPath := filepath.Base(key)
	if relPath == "" || relPath == "." {
		relPath = "index.html"
	}
	// Use key directly as relPath (supports "index.html" etc.)
	relPath = key

	fullPath := filepath.Join(dir, relPath)
	require.NoError(t, os.MkdirAll(filepath.Dir(fullPath), 0755))
	require.NoError(t, os.WriteFile(fullPath, []byte(html), 0644))

	snaps, err := LoadDecoySnapshots(dir, []string{relPath})
	require.NoError(t, err)
	require.Contains(t, snaps, relPath)
	return snaps[relPath], snaps
}

// sentinelSig returns a canonical test RLSentinel.
func sentinelSig() RLSentinel {
	return RLSentinel{
		Bucket:    "handshake",
		BurstLeft: 0,
		RefillIn:  12 * time.Second,
		Exempt:    0,
	}
}

// TestEmit_DualCarrier_BodyAndHeader verifies that when a snapshot is present,
// Emit writes both the body marker and the X-SL-RL header with a consistent value.
func TestEmit_DualCarrier_BodyAndHeader(t *testing.T) {
	snap, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	sig := sentinelSig()
	w := httptest.NewRecorder()
	e.Emit(w, sig, "index.html")

	// Header must be present.
	xlrl := w.Header().Get("X-SL-RL")
	require.NotEmpty(t, xlrl, "X-SL-RL header must be set")

	// Body must be present and match snapshot size.
	body := w.Body.Bytes()
	require.Len(t, body, snap.Size, "body length must equal snapshot Size")

	// The value at the identifier offset in the body must equal the padded RL state.
	off := snap.IdentifierValueOffset
	bodyVal := string(body[off : off+snap.IdentifierValueLength])

	expectedBodyVal, err := FormatRLStateValue(sig)
	require.NoError(t, err)
	assert.Equal(t, expectedBodyVal, bodyVal, "body slot must contain the RL state value")

	// The header value (unpadded) must contain the same semantic fields as the body.
	assert.Contains(t, xlrl, "bucket=handshake")
	assert.Contains(t, xlrl, "burst_left=0")
	assert.Contains(t, xlrl, "refill_in=12")
	assert.Contains(t, xlrl, "exempt=0")

	// Header and body must share the same core (header is stripped form of body).
	// Header should NOT have the trailing semicolons that serve as body padding.
	assert.False(t, strings.HasSuffix(xlrl, ";"),
		"X-SL-RL header must not have trailing semicolons")
}

// TestEmit_MissingSnapshot_HeaderOnly verifies that when the snapshotKey is not
// in the map, the header is emitted but the body is NOT modified (empty/not HTML),
// and RateLimitEmittedByBodyMissing is incremented.
func TestEmit_MissingSnapshot_HeaderOnly(t *testing.T) {
	_, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	w := httptest.NewRecorder()
	wrote := e.Emit(w, sentinelSig(), "nonexistent.html")

	// Header still emitted.
	xlrl := w.Header().Get("X-SL-RL")
	require.NotEmpty(t, xlrl, "X-SL-RL header must be emitted even on missing snapshot")

	// Раунд 18 / C-2: Emit ОБЯЗАН сообщить, что тело не записано, чтобы
	// вызывающий дописал decoy. Прежняя версия теста утверждала «body must be
	// empty» и тем закрепляла оракул (200 + Content-Length: 0).
	assert.False(t, wrote,
		"Emit must return false when no snapshot is available (caller must write the body)")

	// Missing counter incremented.
	assert.EqualValues(t, 1, m.RateLimitEmittedByBodyMissing.Load(),
		"RateLimitEmittedByBodyMissing must be 1 after missing-snapshot emit")

	// Body counter NOT incremented.
	assert.EqualValues(t, 0, m.RateLimitEmittedByBody.Load(),
		"RateLimitEmittedByBody must stay 0 on header-only path")
}

// TestEmit_NilSnapshots_HeaderOnly verifies that an emitter constructed with
// nil snapshots degrades gracefully to header-only mode.
func TestEmit_NilSnapshots_HeaderOnly(t *testing.T) {
	m := NewMetrics()
	e := NewSentinelEmitter(nil, m)

	w := httptest.NewRecorder()
	wrote := e.Emit(w, sentinelSig(), "index.html")

	xlrl := w.Header().Get("X-SL-RL")
	require.NotEmpty(t, xlrl, "X-SL-RL header must be emitted with nil snapshots")

	// Раунд 18 / C-2: см. TestEmit_MissingSnapshot_HeaderOnly.
	assert.False(t, wrote, "Emit must return false with nil snapshots")
	assert.EqualValues(t, 1, m.RateLimitEmittedByBodyMissing.Load())
}

// TestEmit_EmptyKey_DefaultsToIndex verifies that an empty snapshotKey resolves
// to "index.html".
func TestEmit_EmptyKey_DefaultsToIndex(t *testing.T) {
	snap, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	w := httptest.NewRecorder()
	e.Emit(w, sentinelSig(), "") // empty key → should resolve to "index.html"

	body := w.Body.Bytes()
	assert.Len(t, body, snap.Size,
		"empty key must resolve to index.html snapshot: body size mismatch")
	assert.EqualValues(t, 1, m.RateLimitEmittedByBody.Load(),
		"RateLimitEmittedByBody must be incremented when resolved snapshot is found")
}

// TestEmit_RateLimitEmittedByBody_Increments verifies the counter goes 0→1
// on a successful body emit.
func TestEmit_RateLimitEmittedByBody_Increments(t *testing.T) {
	_, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	assert.EqualValues(t, 0, m.RateLimitEmittedByBody.Load(), "pre-condition: counter is 0")

	w := httptest.NewRecorder()
	e.Emit(w, sentinelSig(), "index.html")

	assert.EqualValues(t, 1, m.RateLimitEmittedByBody.Load(),
		"RateLimitEmittedByBody must be 1 after successful emit")
}

// TestEmit_ContentLengthCorrect verifies Content-Length matches the actual
// body byte count (byte-precise substitution keeps total size invariant).
func TestEmit_ContentLengthCorrect(t *testing.T) {
	snap, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	w := httptest.NewRecorder()
	e.Emit(w, sentinelSig(), "index.html")

	body := w.Body.Bytes()
	cl := w.Header().Get("Content-Length")
	require.NotEmpty(t, cl, "Content-Length must be set")

	// Parse Content-Length manually.
	n := 0
	for _, c := range cl {
		if c < '0' || c > '9' {
			t.Fatalf("Content-Length is not a pure integer: %q", cl)
		}
		n = n*10 + int(c-'0')
	}
	assert.Equal(t, snap.Size, n, "Content-Length must equal snap.Size")
	assert.Equal(t, snap.Size, len(body), "body byte count must equal snap.Size")
}

// TestEmit_BodyByteForByteIdenticalExceptValue verifies that all bytes outside
// the IdentifierValueOffset slot are byte-for-byte identical to the original HTML.
func TestEmit_BodyByteForByteIdenticalExceptValue(t *testing.T) {
	snap, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	w := httptest.NewRecorder()
	e.Emit(w, sentinelSig(), "index.html")

	body := w.Body.Bytes()
	require.Len(t, body, snap.Size)

	off := snap.IdentifierValueOffset
	length := snap.IdentifierValueLength

	// Prefix bytes must be identical.
	require.Equal(t, snap.HTML[:off], body[:off],
		"bytes before the value slot must be identical to original HTML")

	// Suffix bytes must be identical.
	require.Equal(t, snap.HTML[off+length:], body[off+length:],
		"bytes after the value slot must be identical to original HTML")

	// The value slot itself must differ from baseline (it now holds the RL state).
	baseline := MakeBaselineValue()
	injected := string(body[off : off+length])
	assert.NotEqual(t, baseline, injected,
		"injected value must differ from baseline (it contains rate-limit state)")
}

// TestEmit_ExemptFieldPropagates verifies that RLSentinel.Exempt=1 appears in
// both the body value and the header.
func TestEmit_ExemptFieldPropagates(t *testing.T) {
	_, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	sig := RLSentinel{
		Bucket:    "ws_upgrade",
		BurstLeft: 5,
		RefillIn:  30 * time.Second,
		Exempt:    1,
	}
	w := httptest.NewRecorder()
	e.Emit(w, sig, "index.html")

	// Header must contain exempt=1.
	xlrl := w.Header().Get("X-SL-RL")
	assert.Contains(t, xlrl, "exempt=1", "header must propagate Exempt=1")

	// Body value at offset must contain exempt=1.
	snap := snaps["index.html"]
	body := w.Body.Bytes()
	off := snap.IdentifierValueOffset
	bodyVal := string(body[off : off+snap.IdentifierValueLength])
	assert.Contains(t, bodyVal, "exempt=1", "body slot must propagate Exempt=1")
}

// TestEmit_StatusCode200_NotRateLimit verifies the masquerade: status is 200, not 429.
func TestEmit_StatusCode200_NotRateLimit(t *testing.T) {
	_, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	w := httptest.NewRecorder()
	e.Emit(w, sentinelSig(), "index.html")

	assert.Equal(t, http.StatusOK, w.Code,
		"Emit must produce HTTP 200, not 429 — masquerade invariant")
}

// TestEmit_BodyParsesAsValidHTMLAfterSubstitution verifies that the emitted body
// still contains the <script type="application/ld+json"> structure and the new
// value is present as a substring.
func TestEmit_BodyParsesAsValidHTMLAfterSubstitution(t *testing.T) {
	_, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	sig := RLSentinel{
		Bucket:    "data",
		BurstLeft: 3,
		RefillIn:  60 * time.Second,
		Exempt:    0,
	}
	w := httptest.NewRecorder()
	e.Emit(w, sig, "index.html")

	bodyStr := w.Body.String()

	// The JSON-LD script tag must still be present.
	assert.Contains(t, bodyStr, `<script type="application/ld+json">`,
		"emitted HTML must still contain the JSON-LD script tag")

	// The rl-state propertyID must still be present.
	assert.Contains(t, bodyStr, `"rl-state"`,
		"emitted HTML must still contain the rl-state propertyID")

	// The new value must appear somewhere in the body (it's embedded in the JSON-LD).
	assert.Contains(t, bodyStr, "bucket=data",
		"emitted HTML must contain the injected bucket label")
}

// TestEmit_ContentTypeHTML verifies that Content-Type is set to text/html.
func TestEmit_ContentTypeHTML(t *testing.T) {
	_, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	w := httptest.NewRecorder()
	e.Emit(w, sentinelSig(), "index.html")

	ct := w.Header().Get("Content-Type")
	assert.Contains(t, ct, "text/html", "Content-Type must be text/html for decoy response")
}

// TestEmit_ConcurrentSafeUnderStorm verifies the buffer aliasing fix (CRIT-3):
// 100 concurrent Emit calls must all return correct, non-corrupted bodies.
// Before the fix, body := buf.Bytes() aliased the pool buffer's backing array,
// so a concurrent Get()+Reset() by another goroutine could overwrite the bytes
// while w.Write(body) was still streaming — resulting in corrupted or
// zero-length responses under rate-limit storms.
func TestEmit_ConcurrentSafeUnderStorm(t *testing.T) {
	snap, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	sig := sentinelSig()
	expectedSnippet, err := FormatRLStateValue(sig)
	require.NoError(t, err)

	var wg sync.WaitGroup
	errsCh := make(chan string, 100)
	for i := range 100 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			w := httptest.NewRecorder()
			e.Emit(w, sig, "index.html")
			body := w.Body.Bytes()
			if len(body) != snap.Size {
				errsCh <- fmt.Sprintf("worker %d: body size %d != snap.Size %d", id, len(body), snap.Size)
				return
			}
			off := snap.IdentifierValueOffset
			actual := string(body[off : off+snap.IdentifierValueLength])
			if actual != expectedSnippet {
				errsCh <- fmt.Sprintf("worker %d: value mismatch: got %q, want %q", id, actual, expectedSnippet)
			}
		}(i)
	}
	wg.Wait()
	close(errsCh)
	for e := range errsCh {
		t.Error(e)
	}
}

// TestEmit_HeaderCounter_AlwaysIncrements verifies that RateLimitSentinelEmitted
// is incremented in both body-emit and missing-snapshot (header-only) scenarios.
func TestEmit_HeaderCounter_AlwaysIncrements(t *testing.T) {
	t.Run("body_emit_increments_sentinel_counter", func(t *testing.T) {
		_, snaps := makeSentinelTestSnap(t, "index.html")
		m := NewMetrics()
		e := NewSentinelEmitter(snaps, m)

		w := httptest.NewRecorder()
		e.Emit(w, sentinelSig(), "index.html")

		assert.EqualValues(t, 1, m.RateLimitSentinelEmitted.Load(),
			"RateLimitSentinelEmitted must be 1 after a successful body emit")
		assert.EqualValues(t, 1, m.RateLimitEmittedByBody.Load(),
			"RateLimitEmittedByBody must also be 1")
	})

	t.Run("missing_snapshot_increments_sentinel_counter", func(t *testing.T) {
		_, snaps := makeSentinelTestSnap(t, "index.html")
		m := NewMetrics()
		e := NewSentinelEmitter(snaps, m)

		w := httptest.NewRecorder()
		e.Emit(w, sentinelSig(), "nonexistent.html")

		assert.EqualValues(t, 1, m.RateLimitSentinelEmitted.Load(),
			"RateLimitSentinelEmitted must be 1 even on missing-snapshot (header-only) path")
		assert.EqualValues(t, 1, m.RateLimitEmittedByBodyMissing.Load(),
			"RateLimitEmittedByBodyMissing must also be 1")
	})
}

// TestEmit_MultipleCallsPoolReuse verifies that calling Emit multiple times
// with the same emitter works correctly (sync.Pool reuse path).
func TestEmit_MultipleCallsPoolReuse(t *testing.T) {
	snap, snaps := makeSentinelTestSnap(t, "index.html")
	m := NewMetrics()
	e := NewSentinelEmitter(snaps, m)

	for i := range 5 {
		w := httptest.NewRecorder()
		e.Emit(w, sentinelSig(), "index.html")

		body := w.Body.Bytes()
		assert.Len(t, body, snap.Size, "iteration %d: body size must match snap.Size", i)

		xlrl := w.Header().Get("X-SL-RL")
		assert.NotEmpty(t, xlrl, "iteration %d: X-SL-RL header must be set", i)
	}

	assert.EqualValues(t, 5, m.RateLimitEmittedByBody.Load(),
		"RateLimitEmittedByBody must be 5 after 5 successful emits")
}
