package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeDecoyHTML constructs a minimal valid decoy HTML file that contains a
// Schema.org JSON-LD block with the rl-state PropertyValue identifier.
func makeDecoyHTML(value string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Test Decoy</title>
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "TestApp",
  "identifier": {
    "@type": "PropertyValue",
    "propertyID": "rl-state",
    "value": "%s"
  }
}
</script>
</head>
<body><p>Test</p></body>
</html>`, value)
}

// TestLoadDecoySnapshots_HappyPath verifies that a valid HTML file with the
// correct Schema.org baseline is loaded and the offset points to the value.
func TestLoadDecoySnapshots_HappyPath(t *testing.T) {
	baseline := MakeBaselineValue()
	require.Len(t, baseline, RLStateValueWidth, "baseline must be RLStateValueWidth bytes")

	html := makeDecoyHTML(baseline)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0644))

	snaps, err := LoadDecoySnapshots(dir, []string{"index.html"})
	require.NoError(t, err)
	require.Contains(t, snaps, "index.html")

	snap := snaps["index.html"]
	assert.Equal(t, "index.html", snap.SourcePath)
	assert.Equal(t, len(html), snap.Size)
	assert.Equal(t, RLStateValueWidth, snap.IdentifierValueLength)
	assert.NotEqual(t, -1, snap.IdentifierValueOffset)

	// Verify the offset actually points to the baseline value in the HTML.
	off := snap.IdentifierValueOffset
	require.GreaterOrEqual(t, off, 0)
	require.LessOrEqual(t, off+RLStateValueWidth, len(snap.HTML))
	got := string(snap.HTML[off : off+RLStateValueWidth])
	assert.Equal(t, baseline, got, "offset must point to the exact value string")
}

// TestLoadDecoySnapshots_MissingIdentifier verifies that an HTML with a
// JSON-LD block but no identifier field causes a fail-fast error.
func TestLoadDecoySnapshots_MissingIdentifier(t *testing.T) {
	html := `<!DOCTYPE html>
<html><head>
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"SoftwareApplication","name":"Test"}
</script>
</head><body></body></html>`

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0644))

	_, err := LoadDecoySnapshots(dir, []string{"index.html"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index.html")
	assert.Contains(t, err.Error(), "Schema.org JSON-LD baseline validation failed")
}

// TestLoadDecoySnapshots_AcceptsAnyPropertyID replaces the former
// TestLoadDecoySnapshots_WrongPropertyID, which asserted that anything other
// than the literal "rl-state" was rejected.
//
// That assertion is now wrong by design (2026-08-08). The identifier is
// derived per host (core.DeriveRLPropertyID) precisely so it is NOT the same
// string everywhere — a fleet-wide constant meant one scan for one substring
// enumerated every server we run. The loader runs at startup with no request
// Host available, and a multi-domain process legitimately serves several
// hosts, so it cannot know which literal to expect and must accept the shape.
//
// Telling detail from the old test: its "wrong" fixture used propertyID
// "ISBN" — a real Schema.org vendor identifier, i.e. exactly the kind of
// value the new derivation is built to imitate.
func TestLoadDecoySnapshots_AcceptsAnyPropertyID(t *testing.T) {
	val := MakeBaselineValue()

	for _, propertyID := range []string{
		"ISBN",                  // real-world vocabulary example
		"sku-417",               // derived shape
		core.LegacyRLPropertyID, // legacy literal still loads
		core.DeriveRLPropertyID("datacanvases.com"),
	} {
		t.Run(propertyID, func(t *testing.T) {
			html := fmt.Sprintf(`<!DOCTYPE html>
<html><head>
<script type="application/ld+json">
{
  "@context":"https://schema.org",
  "@type":"Book",
  "identifier":{
    "@type":"PropertyValue",
    "propertyID":%q,
    "value":"%s"
  }
}
</script>
</head><body></body></html>`, propertyID, val)

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0644))

			snaps, err := LoadDecoySnapshots(dir, []string{"index.html"})
			require.NoError(t, err)
			require.Contains(t, snaps, "index.html")
			assert.Equal(t, propertyID, snaps["index.html"].PropertyID,
				"loader must report back the propertyID it found, for startup logging")
		})
	}
}

// TestLoadDecoySnapshots_EmptyPropertyID pins the one propertyID rule that
// survives: presence. An empty ID yields a malformed JSON-LD block that no
// client carrier will match, so the sentinel would be written into a slot
// nobody reads — silent loss of the rate-limit channel.
func TestLoadDecoySnapshots_EmptyPropertyID(t *testing.T) {
	val := MakeBaselineValue()
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head>
<script type="application/ld+json">
{
  "@context":"https://schema.org",
  "@type":"Book",
  "identifier":{
    "@type":"PropertyValue",
    "propertyID":"",
    "value":"%s"
  }
}
</script>
</head><body></body></html>`, val)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0644))

	_, err := LoadDecoySnapshots(dir, []string{"index.html"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index.html")
}

// TestLoadDecoySnapshots_WrongValueLength verifies that a value with length
// != RLStateValueWidth causes a fail-fast error.
func TestLoadDecoySnapshots_WrongValueLength(t *testing.T) {
	shortVal := "v1;bucket=none;refill_in=0;burst_left=100;exempt=0" // 50 chars, not 80
	require.NotEqual(t, RLStateValueWidth, len(shortVal))

	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head>
<script type="application/ld+json">
{
  "@context":"https://schema.org",
  "@type":"SoftwareApplication",
  "identifier":{
    "@type":"PropertyValue",
    "propertyID":"rl-state",
    "value":"%s"
  }
}
</script>
</head><body></body></html>`, shortVal)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0644))

	_, err := LoadDecoySnapshots(dir, []string{"index.html"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index.html")
}

// TestLoadDecoySnapshots_NoJSONLD verifies that an HTML without any
// <script type="application/ld+json"> causes a fail-fast error.
func TestLoadDecoySnapshots_NoJSONLD(t *testing.T) {
	html := `<!DOCTYPE html>
<html><head><title>No LD</title></head>
<body><p>Hello</p></body></html>`

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0644))

	_, err := LoadDecoySnapshots(dir, []string{"index.html"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index.html")
}

// TestLoadDecoySnapshots_TooLarge verifies that a file exceeding 256 KB is
// rejected with a clear error.
func TestLoadDecoySnapshots_TooLarge(t *testing.T) {
	large := make([]byte, maxDecoyFileSize+1)
	for i := range large {
		large[i] = 'A'
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "big.html"), large, 0644))

	_, err := LoadDecoySnapshots(dir, []string{"big.html"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "big.html")
	assert.Contains(t, err.Error(), "exceeds")
}

// TestLoadDecoySnapshots_MissingFile verifies that a referenced path that
// doesn't exist causes a clear fail-fast error.
func TestLoadDecoySnapshots_MissingFile(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadDecoySnapshots(dir, []string{"does_not_exist.html"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does_not_exist.html")
}

// TestMakeBaselineValue_HasCorrectWidth verifies MakeBaselineValue returns
// exactly RLStateValueWidth bytes.
func TestMakeBaselineValue_HasCorrectWidth(t *testing.T) {
	v := MakeBaselineValue()
	assert.Len(t, v, RLStateValueWidth,
		"MakeBaselineValue must return exactly %d bytes, got %d", RLStateValueWidth, len(v))
}

// TestMakeBaselineValue_HasCorrectFormat verifies the baseline has the
// expected key=value structure.
func TestMakeBaselineValue_HasCorrectFormat(t *testing.T) {
	v := MakeBaselineValue()
	assert.True(t, strings.HasPrefix(v, "v1;"), "must start with v1;")
	assert.Contains(t, v, "bucket=none")
	assert.Contains(t, v, "refill_in=0")
	assert.Contains(t, v, "burst_left=")
	assert.Contains(t, v, "exempt=0")
	// Padding is trailing semicolons — last char must be ';' or it exactly fits.
	// Either way, the length is the critical invariant already tested above.
}

// TestFormatRLStateValue_HappyPath verifies that a known RLSentinel produces
// the correct output of exactly RLStateValueWidth bytes.
func TestFormatRLStateValue_HappyPath(t *testing.T) {
	sig := RLSentinel{
		Bucket:    "handshake",
		BurstLeft: 0,
		RefillIn:  12 * time.Second,
		Exempt:    0,
	}
	v, err := FormatRLStateValue(sig)
	require.NoError(t, err)
	assert.Len(t, v, RLStateValueWidth,
		"FormatRLStateValue must return exactly %d bytes", RLStateValueWidth)

	assert.Contains(t, v, "v1;")
	assert.Contains(t, v, "bucket=handshake")
	assert.Contains(t, v, "refill_in=12")
	assert.Contains(t, v, "burst_left=0")
	assert.Contains(t, v, "exempt=0")
}

// TestFormatRLStateValue_ContentTooLong verifies that a synthetic bucket name
// that would exceed RLStateValueWidth returns an error instead of truncating.
func TestFormatRLStateValue_ContentTooLong(t *testing.T) {
	hugeBucket := strings.Repeat("x", RLStateValueWidth)
	sig := RLSentinel{
		Bucket:    hugeBucket,
		BurstLeft: 999,
		RefillIn:  3600 * time.Second,
		Exempt:    1,
	}
	_, err := FormatRLStateValue(sig)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds RLStateValueWidth")
}

// TestFindIdentifierValueOffset_HappyPath verifies that the function finds
// the correct byte offset for a known HTML input.
func TestFindIdentifierValueOffset_HappyPath(t *testing.T) {
	baseline := MakeBaselineValue()
	html := makeDecoyHTML(baseline)
	htmlBytes := []byte(html)

	offset, length, propertyID, ok := findIdentifierValueOffset(htmlBytes)
	require.True(t, ok, "findIdentifierValueOffset must succeed on valid HTML")
	assert.Equal(t, RLStateValueWidth, length)
	assert.NotEmpty(t, propertyID, "propertyID must be reported back to the caller")

	// Confirm the offset points to the actual value in the HTML.
	require.GreaterOrEqual(t, offset, 0)
	require.LessOrEqual(t, offset+length, len(htmlBytes))
	found := string(htmlBytes[offset : offset+length])
	assert.Equal(t, baseline, found, "offset must point to the exact baseline value")
}

// TestLoadDecoySnapshots_MultipleFiles verifies loading multiple files at once.
func TestLoadDecoySnapshots_MultipleFiles(t *testing.T) {
	baseline := MakeBaselineValue()
	dir := t.TempDir()

	files := []string{"a/index.html", "b/index.html"}
	for _, f := range files {
		full := filepath.Join(dir, f)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0755))
		require.NoError(t, os.WriteFile(full, []byte(makeDecoyHTML(baseline)), 0644))
	}

	snaps, err := LoadDecoySnapshots(dir, files)
	require.NoError(t, err)
	assert.Len(t, snaps, 2)
	for _, f := range files {
		assert.Contains(t, snaps, f)
		assert.NotNil(t, snaps[f])
	}
}

// TestFormatRLStateValue_AllBuckets verifies all known bucket labels fit
// within RLStateValueWidth.
func TestFormatRLStateValue_AllBuckets(t *testing.T) {
	buckets := []string{"ws_upgrade", "handshake", "data"}
	for _, b := range buckets {
		sig := RLSentinel{
			Bucket:    b,
			BurstLeft: 999,
			RefillIn:  3600 * time.Second,
			Exempt:    1,
		}
		v, err := FormatRLStateValue(sig)
		require.NoError(t, err, "bucket %q must fit in RLStateValueWidth", b)
		assert.Len(t, v, RLStateValueWidth, "bucket %q value must be RLStateValueWidth bytes", b)
	}
}

// TestLoadDecoySnapshots_WrongAtType verifies that identifier with @type !=
// "PropertyValue" is rejected.
func TestLoadDecoySnapshots_WrongAtType(t *testing.T) {
	val := strings.Repeat("x", RLStateValueWidth)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html><head>
<script type="application/ld+json">
{
  "@context":"https://schema.org",
  "@type":"SoftwareApplication",
  "identifier":{
    "@type":"Thing",
    "propertyID":"rl-state",
    "value":"%s"
  }
}
</script>
</head><body></body></html>`, val)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(html), 0644))

	_, err := LoadDecoySnapshots(dir, []string{"index.html"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "index.html")
}
