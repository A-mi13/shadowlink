package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RLStateValueWidth is the fixed-width slot for the identifier.value string
// inside the Schema.org JSON-LD block. Chosen to fit the maximum possible
// state string:
//
//	"v1;bucket=ws_upgrade;refill_in=3600;burst_left=999;exempt=1" ≈ 60 chars
//
// with a margin for future fields. Padding uses trailing semicolons, which
// are no-op in our key=value;key=value format.
const RLStateValueWidth = 80

// maxDecoyFileSize is the sanity cap for decoy HTML files loaded at startup.
const maxDecoyFileSize = 256 * 1024 // 256 KB

// DecoySnapshot is a pre-baked decoy HTML response with pre-computed markers
// for Schema.org rate-limit signal injection.
//
// Loaded once at server startup (LoadDecoySnapshots), immutable thereafter.
// On rate-limit hit, SentinelEmitter (Task 1.3) replaces the value at
// IdentifierValueOffset with the actual rl-state string, keeping the rest
// of the HTML byte-for-byte identical — zero DOM structural change.
type DecoySnapshot struct {
	// HTML is the full decoy response body, loaded from disk at startup.
	HTML []byte

	// IdentifierValueOffset is the byte position of the START of the
	// baseline value placeholder string inside the JSON-LD block. The
	// bytes from this offset for IdentifierValueLength bytes contain
	// the current `value` string (e.g., baseline
	// "v1;bucket=none;refill_in=0;burst_left=100;exempt=0;;...").
	//
	// SentinelEmitter writes a new value string at this offset.
	// The replacement value MUST be exactly IdentifierValueLength bytes
	// (pad with trailing semicolons) to keep all subsequent offsets stable.
	//
	// -1 if the snapshot has no Schema.org baseline (which is a hard error
	// at LoadDecoySnapshots time — fail-fast).
	IdentifierValueOffset int

	// IdentifierValueLength is the fixed-width length of the value slot.
	// Always RLStateValueWidth for snapshots loaded by LoadDecoySnapshots.
	IdentifierValueLength int

	// SourcePath is the path relative to the decoy directory.
	SourcePath string

	// Size is len(HTML).
	Size int
}

// LoadDecoySnapshots reads the given paths under decoyDir and validates each
// has a Schema.org JSON-LD baseline with PropertyValue identifier
// (propertyID="rl-state"). Returns a map keyed by relative path.
//
// CRITICAL invariants (enforced fail-fast at startup):
//  1. Each file must contain a <script type="application/ld+json"> tag
//  2. The JSON-LD payload must contain a top-level "identifier" object
//  3. identifier.@type must == "PropertyValue"
//  4. identifier.propertyID must == "rl-state"
//  5. identifier.value must be EXACTLY RLStateValueWidth bytes long
//  6. Total file size <= 256 KB sanity cap
//
// If any invariant fails, LoadDecoySnapshots returns a precise error
// indicating which file and which invariant. Server start halts.
func LoadDecoySnapshots(decoyDir string, paths []string) (map[string]*DecoySnapshot, error) {
	result := make(map[string]*DecoySnapshot, len(paths))

	for _, relPath := range paths {
		fullPath := filepath.Join(decoyDir, relPath)

		data, err := os.ReadFile(fullPath)
		if err != nil {
			return nil, fmt.Errorf("LoadDecoySnapshots %s: cannot read file: %w", relPath, err)
		}

		if len(data) > maxDecoyFileSize {
			return nil, fmt.Errorf("LoadDecoySnapshots %s: file size %d exceeds %d byte limit",
				relPath, len(data), maxDecoyFileSize)
		}

		offset, length, ok := findIdentifierValueOffset(data)
		if !ok {
			return nil, fmt.Errorf("LoadDecoySnapshots %s: Schema.org JSON-LD baseline validation failed — "+
				"file must contain <script type=\"application/ld+json\"> with identifier.@type=PropertyValue, "+
				"identifier.propertyID=\"rl-state\", and identifier.value of exactly %d bytes",
				relPath, RLStateValueWidth)
		}

		result[relPath] = &DecoySnapshot{
			HTML:                  data,
			IdentifierValueOffset: offset,
			IdentifierValueLength: length,
			SourcePath:            relPath,
			Size:                  len(data),
		}
	}

	return result, nil
}

// jsonLDBlock is used for parsing the Schema.org JSON-LD block.
type jsonLDBlock struct {
	Identifier *jsonLDIdentifier `json:"identifier"`
}

type jsonLDIdentifier struct {
	Type       string `json:"@type"`
	PropertyID string `json:"propertyID"`
	Value      string `json:"value"`
}

// findIdentifierValueOffset locates the byte offset of the value field's
// content inside the first matching JSON-LD block. Returns
// (offset, length, true) on success. If structure is invalid → returns
// (0, 0, false).
//
// Pattern detection:
//  1. Find <script type="application/ld+json">...</script>
//  2. Parse the JSON content
//  3. Locate identifier.value
//  4. Compute byte offset of the value string's contents in the original HTML
//
// Strategy: parse JSON once to validate, then use byte-precise search
// in original HTML to find the value string's position.
func findIdentifierValueOffset(html []byte) (offset int, length int, ok bool) {
	// Find the JSON-LD script block.
	scriptStart := findJSONLDScriptContent(html)
	if scriptStart == nil {
		return 0, 0, false
	}

	// scriptStart is the slice of HTML starting at the content after the opening tag.
	// Find where this sub-slice starts within html to compute absolute offsets later.
	scriptContentStart := len(html) - len(scriptStart)

	// Find the closing </script> tag and slice the JSON content.
	jsonContent, _, ok := bytes.Cut(scriptStart, []byte("</script>"))
	if !ok {
		return 0, 0, false
	}

	// Parse the JSON-LD block.
	var block jsonLDBlock
	if err := json.Unmarshal(bytes.TrimSpace(jsonContent), &block); err != nil {
		return 0, 0, false
	}

	// Validate invariants.
	if block.Identifier == nil {
		return 0, 0, false
	}
	if block.Identifier.Type != "PropertyValue" {
		return 0, 0, false
	}
	if block.Identifier.PropertyID != "rl-state" {
		return 0, 0, false
	}
	valueStr := block.Identifier.Value
	if len(valueStr) != RLStateValueWidth {
		return 0, 0, false
	}

	// Find the byte position of the value string inside the original HTML.
	// We search for the literal value string within the JSON-LD block portion.
	needle := []byte(valueStr)
	idxInContent := bytes.Index(jsonContent, needle)
	if idxInContent < 0 {
		// Should not happen if JSON was parsed from this content, but guard anyway.
		return 0, 0, false
	}

	absoluteOffset := scriptContentStart + idxInContent
	return absoluteOffset, RLStateValueWidth, true
}

// findJSONLDScriptContent scans html for the first
// <script type="application/ld+json"> tag and returns the remaining HTML
// slice starting immediately after the closing '>' of the opening tag.
// Returns nil if not found.
//
// If multiple <script type="application/ld+json"> blocks are present in
// the HTML, only the first is matched. This matches the spec contract
// (single Schema.org baseline per decoy template).
func findJSONLDScriptContent(html []byte) []byte {
	// We look for the opening tag in a case-insensitive way using a simple
	// scan. The canonical form used in all our templates is lowercase.
	lower := bytes.ToLower(html)

	// Find <script with type="application/ld+json"
	searchTag := []byte(`<script`)
	ldJSON := []byte(`application/ld+json`)

	pos := 0
	for {
		idx := bytes.Index(lower[pos:], searchTag)
		if idx < 0 {
			return nil
		}
		tagStart := pos + idx

		// Find the closing '>' of this opening tag.
		// NOTE: We assume <script type="..."> tags don't contain literal '>' in
		// any attribute value. Standard HTML never does this for script tags;
		// even title attribute would use &gt; or &#62;. If a pathological
		// template breaks this assumption, parsing will fail with empty
		// JSON content — caller's LoadDecoySnapshots will report the error.
		closeAngle := bytes.IndexByte(lower[tagStart:], '>')
		if closeAngle < 0 {
			return nil
		}
		tagEnd := tagStart + closeAngle

		// Check if this script tag contains the ld+json type.
		tagContent := lower[tagStart : tagEnd+1]
		if bytes.Contains(tagContent, ldJSON) {
			// Return original (non-lowercased) HTML slice after the '>'.
			return html[tagEnd+1:]
		}

		pos = tagEnd + 1
	}
}

// MakeBaselineValue returns the baseline rl-state string ("not rate-limited"),
// padded to RLStateValueWidth with trailing semicolons. Semicolons are no-op
// padding in our key=value;key=value format — parsers skip empty entries.
//
// Used by both decoy template authors (to embed the baseline) and tests
// (to construct test snapshots).
func MakeBaselineValue() string {
	core := "v1;bucket=none;refill_in=0;burst_left=100;exempt=0"
	return padToWidth(core, RLStateValueWidth)
}

// FormatRLStateValue renders an RLSentinel as a value string, padded to
// RLStateValueWidth. Used by SentinelEmitter to overwrite the baseline
// with actual rate-limit state.
//
// Returns error if the unpadded state exceeds RLStateValueWidth.
func FormatRLStateValue(sig RLSentinel) (string, error) {
	core := fmt.Sprintf("v1;bucket=%s;refill_in=%d;burst_left=%d;exempt=%d",
		sig.Bucket,
		int(sig.RefillIn.Seconds()),
		sig.BurstLeft,
		sig.Exempt,
	)
	if len(core) > RLStateValueWidth {
		return "", fmt.Errorf("FormatRLStateValue: state string length %d exceeds RLStateValueWidth %d: %q",
			len(core), RLStateValueWidth, core)
	}
	return padToWidth(core, RLStateValueWidth), nil
}

// padToWidth pads s with trailing semicolons to reach exactly width bytes.
// If s is already width bytes, it is returned as-is.
// Panics if len(s) > width (callers must pre-validate).
func padToWidth(s string, width int) string {
	if len(s) == width {
		return s
	}
	return s + strings.Repeat(";", width-len(s))
}
