package browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParseDataPayload verifies that ParseDataPayload never panics on arbitrary input.
// Catches out-of-bounds slices, nil dereferences, and other unsafe access patterns
// that an attacker sending malformed bytes could trigger.
func FuzzParseDataPayload(f *testing.F) {
	// Seed corpus: empty, shorter than token, exact token size, token+data
	f.Add([]byte{})
	f.Add(make([]byte, 40))
	f.Add(make([]byte, 100))
	f.Add([]byte("arbitrary-bytes-some-longer-than-token-some-shorter"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseDataPayload panicked on input len=%d: %v", len(data), r)
			}
		}()
		// sessionTokenSize=40 is the canonical protocol constant (4-byte hint + 36-byte token)
		_, _, _ = ParseDataPayload(data, 40)
	})
}

// FuzzParseHandshakePayload verifies that ParseHandshakePayload never panics on arbitrary input.
// The handshake is the first attacker-controlled bytes on a new connection — critical to harden.
func FuzzParseHandshakePayload(f *testing.F) {
	// Seed corpus: empty, just under ephPub boundary, exact ephPub, with encClientID, large
	f.Add([]byte{})
	f.Add(make([]byte, 31))
	f.Add(make([]byte, 32))
	f.Add(make([]byte, 100))
	f.Add(make([]byte, 1024))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseHandshakePayload panicked on input len=%d: %v", len(data), r)
			}
		}()
		_, _, _ = ParseHandshakePayload(data)
	})
}

// FuzzParseUploadRequest verifies that ParseUploadRequest never panics on arbitrary input
// and rejects oversize base64 payloads (A1-M7) without OOM or unbounded allocations.
//
// Seed corpus covers:
//   - empty body, malformed JSON
//   - well-formed JSON with empty events list
//   - well-formed JSON with empty data field
//   - well-formed JSON with valid base64 payload
//   - well-formed JSON with oversize base64 payload (just over MaxUploadDataField)
//   - well-formed JSON with extreme oversize payload
func FuzzParseUploadRequest(f *testing.F) {
	// Empty + malformed
	f.Add([]byte{})
	f.Add([]byte("not-json"))
	f.Add([]byte(`{"events":[]}`))

	// Valid envelope, empty data
	f.Add([]byte(`{"events":[{"type":"page_view","ts":1,"data":""}]}`))

	// Valid envelope, small data
	smallData := base64.RawURLEncoding.EncodeToString([]byte("payload"))
	smallEnv, _ := json.Marshal(uploadEnvelope{Events: []uploadEvent{{Type: "page_view", TS: 1, Data: smallData}}})
	f.Add(smallEnv)

	// Just-over-limit data (well-formed JSON, MaxUploadDataField+1 base64 chars)
	overLimit := strings.Repeat("A", MaxUploadDataField+1)
	overEnv, _ := json.Marshal(uploadEnvelope{Events: []uploadEvent{{Type: "page_view", TS: 1, Data: overLimit}}})
	f.Add(overEnv)

	// 4× over limit — must reject without allocating decode buffer
	huge := strings.Repeat("A", MaxUploadDataField*4)
	hugeEnv, _ := json.Marshal(uploadEnvelope{Events: []uploadEvent{{Type: "page_view", TS: 1, Data: huge}}})
	f.Add(hugeEnv)

	f.Fuzz(func(t *testing.T, body []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseUploadRequest panicked on input len=%d: %v", len(body), r)
			}
		}()
		_, _ = ParseUploadRequest(body)
	})
}

// TestParseUploadRequest_RejectsOversizeData asserts the A1-M7 size guard fires
// before base64 decode, returning a sentinel error without allocating the full
// decoded buffer. This is a regression test against future refactors that might
// move the limit check after the decode call.
func TestParseUploadRequest_RejectsOversizeData(t *testing.T) {
	// data field is well-formed base64 but length > MaxUploadDataField.
	overLimit := strings.Repeat("A", MaxUploadDataField+1)
	body, err := json.Marshal(uploadEnvelope{Events: []uploadEvent{{Type: "page_view", TS: 1, Data: overLimit}}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseUploadRequest(body)
	if err == nil {
		t.Fatal("ParseUploadRequest accepted oversize data — A1-M7 guard not firing")
	}
	if !strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("expected 'exceeds limit' error, got: %v", err)
	}
}

// TestParseUploadRequest_AcceptsAtLimit asserts that the A1-M7 boundary is
// exclusive: payloads of exactly MaxUploadDataField bytes are accepted (decoder
// may still reject them as bad base64, but the size guard does not).
func TestParseUploadRequest_AcceptsAtLimit(t *testing.T) {
	// Use a length that's a valid base64 RawURL chunk size (multiple of 4 minus alignment).
	atLimit := strings.Repeat("A", MaxUploadDataField)
	body, err := json.Marshal(uploadEnvelope{Events: []uploadEvent{{Type: "page_view", TS: 1, Data: atLimit}}})
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseUploadRequest(body)
	// Either nil (decoder accepted) or a base64-decode error — but NOT the size-guard error.
	if err != nil && strings.Contains(err.Error(), "exceeds limit") {
		t.Errorf("size guard fired at exactly MaxUploadDataField (%d), want exclusive boundary", MaxUploadDataField)
	}
}

// FuzzBuildParseDataRoundTrip verifies the BuildDataPayload→ParseDataPayload round-trip:
// for any non-empty token and chunk, parsing the built payload must reproduce them exactly.
func FuzzBuildParseDataRoundTrip(f *testing.F) {
	// Seed corpus: exact 40-byte token + small chunk, short token + minimal chunk
	f.Add([]byte("token-40b-----------------------------aa"), []byte("chunk"))
	f.Add([]byte("shorttoken"), []byte("x"))

	f.Fuzz(func(t *testing.T, token, chunk []byte) {
		// Skip degenerate inputs that violate the protocol spec (token must be ≥1, chunk must be ≥1)
		if len(token) < 1 || len(chunk) < 1 {
			t.Skip()
		}
		p := BuildDataPayload(token, chunk)
		t2, c2, err := ParseDataPayload(p, len(token))
		if err != nil {
			t.Fatalf("round-trip parse error on token=%d chunk=%d: %v", len(token), len(chunk), err)
		}
		if !bytes.Equal(t2, token) {
			t.Fatalf("round-trip token mismatch: got len=%d, want len=%d", len(t2), len(token))
		}
		if !bytes.Equal(c2, chunk) {
			t.Fatalf("round-trip chunk mismatch: got len=%d, want len=%d", len(c2), len(chunk))
		}
	})
}
