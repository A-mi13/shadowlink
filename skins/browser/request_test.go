package browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nixavpn/shadowlink/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildUploadRequest(t *testing.T) {
	pool := NewURLPool()
	encryptedChunk := []byte("encrypted-data-here-1234567890")
	sessionToken := []byte("session-token-32bytes-padded!!")
	seqNum := uint32(42)

	req, err := BuildUploadRequest("https://example.com", encryptedChunk, sessionToken, seqNum, pool)
	require.NoError(t, err)

	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	// D1 migration: Authorization header removed — token is now carried inside
	// the body via BuildDataPayload.
	assert.Empty(t, req.Header.Get("Authorization"), "Authorization header must not be set in body-prefix format")
	assert.NotEmpty(t, req.Header.Get("X-Request-ID"), "must have random request ID")
	assert.Contains(t, req.Header.Get("User-Agent"), "Mozilla")
	assert.Equal(t, "application/json", req.Header.Get("Accept"))

	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	assert.True(t, json.Valid(body), "body must be valid JSON")
	assert.Contains(t, string(body), `"data":`)
	assert.Contains(t, string(body), `"type":`)
	assert.Contains(t, string(body), `"ts":`)
}

// TestBuildUploadRequest_NoAuthHeader is the explicit D1 regression guard against
// re-introducing the Authorization header — matching the migration plan test.
func TestBuildUploadRequest_NoAuthHeader(t *testing.T) {
	pool := NewURLPool()
	token := make([]byte, 36)
	chunk := make([]byte, 100)
	req, err := BuildUploadRequest("https://example.com", chunk, token, 0, pool, "ua/1.0")
	require.NoError(t, err)
	assert.Empty(t, req.Header.Get("Authorization"), "body-prefix format must not carry Authorization")
}

// TestBuildUploadRequest_TokenInBody verifies the wire format: base64-decoded data
// MUST start with the session token, followed by the encrypted chunk.
func TestBuildUploadRequest_TokenInBody(t *testing.T) {
	pool := NewURLPool()
	token := make([]byte, 36)
	for i := range token {
		token[i] = byte(i + 1)
	}
	chunk := []byte("chunkbytes")
	req, err := BuildUploadRequest("https://example.com", chunk, token, 0, pool)
	require.NoError(t, err)

	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)

	var env uploadEnvelope
	require.NoError(t, json.Unmarshal(body, &env))
	require.Len(t, env.Events, 1)

	decoded, err := base64.RawURLEncoding.DecodeString(env.Events[0].Data)
	require.NoError(t, err)
	assert.True(t, bytes.HasPrefix(decoded, token), "token must be at start of decoded envelope data")
	assert.Equal(t, chunk, decoded[len(token):], "chunk must follow token")
}

// TestBuildCoverTrafficRequest_NoAuthHeader keeps cover traffic header-set in
// lockstep with data traffic (W4 invariant) after D1 removes Authorization.
func TestBuildCoverTrafficRequest_NoAuthHeader(t *testing.T) {
	pool := NewURLPool()
	token := make([]byte, 36)
	padding := make([]byte, 40)
	req, err := BuildCoverTrafficRequest("https://example.com", token, pool, "ua/1.0", padding)
	require.NoError(t, err)
	assert.Empty(t, req.Header.Get("Authorization"), "cover traffic must not carry Authorization either")
}

func TestBuildUploadRequestURLRotation(t *testing.T) {
	pool := NewURLPool()
	token := []byte("token")
	data := []byte("data")

	paths := map[string]bool{}
	for range 50 {
		req, _ := BuildUploadRequest("https://example.com", data, token, 0, pool)
		paths[req.URL.Path] = true
	}
	assert.Greater(t, len(paths), 1, "should use multiple URL paths")
}

func TestParseUploadRequest(t *testing.T) {
	pool := NewURLPool()
	original := []byte("test-encrypted-payload-bytes-here")
	token := []byte("token-bytes-here-padded-to-36b!!!!!!")

	req, err := BuildUploadRequest("https://example.com", original, token, 1, pool)
	require.NoError(t, err)

	body, _ := io.ReadAll(req.Body)
	decoded, err := ParseUploadRequest(body)
	require.NoError(t, err)

	// D1 migration: ParseUploadRequest returns the raw base64-decoded payload,
	// which in body-prefix format is [token][encrypted_chunk]. Callers recover
	// the chunk via ParseDataPayload on the protocol sessionTokenSize boundary.
	gotToken, gotChunk, err := ParseDataPayload(decoded, len(token))
	require.NoError(t, err)
	assert.Equal(t, token, gotToken)
	assert.Equal(t, original, gotChunk)
}

func TestBuildAndParseDownloadResponse(t *testing.T) {
	original := []byte("server-response-encrypted-data")
	seqNum := uint32(99)

	respBody, err := BuildDownloadResponse(original, seqNum)
	require.NoError(t, err)
	assert.True(t, json.Valid(respBody))

	decoded, _, err := ParseDownloadResponse(respBody)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
}

func TestExtractSeqNum(t *testing.T) {
	pool := NewURLPool()
	req, _ := BuildUploadRequest("https://example.com", []byte("data"), []byte("tok"), 255, pool)

	// C2 fix: X-Request-ID is random now, not seq_num — just verify it's valid hex
	seq, err := ExtractSeqNum(req)
	require.NoError(t, err)
	assert.NotEqual(t, uint32(0), seq, "should have a non-zero random ID")
}

func TestBuildCoverTrafficRequest(t *testing.T) {
	pool := NewURLPool()
	token := []byte("token")
	padding := []byte("encrypted-padding-data-here-1234")

	req, err := BuildCoverTrafficRequest("https://example.com", token, pool, "Mozilla/5.0 Test UA", padding)
	require.NoError(t, err)

	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.Equal(t, "Mozilla/5.0 Test UA", req.Header.Get("User-Agent"))
	assert.NotEmpty(t, req.Header.Get("X-Request-ID"))
	assert.Equal(t, "gzip, deflate, br", req.Header.Get("Accept-Encoding"))

	body, _ := io.ReadAll(req.Body)
	assert.True(t, json.Valid(body))

	// C3 fix: cover uses same events envelope as data with non-empty payload
	var parsed uploadEnvelope
	require.NoError(t, json.Unmarshal(body, &parsed))
	assert.Len(t, parsed.Events, 1)
	assert.NotEmpty(t, parsed.Events[0].Type)
	assert.NotZero(t, parsed.Events[0].TS)
	assert.NotEmpty(t, parsed.Events[0].Data, "cover traffic must have encrypted padding data")
}

// TestInflatedResponseHasNoFingerprintableFields guards against reintroducing
// config_version / experiment_id / variant — all three are JSON-fingerprintable
// (TSPU-class DPI can match them with a single parser). See 2026-04 DPI audit V3.
func TestInflatedResponseHasNoFingerprintableFields(t *testing.T) {
	encrypted := []byte("some-encrypted-chunk-data")
	for range 100 {
		body, err := BuildInflatedDownloadResponse(encrypted, 0, nil)
		require.NoError(t, err)
		s := string(body)
		assert.NotContains(t, s, "config_version", "V3: config_version must not appear in responses")
		assert.NotContains(t, s, "experiment_id", "V3: experiment_id must not appear in responses")
		assert.NotContains(t, s, `"variant"`, "V3: variant must not appear in responses")
	}
}

// TestInflatedResponseNextPollIsNonDeterministic verifies next_poll is emitted
// only sometimes (not every response), so its presence itself is not a signal.
func TestInflatedResponseNextPollIsNonDeterministic(t *testing.T) {
	encrypted := []byte("data")
	withPoll := 0
	withoutPoll := 0
	for range 200 {
		body, _ := BuildInflatedDownloadResponse(encrypted, 0, nil)
		if bytesContains(body, []byte(`"next_poll"`)) {
			withPoll++
		} else {
			withoutPoll++
		}
	}
	assert.Greater(t, withPoll, 30, "next_poll should sometimes appear")
	assert.Greater(t, withoutPoll, 30, "next_poll should sometimes be absent")
}

func TestBuildParseDataPayload_RoundTrip(t *testing.T) {
	token := make([]byte, 40)
	for i := range token {
		token[i] = byte(i)
	}
	chunk := []byte("encrypted-chunk-bytes-payload-here")

	payload := BuildDataPayload(token, chunk)

	gotToken, gotChunk, err := ParseDataPayload(payload, len(token))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotToken, token) {
		t.Errorf("token mismatch: got %x want %x", gotToken, token)
	}
	if !bytes.Equal(gotChunk, chunk) {
		t.Errorf("chunk mismatch: got %q want %q", gotChunk, chunk)
	}
}

func TestParseDataPayload_TooShort(t *testing.T) {
	_, _, err := ParseDataPayload(make([]byte, 10), 40)
	if err == nil {
		t.Error("expected error on short payload")
	}
}

func TestParseDataPayload_ExactTokenOnly_IsError(t *testing.T) {
	// Payload of exactly tokenSize with no chunk should fail — data request must carry a chunk
	_, _, err := ParseDataPayload(make([]byte, 40), 40)
	if err == nil {
		t.Error("expected error when payload has no chunk bytes after token")
	}
}

func TestBuildHandshakePayload_PaddingDistribution(t *testing.T) {
	// A2-HIGH-5 (Phase 3 Plan A) + may-audit C6 (2026-05-02): handshake
	// padding sourced from SampleHandshakePaddingTarget (μ_log=ln(350),
	// σ=0.5, capped [200, 800]) — independent of PayloadDistribution.
	// Mean target ≈ 397 is well above base = 32 + EncryptedClientIDSize,
	// so the pad branch fires on virtually every draw post-shift. We assert:
	//   1) ephPub / encClientID prefixes are preserved.
	//   2) variance exists (pad branch fires).
	//   3) all observed lengths fall within the new sampler's bounds.
	pd := NewPayloadDistribution()
	ephPub := make([]byte, 32)
	encClientID := make([]byte, core.EncryptedClientIDSize)
	for i := range ephPub {
		ephPub[i] = byte(i)
	}
	for i := range encClientID {
		encClientID[i] = byte(255 - i)
	}

	const minBase = 32 + core.EncryptedClientIDSize
	const maxLen = minBase + 800 // sampler cap is total target, not delta

	seen := map[int]bool{}
	for i := 0; i < 1000; i++ {
		p := BuildHandshakePayload(ephPub, encClientID, pd)
		if !bytes.Equal(p[:32], ephPub) {
			t.Fatal("ephPub prefix corrupted")
		}
		if !bytes.Equal(p[32:32+core.EncryptedClientIDSize], encClientID) {
			t.Fatal("encClientID prefix corrupted")
		}
		if len(p) < minBase {
			t.Fatalf("sample %d: payload len %d below floor %d", i, len(p), minBase)
		}
		if len(p) > maxLen {
			t.Fatalf("sample %d: payload len %d exceeds handshake sampler cap %d", i, len(p), maxLen)
		}
		seen[len(p)] = true
	}
	// Post-C6 shift the sampler caps target at 800; with base ≈ 97 the
	// pad branch fires on every draw and we get many distinct lengths.
	// Threshold raised to 50 (was 2) to catch regressions where the sampler
	// silently collapses to a single value.
	if len(seen) < 50 {
		t.Errorf("pad size variance too low: only %d distinct lengths in 1000 samples", len(seen))
	}
}

func TestParseHandshakePayload_IgnoresPad(t *testing.T) {
	ephPub := bytes.Repeat([]byte{0x42}, 32)
	encClientID := bytes.Repeat([]byte{0x7E}, core.EncryptedClientIDSize)
	pad := bytes.Repeat([]byte{0xDE}, 1234)
	payload := append(append(append([]byte{}, ephPub...), encClientID...), pad...)

	gotEph, gotEnc, err := ParseHandshakePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotEph, ephPub) {
		t.Error("ephPub mismatch")
	}
	if !bytes.Equal(gotEnc, encClientID) {
		t.Error("encClientID mismatch")
	}
}

func TestParseHandshakePayload_TooShort(t *testing.T) {
	_, _, err := ParseHandshakePayload(make([]byte, 30))
	if err == nil {
		t.Error("expected error on payload shorter than 32 bytes")
	}
	_, _, err = ParseHandshakePayload(make([]byte, 32+core.EncryptedClientIDSize-1))
	if err == nil {
		t.Error("expected error on payload shorter than 32+EncryptedClientIDSize")
	}
}

func TestBuildHandshakePayload_MinimumSize(t *testing.T) {
	// Even if distribution returns a tiny value, payload must contain full base
	pd := NewPayloadDistribution()
	ephPub := make([]byte, 32)
	encClientID := make([]byte, core.EncryptedClientIDSize)

	p := BuildHandshakePayload(ephPub, encClientID, pd)
	minBase := 32 + core.EncryptedClientIDSize
	if len(p) < minBase {
		t.Errorf("payload len %d < minimum base %d", len(p), minBase)
	}
}

func bytesContains(hay, needle []byte) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if string(hay[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}

func TestURLPoolRotation(t *testing.T) {
	pool := NewURLPool()
	seen := map[string]bool{}
	for range 100 {
		u := pool.NextUploadPath()
		seen[u] = true
	}
	assert.Greater(t, len(seen), 1, "should rotate between multiple URLs")
}

// TestURLPool_NextPathsFromDefaultPool replaces the deleted TestURLPoolCustom
// (T4 P2-17 cleanup, final audit 2026-05-03). The previous test exercised
// NewURLPoolCustom — a constructor that was only called from this test and
// from a server-paths-feature that never shipped. Now the contract under
// test is: NewURLPool returns a pool whose NextUploadPath / NextDownloadPath
// always come from the registered default lists.
func TestURLPool_NextPathsFromDefaultPool(t *testing.T) {
	pool := NewURLPool()
	uploads := pool.UploadPaths()
	assert.NotEmpty(t, uploads, "default upload pool must be non-empty")

	// 100 samples cover the small default pool with overwhelming probability.
	uploadSet := map[string]bool{}
	downloadSet := map[string]bool{}
	for range 100 {
		uploadSet[pool.NextUploadPath()] = true
		downloadSet[pool.NextDownloadPath()] = true
	}
	for u := range uploadSet {
		assert.Contains(t, uploads, u, "NextUploadPath returned a path outside the default pool")
	}
	assert.NotEmpty(t, downloadSet)
}

func TestFullRequestResponseCycle(t *testing.T) {
	pool := NewURLPool()
	token := []byte("session-token-value-padded-36b!!!!!")

	// Client builds upload request (body-prefix format — D1)
	clientData := []byte("encrypted-vpn-packet-from-client")
	req, err := BuildUploadRequest("https://api.example.com", clientData, token, 7, pool)
	require.NoError(t, err)

	// Server-side: base64 + ParseDataPayload split recovers token and chunk
	reqBody, _ := io.ReadAll(req.Body)
	decoded, err := ParseUploadRequest(reqBody)
	require.NoError(t, err)
	gotToken, gotChunk, err := ParseDataPayload(decoded, len(token))
	require.NoError(t, err)
	assert.Equal(t, token, gotToken)
	assert.Equal(t, clientData, gotChunk)

	// Server builds response
	serverData := []byte("encrypted-vpn-packet-from-server")
	respBody, err := BuildDownloadResponse(serverData, 7)
	require.NoError(t, err)

	// Client parses response
	clientReceived, _, err := ParseDownloadResponse(respBody)
	require.NoError(t, err)
	assert.Equal(t, serverData, clientReceived)
}

func TestHandshakePayload_PaddingHighEntropy(t *testing.T) {
	pd := NewPayloadDistribution()
	ephPub := make([]byte, 32)
	encClientID := make([]byte, core.EncryptedClientIDSize)

	const samples = 200
	baseLen := 32 + core.EncryptedClientIDSize

	// Collect byte values at pad position 0 across many samples that actually have pad
	byteFreq := make(map[byte]int)
	collected := 0
	for i := 0; i < samples*3; i++ { // over-sample to tolerate short payloads
		p := BuildHandshakePayload(ephPub, encClientID, pd)
		if len(p) > baseLen {
			byteFreq[p[baseLen]]++
			collected++
			if collected >= samples {
				break
			}
		}
	}
	if collected < samples/2 {
		t.Skip("PayloadDistribution rarely produces padding — skipping entropy check")
	}

	// crypto/rand should produce at least ~30 distinct values in samples=200
	// (uniform over 256 → birthday-paradox coverage is high)
	if len(byteFreq) < 30 {
		t.Errorf("low entropy at pad[0]: only %d distinct values in %d samples", len(byteFreq), collected)
	}
}

func TestRequestLooksLikeRealAPI(t *testing.T) {
	pool := NewURLPool()
	req, _ := BuildUploadRequest("https://api.example.com", []byte("data"), []byte("tok"), 0, pool)

	// Check that it would pass basic API gateway validation
	assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
	assert.NotEmpty(t, req.Header.Get("User-Agent"))

	// URL should look like an API endpoint
	path := req.URL.Path
	assert.True(t, len(path) > 1, "path should be a valid endpoint: %s", path)

	// Response should have standard status
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, _ := BuildDownloadResponse([]byte("resp"), 0)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(resp)
	})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assert.Equal(t, 200, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
}
