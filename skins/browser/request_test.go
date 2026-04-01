package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

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
	assert.Contains(t, req.Header.Get("Authorization"), "Bearer ")
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
	token := []byte("token")

	req, err := BuildUploadRequest("https://example.com", original, token, 1, pool)
	require.NoError(t, err)

	body, _ := io.ReadAll(req.Body)
	decoded, err := ParseUploadRequest(body)
	require.NoError(t, err)
	assert.Equal(t, original, decoded)
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

func TestExtractSessionToken(t *testing.T) {
	pool := NewURLPool()
	token := []byte("my-secret-session-token-32b!!")
	req, _ := BuildUploadRequest("https://example.com", []byte("data"), token, 0, pool)

	extracted, err := ExtractSessionToken(req)
	require.NoError(t, err)
	assert.Equal(t, token, extracted)
}

func TestExtractSessionTokenMissing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	_, err := ExtractSessionToken(req)
	assert.Error(t, err)
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

func TestIsCoverTraffic(t *testing.T) {
	// C3 fix: IsCoverTraffic always returns false now — cover is indistinguishable
	// from data at the JSON level. Server detects cover via FlagPadding after decryption.
	dataBody := `{"events":[{"type":"click","ts":1234,"data":"aGVsbG8"}]}`
	assert.False(t, IsCoverTraffic([]byte(dataBody)))

	coverBody := `{"events":[{"type":"session_ping","ts":1234,"data":"encrypted-padding"}]}`
	assert.False(t, IsCoverTraffic([]byte(coverBody)))
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

func TestURLPoolCustom(t *testing.T) {
	pool := NewURLPoolCustom(
		[]string{"/custom/upload"},
		[]string{"/custom/download"},
	)
	assert.Equal(t, "/custom/upload", pool.NextUploadPath())
	assert.Equal(t, "/custom/download", pool.NextDownloadPath())
}

func TestFullRequestResponseCycle(t *testing.T) {
	pool := NewURLPool()
	token := []byte("session-token-value")

	// Client builds upload request
	clientData := []byte("encrypted-vpn-packet-from-client")
	req, err := BuildUploadRequest("https://api.example.com", clientData, token, 7, pool)
	require.NoError(t, err)

	// Server receives and parses
	reqBody, _ := io.ReadAll(req.Body)
	serverReceived, err := ParseUploadRequest(reqBody)
	require.NoError(t, err)
	assert.Equal(t, clientData, serverReceived)

	// Server token extraction
	serverToken, _ := ExtractSessionToken(req)
	assert.Equal(t, token, serverToken)

	// Server builds response
	serverData := []byte("encrypted-vpn-packet-from-server")
	respBody, err := BuildDownloadResponse(serverData, 7)
	require.NoError(t, err)

	// Client parses response
	clientReceived, _, err := ParseDownloadResponse(respBody)
	require.NoError(t, err)
	assert.Equal(t, serverData, clientReceived)
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
