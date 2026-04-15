package browser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// UserAgents — pool of real browser User-Agent strings.
// Deprecated: Use Fingerprint.UserAgent() instead for fingerprint-matched UAs (M1 audit fix).
// Kept for backward compatibility; will be removed in future.
var UserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.81 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
}

// PickUserAgent selects a random UA to use for the entire session.
// Deprecated: Use Fingerprint.UserAgent() for fingerprint-matched UAs (M1 audit fix).
func PickUserAgent() string {
	return UserAgents[rand.IntN(len(UserAgents))]
}

// defaultUserAgent is set once at init — fallback if not configured per-session.
var defaultUserAgent = UserAgents[0]

// uploadEnvelope is the JSON structure for upload requests.
type uploadEnvelope struct {
	Events []uploadEvent `json:"events"`
}

type uploadEvent struct {
	Type string `json:"type"`
	TS   int64  `json:"ts"`
	Data string `json:"data"`
}

// downloadEnvelope is the JSON structure for download responses.
type downloadEnvelope struct {
	Status        string           `json:"status"`
	Results       []downloadResult `json:"results"`
	ConfigVersion string           `json:"config_version,omitempty"`
	ExperimentID  string           `json:"experiment_id,omitempty"`
	Variant       string           `json:"variant,omitempty"`
	NextPoll      int              `json:"next_poll,omitempty"`
}

type downloadResult struct {
	ID      string `json:"id"`
	Payload string `json:"payload"`
}

// BuildUploadRequest creates an HTTP request wrapping an encrypted chunk in JSON.
// userAgent should be picked once per session via PickUserAgent() (L3 audit fix).
func BuildUploadRequest(baseURL string, encryptedChunk []byte, sessionToken []byte, seqNum uint32, urlPool *URLPool, userAgent ...string) (*http.Request, error) {
	ua := defaultUserAgent
	if len(userAgent) > 0 && userAgent[0] != "" {
		ua = userAgent[0]
	}
	// Encode chunk as base64
	payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)

	// Build JSON envelope
	env := uploadEnvelope{
		Events: []uploadEvent{
			{
				Type: randomEventType(),
				TS:   time.Now().UnixMilli(),
				Data: payload,
			},
		},
	}

	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	// Pick random URL path
	path := urlPool.NextUploadPath()
	url := baseURL + path

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// Headers that look like a real browser/SPA
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(sessionToken))
	// C2 audit fix: use random request ID, not monotonic seq_num.
	// Seq_num is already inside the encrypted chunk — no need to expose in cleartext headers.
	req.Header.Set("X-Request-ID", fmt.Sprintf("%08x", rand.Uint32()))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br") // I3: browsers always send this
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", baseURL)                       // I5: SPA API calls include Origin
	req.Header.Set("Referer", baseURL+"/")                  // I5: and Referer
	req.Header.Set("Cache-Control", "no-cache")

	return req, nil
}

// BuildCoverTrafficRequest creates a request that looks like app telemetry (no VPN payload).
// C3 audit fix: uses random base64 data so DPI can't distinguish cover from real data.
// The server detects cover via encrypted FlagPadding chunk, NOT by checking for empty data.
func BuildCoverTrafficRequest(baseURL string, sessionToken []byte, urlPool *URLPool, userAgent string, encryptedPadding []byte) (*http.Request, error) {
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	// C3 fix: cover traffic carries encrypted padding, indistinguishable from real data
	payload := base64.RawURLEncoding.EncodeToString(encryptedPadding)

	env := uploadEnvelope{
		Events: []uploadEvent{
			{
				Type: randomEventType(), // same event types as data
				TS:   time.Now().UnixMilli(),
				Data: payload, // encrypted padding — same format as real chunks
			},
		},
	}

	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}

	path := urlPool.NextUploadPath()
	req, err := http.NewRequest("POST", baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	// W4 fix: cover traffic must have same headers as data traffic
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(sessionToken))
	req.Header.Set("X-Request-ID", fmt.Sprintf("%08x", rand.Uint32()))
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Cache-Control", "no-cache")

	return req, nil
}

// ParseUploadRequest extracts the encrypted chunk from an incoming upload request body.
func ParseUploadRequest(body []byte) ([]byte, error) {
	var env uploadEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if len(env.Events) == 0 {
		return nil, errors.New("no events in request")
	}
	if env.Events[0].Data == "" {
		return nil, errors.New("empty payload")
	}
	return base64.RawURLEncoding.DecodeString(env.Events[0].Data)
}

// BuildDownloadResponse creates an HTTP response body wrapping an encrypted chunk in JSON.
// M5 fix: ID field uses random value, not monotonic seq_num (prevents correlation).
func BuildDownloadResponse(encryptedChunk []byte, seqNum uint32) ([]byte, error) {
	payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)

	env := downloadEnvelope{
		Status: "ok",
		Results: []downloadResult{
			{
				ID:      fmt.Sprintf("%08x", rand.Uint32()), // random, not seq_num
				Payload: payload,
			},
		},
	}

	return json.Marshal(env)
}

// BuildDownloadResponseMulti creates an HTTP response with multiple encrypted chunks.
// Batches multiple chunks per response to reduce round-trips through CDN.
func BuildDownloadResponseMulti(encryptedChunks [][]byte) ([]byte, error) {
	results := make([]downloadResult, 0, len(encryptedChunks))
	for _, chunk := range encryptedChunks {
		results = append(results, downloadResult{
			ID:      fmt.Sprintf("%08x", rand.Uint32()),
			Payload: base64.RawURLEncoding.EncodeToString(chunk),
		})
	}
	env := downloadEnvelope{
		Status:  "ok",
		Results: results,
	}
	return json.Marshal(env)
}

// BuildInflatedDownloadResponse creates an HTTP response body with realistic extra fields
// that make the JSON look like a real SaaS analytics API response.
// This is the MimicryEngine integration for download responses — adds config_version,
// experiment_id, variant, and next_poll fields to defeat JSON structure fingerprinting.
// Existing BuildDownloadResponse is kept unchanged for backward compatibility.
func BuildInflatedDownloadResponse(encryptedChunk []byte, seqNum uint32) ([]byte, error) {
	payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)

	// Generate realistic config_version: "2026.MM.DD.N"
	now := time.Now()
	configVersion := fmt.Sprintf("%d.%02d.%02d.%d", now.Year(), now.Month(), now.Day(), rand.IntN(10)+1)

	// Generate experiment ID: "exp_" + random hex
	experimentID := fmt.Sprintf("exp_%08x", rand.Uint32())

	// Random variant
	variants := []string{"control", "treatment_a", "treatment_b"}
	variant := variants[rand.IntN(len(variants))]

	// Random next_poll interval (30-89 seconds)
	nextPoll := 30 + rand.IntN(60)

	env := downloadEnvelope{
		Status: "ok",
		Results: []downloadResult{
			{
				ID:      fmt.Sprintf("%08x", rand.Uint32()),
				Payload: payload,
			},
		},
		ConfigVersion: configVersion,
		ExperimentID:  experimentID,
		Variant:       variant,
		NextPoll:      nextPoll,
	}

	return json.Marshal(env)
}

// ParseDownloadResponse extracts the first encrypted chunk from a download response body.
// For multi-chunk responses, use ParseDownloadResponseMulti.
func ParseDownloadResponse(body []byte) ([]byte, uint32, error) {
	var env downloadEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, 0, err
	}
	if env.Status != "ok" {
		return nil, 0, fmt.Errorf("server returned status: %s", env.Status)
	}
	if len(env.Results) == 0 {
		return nil, 0, errors.New("no results in response")
	}

	r := env.Results[0]
	data, err := base64.RawURLEncoding.DecodeString(r.Payload)
	if err != nil {
		return nil, 0, err
	}

	seqNum, _ := strconv.ParseUint(r.ID, 16, 32)
	return data, uint32(seqNum), nil
}

// ParseDownloadResponseMulti extracts ALL encrypted chunks from a download response.
// Returns a slice of encrypted chunks. Servers may batch multiple chunks per response
// to reduce round-trips through CDN.
func ParseDownloadResponseMulti(body []byte) ([][]byte, error) {
	var env downloadEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	if env.Status != "ok" {
		return nil, fmt.Errorf("server returned status: %s", env.Status)
	}
	if len(env.Results) == 0 {
		return nil, errors.New("no results in response")
	}

	chunks := make([][]byte, 0, len(env.Results))
	for _, r := range env.Results {
		if r.Payload == "" {
			continue
		}
		data, err := base64.RawURLEncoding.DecodeString(r.Payload)
		if err != nil {
			continue
		}
		chunks = append(chunks, data)
	}
	if len(chunks) == 0 {
		return nil, errors.New("no results in response")
	}
	return chunks, nil
}

// ExtractSessionToken extracts session token from Authorization header.
func ExtractSessionToken(r *http.Request) ([]byte, error) {
	auth := r.Header.Get("Authorization")
	if len(auth) < 8 || auth[:7] != "Bearer " {
		return nil, errors.New("missing or invalid Authorization header")
	}
	return base64.RawURLEncoding.DecodeString(auth[7:])
}

// ExtractSeqNum extracts seq_num from X-Request-ID header.
func ExtractSeqNum(r *http.Request) (uint32, error) {
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		return 0, errors.New("missing X-Request-ID header")
	}
	val, err := strconv.ParseUint(id, 16, 32)
	return uint32(val), err
}

// IsCoverTraffic is no longer used — cover traffic is now indistinguishable from
// real data at the JSON level (C3 audit fix). The server detects cover via the
// encrypted FlagPadding chunk flag after decryption.
// Kept for backward compatibility; returns false always.
func IsCoverTraffic(_ []byte) bool {
	return false
}

// EncodeTokenWithHint prepends a 4-byte XOR-obfuscated session_id hint to the token.
// This enables O(1) session lookup on the server instead of O(N) trial decryption.
// Hint = sessionID XOR first4bytes(token). Not security-critical — session_id is inside encrypted chunk.
func EncodeTokenWithHint(sessionID uint32, token []byte) []byte {
	if len(token) < 4 {
		return token
	}
	hint := make([]byte, 4)
	var xorMask [4]byte
	copy(xorMask[:], token[:4])
	xored := sessionID ^ (uint32(xorMask[0])<<24 | uint32(xorMask[1])<<16 | uint32(xorMask[2])<<8 | uint32(xorMask[3]))
	hint[0] = byte(xored >> 24)
	hint[1] = byte(xored >> 16)
	hint[2] = byte(xored >> 8)
	hint[3] = byte(xored)
	return append(hint, token...)
}

// ReadBodyLimited reads request body with a size limit.
func ReadBodyLimited(r io.Reader, maxBytes int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxBytes))
}

func randomEventType() string {
	types := []string{"page_view", "click", "scroll", "session_ping", "form_submit", "nav"}
	return types[rand.IntN(len(types))]
}

// RandomEventType returns a random analytics event type (exported for transport layer).
func RandomEventType() string { return randomEventType() }

// RandomUint32 returns a random uint32 (for X-Request-ID).
func RandomUint32() uint32 { return rand.Uint32() }

