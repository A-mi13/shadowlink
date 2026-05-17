package browser

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// handshakePadRNG is a process-wide log-normal RNG used to size handshake
// padding. Seeded once from crypto/rand so concurrent BuildHandshakePayload
// calls within the same time-tick (Windows ~15ms resolution) still produce
// independent draws.
var (
	handshakePadRNGMu   sync.Mutex
	handshakePadRNG     *mathrand.Rand
	handshakePadRNGOnce sync.Once
)

func handshakePadDraw() int {
	handshakePadRNGOnce.Do(func() {
		var seed [8]byte
		if _, err := crand.Read(seed[:]); err != nil {
			// Fallback to nano time if crypto/rand fails (extremely unlikely).
			handshakePadRNG = mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
			return
		}
		handshakePadRNG = mathrand.New(mathrand.NewSource(int64(binary.LittleEndian.Uint64(seed[:]))))
	})
	handshakePadRNGMu.Lock()
	defer handshakePadRNGMu.Unlock()
	return SampleHandshakePaddingTarget(handshakePadRNG)
}

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
//
// Aligned with the locked Chrome major (133) so the four wire surfaces
// (uTLS JA4 / bogdanfinn H2 SETTINGS / UA / sec-ch-ua) emit a consistent
// Chrome version triple. Previously this fell back to UserAgents[0]
// (Chrome/131), introducing a fourth Chrome major into wire traffic on
// any code path that didn't pass an explicit fingerprint UA — see the
// 2026-05-02 wire-trigger audit NEW-3 finding.
var defaultUserAgent = LockedChromeUA()

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
//
// Historical note (2026-04 DPI audit, vector V3): earlier versions carried
// config_version / experiment_id / variant fields in every response. Those
// fields were JSON-fingerprintable — real GA4/Mixpanel APIs do not attach
// A/B experiment metadata to every analytics ack. TSPU-class DPI can detect
// the pattern with a single JSON parser. Removed. Only next_poll remains
// (legitimate in most analytics APIs and harmless as a single optional field).
type downloadEnvelope struct {
	Status   string           `json:"status"`
	Results  []downloadResult `json:"results"`
	NextPoll int              `json:"next_poll,omitempty"`
}

type downloadResult struct {
	ID      string `json:"id"`
	Payload string `json:"payload"`
}

// BuildUploadRequest creates an HTTP request wrapping an encrypted chunk in JSON.
// userAgent should be picked once per session via PickUserAgent() (L3 audit fix).
//
// Body-prefix wire format (2026-04 migration, D1): session token is packed at the
// start of the base64-encoded payload via BuildDataPayload instead of being sent
// as `Authorization: Bearer`. Closes DPI vector V1 (Authorization-on-every-frame).
func BuildUploadRequest(baseURL string, encryptedChunk []byte, sessionToken []byte, seqNum uint32, urlPool *URLPool, userAgent ...string) (*http.Request, error) {
	ua := defaultUserAgent
	if len(userAgent) > 0 && userAgent[0] != "" {
		ua = userAgent[0]
	}
	// [token][encrypted_chunk] packed into the data field
	combined := BuildDataPayload(sessionToken, encryptedChunk)
	payload := base64.RawURLEncoding.EncodeToString(combined)

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
	// D1: Authorization header removed — token now travels inside the JSON body.
	// C2 audit fix: use random request ID, not monotonic seq_num.
	// Seq_num is already inside the encrypted chunk — no need to expose in cleartext headers.
	req.Header.Set("X-Request-ID", fmt.Sprintf("%08x", rand.Uint32()))
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br") // I3: browsers always send this
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", baseURL)      // I5: SPA API calls include Origin
	req.Header.Set("Referer", baseURL+"/") // I5: and Referer
	req.Header.Set("Cache-Control", "no-cache")
	// 2026-05-02 wire-trigger followup NEW-2: Chrome 90+ unconditionally
	// emits sec-ch-ua / sec-ch-ua-mobile / sec-ch-ua-platform on every
	// HTTPS request. Their absence on a connection that simultaneously
	// presents a Chrome JA4 fingerprint is a browser-class contradiction.
	ApplyChromeCHUAForUA(req.Header, ua)

	return req, nil
}

// BuildCoverTrafficRequest creates a request that looks like app telemetry (no VPN payload).
// C3 audit fix: uses random base64 data so DPI can't distinguish cover from real data.
// The server detects cover via encrypted FlagPadding chunk, NOT by checking for empty data.
//
// Body-prefix wire format (2026-04 migration, D1): session token is packed at the
// start of the payload via BuildDataPayload — headers must match data requests
// exactly, so Authorization is absent here too (W4 invariant preserved).
func BuildCoverTrafficRequest(baseURL string, sessionToken []byte, urlPool *URLPool, userAgent string, encryptedPadding []byte) (*http.Request, error) {
	if userAgent == "" {
		userAgent = defaultUserAgent
	}

	// C3 fix: cover traffic carries encrypted padding, indistinguishable from real data.
	// D1: pack [token][encrypted_padding] via BuildDataPayload so cover and data share
	// the same body shape; server routes via encrypted FlagPadding after decryption.
	combined := BuildDataPayload(sessionToken, encryptedPadding)
	payload := base64.RawURLEncoding.EncodeToString(combined)

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

	// W4 fix: cover traffic must have same headers as data traffic.
	// D1: Authorization removed from both — header-set stays in lockstep.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", fmt.Sprintf("%08x", rand.Uint32()))
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", baseURL+"/")
	req.Header.Set("Cache-Control", "no-cache")
	// 2026-05-02 wire-trigger followup NEW-2 — same sec-ch-ua header set
	// data traffic emits, keeping cover and data headers indistinguishable.
	ApplyChromeCHUAForUA(req.Header, userAgent)

	return req, nil
}

// MaxUploadDataField is the upper bound on the base64-encoded `data` field in an
// upload envelope. Server `chunk-size` defaults to 12288 bytes — base64 encodes that
// to ~16400 bytes, plus the body-prefix token (40 bytes → ~54 base64 bytes). Capping
// at 65536 (≈4× chunk-size) leaves ample headroom for protocol evolution while
// rejecting pathological allocations a fuzz/attacker can request.
//
// A1-M7 fix: enforced inside ParseUploadRequest before base64 decode so an attacker
// cannot OOM the decoder by submitting a multi-MB base64 string.
const MaxUploadDataField = 65536

// ParseUploadRequest extracts the encrypted chunk from an incoming upload request body.
//
// A1-M7 fix: rejects oversize base64 payloads pre-decode. This complements the
// transport-layer io.LimitReader (ReadBodyLimited) by guarding against well-formed
// JSON whose `data` field is itself enormous — the JSON parser would happily allocate
// the full string before this function ever saw it. Limit applies to base64 input,
// before decode (decoded size = ~3/4 of input).
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
	if len(env.Events[0].Data) > MaxUploadDataField {
		return nil, fmt.Errorf("upload data field exceeds limit: %d > %d bytes", len(env.Events[0].Data), MaxUploadDataField)
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

// BuildInflatedDownloadResponse returns a download response with a single optional
// next_poll field to vary response size and shape slightly vs the bare response.
//
// 2026-04 DPI audit (vector V3): previous implementation attached
// config_version / experiment_id / variant to every response. That pattern is
// JSON-fingerprintable — real analytics APIs don't ship A/B metadata on every
// ack. All three fields removed. Only next_poll remains; it's a single,
// commonly-seen optional field that does not in itself form a pattern.
//
// Phase 3 Plan A § 4.4 (T2.4): next_poll is now a sticky per-session sample
// from Pareto(α=1.5) truncated [5, 600] with ±15% jitter — real analytics
// SDKs sample polling cadence once at session start and hold it. The legacy
// uniform 30..89s fallback is preserved for nil-session callers (tests,
// transitional code paths that don't carry session state).
//
// Server gate: Config.UseInflatedResponses (default false).
func BuildInflatedDownloadResponse(encryptedChunk []byte, seqNum uint32, sess *core.MimicrySession) ([]byte, error) {
	payload := base64.RawURLEncoding.EncodeToString(encryptedChunk)

	// next_poll: sticky per-session sample (Pareto α=1.5 truncated [5, 600]) +
	// ±15% jitter. Real analytics SDKs sample polling cadence once at session
	// start and hold it. T2.4 closure (Phase 3 Plan A).
	//
	// nil session → fallback to legacy uniform 30..89s for code paths that
	// don't carry session state.
	var nextPoll int
	if rand.IntN(2) == 0 { // emit ~50% of the time, matches existing cadence
		if sess != nil {
			nextPoll = NextPollSeconds(sess)
		} else {
			nextPoll = 30 + rand.IntN(60)
		}
	}

	env := downloadEnvelope{
		Status: "ok",
		Results: []downloadResult{
			{
				ID:      fmt.Sprintf("%08x", rand.Uint32()),
				Payload: payload,
			},
		},
		NextPoll: nextPoll,
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

// ExtractSeqNum extracts seq_num from X-Request-ID header.
func ExtractSeqNum(r *http.Request) (uint32, error) {
	id := r.Header.Get("X-Request-ID")
	if id == "" {
		return 0, errors.New("missing X-Request-ID header")
	}
	val, err := strconv.ParseUint(id, 16, 32)
	return uint32(val), err
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

// eventTypePool — расширенный enum реалистичных Mixpanel/SPA-аналитических
// событий. Финал-аудит 2026-05-03 P2-6: предыдущий enum из 6 entries
// (`page_view`, `click`, `scroll`, `session_ping`, `form_submit`, `nav`)
// давал ML-детектору body-content однозначный сигнал — реальные SPA emit
// десятки видов событий с долгим хвостом. Новый pool 17 entries покрывает
// доминантные паттерны: pageview-семейство (`$pageview` mirror у Mixpanel SDK),
// session lifecycle, click-семейство, медиа/форма/поиск/конверсия.
//
// Weighted distribution (target spread):
//   - page_view family    ≈ 30% (page_view 15% + $pageview 15%)
//   - session_*           ≈ 20% (start 7% + end 6% + ping 7%)
//   - click_*             ≈ 25% (button_click 12% + link_click 13%)
//   - long-tail остаток   ≈ 25% (12 событий, ~2% каждое)
//
// Pool заранее раскатан в 100-element slice — `rand.IntN(100)` →
// O(1) lookup без повторной канализации weights в hot path. Сумма
// весов = 100 (см. TestRandomEventType_PoolWellFormed).
var eventTypePool = func() []string {
	type weighted struct {
		name   string
		weight int
	}
	weights := []weighted{
		{"page_view", 15},
		{"$pageview", 15},
		{"session_start", 7},
		{"session_end", 6},
		{"session_ping", 7},
		{"button_click", 12},
		{"link_click", 13},
		{"scroll", 3},
		{"form_submit", 2},
		{"form_focus", 2},
		{"video_play", 2},
		{"video_pause", 2},
		{"video_complete", 2},
		{"search", 3},
		{"download", 2},
		{"share", 2},
		{"signup_start", 1},
		{"signup_complete", 1},
		{"purchase", 3},
	}
	pool := make([]string, 0, 100)
	for _, w := range weights {
		for i := 0; i < w.weight; i++ {
			pool = append(pool, w.name)
		}
	}
	return pool
}()

func randomEventType() string {
	return eventTypePool[rand.IntN(len(eventTypePool))]
}

// RandomEventType returns a random analytics event type (exported for transport layer).
func RandomEventType() string { return randomEventType() }

// RandomUint32 returns a random uint32 (for X-Request-ID).
func RandomUint32() uint32 { return rand.Uint32() }

// BuildDataPayload packs session token + encrypted chunk into the body-prefix wire format.
// Format: [token bytes][encrypted_chunk bytes]. The token already contains the 4-byte
// XOR hint prefix (see EncodeTokenWithHint). Server disambiguates token and chunk by the
// fixed sessionTokenSize protocol constant.
func BuildDataPayload(tokenWithHint, encryptedChunk []byte) []byte {
	out := make([]byte, 0, len(tokenWithHint)+len(encryptedChunk))
	out = append(out, tokenWithHint...)
	out = append(out, encryptedChunk...)
	return out
}

// ParseDataPayload splits body-prefix on the fixed session-token boundary.
// sessionTokenSize is a protocol constant. Returns (token, chunk, err).
// Errors if payload is too short to contain token + at least 1 chunk byte.
func ParseDataPayload(payload []byte, sessionTokenSize int) (token, chunk []byte, err error) {
	if len(payload) < sessionTokenSize+1 {
		return nil, nil, errors.New("data payload: too short for token + chunk")
	}
	return payload[:sessionTokenSize], payload[sessionTokenSize:], nil
}

// BuildHandshakePayload packs ClientHello bytes with random padding sampled from
// SampleHandshakePaddingTarget (handshake-specific distribution, smaller mean
// than data-payload padding). A2-HIGH-5 closure: KS-test confirms distribution
// divergence vs SamplePaddingTarget used in SendChunk.
//
// Format: [ephPub(32)][encClientID(core.EncryptedClientIDSize)][random_pad].
//
// Note: the pd *PayloadDistribution parameter is retained for ABI stability
// (existing callers in client/ pass it). It is no longer consulted; padding
// target is now sampled from SampleHandshakePaddingTarget. A follow-up cleanup
// task may drop the parameter once all callers are audited.
func BuildHandshakePayload(ephPub, encClientID []byte, pd *PayloadDistribution) []byte {
	_ = pd // unused; kept for ABI stability — see doc-comment above

	base := make([]byte, 0, 32+len(encClientID)+512)
	base = append(base, ephPub...)
	base = append(base, encClientID...)

	target := handshakePadDraw()
	if target <= len(base) {
		return base
	}
	pad := make([]byte, target-len(base))
	_, _ = crand.Read(pad) // padding BYTES still cryptographic-quality
	return append(base, pad...)
}

// ParseHandshakePayload extracts ClientHello bytes, ignoring trailing random padding.
// Uses fixed core.EncryptedClientIDSize — bumping the protocol version (ServerHello._v)
// is required to change this boundary.
func ParseHandshakePayload(payload []byte) (ephPub, encClientID []byte, err error) {
	if len(payload) < 32 {
		return nil, nil, errors.New("handshake payload: too short for ephPub")
	}
	need := 32 + core.EncryptedClientIDSize
	if len(payload) < need {
		return nil, nil, errors.New("handshake payload: too short for encClientID")
	}
	return payload[:32], payload[32:need], nil
}
