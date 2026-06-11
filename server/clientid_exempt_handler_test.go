package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/skins/browser"
	"github.com/stretchr/testify/require"
)

// Plan §C4 (May audit, 2026-05-02): handler-level integration of
// ClientIDExemption. Tests below pin the dance: post-success MarkSeen,
// data-path bypass when exempt, soft-limit reject after burst, env-flag
// disable. Lives next to ratelimit_test.go's TokenBucket cousins.

// completeHandshakeWithClientID drives one body-prefix handshake against
// handler h using the supplied serverKey + explicit clientID (16 bytes), and
// returns the resulting client-side session + the encoded session token
// (with hint). Distinct from completeHandshakeForTest in handler_test.go
// (which generates a random UUID) — the §C4 tests need to assert on a
// specific clientID for exemption lookups.
func completeHandshakeWithClientID(t *testing.T, h *Handler, serverKey *core.KeyPair, clientID string, remoteAddr string) (*core.Session, []byte) {
	t.Helper()
	clientHello, clientState, err := core.NewClientHello([]byte(clientID), serverKey.Public)
	require.NoError(t, err)

	helloPayload := append(clientHello.EphemeralPub, clientHello.EncryptedClientID...)
	encoded := base64.RawURLEncoding.EncodeToString(helloPayload)
	helloBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "init", "ts": 1234, "data": encoded}},
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(helloBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = remoteAddr
	h.ServeHTTP(rec, req)
	require.Equal(t, 200, rec.Code, "handshake should succeed for clientID=%q", clientID)

	respData, _, err := browser.ParseDownloadResponse(rec.Body.Bytes())
	require.NoError(t, err)

	var shData struct {
		EphPub       []byte `json:"eph"`
		Token        []byte `json:"tok"`
		MaxConns     uint8  `json:"mc"`
		ChunkSize    uint16 `json:"cs"`
		ProtoVersion *uint8 `json:"_v"`
	}
	require.NoError(t, json.Unmarshal(respData, &shData))

	serverHello := &core.ServerHello{
		EphemeralPub:          shData.EphPub,
		EncryptedSessionToken: shData.Token,
		ProtoVersion:          shData.ProtoVersion,
		MaxConnsPerClient:     shData.MaxConns,
		ChunkSize:             shData.ChunkSize,
	}
	clientSession, err := core.CompleteHandshake(clientState, serverHello)
	require.NoError(t, err)

	tokenWithHint := browser.EncodeTokenWithHint(clientSession.ID, shData.Token)
	return clientSession, tokenWithHint
}

// dataPostForTest sends one encrypted data chunk against handler h and
// returns the recorder. Helper used by exemption tests to drive the data
// path after a completed handshake.
func dataPostForTest(t *testing.T, h *Handler, sess *core.Session, tokenWithHint []byte, payload []byte, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	dataChunk := core.NewDataChunk(sess.ID, sess.NextSeqNum(), payload)
	encChunk, err := dataChunk.Encrypt(sess.SendKey)
	require.NoError(t, err)

	body := browser.BuildDataPayload(tokenWithHint, encChunk)
	encoded := base64.RawURLEncoding.EncodeToString(body)
	wireBody, _ := json.Marshal(map[string]any{
		"events": []map[string]any{{"type": "data", "ts": 1234, "data": encoded}},
	})
	req := httptest.NewRequest("POST", "/api/v2/events", bytes.NewReader(wireBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", fmt.Sprintf("%08x", dataChunk.SeqNum))
	req.RemoteAddr = remoteAddr
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestHandshake_ExemptionFlow drives the full §C4 fast path:
//  1. fresh clientID handshake succeeds (MarkSeen fires)
//  2. data-path bucket is drained from a different IP
//  3. data-path POST from the SAME clientID bypasses bucket via exemption
//  4. 60+ data-path POSTs trip the soft-cap (default 60/min) → Exempt=1
//     sentinel
func TestHandshake_ExemptionFlow(t *testing.T) {
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "1")
	t.Setenv("SHADOWLINK_RL_CLIENTID_EXEMPT", "1")

	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)
	cfg := TestConfig()
	h := NewHandler(serverKey, cfg, "")
	disableBackpressureForTest(h)
	require.NotNil(t, h.exemption, "exemption must be wired when env flag is on")

	// Handshake — happy path. Different IP than the data-path so we keep the
	// per-IP buckets independent. MarkSeen fires after auth + device-limit.
	clientSession, tokenWithHint := completeHandshakeWithClientID(t, h, serverKey, "exempt-cid-aaaab", "203.0.113.50:1")
	require.True(t, h.exemption.IsExempt([]byte("exempt-cid-aaaab")),
		"after successful handshake, clientID must be in exemption LRU")

	// Drain the data bucket on the data-path IP. Replace with a tiny bucket
	// so we don't have to consume 100 tokens; this proves the bypass
	// actually skips the bucket consume.
	h.rateLimiters.DataBucket = NewTokenBucket(1, 0.0001, 10)
	exhaustIP := "203.0.113.51"
	allow1, _, _ := h.rateLimiters.AllowData(exhaustIP)
	require.True(t, allow1, "first AllowData on fresh IP must pass")
	allow2, _, _ := h.rateLimiters.AllowData(exhaustIP)
	require.False(t, allow2, "second AllowData on same IP must fail (bucket=1)")

	// Exemption bypass: data-path POST from authenticated clientID must
	// succeed even though the bucket is exhausted on this IP. We assert
	// this via the metrics counter — the wire response is decoy-shaped
	// indistinguishable from a regular successful POST so a header check
	// would not be conclusive.
	beforeExempt := h.metrics.RatelimitClientIDExempted.Load()
	rec := dataPostForTest(t, h, clientSession, tokenWithHint, []byte("ping"), exhaustIP+":42")
	afterExempt := h.metrics.RatelimitClientIDExempted.Load()
	require.Equal(t, 200, rec.Code,
		"exempted data-path POST must return 200 even with empty bucket")
	require.Equal(t, beforeExempt+1, afterExempt,
		"exempted POST must tick RatelimitClientIDExempted")
	// And no rate-limit sentinel was emitted on the bypass — the response
	// looks like a successful chunk, not a rate-limit decoy.
	require.Empty(t, rec.Header().Get("X-SL-RL"),
		"exempted POST must NOT emit X-SL-RL sentinel; it bypassed the bucket")

	// Sustained flood: data path intentionally skips the AllowExempted
	// soft-cap (X1 Stage 2 follow-up, 2026-05-03). Soft-cap=60/min was
	// sized for handshake spam protection; applying it per-chunk capped
	// VPN throughput at ~12 KB/s. After the fix, all 70 follow-up POSTs
	// tick RatelimitClientIDExempted and zero of them tick the soft-cap
	// reject counter — proving the data plane is unrestricted for an
	// authenticated clientID.
	beforeSoft := h.metrics.RatelimitClientIDSoftLimitRejected.Load()
	beforeExempt = h.metrics.RatelimitClientIDExempted.Load()
	for i := 0; i < 70; i++ {
		dataPostForTest(t, h, clientSession, tokenWithHint, []byte("flood"), exhaustIP+":42")
	}
	afterSoft := h.metrics.RatelimitClientIDSoftLimitRejected.Load()
	afterExempt = h.metrics.RatelimitClientIDExempted.Load()
	require.Equal(t, beforeSoft, afterSoft,
		"data path no longer enforces soft-cap; rejected counter must NOT tick")
	require.Equal(t, beforeExempt+70, afterExempt,
		"every one of 70 data POSTs must tick exempt (data plane unrestricted)")
}

// TestHandshake_ExemptionDisabledByEnv pins the env-flag disable: setting
// SHADOWLINK_RL_CLIENTID_EXEMPT=0 must produce a Handler with exemption=nil
// so the existing rate-limit flow stays intact bit-for-bit.
func TestHandshake_ExemptionDisabledByEnv(t *testing.T) {
	t.Setenv("SHADOWLINK_RL_CLIENTID_EXEMPT", "0")
	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)
	cfg := TestConfig()
	h := NewHandler(serverKey, cfg, "")
	require.Nil(t, h.exemption, "exemption must be nil when env flag is off")
}

// TestNewRateLimitersWithConfig_Defaults verifies that calling the new
// constructor with zero specs produces the same protocol-policy defaults the
// legacy NewRateLimiters(0, true) call site would hand out. Plan §C6 zero-
// fallback contract.
func TestNewRateLimitersWithConfig_Defaults(t *testing.T) {
	r := NewRateLimitersWithConfig(RateLimitBucketSpec{}, RateLimitBucketSpec{}, true)
	require.True(t, r.UseBucket)
	require.NotNil(t, r.HandshakeBucket)
	require.NotNil(t, r.DataBucket)
	require.NotNil(t, r.WSUpgradeBucket)

	// Compare with the legacy 2-arg constructor: same Burst values, same
	// refill rates. 50/300, 100/600, 18/30 by spec.
	legacy := NewRateLimiters(0, true)
	require.NotNil(t, legacy.HandshakeBucket)

	// Drain HandshakeBucket of both: each must accept exactly 50 tokens
	// before refusing on a fresh IP. Use distinct IPs so neither sees
	// state from the other.
	for i := 0; i < 50; i++ {
		ok, _, _ := r.HandshakeBucket.Allow("198.51.100.1")
		require.True(t, ok, "new constructor must accept 50 burst tokens (i=%d)", i)
	}
	rejected, _, _ := r.HandshakeBucket.Allow("198.51.100.1")
	require.False(t, rejected, "new constructor must reject the 51st request")

	for i := 0; i < 50; i++ {
		ok, _, _ := legacy.HandshakeBucket.Allow("198.51.100.2")
		require.True(t, ok, "legacy constructor must accept 50 burst tokens (i=%d)", i)
	}
	rejected, _, _ = legacy.HandshakeBucket.Allow("198.51.100.2")
	require.False(t, rejected, "legacy constructor must reject the 51st request")

	// WSUpgrade burst = 18 in both.
	for i := 0; i < 18; i++ {
		ok, _, _ := r.WSUpgradeBucket.Allow("198.51.100.3")
		require.True(t, ok, "ws_upgrade burst must hold 18 tokens (i=%d)", i)
	}
	rejected, _, _ = r.WSUpgradeBucket.Allow("198.51.100.3")
	require.False(t, rejected, "ws_upgrade must reject the 19th request")
}

// TestNewRateLimitersWithConfig_RespectsExplicitSpec proves that a non-zero
// spec actually flows through to the bucket. Burst=2 means 2 tokens then
// reject — the "accept everything" anti-pattern would mask this.
func TestNewRateLimitersWithConfig_RespectsExplicitSpec(t *testing.T) {
	r := NewRateLimitersWithConfig(
		RateLimitBucketSpec{Burst: 2, RefillPerMin: 60},
		RateLimitBucketSpec{Burst: 5, RefillPerMin: 60},
		true,
	)
	for i := 0; i < 2; i++ {
		ok, _, _ := r.HandshakeBucket.Allow("198.51.100.4")
		require.True(t, ok, "handshake burst=2 must accept first 2 (i=%d)", i)
	}
	rejected, _, _ := r.HandshakeBucket.Allow("198.51.100.4")
	require.False(t, rejected, "handshake burst=2 must reject the 3rd")

	for i := 0; i < 5; i++ {
		ok, _, _ := r.WSUpgradeBucket.Allow("198.51.100.5")
		require.True(t, ok, "ws_upgrade burst=5 must accept first 5 (i=%d)", i)
	}
	rejected, _, _ = r.WSUpgradeBucket.Allow("198.51.100.5")
	require.False(t, rejected, "ws_upgrade burst=5 must reject the 6th")
}

// TestConfig_RateLimitYAMLLoad — load a minimal YAML fixture into FileConfig
// and verify ApplyTo populates Config.RateLimit exactly as written. Pinning
// the YAML mapping prevents a future struct rename from silently dropping
// the operator override.
func TestConfig_RateLimitYAMLLoad(t *testing.T) {
	yaml := `
rate_limit:
  handshake:
    burst: 7
    refill_per_min: 42
  ws_upgrade:
    burst: 11
    refill_per_min: 13
  client_id_lru_size: 99
  client_id_ttl_min: 17
  client_id_soft_limit: 5
  client_id_soft_window_sec: 21
`
	tmp := filepath.Join(t.TempDir(), "cfg.yaml")
	require.NoError(t, os.WriteFile(tmp, []byte(yaml), 0o600))
	fc, err := LoadConfigFile(tmp)
	require.NoError(t, err)

	cfg := TestConfig()
	fc.ApplyTo(&cfg)

	require.Equal(t, 7, cfg.RateLimit.Handshake.Burst)
	require.Equal(t, 42, cfg.RateLimit.Handshake.RefillPerMin)
	require.Equal(t, 11, cfg.RateLimit.WSUpgrade.Burst)
	require.Equal(t, 13, cfg.RateLimit.WSUpgrade.RefillPerMin)
	require.Equal(t, 99, cfg.RateLimit.ClientIDLruSize)
	require.Equal(t, 17, cfg.RateLimit.ClientIDTTLMin)
	require.Equal(t, 5, cfg.RateLimit.ClientIDSoftLimit)
	require.Equal(t, 21, cfg.RateLimit.ClientIDSoftWindowSec)
}

// TestNewHandler_RespectsConfigRateLimit handler with config that has
// RateLimit.Handshake.Burst=2 actually rate-limits at 2/burst — the
// 3rd HTTP request hits the rate-limit decoy with bucket=handshake.
func TestNewHandler_RespectsConfigRateLimit(t *testing.T) {
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "1")
	t.Setenv("SHADOWLINK_RL_CLIENTID_EXEMPT", "0") // keep exemption out of this test

	serverKey, err := core.GenerateKeyPair()
	require.NoError(t, err)
	cfg := TestConfig()
	cfg.RateLimit.Handshake.Burst = 2
	// Use a slow refill so we don't accidentally regen tokens during the
	// 3-request burst (refill = 1/min ≈ 17ms/token even at fast clock).
	cfg.RateLimit.Handshake.RefillPerMin = 1
	h := NewHandler(serverKey, cfg, "")

	ip := "203.0.113.99"
	// First 2 requests must succeed (no sentinel). Throwaway garbage —
	// the rate-limit gate fires before DecryptClientID.
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
		req.RemoteAddr = ip + ":1"
		h.handleHandshakeNew(rec, req, []byte("eph"), []byte("enc"))
		require.Empty(t, rec.Header().Get("X-SL-RL"),
			"request %d under burst=2 must NOT trigger sentinel", i+1)
	}
	// 3rd request hits empty bucket → sentinel.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/a", bytes.NewReader([]byte("{}")))
	req.RemoteAddr = ip + ":1"
	h.handleHandshakeNew(rec, req, []byte("eph"), []byte("enc"))
	got := rec.Header().Get("X-SL-RL")
	require.Contains(t, got, "bucket=handshake",
		"3rd request must trip the configured burst=2 cap; got X-SL-RL=%q", got)
}
