package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// dataPathBodyPrefixEnabled is true when the client routes SendChunk /
// SendChunkRawBody through the body-prefix wire format instead of the legacy
// Authorization: Bearer header. Gated via SHADOWLINK_DATAPATH_BODYPREFIX env
// var. Default ON since 2026-04-26 (Phase 0 T1.4 flip after canary soak).
// Set SHADOWLINK_DATAPATH_BODYPREFIX=0 (or "false"/"no"/"off") for emergency
// disable — restores legacy Authorization-header data path.
//
// Package-init read (not per-request) so tests can override by setting the
// env var before importing, or via the `withDataPathBodyPrefix` helper.
var dataPathBodyPrefixEnabled = parseDataPathBodyPrefixEnv(os.Getenv("SHADOWLINK_DATAPATH_BODYPREFIX"))

func parseDataPathBodyPrefixEnv(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// withDataPathBodyPrefix temporarily overrides the flag for the duration of a
// test. Use via t.Cleanup for restore. Not safe for concurrent tests that
// observe the flag value from different goroutines.
func withDataPathBodyPrefix(enabled bool) func() {
	prev := dataPathBodyPrefixEnabled
	dataPathBodyPrefixEnabled = enabled
	return func() { dataPathBodyPrefixEnabled = prev }
}

// buildDataEnvelope wraps an encrypted chunk in the analytics JSON envelope
// for the body-prefix data-path. Shared producer of the data-path envelope
// for cover traffic and `SendChunk`/`SendChunkRawBody` — ensures W4
// byte-identity across all three call sites.
//
//	{"events":[{"type":<random>,"ts":<ms>,"data":"<base64url(tokenWithHint||enc)>"}]}
//
// token is the session token (first 4 bytes hint, next 32 bytes encrypted);
// enc is the AES-GCM ciphertext of a core.Chunk.
func buildDataEnvelope(token, enc []byte) ([]byte, error) {
	combined := browser.BuildDataPayload(token, enc)
	payload := base64.RawURLEncoding.EncodeToString(combined)

	type evt struct {
		Type string `json:"type"`
		TS   int64  `json:"ts"`
		Data string `json:"data"`
	}
	type envelope struct {
		Events []evt `json:"events"`
	}
	body, err := json.Marshal(envelope{Events: []evt{{
		Type: browser.RandomEventType(),
		TS:   time.Now().UnixMilli(),
		Data: payload,
	}}})
	if err != nil {
		return nil, fmt.Errorf("marshal data envelope: %w", err)
	}
	return body, nil
}

// buildDataPostHeaders returns the http.Header for a body-prefix data POST.
// Shared header set for cover traffic and `SendChunk`/`SendChunkRawBody`
// body-prefix path — W4 requires byte-identity across all three.
// CRITICAL: any edit here changes wire output for every body-prefix POST.
func buildDataPostHeaders(ua, publicURL string) http.Header {
	h := http.Header{
		"content-type":    {"application/json"},
		"x-request-id":    {fmt.Sprintf("%08x", browser.RandomUint32())},
		"user-agent":      {ua},
		"accept":          {"application/json"},
		"accept-encoding": {"gzip, deflate, br"},
		"accept-language": {"en-US,en;q=0.9"},
		"origin":          {publicURL},
		"referer":         {publicURL + "/"},
		"cache-control":   {"no-cache"},
		http.HeaderOrderKey: {
			"content-type",
			"x-request-id",
			"user-agent",
			"accept",
			"accept-encoding",
			"accept-language",
			"origin",
			"referer",
			"cache-control",
		},
	}
	return h
}
