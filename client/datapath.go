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

// defaultDataPathBodyPrefix — ДЕФОЛТ выбора формата data-path (body-prefix vs
// legacy Authorization: Bearer), считанный из SHADOWLINK_DATAPATH_BODYPREFIX на
// инициализации пакета. Default ON с 2026-04-26 (Phase 0 T1.4 flip после canary
// soak); SHADOWLINK_DATAPATH_BODYPREFIX=0 (или "false"/"no"/"off") — аварийный
// откат на legacy Authorization-header путь.
//
// ⚠ Это лишь ДЕФОЛТ, а не единственный источник истины. Мобильный фасад
// (gomobile) физически не может выставить окружение до импорта пакета — там нет
// процесса, стартующего с env. Поэтому эффективное значение живёт per-instance в
// DirectTransport.dataPathBodyPrefix, а ClientConfig.DataPathBodyPrefix может
// его переопределить программно (см. resolveDataPathBodyPrefix). Package-var
// остаётся дефолтом, чтобы CLI продолжал управляться через env без правок.
//
// Снимок берётся на КОНСТРУИРОВАНИИ транспорта, поэтому withDataPathBodyPrefix,
// выставленный тестом до NewDirectTransport, наследуется этим транспортом.
var defaultDataPathBodyPrefix = parseDataPathBodyPrefixEnv(os.Getenv("SHADOWLINK_DATAPATH_BODYPREFIX"))

func parseDataPathBodyPrefixEnv(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

// withDataPathBodyPrefix временно переопределяет ДЕФОЛТ на время теста. Транспорт
// снимает значение на конструировании, поэтому вызывать до NewDirectTransport.
// Use via t.Cleanup for restore. Not safe for concurrent tests that observe the
// value from different goroutines.
func withDataPathBodyPrefix(enabled bool) func() {
	prev := defaultDataPathBodyPrefix
	defaultDataPathBodyPrefix = enabled
	return func() { defaultDataPathBodyPrefix = prev }
}

// resolveDataPathBodyPrefix вычисляет эффективный флаг data-path для конкретного
// клиента: явное поле ClientConfig побеждает, иначе берётся пакетный дефолт (env).
// Приоритет — «дефолт(env) → явное поле», ровно как требует спека мобильного
// фасада: CLI работает через env без правок, а нативка задаёт значение
// программно, не имея возможности выставить окружение до импорта пакета.
func resolveDataPathBodyPrefix(override *bool) bool {
	if override != nil {
		return *override
	}
	return defaultDataPathBodyPrefix
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
