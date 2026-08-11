package client

import (
	"errors"
	"fmt"
	"io"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClassifyWSReadError_KnownPatterns covers the canonical error strings
// gorilla/websocket and the net stack emit when a WS read fails. New
// classifications added to classifyWSReadError MUST land here too — the
// dashboard cardinality is bounded by frameAnomalyReasons (stats.go), and
// anything not in that list silently collapses to "other".
func TestClassifyWSReadError_KnownPatterns(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "rsv set",
			err:  errors.New("websocket: RSV1 set, RSV2 set, and RSV3 set, none of which is supported"),
			want: "rsv",
		},
		{
			name: "rsv1 only",
			err:  errors.New("websocket: RSV1 set, none of which is supported"),
			want: "rsv",
		},
		{
			name: "bad opcode",
			err:  errors.New("websocket: bad opcode 0xff"),
			want: "opcode",
		},
		{
			name: "closed local",
			err:  errors.New("read tcp 1.2.3.4:443: use of closed network connection"),
			want: "closed_local",
		},
		{
			name: "close 1011",
			err:  errors.New("websocket: close 1011 (internal server error): going away"),
			want: "close_1011",
		},
		{
			name: "close 1006",
			err:  errors.New("websocket: close 1006 (abnormal closure): unexpected EOF"),
			want: "close_other",
		},
		{
			name: "tls record",
			err:  errors.New("tls: bad record MAC"),
			want: "tls",
		},
		{
			name: "connection reset by peer",
			err:  errors.New("read tcp 1.2.3.4:443->5.6.7.8:51234: read: connection reset by peer"),
			want: "reset_by_peer",
		},
		{
			name: "i/o timeout",
			err:  errors.New("read tcp 1.2.3.4:443->5.6.7.8:51234: i/o timeout"),
			want: "io_timeout",
		},
		{
			name: "message too big",
			err:  errors.New("websocket: message too big"),
			want: "message_too_big",
		},
		{
			name: "read limit exceeded",
			err:  errors.New("websocket: read limit exceeded — message too big for buffer"),
			want: "message_too_big",
		},
		{
			// Canonical gorilla CloseError for close-code 1009 — substring
			// "websocket: close" overlaps with close_other but message_too_big
			// MUST win (precedence invariant, see ordering test below).
			name: "close 1009",
			err:  errors.New("websocket: close 1009 (message too big)"),
			want: "message_too_big",
		},
		{
			name: "io.EOF",
			err:  io.EOF,
			want: "eof",
		},
		{
			name: "unexpected EOF",
			err:  errors.New("unexpected EOF"),
			want: "eof",
		},
		{
			name: "html doctype leak",
			err:  errors.New("websocket: invalid UTF-8 payload data: <!DOCTYPE html>"),
			want: "html",
		},
		{
			name: "http error page leak",
			err:  errors.New("websocket: payload not valid: HTTP/1.1 502 Bad Gateway"),
			want: "html",
		},
		{
			name: "html tag",
			err:  errors.New("websocket: control frame too large: <html><body>"),
			want: "html",
		},
		{
			// Windows WSAETIMEDOUT. The Go net stack does NOT rewrite this to
			// "i/o timeout" — the raw winsock text surfaces verbatim, so the
			// POSIX-shaped pattern above never matches on Windows.
			//
			// Полевой замер 2026-08-11 (лог nixavpn-DEBUG-20260811-145918):
			// 11 таких смертей в одном инциденте падения origin ушли в "other".
			// filterNoise (slotobs/infer.go) отсеивает io_timeout, но "other"
			// не отсеивает — шесть из них (возраст 55-79s, выше ageCutMinAge
			// 45s) попали в чистую выборку, уронили p10 с 84.0s до 59.7s и
			// сжали порог ротации с 66s до 47s на 2ч48м. Ротация участилась на
			// ~20% (533 -> 641 соединений/час к origin IP) — ровно тот
			// counting-сигнал, от которого уходит модель угрозы.
			name: "windows WSAETIMEDOUT (wsarecv)",
			err: errors.New("read tcp 192.168.1.137:64907->104.222.177.67:443: wsarecv: " +
				"A connection attempt failed because the connected party did not properly " +
				"respond after a period of time, or established connection failed because " +
				"connected host has failed to respond."),
			want: "io_timeout",
		},
		{
			// Windows WSAECONNRESET — тот же RST, что POSIX отдаёт как
			// "connection reset by peer". Без этого паттерна сигнал
			// RST-инъекции на Windows недостижим в принципе.
			name: "windows WSAECONNRESET (forcibly closed)",
			err: errors.New("write tcp 192.168.1.137:54385->104.222.177.67:443: wsasend: " +
				"An existing connection was forcibly closed by the remote host."),
			want: "reset_by_peer",
		},
		{
			name: "unknown",
			err:  errors.New("disk quota exceeded"),
			want: "other",
		},
		{
			name: "nil",
			err:  nil,
			want: "other",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyWSReadError(tc.err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestClassifyWSReadError_OrderingInvariants documents the precedence
// invariants that future additions must NOT break:
//   - "use of closed network connection" maps to closed_local even when it
//     comes packaged as part of a larger gorilla error string.
//   - "tls:" is checked before "EOF" because "tls: read EOF" should classify
//     as tls, not eof.
//   - "connection reset by peer" maps to reset_by_peer even when the kernel
//     packages it alongside a generic "EOF" footer.
//   - "i/o timeout" beats "EOF" — a deadline expiry that the runtime then
//     surfaces as a wrapped EOF must still classify as io_timeout.
//   - close-1009 (message too big) beats close_other — both substrings
//     appear in the canonical gorilla CloseError string, but the
//     size-violation signal is the actionable one for forensics.
func TestClassifyWSReadError_OrderingInvariants(t *testing.T) {
	// closed_local takes precedence over generic eof matching when both
	// substrings could appear in the same message.
	combined := errors.New("read tcp: use of closed network connection (after EOF)")
	assert.Equal(t, "closed_local", classifyWSReadError(combined))

	tlsEOF := errors.New("tls: read EOF on record layer")
	assert.Equal(t, "tls", classifyWSReadError(tlsEOF))

	rstWithEOF := errors.New("read tcp: connection reset by peer (EOF)")
	assert.Equal(t, "reset_by_peer", classifyWSReadError(rstWithEOF))

	timeoutWithEOF := errors.New("read tcp: i/o timeout — unexpected EOF")
	assert.Equal(t, "io_timeout", classifyWSReadError(timeoutWithEOF))

	// close-1009 must NOT collapse into close_other — without precedence
	// the "websocket: close" substring would match first.
	closeMsgTooBig := errors.New("websocket: close 1009 (message too big)")
	assert.Equal(t, "message_too_big", classifyWSReadError(closeMsgTooBig))
}

// TestSlotBackoffDuration_RangesPerAttempt verifies the per-slot reconnect
// backoff stays within the documented [base × 2^attempt × 1.0,
// base × 2^attempt × 2.0] envelope, and saturates at 60s.
//
// 200 samples per attempt — Float64 jitter in [1.0, 2.0) means individual
// draws have ~0.1% probability of landing within ε of either bound, so a
// 200-sample run is comfortably within statistical tolerance for asserting
// that the bound holds for ALL draws in the run.
func TestSlotBackoffDuration_RangesPerAttempt(t *testing.T) {
	const samples = 200
	// Floor / ceiling per attempt — cap applies AFTER jitter, so any case
	// whose unclamped ceiling exceeds 60s collapses both bounds to 60s for
	// the assertion (ceiling pinned, floor still open from below since the
	// jitter draw is uniform).
	cases := []struct {
		attempt    int
		minExp     time.Duration
		maxExp     time.Duration
		floorIsCap bool
	}{
		{attempt: 0, minExp: 5 * time.Second, maxExp: 10 * time.Second},
		{attempt: 1, minExp: 10 * time.Second, maxExp: 20 * time.Second},
		{attempt: 2, minExp: 20 * time.Second, maxExp: 40 * time.Second},
		{attempt: 3, minExp: 40 * time.Second, maxExp: 60 * time.Second}, // 80s pre-cap → 60s post-cap
		{attempt: 5, minExp: 60 * time.Second, maxExp: 60 * time.Second, floorIsCap: true},
		{attempt: 10, minExp: 60 * time.Second, maxExp: 60 * time.Second, floorIsCap: true},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("attempt=%d", tc.attempt), func(t *testing.T) {
			minSeen, maxSeen := time.Hour, time.Duration(0)
			for range samples {
				d := slotBackoffDuration(tc.attempt)
				if d < minSeen {
					minSeen = d
				}
				if d > maxSeen {
					maxSeen = d
				}
				assert.GreaterOrEqual(t, d, tc.minExp, "below floor")
				assert.LessOrEqual(t, d, tc.maxExp, "above ceiling")
			}
			// Reasonable spread sanity: across 200 samples we should see
			// >200ms variation when the bound isn't entirely pinned to the
			// 60s cap.
			if !tc.floorIsCap {
				assert.Greater(t, maxSeen-minSeen, 200*time.Millisecond,
					"jitter spread should be visible across 200 samples")
			}
		})
	}
}

// TestSlotBackoffDuration_DecorrelatesEightSlots simulates the field-observed
// 8-slot meltdown: all 8 readers die at the same instant and each spawns a
// reconnectLoop; we want their attempt-0 backoffs spread far enough that the
// server's per-IP handshake rate limit (which lets through ~5 handshakes per
// second from any single IP) is not blown.
//
// The assertion: the difference between the earliest and latest attempt-0
// backoff is at least 1 second across the 8 simulated reconnects. With a
// 5-10s draw window and 8 samples, the expected min-max gap is well above
// 2 seconds — 1 second is a defensive lower bound that catches a regression
// where the jitter window is accidentally narrowed.
func TestSlotBackoffDuration_DecorrelatesEightSlots(t *testing.T) {
	const slots = 8
	min, max := time.Hour, time.Duration(0)
	for range slots {
		d := slotBackoffDuration(0)
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	require.Greater(t, max-min, 1*time.Second,
		"8 attempt-0 reconnects should spread by >1s — got min=%v max=%v gap=%v",
		min, max, max-min)
}

// TestSlotBackoffDuration_HighAttemptDoesNotOverflow guards the May 2026
// audit P0 finding (F1): without an attempt clamp, `5s × 2^attempt` for
// attempt~37+ overflows time.Duration to MinInt64, producing a negative
// backoff that time.Sleep returns from instantly — observed in the field
// log 2026-05-01 10:44 MSK as `backoff=-2562047h47m16.854775808s` followed
// by a 13-attempt reconnect storm in <30s.
//
// Acceptance: even at extreme attempts (37, 100, math.MaxInt32), backoff
// MUST stay positive and bounded by the 60s cap.
func TestSlotBackoffDuration_HighAttemptDoesNotOverflow(t *testing.T) {
	const samples = 200
	cases := []int{6, 37, 100, 1000, math.MaxInt32}
	for _, attempt := range cases {
		t.Run(fmt.Sprintf("attempt=%d", attempt), func(t *testing.T) {
			for range samples {
				d := slotBackoffDuration(attempt)
				require.Greater(t, d, time.Duration(0),
					"backoff must be strictly positive at attempt=%d, got %v",
					attempt, d)
				require.LessOrEqual(t, d, 60*time.Second,
					"backoff must be capped at 60s at attempt=%d, got %v",
					attempt, d)
			}
		})
	}
}
