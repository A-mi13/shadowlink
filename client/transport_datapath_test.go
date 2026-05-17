package client

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/core"
	"github.com/nixavpn/shadowlink/server"
)

// newInProcServer spins up a real shadowlink server.Handler in-process and
// wraps it with httptest.NewServer. Returns a "host:port" addr usable by
// NewDirectTransport, the server's public key bytes, and the live handler
// (for test-side injection in later R-tests). The httptest.Server is stopped
// via t.Cleanup registered inside the helper, so callers don't need to invoke
// teardown manually.
//
// Why Handler (not Server.Start): the plan pins on httptest.NewServer so each
// R-test gets a plain HTTP loopback without any listener lifecycle surprises
// (no cleanup goroutine, no UDP listener, no TLS). Handler alone is enough —
// ServeHTTP covers the entire POST / WebSocket dispatch. Cleanup routines
// (session GC, etc.) are not needed for a short round-trip test.
func newInProcServer(t *testing.T) (serverAddr string, srvKeyPub []byte, h *server.Handler) {
	t.Helper()

	kp, err := core.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// server.TestConfig() baseline (ChunkSize=12288 already). Override the
	// three fields that matter for R-tests: higher client / conn caps and a
	// non-zero device limit so the handshake doesn't hit the per-user device
	// cap on the first connection.
	cfg := server.TestConfig()
	cfg.MaxClients = 100
	cfg.MaxConnsPerClient = 8
	cfg.DefaultMaxDevices = 3
	// NewHandler returns *Handler without error (see server/handler.go:86).
	h = server.NewHandler(kp, cfg, "")

	ts := httptest.NewServer(h)
	t.Cleanup(func() { ts.Close() })

	// httptest.NewServer returns "http://127.0.0.1:PORT"; strip the scheme so
	// NewDirectTransport(useTLS=false) can dial it directly.
	addr := strings.TrimPrefix(ts.URL, "http://")
	return addr, kp.Public, h
}

// establishSession drives a real ShadowLink handshake and returns a connected
// session + its session token. The transport is consumed by the returned
// client — do NOT close the transport separately; Client.Close() is registered
// via t.Cleanup and will release it.
//
// ClientID is fixed to a 16-byte ASCII literal so the handshake lands on the
// Phase B new-format path (non-UUID-sized IDs skip the body-prefix keys — see
// phase-d-nuances N-D2). Count: t(1) 1(2) 4(3) -(4) r(5) 1(6) -(7) t(8) e(9)
// s(10) t(11) u(12) u(13) i(14) d(15) !(16) — exactly 16 bytes.
func establishSession(t *testing.T, tr *DirectTransport, srvPub []byte) (*Client, *core.Session, []byte) {
	t.Helper()

	clientID := []byte("t14-r1-testuuid!")
	if len(clientID) != 16 {
		t.Fatalf("clientID must be 16 bytes, got %d", len(clientID))
	}

	// NewClientWithTransport takes (Transport, serverPub, clientID) directly —
	// no ClientConfig — and returns *Client without error.
	// See client/client.go:168.
	cl := NewClientWithTransport(tr, srvPub, clientID)
	t.Cleanup(func() { _ = cl.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := cl.Connect(ctx); err != nil {
		t.Fatalf("Connect: %v", err)
	}

	sess := cl.Session()
	if sess == nil {
		t.Fatalf("nil session after Connect")
	}
	return cl, sess, cl.Token()
}

// TestR1_SendChunk_BodyPrefix_RoundTrip verifies that a flag-on SendChunk
// round-trips through a real server.Handler via handleNewFormatPost →
// findSessionByHint → handleData without errors. This is the R1 baseline
// from the T1.4 plan (first real confidence signal that the 2026-04-20 B2
// rollback was NOT caused by a server-side body-prefix dispatch gap).
func TestR1_SendChunk_BodyPrefix_RoundTrip(t *testing.T) {
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)

	addr, srvPub, _ := newInProcServer(t)

	tr := NewDirectTransport(addr, false, true)
	// Transport ownership passes to the Client via establishSession; no
	// explicit Close needed here — Client.Close() handles teardown.

	_, sess, token := establishSession(t, tr, srvPub)

	// After new-format handshake the session MUST be pinned to ProtoVersion=1;
	// if this regresses, SendChunk would fall back to Bearer and the test
	// would silently stop exercising the body-prefix path we care about.
	if sess.ProtoVersion != 1 {
		t.Fatalf("expected ProtoVersion=1 after new-format handshake, got %d", sess.ProtoVersion)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	chunk := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagData,
		Payload:   []byte("hello-r1"),
	}
	enc, err := sess.EncryptChunk(chunk)
	if err != nil {
		t.Fatalf("EncryptChunk: %v", err)
	}

	if _, err := tr.SendChunk(ctx, enc, token, chunk.SeqNum); err != nil {
		t.Fatalf("SendChunk: %v", err)
	}
}

// TestR2_SendChunk_BodyPrefix_SequentialSoak sends 500 sequential 12KB chunks
// through SendChunk with the body-prefix flag on. This is the local analogue
// of the sustained-traffic scenario that triggered the 2026-04-20 B2 field
// rollback (users reported "сайты не грузятся" / "downlink cancelled
// elapsed=15-17s" after extended use). If this test fails — cancellation,
// decrypt failure, or wall-clock blowout — we've reproduced the field bug
// locally and MUST halt further migration tasks to root-cause.
//
// If it passes cleanly, the field bug was not reproducible in a clean
// in-process harness, meaning it likely required a specific production
// condition (CF edge, nginx buffering, real concurrency). Canary phase
// becomes the actual verification gate.
func TestR2_SendChunk_BodyPrefix_SequentialSoak(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test — skip under -short")
	}
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)
	// 500 chunks at local-loopback rate exceed the default TokenBucket data
	// burst (100 + 100/min refill). This test verifies datapath wire format,
	// not rate-limiter behavior — disable the bucket so we don't hit decoy
	// fail-closed at chunk #~126. See C3 (batch 4) for default-on flip.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	// §C4 (May audit, 2026-05-02): also disable the ClientID exemption so the
	// soft cap (60/min/clientID) doesn't cut off chunks #60+. The exemption
	// fast path is orthogonal to the wire-format invariants this test pins.
	t.Setenv("SHADOWLINK_RL_CLIENTID_EXEMPT", "0")

	addr, srvPub, _ := newInProcServer(t)

	tr := NewDirectTransport(addr, false, true)
	// Transport is consumed by the Client — cl.Close() (registered in
	// establishSession via t.Cleanup) tears it down.

	_, sess, token := establishSession(t, tr, srvPub)

	const N = 500
	const chunkPayloadSize = 12288

	start := time.Now()
	for i := 0; i < N; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

		payload := make([]byte, chunkPayloadSize)
		for j := range payload {
			payload[j] = byte(i + j)
		}

		chunk := &core.Chunk{
			SessionID: sess.ID,
			SeqNum:    sess.NextSeqNum(),
			Flags:     core.FlagData,
			Payload:   payload,
		}
		enc, err := sess.EncryptChunk(chunk)
		if err != nil {
			cancel()
			t.Fatalf("EncryptChunk #%d: %v", i, err)
		}

		if _, err := tr.SendChunk(ctx, enc, token, chunk.SeqNum); err != nil {
			cancel()
			t.Fatalf("SendChunk #%d (elapsed since start: %v): %v", i, time.Since(start), err)
		}
		cancel()
	}
	elapsed := time.Since(start)

	// Per-chunk local-loopback latency is typically < 2ms. 500 chunks × 2ms =
	// 1s. Give a 30s wall-clock budget — covers CI variance but catches the
	// field-bug pathology (15-17s cancellation after each chunk would blow this
	// within ~50 chunks).
	if elapsed > 30*time.Second {
		t.Fatalf("soak too slow: %v total for %d chunks (>30s suggests field-bug pathology)", elapsed, N)
	}
	t.Logf("R2 soak: %d chunks in %v (%.2f chunks/s)", N, elapsed, float64(N)/elapsed.Seconds())
}

// TestR3_SendChunk_BodyPrefix_Concurrent stresses the body-prefix path with
// interleaved SendChunk calls from 8 goroutines sharing one session. The
// primary intent is race detector coverage (run with -race on CI Linux).
// Invariants verified:
//   - session.NextSeqNum() monotonically advances under concurrent callers
//     (core.Session is documented safe for concurrent chunk production).
//   - server's findSessionByHint (O(1) map lookup) tolerates parallel hints
//     from the same session token without corruption.
//   - DecryptChunkSafe sliding window (16384 slots) accepts out-of-order
//     arrivals from interleaved goroutines.
//
// If this test fails (races, decrypt_fails, or "session not found"), it's a
// real concurrency bug in either core.Session, server dispatch, or the body-
// prefix wire format — halt and root-cause.
func TestR3_SendChunk_BodyPrefix_Concurrent(t *testing.T) {
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)
	// 8×25=200 concurrent chunks exceed the default TokenBucket data burst.
	// This test verifies concurrency invariants, not rate-limiter behavior.
	t.Setenv("SHADOWLINK_RL_TOKENBUCKET", "0")
	// §C4 (May audit, 2026-05-02): also disable the ClientID exemption so the
	// soft cap (60/min/clientID) doesn't reject the 8×25=200 chunk burst.
	t.Setenv("SHADOWLINK_RL_CLIENTID_EXEMPT", "0")

	addr, srvPub, _ := newInProcServer(t)

	tr := NewDirectTransport(addr, false, true)

	_, sess, token := establishSession(t, tr, srvPub)

	const workers = 8
	const perWorker = 25

	var wg sync.WaitGroup
	errCh := make(chan error, workers*perWorker)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

				chunk := &core.Chunk{
					SessionID: sess.ID,
					SeqNum:    sess.NextSeqNum(),
					Flags:     core.FlagData,
					Payload:   []byte{byte(wid), byte(i)},
				}
				enc, err := sess.EncryptChunk(chunk)
				if err != nil {
					errCh <- err
					cancel()
					return
				}
				if _, err := tr.SendChunk(ctx, enc, token, chunk.SeqNum); err != nil {
					errCh <- err
					cancel()
					return
				}
				cancel()
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	var failures []error
	for err := range errCh {
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		t.Fatalf("concurrent SendChunk: %d errors (first: %v)", len(failures), failures[0])
	}
}

// TestR4_SendChunk_DownstreamFullBody attempts to reproduce the 2026-04-20
// field regression: "downlink cancelled elapsed=15-17s" reported after B2
// migrated SendChunk to body-prefix. Hypothesis: the server response path
// entered a divergent code path when no Authorization header was present,
// causing partial-body or timeout-on-poll symptoms.
//
// Harness: pre-seed ~15KB of raw payload on the session's tunnel.Outgoing
// channel via the test-only Handler.TestEnqueueDownstream hook, then issue
// one flag-on SendChunk and assert the full encrypted response is delivered
// quickly.
//
// Adaptation from plan: the plan sketch assumed Outgoing was `chan *core.Chunk`;
// in the real handler (server/handler.go:59) it's `chan []byte` holding raw
// pre-encryption payload. handleDataChunk encrypts each drained []byte via
// session.EncryptChunk before writing the POST response. So we inject raw
// bytes, not a pre-built Chunk — and the encrypted response SIZE will be
// 15360 (payload) + 13 (core.Chunk header) + 12 (nonce) + 16 (GCM tag) =
// 15401 bytes of encrypted chunk, wrapped in the JSON analytics envelope.
// The test only checks non-empty body + timely delivery — exact bytes don't
// matter for R4's diagnostic purpose.
//
// If this test FAILS: we've locally reproduced the field bug. Halt further
// migration work and dig into handleDataChunk / handleNewFormatPost vs. the
// legacy path to find the divergence.
//
// If it PASSES: we did not reproduce, meaning the field regression was
// likely environment-specific (CF edge, nginx buffering, real concurrency).
// Canary phase becomes the real verification gate.
func TestR4_SendChunk_DownstreamFullBody(t *testing.T) {
	restore := withDataPathBodyPrefix(true)
	t.Cleanup(restore)

	addr, srvPub, h := newInProcServer(t)

	tr := NewDirectTransport(addr, false, true)

	_, sess, token := establishSession(t, tr, srvPub)

	const downstreamBytes = 15 * 1024 // 15360 — non-tier size, PutBuffer silently drops
	downstream := make([]byte, downstreamBytes)
	for i := range downstream {
		downstream[i] = byte(i % 251)
	}

	if !h.TestEnqueueDownstream(sess.ID, downstream) {
		t.Fatalf("TestEnqueueDownstream: session %d not found or Outgoing full", sess.ID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := &core.Chunk{
		SessionID: sess.ID,
		SeqNum:    sess.NextSeqNum(),
		Flags:     core.FlagData,
		Payload:   []byte("r4-request"),
	}
	encReq, err := sess.EncryptChunk(req)
	if err != nil {
		t.Fatalf("EncryptChunk: %v", err)
	}

	start := time.Now()
	respEnc, err := tr.SendChunk(ctx, encReq, token, req.SeqNum)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("SendChunk (elapsed=%v): %v — possible R4 field-bug reproduction", elapsed, err)
	}
	if len(respEnc) == 0 {
		t.Fatalf("SendChunk returned empty body — expected ~%d bytes downstream (elapsed=%v)", downstreamBytes, elapsed)
	}
	if elapsed > 5*time.Second {
		// Field bug threshold was 15-17s; anything > 5s on a loopback is suspicious.
		t.Fatalf("slow downstream: elapsed=%v — field-bug threshold was 15-17s", elapsed)
	}
	t.Logf("R4: downstream delivered %d bytes in %v", len(respEnc), elapsed)
}
