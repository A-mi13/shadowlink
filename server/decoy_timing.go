package server

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"fmt"
	mathrand "math/rand/v2"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/nixavpn/shadowlink/core"
)

// asymmetricDecoyFixture holds pre-computed NaCl box inputs that produce a
// guaranteed-failing box.Open. The Open call still performs the full X25519
// ScalarMult + Poly1305 verification before returning ok=false, so it costs
// the same CPU budget as a real DecryptClientID(box.Open) hit on the success
// path. Initialised once at package init so the cost we add to
// runSyntheticDispatch is exclusively the asymmetric work, not key-material
// generation.
//
// The fixture is shared read-only across all goroutines; box.Open is pure
// (no internal mutation of inputs) so concurrent dispatch is race-free.
var (
	asymDecoyFixtureOnce sync.Once
	asymDecoyPeerPub     [32]byte
	asymDecoyPriv        [32]byte
	asymDecoyNonce       [24]byte
	asymDecoyCT          []byte
)

// EnsureDecoyFixtureInitialized triggers initAsymDecoyFixture eagerly so the
// first runSyntheticDispatch on the hot path does not pay the cold-RNG
// keypair-generation cost (tens of ms on cold caches) under a sync.Once
// mutex that would block every concurrent goroutine landing on the
// failClosedToDecoy path. Called from NewHandler at construction time and
// from setupTestHandler in tests; idempotent (sync.Once guards
// re-execution).
//
// Closes Review 1 M-2 of final-audit-2026-05-05.
func EnsureDecoyFixtureInitialized() {
	asymDecoyFixtureOnce.Do(initAsymDecoyFixture)
}

// initAsymDecoyFixture builds an invalid box.Seal output that box.Open will
// reject only after running the full ScalarMult + tag verify. The peer pub +
// receiver priv are independent CSPRNG keypairs (no relation), so the derived
// shared secret has no validity property — Poly1305 verify fails — but the
// X25519 ScalarMult still runs to completion. Result: deterministic
// fail-after-full-cost behaviour.
func initAsymDecoyFixture() {
	// Two independent ed25519/curve25519 keypairs — we only need their public
	// halves to look like real curve points; the deterministic byte layout
	// emitted by box.GenerateKey gives a valid-looking ScalarMult input.
	pubA, _, err := box.GenerateKey(cryptorand.Reader)
	if err != nil {
		// Fall back to fixed-but-non-zero bytes; box.Open will still execute
		// ScalarMult on whatever 32 bytes are supplied, so cost is preserved.
		for i := range pubA {
			pubA[i] = byte(i*7 + 3)
		}
	}
	_, privB, err := box.GenerateKey(cryptorand.Reader)
	if err != nil {
		for i := range privB {
			privB[i] = byte(i*11 + 5)
		}
	}
	asymDecoyPeerPub = *pubA
	asymDecoyPriv = *privB

	if _, err := cryptorand.Read(asymDecoyNonce[:]); err != nil {
		for i := range asymDecoyNonce {
			asymDecoyNonce[i] = byte(i*13 + 1)
		}
	}

	// 80-byte ciphertext — same magnitude as a real EncryptClientID body
	// (16-byte tag + 9..25-byte plaintext + 16-byte auth overhead),
	// padded to keep the Poly1305 verify time stable.
	asymDecoyCT = make([]byte, 80)
	if _, err := cryptorand.Read(asymDecoyCT); err != nil {
		for i := range asymDecoyCT {
			asymDecoyCT[i] = byte(i*17 + 9)
		}
	}
}

// RLSentinel carries structured rate-limit feedback emitted via the X-SL-RL
// response header. Replaces the legacy literal `X-SL-RL: 1` sentinel from
// May-audit Task A2 with a verbose key=value form so the client can apply
// per-bucket cool-downs (handshake vs ws_upgrade vs data) and skip backoff
// when the server signals an exemption (e.g. ClientID-trusted under §C4).
//
// Wire format: "bucket=<label>,burst_left=<int>,refill_in=<seconds>s,exempt=<0|1>"
// Bucket labels are stable: "ws_upgrade" | "handshake" | "data".
// Exempt is reserved for §C4 (ClientID exemption integration) — current call
// sites pass 0 with a TODO; a parallel agent owns that wiring.
type RLSentinel struct {
	Bucket    string        // "ws_upgrade"|"handshake"|"data"
	BurstLeft int           // remaining tokens in the bucket at the time of the rejection
	RefillIn  time.Duration // wall-clock time until the next token is available
	Exempt    int           // 0|1 — populated by §C4 ClientID exemption integration
}

// writeRateLimitSentinelV2 emits the verbose X-SL-RL header before any body
// write. Header MUST be set BEFORE the decoy handler flushes — once
// w.WriteHeader(200) has fired the header map is read-only.
//
// ASCII-only payload by contract: bucket label is a fixed enum, the rest are
// integers. Russian user-facing strings are not allowed in this value (see
// CLAUDE.md, §Conventions).
func writeRateLimitSentinelV2(w http.ResponseWriter, info RLSentinel) {
	val := fmt.Sprintf("bucket=%s,burst_left=%d,refill_in=%ds,exempt=%d",
		info.Bucket, info.BurstLeft, int(info.RefillIn.Seconds()), info.Exempt)
	w.Header().Set("X-SL-RL", val)
}

// fillRandom writes len(b) bytes of pseudo-random data to b. Used ONLY for
// synthetic decoy-pipeline inputs where cryptographic quality is irrelevant —
// the bytes are immediately fed to GCM.Open and discarded. Using mathrand
// instead of crypto/rand removes the variable-latency entropy-pool dependency
// that A2-MED-7 flagged as a potential timing oracle.
func fillRandom(b []byte) {
	for i := range b {
		b[i] = byte(mathrand.Uint32())
	}
}

// failClosedToDecoy responds with the decoy static site after executing a
// fixed-cost stand-in for the real Phase B dispatch pipeline, so a timing
// oracle cannot distinguish failed auth / replay / decrypt errors from a
// successful route by response latency.
//
// Cost budget (matches handleNewFormatPost success path):
//  1. Synthetic 4-byte hint → findSessionByHint map walk (negligible, but
//     keeps the RLock acquire in the profile).
//  2. Asymmetric ScalarMult parity (T1 §P1-1, May 2026 audit):
//     2a. core.GenerateKeyPair() — stand-in for the server-eph keypair
//     created inside HandleClientHelloWithVersion (1× X25519 ScalarMult).
//     2b. core.GenerateKeyPair() — stand-in for the ComputeSharedSecret
//     ECDH that HandleClientHelloWithVersion performs against the
//     client ephemeral public key (1× X25519 ScalarMult).
//     2c. nacl/box.Open against a pre-built invalid ciphertext — stand-in
//     for the DecryptClientID call on the success path (1× X25519
//     ScalarMult + Poly1305 verify before returning ok=false).
//     Total: 3× X25519 ScalarMult + 1× Poly1305 verify, mirroring the real
//     handshake within the ackJitter noise floor.
//  3. AES-256-GCM Open on random bytes — fails with ErrAuth, but the constant
//     tag compare + key schedule cost matches a real DecryptChunkSafe miss.
//  4. ackJitter() sleep — same distribution as the real ACK paths
//     (exponential scale ~18ms, capped at 150ms) so the response delay
//     histogram overlaps the legit-traffic one.
//
// After the synthetic pipeline runs, the request is handed to the decoy
// handler with a sanitized placeholder so all failure modes serve the same
// static URL — different paths would produce different decoy response sizes
// and leak the failure cause through body length.
//
// A2-MED-7 mitigation: synthetic random bytes are sourced from math/rand/v2
// (constant latency) rather than crypto/rand (variable latency due to
// entropy pool refresh). The bytes are immediately consumed by GCM.Open
// which always fails — they never leave this function — so degraded
// randomness has no security implication.
func (h *Handler) failClosedToDecoy(w http.ResponseWriter, r *http.Request) {
	// Backward-compat wrapper kept for existing tests + edge call paths that
	// have not yet been threaded with a reason. New code MUST call
	// failClosedToDecoyWithReason directly. Any sustained non-zero rate of
	// `unspecified` in `shadowlink_decoy_served_total{reason="unspecified"}`
	// is an observability bug — find the offending caller and assign a reason.
	h.failClosedToDecoyWithReason(w, r, DecoyReasonUnspecified)
}

// failClosedToDecoyWithReason is the full-fidelity variant: emits a structured
// WARN log (rate-limited per source IP) and bumps the per-reason Prom counter
// before running the timing-match pipeline. Body shape and timing distribution
// are bit-identical to the legacy two-arg variant — observability is purely
// additive, no wire change.
func (h *Handler) failClosedToDecoyWithReason(w http.ResponseWriter, r *http.Request, reason DecoyReason) {
	// Step 1: observability (emit BEFORE the synthetic-dispatch sleep so a
	// process-wide panic during dispatch still produces an audit trail of the
	// dispatch attempt).
	if r != nil {
		clientIP := h.clientIP(r)
		logDecoyServed(reason, r, clientIP)
	}
	h.metrics.IncDecoyServed(reason)

	// Step 2: timing-match pipeline (unchanged).
	h.runSyntheticDispatch()

	// Step 3: distribution-matched response jitter (Plan §C5 mixture).
	time.Sleep(ackJitter())

	h.metrics.TimingOracleHits.Add(1)
	// Sanitized placeholder: every failClosedToDecoy call resolves the decoy to
	// GET "/" so the response size is constant. Raw `r` would echo POST body
	// length / URL path into decoy routing and leak the failure mode.
	h.decoy.ServeHTTP(w, httpPlaceholderRequest())
}

// failClosedToDecoyRateLimitedV2 is failClosedToDecoy with one extra step: it
// sets `X-SL-RL: bucket=<label>,burst_left=<n>,refill_in=<n>s,exempt=<0|1>` on
// the response BEFORE the decoy handler writes anything, so the client
// (ws_pool.connectSlot) can distinguish "rate-limited by server" from "html
// decoy returned by middlebox" and apply a fixed cool-down instead of exp
// backoff. Closes Task A2 of the May 2026 audit. C5 (2026-05-02) extended
// the value from literal "1" to a verbose key=value form so the client can
// surface remaining-burst / refill-in to ops; client detection is by header
// presence, not value equality.
//
// Wire-level marker rationale (variant a chosen by user): a response header is
// neutral on the wire — DPI sees the WS upgrade decoy body identical to a
// generic 404 and picks up nothing extra. The header is consumed only by our
// own client.
//
// Timing pipeline (synthetic dispatch + ackJitter) is identical to
// failClosedToDecoy — every gate that calls EITHER variant is observably
// indistinguishable in latency to a passive attacker. This is enforced by
// TestRateLimitSentinel_TimingPipelinePreserved (decoy_timing pipeline still
// fires) and TestFailClosedToDecoy_TimingVariance (variance bound on the
// shared synthetic-dispatch step).
//
// Restricted call sites: ONLY the two `rateLimiters.*.Allow()` returns-false
// branches in handleHandshakeNew + handleWebSocket. Other callers
// (decrypt-fail, replay-reject, backpressure, max-clients, auth/device
// reject) MUST keep using failClosedToDecoy without the sentinel — see
// TestFailClosedToDecoy_DoesNotEmitXSLRLHeader.
//
// C5 (May audit, 2026-05-02): callsites pass an RLSentinel struct with
// the bucket label + remaining/retryAfter values from the C3 RateLimiters
// shim returns. The legacy two-arg form was removed once all callsites
// migrated.
func (h *Handler) failClosedToDecoyRateLimitedV2(w http.ResponseWriter, r *http.Request, info RLSentinel) {
	// Phase 1 (2026-05-14): rate-limit response via SentinelEmitter (dual-carrier:
	// Schema.org body marker + X-SL-RL semicolon format). Falls back to legacy
	// writeRateLimitSentinelV2 (comma format) if emitter not configured at startup
	// — supports header-only deployments (Telegraph-proxy) and back-compat with
	// pre-Phase-1 clients still parsing the comma format.
	//
	// Header format coexistence rationale:
	//   - writeRateLimitSentinelV2 (legacy): "bucket=X,burst_left=N,refill_in=Ns,exempt=K"
	//   - SentinelEmitter (new):  "v1;bucket=X;refill_in=N;burst_left=M;exempt=K"
	// Both coexist intentionally. The legacy comma format is used ONLY when
	// sentinelEmitter is nil (pre-Phase-1 deploy or Telegraph-proxy). The new
	// semicolon format is used by sentinelEmitter and also encodes into the body
	// marker. Old clients parsing the comma format will continue to work on
	// legacy deploys; new clients parse both forms (by header presence, not equality).
	// Future migration path: once all clients support both formats, deprecate
	// the comma form and remove writeRateLimitSentinelV2 legacy path.
	if h.sentinelEmitter != nil {
		// Dual-carrier path: body marker + X-SL-RL (semicolon format).
		// Emit writes the complete response (status + headers + body); do NOT
		// chain failClosedToDecoyWithReason — that would overwrite the response.
		//
		// CRITICAL invariant: early return here. The emitter wrote a complete
		// 200 response including WriteHeader; chaining decoy.ServeHTTP would
		// corrupt the response (double WriteHeader or appended bytes).
		h.sentinelEmitter.Emit(w, info, "")
		// Phase 1 timing parity (CRIT-finding 2026-05-14): match the legacy path's
		// 5-1500ms tail latency profile to avoid creating a bimodal distribution
		// that DPI ML can fingerprint as "fast = rate-limited via new emitter".
		// The ackJitter call here is BEFORE response is flushed (technically — Go
		// flushes on handler return), so the wall-clock delay shapes the response.
		time.Sleep(ackJitter())
		return
	}

	// Legacy fallback: header-only sentinel (comma format) + timing pipeline.
	// Header MUST be set before any body write. Setting after ServeHTTP would
	// be a no-op once the decoy has flushed; setting before tee's the header
	// into the responseWriter's pending header map and the decoy handler's
	// own w.WriteHeader() call (200) propagates it to the client.
	writeRateLimitSentinelV2(w, info)
	h.metrics.RateLimitSentinelEmitted.Add(1)

	// Derive the structured reason from the bucket label so the WARN log and
	// the `shadowlink_decoy_served_total{reason}` counter both carry the
	// per-bucket vocabulary. Soft-cap exemption rejection (Exempt=1 with the
	// handshake bucket) gets its own reason so ops can isolate the §C4
	// soft-limit branch from a generic bucket-empty rejection.
	reason := decoyReasonForRLSentinel(info)
	h.failClosedToDecoyWithReason(w, r, reason)
}

// decoyReasonForRLSentinel maps the RLSentinel bucket label + Exempt flag onto
// the DecoyReason enum used by the structured log + counter. Unknown buckets
// fall back to `unspecified` rather than panicking — the gate path stays hot
// even if a typo lands at a call site.
func decoyReasonForRLSentinel(info RLSentinel) DecoyReason {
	if info.Exempt == 1 {
		return DecoyReasonRateLimitSoftLimit
	}
	switch info.Bucket {
	case "ws_upgrade":
		return DecoyReasonRateLimitWSUpgrade
	case "handshake":
		return DecoyReasonRateLimitHandshake
	case "data":
		return DecoyReasonRateLimitData
	default:
		return DecoyReasonUnspecified
	}
}

// decoyWithTimingParity serves the decoy page with CPU+latency profile
// matching failClosedToDecoy: runs runSyntheticDispatch (3× ScalarMult +
// Poly1305 + AES-GCM) + ackJitter sleep, then forwards to decoy.
//
// Closes the passive-probe timing oracle where GET / direct-decoy responded
// in <5ms while POST-JSON-invalid took ~10ms (full failClosedToDecoy path).
//
// Performance budget: ~5ms per request. At 1000 req/s ≈ 0.5 CPU core,
// acceptable on pl1. DO NOT pre-compute or cache the synthetic result —
// constant-time path reintroduces the very oracle this defends against.
// Under extreme load, rely on IP-level RateLimiter, not on dispatch shortcut.
func (h *Handler) decoyWithTimingParity(w http.ResponseWriter, r *http.Request) {
	h.runSyntheticDispatch()
	time.Sleep(ackJitter())
	h.decoy.ServeHTTP(w, r)
}

// runSyntheticDispatch executes steps 1-3 of the failClosedToDecoy pipeline
// (hint lookup + asymmetric ScalarMult parity + AES-GCM Open). Split out so
// timing-variance tests can measure the CPU-work portion in isolation,
// without the distribution-matched ackJitter() sleep dominating the std-dev.
//
// A2-MED-7: the variance of this function (math/rand-sourced random inputs)
// is what the original entropy-pool oracle targeted.
//
// T1 §P1-1 (May 2026 audit): the ScalarMult cost was previously asymmetric —
// success path runs DecryptClientID (1× ScalarMult + Poly1305) plus the two
// ScalarMult calls inside HandleClientHelloWithVersion (server-eph
// GenerateKeyPair + ComputeSharedSecret), while failClosedToDecoy ran only
// one GenerateKeyPair. That ~150-200µs delta is detectable by a stationary
// observer aggregating per-IP latency histograms. We now run two extra
// GenerateKeyPair calls and one box.Open against a pre-built invalid
// ciphertext, restoring 3× ScalarMult + 1× Poly1305 verify symmetry.
func (h *Handler) runSyntheticDispatch() {
	// 1. Synthetic hint lookup — touches the sessions RLock like the real path.
	synHint := make([]byte, 4)
	fillRandom(synHint)
	// Pad to tokenLen so findSessionByHint's length check doesn't short-circuit
	// before the map walk (synHint alone is 4B; helper requires 20B prefix).
	synPrefix := make([]byte, h.sessionTokenSize())
	copy(synPrefix, synHint)
	fillRandom(synPrefix[4:])
	_ = h.findSessionByHint(synPrefix)

	// 2a/2b. Two X25519 keypair generations — stand-ins for the server-eph
	// GenerateKeyPair + ComputeSharedSecret ScalarMult work that
	// HandleClientHelloWithVersion performs on the success path. Each call
	// is ~50-100µs on x86_64, dominating the symmetric-crypto cost.
	_, _ = core.GenerateKeyPair()
	_, _ = core.GenerateKeyPair()

	// 2c. box.Open against a pre-built invalid ciphertext — stand-in for the
	// DecryptClientID call on the success path. The fixture is initialised
	// once at first use; box.Open is pure (read-only inputs), so concurrent
	// dispatch calls are race-free against the shared fixture.
	asymDecoyFixtureOnce.Do(initAsymDecoyFixture)
	_, _ = box.Open(nil, asymDecoyCT, &asymDecoyNonce, &asymDecoyPeerPub, &asymDecoyPriv)

	// 3. AES-256-GCM Open on random inputs — fails, but only after the same
	//    key schedule + tag compare the real DecryptChunkSafe runs.
	synKey := make([]byte, 32)
	synNonce := make([]byte, 12)
	synCT := make([]byte, 64)
	fillRandom(synKey)
	fillRandom(synNonce)
	fillRandom(synCT)
	if block, err := aes.NewCipher(synKey); err == nil {
		if gcm, err := cipher.NewGCM(block); err == nil {
			_, _ = gcm.Open(nil, synNonce, synCT, nil)
		}
	}
}
