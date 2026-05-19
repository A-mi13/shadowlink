package client

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	utls "github.com/refraction-networking/utls"
)

// TestPQClientHelloSpec_KeyShareIncludesMLKEM768 verifies that pqClientHelloSpec
// returns a spec whose KeyShareExtension lists X25519MLKEM768 (typically as the
// first non-GREASE key-share group; per RFC 8701, real Chrome 135+ puts a
// GREASE placeholder before MLKEM). Wire-order matters because passive
// observers fingerprint the first non-GREASE key_share group as the
// "preferred" curve. T1.1 plan T3 Step 1.
func TestPQClientHelloSpec_KeyShareIncludesMLKEM768(t *testing.T) {
	spec, err := pqClientHelloSpec()
	if err != nil {
		t.Fatalf("pqClientHelloSpec: %v", err)
	}

	var ks *utls.KeyShareExtension
	for _, ext := range spec.Extensions {
		if v, ok := ext.(*utls.KeyShareExtension); ok {
			ks = v
			break
		}
	}
	if ks == nil {
		t.Fatal("KeyShareExtension missing from PQ spec")
	}
	if len(ks.KeyShares) == 0 {
		t.Fatal("KeyShareExtension has no key shares")
	}

	// First non-GREASE entry must be MLKEM768.
	firstNonGREASE := -1
	for i, k := range ks.KeyShares {
		if !isGREASE(uint16(k.Group)) {
			firstNonGREASE = i
			break
		}
	}
	if firstNonGREASE < 0 {
		t.Fatal("no non-GREASE key-share entries found")
	}
	if ks.KeyShares[firstNonGREASE].Group != utls.X25519MLKEM768 {
		t.Fatalf("first non-GREASE key share group at idx=%d = %v, want X25519MLKEM768 (%v)",
			firstNonGREASE, ks.KeyShares[firstNonGREASE].Group, utls.X25519MLKEM768)
	}
}

// TestPQClientHelloSpec_SupportedCurvesPrepend verifies that the supported_groups
// extension (named SupportedCurvesExtension in utls) places X25519MLKEM768
// before any other real curve (a GREASE placeholder per RFC 8701 may legally
// occupy index 0). RFC 8446 §4.2.7: the order signals client preference;
// Chrome 135+ wire-captures show MLKEM first non-GREASE. T1.1 plan T3 Step 1.
func TestPQClientHelloSpec_SupportedCurvesPrepend(t *testing.T) {
	spec, err := pqClientHelloSpec()
	if err != nil {
		t.Fatalf("pqClientHelloSpec: %v", err)
	}

	var sc *utls.SupportedCurvesExtension
	for _, ext := range spec.Extensions {
		if v, ok := ext.(*utls.SupportedCurvesExtension); ok {
			sc = v
			break
		}
	}
	if sc == nil {
		t.Fatal("SupportedCurvesExtension missing from PQ spec")
	}
	if len(sc.Curves) == 0 {
		t.Fatal("SupportedCurvesExtension has no curves")
	}

	firstNonGREASE := -1
	for i, c := range sc.Curves {
		if !isGREASE(uint16(c)) {
			firstNonGREASE = i
			break
		}
	}
	if firstNonGREASE < 0 {
		t.Fatal("no non-GREASE supported curves found")
	}
	if sc.Curves[firstNonGREASE] != utls.X25519MLKEM768 {
		t.Fatalf("first non-GREASE supported curve at idx=%d = %v, want X25519MLKEM768 (%v)",
			firstNonGREASE, sc.Curves[firstNonGREASE], utls.X25519MLKEM768)
	}
}

// TestPQClientHelloSpec_NoDuplicateMLKEM verifies that pqClientHelloSpec is
// idempotent and never produces duplicate X25519MLKEM768 entries in either
// SupportedCurves or KeyShares. Regression guard for the C1 bug (2026-04-26):
// the original idempotency check looked at index 0 only, but the base
// HelloChrome_133 spec puts a GREASE placeholder at index 0 with MLKEM at
// index 1, so the check fired every call and prepended a second MLKEM ahead
// of GREASE — adding ~2.4KB to ClientHello and breaking RFC 8701 GREASE
// ordering.
func TestPQClientHelloSpec_NoDuplicateMLKEM(t *testing.T) {
	spec, err := pqClientHelloSpec()
	if err != nil {
		t.Fatalf("pqClientHelloSpec: %v", err)
	}

	var curves *utls.SupportedCurvesExtension
	var ks *utls.KeyShareExtension
	for _, ext := range spec.Extensions {
		if v, ok := ext.(*utls.SupportedCurvesExtension); ok {
			curves = v
		}
		if v, ok := ext.(*utls.KeyShareExtension); ok {
			ks = v
		}
	}
	if curves == nil || ks == nil {
		t.Fatal("missing extensions")
	}

	countCurves := 0
	for _, c := range curves.Curves {
		if c == utls.X25519MLKEM768 {
			countCurves++
		}
	}
	if countCurves != 1 {
		t.Errorf("X25519MLKEM768 in SupportedCurves count = %d, want 1", countCurves)
	}

	countKS := 0
	for _, k := range ks.KeyShares {
		if k.Group == utls.X25519MLKEM768 {
			countKS++
		}
	}
	if countKS != 1 {
		t.Errorf("X25519MLKEM768 in KeyShares count = %d, want 1", countKS)
	}
}

// TestPQEnabled_EnvFlag verifies that SHADOWLINK_TLS_PQ=1 keeps PQ on
// (post-flip semantics: 1 is still a valid opt-in, just redundant since
// default is on).
func TestPQEnabled_EnvFlag(t *testing.T) {
	t.Setenv("SHADOWLINK_TLS_PQ", "1")
	if !pqEnabled() {
		t.Fatal("pqEnabled() = false with SHADOWLINK_TLS_PQ=1; want true")
	}
}

// TestPQEnabled_DefaultOn verifies that an unset env returns true (default
// is now ON since 2026-04-28 Phase 2 closure flip). Mirrors
// SHADOWLINK_DATAPATH_BODYPREFIX semantics: unset → enabled.
func TestPQEnabled_DefaultOn(t *testing.T) {
	old, hadOld := os.LookupEnv("SHADOWLINK_TLS_PQ")
	os.Unsetenv("SHADOWLINK_TLS_PQ")
	t.Cleanup(func() {
		if hadOld {
			os.Setenv("SHADOWLINK_TLS_PQ", old)
		} else {
			os.Unsetenv("SHADOWLINK_TLS_PQ")
		}
	})
	if !pqEnabled() {
		t.Fatal("pqEnabled() = false with SHADOWLINK_TLS_PQ unset; want true (default-on)")
	}
}

// TestPQHandshakeMetrics_PromExposition verifies the Prom exporter emits all
// three labels of shadowlink_tls_pq_handshake_total with the current counter
// values. Counters increment in a controlled way, then we scrape and assert
// the text output. T1.1 plan T6.
func TestPQHandshakeMetrics_PromExposition(t *testing.T) {
	// Snapshot counters so this test is hermetic w.r.t. previous tests in
	// the same run (counters are package-globals).
	beforeSucc := Stats.PQClientHelloSent.Load()
	beforeFall := Stats.PQHandshakeFallback.Load()
	beforeErr := Stats.PQHandshakeError.Load()

	Stats.PQClientHelloSent.Add(2)
	Stats.PQHandshakeFallback.Add(1)
	Stats.PQHandshakeError.Add(3)

	var buf bytes.Buffer
	WritePromMetrics(&buf)
	out := buf.String()

	for _, want := range []string{
		"# HELP shadowlink_tls_pq_handshake_total",
		"# TYPE shadowlink_tls_pq_handshake_total counter",
		`shadowlink_tls_pq_handshake_total{result="clienthello_sent"}`,
		`shadowlink_tls_pq_handshake_total{result="fallback"}`,
		`shadowlink_tls_pq_handshake_total{result="error"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Prom output missing %q\n\n%s", want, out)
		}
	}

	// Reset counters back to their prior values so other tests don't see drift.
	// atomic.Uint64 has no Sub; do it via Store after a load.
	Stats.PQClientHelloSent.Store(beforeSucc)
	Stats.PQHandshakeFallback.Store(beforeFall)
	Stats.PQHandshakeError.Store(beforeErr)
}

// TestPQEnabled_ExplicitOff verifies that the documented opt-out values
// ("0"/"false"/"no"/"off", case-insensitive, with surrounding whitespace
// tolerated) route through the legacy helloID path. All other values
// (including unknown/garbage) keep PQ on per default-on semantics.
func TestPQEnabled_ExplicitOff(t *testing.T) {
	for _, v := range []string{"0", "false", "no", "off", "FALSE", "  off  "} {
		t.Setenv("SHADOWLINK_TLS_PQ", v)
		if pqEnabled() {
			t.Fatalf("pqEnabled() = true with SHADOWLINK_TLS_PQ=%q; want false (opt-out)", v)
		}
	}
}

// TestPQEnabled_UnknownValueIsOn verifies post-flip semantics: any value
// outside the documented opt-out set ("0"/"false"/"no"/"off") keeps PQ on.
// This guards against the previous strict-"1" semantics leaking back.
func TestPQEnabled_UnknownValueIsOn(t *testing.T) {
	for _, v := range []string{"1", "yes", "on", "true", "maybe", "garbage", ""} {
		t.Setenv("SHADOWLINK_TLS_PQ", v)
		if !pqEnabled() {
			t.Errorf("pqEnabled() = false with SHADOWLINK_TLS_PQ=%q; want true (default-on)", v)
		}
	}
}

// TestClientHelloBytes_PQ_OnWire builds a real UConn with the PQ spec, drives
// it as far as MarshalClientHello, and asserts that the X25519MLKEM768 curve
// id (0x11ec / 4588) appears in the on-wire ClientHello bytes. Without this
// the spec helper could be silently bypassed by a future utls change. T1.1
// plan T8.
func TestClientHelloBytes_PQ_OnWire(t *testing.T) {
	hello, raw, err := buildPQClientHelloForCapture()
	if err != nil {
		t.Fatalf("buildPQClientHelloForCapture: %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("ClientHello raw bytes empty after BuildHandshakeState")
	}

	// Sanity: the parsed hello surface must show MLKEM768 as the first
	// non-GREASE entry (RFC 8701 GREASE often occupies index 0).
	if len(hello.KeyShares) == 0 {
		t.Fatal("parsed KeyShares empty")
	}
	firstNonGREASEKS := -1
	for i, ks := range hello.KeyShares {
		if !isGREASE(uint16(ks.Group)) {
			firstNonGREASEKS = i
			break
		}
	}
	if firstNonGREASEKS < 0 || hello.KeyShares[firstNonGREASEKS].Group != utls.X25519MLKEM768 {
		t.Fatalf("parsed first non-GREASE KeyShares group = %v, want X25519MLKEM768",
			func() any {
				if firstNonGREASEKS < 0 {
					return "<none>"
				}
				return hello.KeyShares[firstNonGREASEKS].Group
			}())
	}

	if len(hello.SupportedCurves) == 0 {
		t.Fatal("parsed SupportedCurves empty")
	}
	firstNonGREASESC := -1
	for i, c := range hello.SupportedCurves {
		if !isGREASE(uint16(c)) {
			firstNonGREASESC = i
			break
		}
	}
	if firstNonGREASESC < 0 || hello.SupportedCurves[firstNonGREASESC] != utls.X25519MLKEM768 {
		t.Fatalf("parsed first non-GREASE SupportedCurves = %v, want X25519MLKEM768",
			func() any {
				if firstNonGREASESC < 0 {
					return "<none>"
				}
				return hello.SupportedCurves[firstNonGREASESC]
			}())
	}

	// On-wire byte assertion: the 0x11ec marker MUST appear in the raw bytes.
	if !containsCurveID(raw, uint16(utls.X25519MLKEM768)) {
		t.Fatalf("X25519MLKEM768 (0x11ec) marker NOT found in raw ClientHello bytes (len=%d)", len(raw))
	}
}

// TestClientHelloBytes_JA4MatchesChromeReference computes the deterministic
// JA4-shaped fingerprint over the PQ ClientHello and compares it against the
// fixture in testdata/ja4/chrome_133_pq.txt. Skips with a logged hash when
// the fixture still holds the placeholder marker — this is the bootstrap path
// per testdata/ja4/REFRESH.md. T1.1 plan T8.
func TestClientHelloBytes_JA4MatchesChromeReference(t *testing.T) {
	hello, _, err := buildPQClientHelloForCapture()
	if err != nil {
		t.Fatalf("buildPQClientHelloForCapture: %v", err)
	}

	got := computeJA4(hello)
	if got == "" {
		t.Fatal("computeJA4 returned empty string")
	}

	fixturePath := filepath.Join("testdata", "ja4", "chrome_133_pq.txt")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture %s: %v", fixturePath, err)
	}
	want := strings.TrimSpace(string(raw))

	if want == "PLACEHOLDER_REPLACE_AFTER_FIRST_TEST_RUN" || want == "" {
		t.Logf("computed JA4 = %s", got)
		t.Skip("fixture chrome_133_pq.txt still holds placeholder; replace it with the computed hash and re-run (see testdata/ja4/REFRESH.md)")
	}

	if got != want {
		t.Fatalf("JA4 mismatch:\n  got  = %s\n  want = %s\n(see testdata/ja4/REFRESH.md if this drift is intentional)", got, want)
	}
}

// TestPQClientHelloSpec_DoesNotMutateSharedSpec is the regression guard for
// T1 §P1-2 (May 2026 audit, 2026-05-03). utls.UTLSIdToSpec returns extension
// pointers that are NOT guaranteed to be freshly allocated per call —
// upstream may serve them from a shared package-level descriptor table.
// Mutating those structs in pqClientHelloSpec (without the deep-copy applied
// in this fix) would race with concurrent cold-path handshakes (split
// transport, ws warmup, probe.probeHTTPS, ECH DoH) and could corrupt the
// ClientHello when the append branch fires after an upstream that drops
// MLKEM from the canonical Chrome_133 spec.
//
// We exercise the dangerous code path by snapshotting the bytes of the
// SupportedCurves and KeyShares slices on a fresh utls.UTLSIdToSpec call
// BEFORE invoking pqClientHelloSpec, then re-snapshotting AFTER multiple
// invocations and asserting bit-for-bit equality. If pqClientHelloSpec
// leaked its mutation back into the upstream-shared backing array, the
// MLKEM prepend would be visible on the second snapshot — assuming utls
// upstream changes such that the append branch fires (idempotent skip on
// current Chrome_133 silently passes the test, which is the correct
// behaviour: with MLKEM already present we never mutate, deep-copy still
// runs as defensive guarantee).
func TestPQClientHelloSpec_DoesNotMutateSharedSpec(t *testing.T) {
	// Snapshot the upstream spec BEFORE any pqClientHelloSpec call.
	preSpec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		t.Fatalf("utls.UTLSIdToSpec (pre): %v", err)
	}
	preCurves, preKS := snapshotMLKEMRelevantExtensions(t, preSpec)

	// Call pqClientHelloSpec multiple times — both serially and in parallel —
	// so any mutation of shared backing storage would compound.
	for i := 0; i < 4; i++ {
		if _, err := pqClientHelloSpec(); err != nil {
			t.Fatalf("pqClientHelloSpec call #%d: %v", i, err)
		}
	}

	const parallelism = 8
	done := make(chan error, parallelism)
	for i := 0; i < parallelism; i++ {
		go func() {
			_, err := pqClientHelloSpec()
			done <- err
		}()
	}
	for i := 0; i < parallelism; i++ {
		if err := <-done; err != nil {
			t.Fatalf("parallel pqClientHelloSpec call: %v", err)
		}
	}

	// Re-snapshot the upstream spec AFTER the calls and compare.
	postSpec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		t.Fatalf("utls.UTLSIdToSpec (post): %v", err)
	}
	postCurves, postKS := snapshotMLKEMRelevantExtensions(t, postSpec)

	if len(preCurves) != len(postCurves) {
		t.Fatalf("SupportedCurves len drifted: pre=%d post=%d (pqClientHelloSpec mutated shared spec)",
			len(preCurves), len(postCurves))
	}
	for i := range preCurves {
		if preCurves[i] != postCurves[i] {
			t.Fatalf("SupportedCurves[%d] mutated: pre=%v post=%v", i, preCurves[i], postCurves[i])
		}
	}

	if len(preKS) != len(postKS) {
		t.Fatalf("KeyShares len drifted: pre=%d post=%d (pqClientHelloSpec mutated shared spec)",
			len(preKS), len(postKS))
	}
	for i := range preKS {
		if preKS[i] != postKS[i] {
			t.Fatalf("KeyShares[%d] mutated: pre=%v post=%v", i, preKS[i], postKS[i])
		}
	}
}

// snapshotMLKEMRelevantExtensions extracts copies of the SupportedCurves and
// KeyShares group slices for comparison. Returns plain CurveID slices (no
// pointer aliasing) so the caller can safely compare across pqClientHelloSpec
// calls.
func snapshotMLKEMRelevantExtensions(t *testing.T, spec utls.ClientHelloSpec) (curves []utls.CurveID, kShares []utls.CurveID) {
	t.Helper()
	for _, ext := range spec.Extensions {
		switch v := ext.(type) {
		case *utls.SupportedCurvesExtension:
			curves = append([]utls.CurveID(nil), v.Curves...)
		case *utls.KeyShareExtension:
			kShares = make([]utls.CurveID, len(v.KeyShares))
			for i, ks := range v.KeyShares {
				kShares[i] = ks.Group
			}
		}
	}
	return curves, kShares
}
