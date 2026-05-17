package core

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// resetStatsCallbacksForTest clears the package-global atomic.Pointer so each
// test starts in a known empty state. Plain Store(nil) on atomic.Pointer is
// supported and equivalent to "no callbacks installed". Subsequent tests in
// the same package may set their own callbacks.
func resetStatsCallbacksForTest() {
	sessionStatsCallbacks.Store(nil)
}

// TestSetStatsCallbacks_NilSafe verifies that EncryptChunk does not panic
// when no callbacks have been installed (initial process state). Plan §C11.2.
func TestSetStatsCallbacks_NilSafe(t *testing.T) {
	resetStatsCallbacksForTest()
	defer resetStatsCallbacksForTest()

	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	chunk := &Chunk{SessionID: s.ID, SeqNum: 0, Flags: FlagKeepalive}
	// Should not panic even though no callbacks are set.
	_, err := s.EncryptChunk(chunk)
	require.NoError(t, err, "EncryptChunk must work with no callbacks installed")
}

// TestSetStatsCallbacks_OverwriteSemantics verifies that a second
// SetStatsCallbacks call wholesale replaces the previous set — readers see
// the new callbacks atomically, never a torn intermediate. Plan §C11.2.
func TestSetStatsCallbacks_OverwriteSemantics(t *testing.T) {
	resetStatsCallbacksForTest()
	defer resetStatsCallbacksForTest()

	var firstHits, secondHits atomic.Int64
	SetStatsCallbacks(
		func() { firstHits.Add(1) },
		func() { firstHits.Add(1) },
		func() { firstHits.Add(1) },
	)

	s := NewSession(1, make([]byte, 32), make([]byte, 32))
	chunk := &Chunk{SessionID: s.ID, SeqNum: 0, Flags: FlagKeepalive}
	_, err := s.EncryptChunk(chunk)
	require.NoError(t, err)
	require.EqualValues(t, 1, firstHits.Load(), "first set must fire once before overwrite")

	// Now overwrite with a fresh set — first-set callbacks must NEVER fire again.
	SetStatsCallbacks(
		func() { secondHits.Add(1) },
		func() { secondHits.Add(1) },
		func() { secondHits.Add(1) },
	)
	_, err = s.EncryptChunk(chunk)
	require.NoError(t, err)
	require.EqualValues(t, 1, firstHits.Load(),
		"first-set onEncrypt must not fire after overwrite")
	require.EqualValues(t, 1, secondHits.Load(),
		"second-set onEncrypt must fire exactly once after overwrite")
}

// TestSetStatsCallbacks_AtomicPublish exercises concurrent SetStatsCallbacks
// callers against concurrent EncryptChunk hot-path readers. The previous
// design (three plain func() globals written non-atomically) tripped the
// race detector here; the atomic.Pointer publish must satisfy `-race`.
//
// Skip when run without CGO (Windows dev hosts often lack gcc) — the test
// still compiles and runs without the race detector but loses its purpose.
func TestSetStatsCallbacks_AtomicPublish(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("race-sensitive concurrency test; run on Linux/macOS CI under -race")
	}
	resetStatsCallbacksForTest()
	defer resetStatsCallbacksForTest()

	var stop atomic.Bool
	var wg sync.WaitGroup

	// Writer: continuously rebind callbacks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var n atomic.Int64
		for !stop.Load() {
			SetStatsCallbacks(
				func() { n.Add(1) },
				func() { n.Add(1) },
				func() { n.Add(1) },
			)
		}
	}()

	// Readers: run EncryptChunk on independent sessions concurrently.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := NewSession(1, make([]byte, 32), make([]byte, 32))
			chunk := &Chunk{SessionID: s.ID, SeqNum: 0, Flags: FlagKeepalive}
			for !stop.Load() {
				_, _ = s.EncryptChunk(chunk)
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
	// No panic + race detector passes (when run with -race) ⇒ success.
}
