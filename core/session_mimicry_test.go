package core

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSessionManagerCreate_MimicrySessionPopulated guards Plan §C11.3
// (May 2026 audit, T1 M3): MimicrySession must be populated BEFORE the
// session is observable from the manager map. We assert the returned
// session carries a non-nil MimicrySession with a sensibly-bounded
// NextPollLambda — the post-Create read happens through the same map
// publish edge that any concurrent reader would use.
func TestSessionManagerCreate_MimicrySessionPopulated(t *testing.T) {
	sm := NewSessionManager(time.Minute)
	s, err := sm.Create(make([]byte, 32), make([]byte, 32))
	require.NoError(t, err)
	require.NotNil(t, s.MimicrySession,
		"SessionManager.Create must populate MimicrySession before returning")
	require.GreaterOrEqual(t, s.MimicrySession.NextPollLambda, 5.0,
		"NextPollLambda below truncation lower bound")
	require.LessOrEqual(t, s.MimicrySession.NextPollLambda, 600.0,
		"NextPollLambda above truncation upper bound")

	// Verify the same session retrieved through the public Get() path also
	// sees the populated MimicrySession — this is the path real readers
	// (e.g. server/handler.go::buildResponse) traverse.
	got, ok := sm.Get(s.ID)
	require.True(t, ok)
	require.NotNil(t, got.MimicrySession)
}

// TestSessionManagerCreate_NoRaceMimicrySession exercises concurrent Create
// + Get readers — the readers simulate the buildResponse hot path in the
// server. The previous design assigned MimicrySession AFTER Create returned,
// so a Get() racing the assignment could observe nil. With §C11.3 the
// assignment happens before the map publish, so every Get must observe a
// populated MimicrySession.
//
// Skipped on Windows because race detection (-race) requires CGO; the test
// is structured so it still compiles and runs without -race but loses its
// teeth.
func TestSessionManagerCreate_NoRaceMimicrySession(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("race-sensitive concurrency test; run on Linux/macOS CI under -race")
	}

	sm := NewSessionManager(time.Minute)

	const writers = 4
	const readers = 4
	const perWriter = 200

	var (
		wg          sync.WaitGroup
		writerWg    sync.WaitGroup
		readerStop  = make(chan struct{})
		nilObserved atomic.Int64
	)

	// Writers — Create sessions concurrently.
	for i := 0; i < writers; i++ {
		writerWg.Add(1)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer writerWg.Done()
			for j := 0; j < perWriter; j++ {
				s, err := sm.Create(make([]byte, 32), make([]byte, 32))
				if err != nil {
					t.Errorf("Create: %v", err)
					return
				}
				if s.MimicrySession == nil {
					nilObserved.Add(1)
					return
				}
			}
		}()
	}

	// Readers — Get sessions repeatedly via ForEach and dereference
	// MimicrySession on every visit. Ranging the live map via ForEach is the
	// production read path that races against Create's map publish.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-readerStop:
					return
				default:
				}
				sm.ForEach(func(s *Session) bool {
					if s.MimicrySession == nil {
						nilObserved.Add(1)
						return true
					}
					_ = s.MimicrySession.NextPollLambda
					return false
				})
			}
		}()
	}

	// Wait for writers, then signal readers to stop.
	writerWg.Wait()
	close(readerStop)
	wg.Wait()

	require.Zero(t, nilObserved.Load(),
		"observed nil MimicrySession on a published session — §C11.3 ordering broken")
}
