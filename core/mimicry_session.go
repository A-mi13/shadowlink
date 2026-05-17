// Package core — see session.go for the broader Session lifecycle.
package core

import (
	"math"
	mathrand "math/rand/v2"
)

// MimicrySession holds per-session sticky state for browser-skin distribution
// samplers. Lives in core (not skins/browser) so that core.SessionManager.Create
// can populate it BEFORE the session is published into the manager map — that
// guarantees a happens-before edge from the assignment to every concurrent
// reader of session.MimicrySession. Plan §C11.3 (May 2026 audit, T1 M3): the
// previous design assigned MimicrySession after Create returned, leaving the
// hot-path buildResponse reader without an explicit memory ordering edge to
// the assignment. On x86 TSO it worked; a future ARM port or reordering
// compiler pass could observe a torn read.
//
// Lifetime: created at session creation by core.NewMimicrySession, discarded
// on session removal.
//
// Concurrency: NextPollLambda is set once at session creation and read-only
// thereafter; safe for concurrent reads. Per-event jitter (browser.NextPollSeconds
// in skins/browser/mimicry.go) applies its own ±15% jitter using math/rand/v2
// globals (goroutine-safe).
//
// T2.4 closure (Phase 3 Plan A); publish ordering tightened by §C11.3 (May 2026).
type MimicrySession struct {
	// NextPollLambda is the Pareto-sampled mean polling interval in seconds,
	// truncated to [5, 600]. Sticky for session lifetime.
	NextPollLambda float64
}

// NewMimicrySession constructs a sticky-state container with NextPollLambda
// sampled from Pareto(α=1.5) truncated to [5, 600] seconds. Pure stdlib
// implementation so SessionManager.Create can call it without importing
// skins/browser (which would create an import cycle: browser → core → browser).
//
// skins/browser.NewMimicrySession is preserved as a thin shim over this
// constructor for backward compatibility with any external callers; it
// returns the same value (same sampler, same parameters).
//
// Plan §C11.3 (May 2026 audit) moved the constructor here so that
// SessionManager.Create can populate session.MimicrySession before the
// session is published into the sessions map — establishing a clean
// happens-before edge from initialization to every concurrent reader.
func NewMimicrySession() *MimicrySession {
	return &MimicrySession{
		NextPollLambda: paretoTruncated(1.5, 5.0, 600.0),
	}
}

// paretoTruncated returns a Pareto(alpha) variate truncated to [lo, hi].
// Inverse-CDF sampling x = lo / (1 - U)^(1/alpha) with rejection for x > hi.
// math/rand/v2 globals are goroutine-safe.
func paretoTruncated(alpha, lo, hi float64) float64 {
	for {
		u := mathrand.Float64()
		if u >= 1.0 {
			continue
		}
		x := lo / math.Pow(1.0-u, 1.0/alpha)
		if x <= hi {
			return x
		}
	}
}
