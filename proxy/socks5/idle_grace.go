package socks5

import (
	"context"
	"sync/atomic"
	"time"
)

// downlinkIdleGrace / downlinkIdlePoll are var (not const) only so tests can
// shrink them to keep timing assertions fast. Production values are unchanged.
var (
	// downlinkIdleGrace is how long the uplink goroutine waits after the
	// request finished (uplink EOF) without ANY downlink activity before
	// tearing down the relay. Preserves the original 15s intent — but as an
	// idle window, not a hard cap on the whole download. ONLY consulted on the
	// loopback SOCKS5 path (socks5Replies=true). The in-process tun2socks path
	// does not idle-grace at all: it relies on memConn half-close vs full-close
	// to drive teardown (see tunnelTCPStream uplink goroutine).
	downlinkIdleGrace = 15 * time.Second

	// downlinkIdlePoll is the re-check granularity for the idle deadline.
	// 1s keeps teardown latency low without busy-waiting.
	downlinkIdlePoll = 1 * time.Second
)

// waitForIdleOrCancel blocks until either:
//   - the context is cancelled (the relay is shutting down for another
//     reason), or
//   - at least `grace` has elapsed since the most recent downlink activity
//     recorded in lastActivityNs (a Unix-nanosecond timestamp).
//
// It is the idle-aware replacement for the old fixed `time.After(grace)`
// guard in the uplink goroutine. The bug it fixes: once the SOCKS client
// finished sending its request (uplink EOF), the old code unconditionally
// cancelled the whole relay after 15s — killing large downloads that were
// still actively streaming the response body (e.g. `claude update`, npm
// installs, GitHub release binaries). Downloads taking longer than 15s after
// the request was sent were severed mid-transfer at exactly the 15s mark.
//
// With this function, the downlink goroutine stamps lastActivityNs on every
// received frame, so the deadline keeps moving forward as long as data is
// flowing. The relay is only torn down after `grace` of genuine silence —
// the original intent (don't hang forever on a half-closed connection)
// without the collateral damage to active downloads.
//
// poll is the granularity at which the deadline is re-checked; a small value
// (e.g. 1s in production) keeps teardown latency low without busy-waiting.
func waitForIdleOrCancel(ctx context.Context, lastActivityNs *atomic.Int64, grace, poll time.Duration) {
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	graceNs := grace.Nanoseconds()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			idle := time.Now().UnixNano() - lastActivityNs.Load()
			if idle >= graceNs {
				return
			}
		}
	}
}
