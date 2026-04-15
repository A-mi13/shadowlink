package client

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/nixavpn/shadowlink/core"
)

// Stats holds live counters for debugging throughput/contention issues.
//
// Counters are package-global and accessed via atomic ops so hot paths pay
// nothing more than a CAS. The StartStatsLogger goroutine periodically logs
// *deltas* (not totals) so you can tell at a glance how much traffic each
// subsystem is generating right now — e.g. "is UDP poll storm dominating
// the HTTP transport?" or "how many per-stream WSs open per second?".
type statsRegistry struct {
	// Cover traffic HTTP POSTs from DirectTransport/CDNTransport.
	CoverPosts atomic.Int64
	// UDP ASSOCIATE poll ticker fires (20ms each) sending a poll POST.
	UdpPolls atomic.Int64
	// Per-stream WebSocket connections opened (fresh WS per SOCKS5 CONNECT).
	WsCreated atomic.Int64
	// Per-stream WebSocket connections died (reader/writer exit).
	WsDied atomic.Int64
	// Per-stream WS upgrades via the ready pool (Acquire returned a warmed WS).
	WsFromPool atomic.Int64
	// Session.EncryptChunk calls (every outgoing data/control frame).
	Encrypts atomic.Int64
	// Session.DecryptChunkSafe calls (every incoming frame).
	Decrypts atomic.Int64
	// Session.DecryptChunkSafe that failed — high number ⇒ wrong key, out-of-window
	// seq, or anti-replay rejection. A healthy client should see zero.
	DecryptFails atomic.Int64
	// SOCKS5 CONNECT requests accepted (both per-stream and pooled paths).
	SocksConnects atomic.Int64
	// Uplink bytes read from SOCKS5 client (before encryption).
	UplinkBytes atomic.Int64
	// Downlink bytes written to SOCKS5 client (after decryption).
	DownlinkBytes atomic.Int64
}

// Stats is the singleton stats registry. All increments across the codebase
// use this variable directly.
var Stats statsRegistry

func init() {
	// Wire core.Session encrypt/decrypt counters into our atomic stats without
	// making core/ depend on client/.
	core.SetStatsCallbacks(
		func() { Stats.Encrypts.Add(1) },
		func() { Stats.Decrypts.Add(1) },
		func() { Stats.DecryptFails.Add(1) },
	)
}

// StartStatsLogger launches a goroutine that logs counter deltas every
// interval until ctx is cancelled. Called from the client engine after
// Connect() succeeds so we don't log while the session is still coming up.
//
// First line after the first interval is `delta over N.Ns` so it's obvious
// the numbers are per-interval, not cumulative.
func StartStatsLogger(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go func() {
		var (
			lastCover, lastUDP, lastWSNew, lastWSDie, lastPool int64
			lastEnc, lastDec, lastDecFail                      int64
			lastSocks, lastUp, lastDown                        int64
		)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			cover := Stats.CoverPosts.Load()
			udp := Stats.UdpPolls.Load()
			wsNew := Stats.WsCreated.Load()
			wsDie := Stats.WsDied.Load()
			pool := Stats.WsFromPool.Load()
			enc := Stats.Encrypts.Load()
			dec := Stats.Decrypts.Load()
			decFail := Stats.DecryptFails.Load()
			socks := Stats.SocksConnects.Load()
			up := Stats.UplinkBytes.Load()
			down := Stats.DownlinkBytes.Load()

			slog.Info("shadowlink client stats (delta)",
				"interval", interval,
				"cover_posts", cover-lastCover,
				"udp_polls", udp-lastUDP,
				"ws_created", wsNew-lastWSNew,
				"ws_died", wsDie-lastWSDie,
				"ws_from_pool", pool-lastPool,
				"encrypts", enc-lastEnc,
				"decrypts", dec-lastDec,
				"decrypt_fails", decFail-lastDecFail,
				"socks_connects", socks-lastSocks,
				"uplink_kb", (up-lastUp)/1024,
				"downlink_kb", (down-lastDown)/1024,
			)

			lastCover, lastUDP, lastWSNew, lastWSDie, lastPool = cover, udp, wsNew, wsDie, pool
			lastEnc, lastDec, lastDecFail = enc, dec, decFail
			lastSocks, lastUp, lastDown = socks, up, down
		}
	}()
}
