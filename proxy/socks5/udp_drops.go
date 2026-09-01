package socks5

import (
	"sort"
	"strings"
	"sync/atomic"

	"github.com/nixavpn/shadowlink/client"
)

// Observability for silently dropped UDP datagrams.
//
// Every discard on the client UDP path used to be a bare `continue`: no log
// line, no counter. When the NixaVPN client team measured 33% DNS success over
// sing-box (2026-09-01), nothing on our side could say which of the six
// discard branches was firing — the only UDP-adjacent metric we had,
// shadowlink_ws_frames_discarded_total, lives on the SERVER and counts AEAD and
// sequence-window failures, so it is silent by construction for a datagram
// dropped before it is ever sealed.
//
// Logging these is not an option: a peer that floods malformed datagrams would
// fill the disk. Counters are the observable form that survives that, which is
// the same conclusion the server reached for undecryptable frames.
//
// These are process-wide and cumulative across associations, matching how the
// client's other counters are reported. Deltas between reads give the rate.

type udpDropReason int

const (
	dropReasonShort udpDropReason = iota // datagram shorter than a SOCKS5 UDP header
	dropReasonBadHeader                  // FRAG != 0, unknown ATYP, or truncated address
	dropReasonForeignIP                  // source IP differs from the association's pinned IP
	dropReasonEmptyPayload               // header parsed but no data followed
	dropReasonBadChunk                   // downlink chunk unparseable or empty
	dropReasonUnroutableReply            // response could not be addressed back to a client
	dropReasonNoClientYet                // response arrived before the client sent anything

	udpDropReasonCount
)

var udpDropNames = [udpDropReasonCount]string{
	dropReasonShort:           "short_datagram",
	dropReasonBadHeader:       "bad_header",
	dropReasonForeignIP:       "foreign_source_ip",
	dropReasonEmptyPayload:    "empty_payload",
	dropReasonBadChunk:        "bad_downlink_chunk",
	dropReasonUnroutableReply: "unroutable_reply",
	dropReasonNoClientYet:     "no_client_yet",
}

// udpDropCounters holds one counter per discard reason.
type udpDropCounters struct {
	n [udpDropReasonCount]atomic.Uint64
}

// udpDrops is the process-wide counter set for the SOCKS5 UDP path.
var udpDrops udpDropCounters

// Register the per-reason breakdown with the client's stats line. Without this
// the aggregate in client.Stats would say only that datagrams were lost, which
// is exactly the blind spot these counters exist to remove.
func init() { client.SetUDPDropReporter(UDPDropsSummary) }

// Add increments the counter for reason by delta. Unknown reasons are ignored
// rather than panicking: a metric must never take down the data path.
//
// The aggregate is mirrored into client.Stats so it reaches the client's
// Prometheus output; the per-reason detail stays here because client cannot
// import this package (proxy/socks5 -> client is the only legal direction).
func (c *udpDropCounters) Add(reason udpDropReason, delta uint64) {
	if reason < 0 || reason >= udpDropReasonCount {
		return
	}
	c.n[reason].Add(delta)
	client.Stats.UDPDatagramsDroppedTotal.Add(delta)
}

// Get returns the current count for reason.
func (c *udpDropCounters) Get(reason udpDropReason) uint64 {
	if reason < 0 || reason >= udpDropReasonCount {
		return 0
	}
	return c.n[reason].Load()
}

// Total returns the sum across all reasons.
func (c *udpDropCounters) Total() uint64 {
	var sum uint64
	for i := range c.n {
		sum += c.n[i].Load()
	}
	return sum
}

// Snapshot returns non-zero counters keyed by reason name. Zero-valued reasons
// are omitted so a caller logging this does not emit seven constant zeros every
// interval.
func (c *udpDropCounters) Snapshot() map[string]uint64 {
	out := make(map[string]uint64, udpDropReasonCount)
	for i := range c.n {
		if v := c.n[i].Load(); v != 0 {
			out[udpDropNames[i]] = v
		}
	}
	return out
}

// reset zeroes every counter, including the client.Stats mirror. Test-only;
// there is no production reason to clear a cumulative counter. The mirror is
// reset too so tests asserting on it do not inherit another test's drops.
func (c *udpDropCounters) reset() {
	for i := range c.n {
		c.n[i].Store(0)
	}
	client.Stats.UDPDatagramsDroppedTotal.Store(0)
}

// UDPDropsSnapshot exposes the counters for the client's stats reporting.
// Returns nil when nothing has been dropped, so the caller can omit the field
// entirely rather than logging an empty map.
func UDPDropsSnapshot() map[string]uint64 {
	s := udpDrops.Snapshot()
	if len(s) == 0 {
		return nil
	}
	return s
}

// UDPDropsSummary renders the non-zero counters as a stable "reason=n" string
// for a single log field, or "" when there is nothing to report. Sorted so the
// field is diffable between intervals.
func UDPDropsSummary() string {
	s := udpDrops.Snapshot()
	if len(s) == 0 {
		return ""
	}
	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(utoa(s[k]))
	}
	return b.String()
}

func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
