package client

import (
	"sync/atomic"
	"time"
)

// streamEntry tracks per-stream state required for both routing
// (which slot owns the stream) and diagnostics (when this stream
// last had wire activity).
//
// Stored as *streamEntry in WSPoolTransport.streamMap (sync.Map);
// pointer storage avoids re-Store on lastWriteNs updates.
//
// Concurrency: slotIdx is set once at construction by newStreamEntry
// and never mutated thereafter — safe for unlocked reads. lastWriteNs
// is updated and read exclusively through its atomic.Int64 methods.
type streamEntry struct {
	slotIdx     int
	lastWriteNs atomic.Int64
}

// newStreamEntry constructs a fully-initialized entry: slotIdx pinned,
// lastWriteNs pre-stamped to time.Now() so snapshot logic never sees
// a zero clock.
func newStreamEntry(slotIdx int) *streamEntry {
	e := &streamEntry{slotIdx: slotIdx}
	e.lastWriteNs.Store(time.Now().UnixNano())
	return e
}
