package client

import (
	"time"
)

// storeStreamForTest constructs and stores a streamEntry with a
// fresh lastWriteNs stamp. Tests use this instead of constructing
// streamEntry directly to keep newStreamEntry's invariants centralized.
func storeStreamForTest(p *WSPoolTransport, streamID uint16, slotIdx int) {
	p.streamMap.Store(streamID, newStreamEntry(slotIdx))
}

// storeStreamForTestWithAge stores an entry whose lastWriteNs is offset
// `age` into the past — used to drive idle/active scenarios in snapshot
// and drain tests.
func storeStreamForTestWithAge(p *WSPoolTransport, streamID uint16, slotIdx int, age time.Duration) {
	e := newStreamEntry(slotIdx)
	e.lastWriteNs.Store(time.Now().Add(-age).UnixNano())
	p.streamMap.Store(streamID, e)
}
