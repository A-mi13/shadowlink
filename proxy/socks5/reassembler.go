package socks5

type reasmStatus int

const (
	reasmOK       reasmStatus = iota // out holds 0+ in-order frames to write
	reasmDup                         // duplicate (seq < expected) — dropped
	reasmOverflow                    // size cap exceeded → caller breaks stream
)

// reassembler reorders per-stream downlink chunks by their server-assigned
// downSeq into a strictly monotonic stream for conn.Write (§5.4, F1).
// expectedSeq starts at 1 (NEW-2: seq 0 is control, never reaches here).
// Not safe for concurrent use — owned by one downlink goroutine.
type reassembler struct {
	expectedSeq uint64
	pending     map[uint64][]byte
	bufBytes    int
	maxBytes    int
}

func newReassembler(maxBytes int) *reassembler {
	return &reassembler{expectedSeq: 1, pending: make(map[uint64][]byte), maxBytes: maxBytes}
}

// push offers one (seq, data). Returns the ordered run now ready for
// conn.Write (possibly empty) and a status. On reasmOverflow the caller MUST
// break the stream (degradation, not corruption).
func (r *reassembler) push(seq uint64, data []byte) (out [][]byte, st reasmStatus) {
	if seq < r.expectedSeq {
		return nil, reasmDup
	}
	if _, exists := r.pending[seq]; !exists {
		r.pending[seq] = data
		r.bufBytes += len(data)
	}
	for {
		nf, ok := r.pending[r.expectedSeq]
		if !ok {
			break
		}
		out = append(out, nf)
		r.bufBytes -= len(nf)
		delete(r.pending, r.expectedSeq)
		r.expectedSeq++
	}
	if r.bufBytes > r.maxBytes {
		return out, reasmOverflow
	}
	return out, reasmOK
}

// hasGap reports whether buffered frames sit past expectedSeq (a hole exists)
// — drives the gap-timer (NEW-1, §5.4).
func (r *reassembler) hasGap() bool { return len(r.pending) > 0 }
