package core

import (
	"runtime"
	"sync"
)

var bufPools = [4]sync.Pool{
	{New: func() any { b := make([]byte, 512); return &b }},
	{New: func() any { b := make([]byte, 4096); return &b }},
	{New: func() any { b := make([]byte, 16384); return &b }},
	{New: func() any { b := make([]byte, 65536); return &b }},
}

var tierSizes = [4]int{512, 4096, 16384, 65536}

func tierIndex(minSize int) int {
	for i, s := range tierSizes {
		if minSize <= s {
			return i
		}
	}
	return 3
}

// GetBuffer returns a pooled buffer with cap >= minSize.
func GetBuffer(minSize int) []byte {
	idx := tierIndex(minSize)
	bp := bufPools[idx].Get().(*[]byte)
	return (*bp)[:tierSizes[idx]]
}

// PutBuffer returns buf to the pool. buf must have been obtained from GetBuffer.
// Buffers with non-standard capacities are silently discarded.
func PutBuffer(buf []byte) {
	c := cap(buf)
	idx := -1
	for i, s := range tierSizes {
		if c == s {
			idx = i
			break
		}
	}
	if idx < 0 {
		return
	}
	b := buf[:c]
	bufPools[idx].Put(&b)
}

// PutBufferZero zeroes buf before returning it to the pool.
// Use when buf may have contained sensitive data (keys, decrypted payloads).
// P-2 fix: runtime.KeepAlive prevents the compiler from eliminating the zeroing
// loop as a dead store (the slice is "used" after the loop from the compiler's perspective).
func PutBufferZero(buf []byte) {
	b := buf[:cap(buf)]
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(&b)
	PutBuffer(buf)
}
