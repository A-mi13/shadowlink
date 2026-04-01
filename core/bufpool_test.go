package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetBuffer_Sizes(t *testing.T) {
	tests := []struct{ minSize, wantCap int }{
		{100, 512}, {512, 512}, {513, 4096}, {4000, 4096},
		{4097, 16384}, {16000, 16384}, {16385, 65536},
	}
	for _, tt := range tests {
		buf := GetBuffer(tt.minSize)
		assert.GreaterOrEqual(t, cap(buf), tt.wantCap, "minSize=%d", tt.minSize)
		PutBuffer(buf)
	}
}

func TestPutBufferZero_Clears(t *testing.T) {
	buf := GetBuffer(100)
	for i := range buf[:100] {
		buf[i] = 0xff
	}
	PutBufferZero(buf)
}

func BenchmarkGetPutBuffer(b *testing.B) {
	for b.Loop() {
		buf := GetBuffer(4096)
		PutBuffer(buf)
	}
}
