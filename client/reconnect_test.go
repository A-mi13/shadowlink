package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackoffDuration(t *testing.T) {
	tests := []struct {
		attempt int
		minExp  time.Duration
		maxExp  time.Duration
	}{
		{0, 750 * time.Millisecond, 1250 * time.Millisecond},
		{1, 1500 * time.Millisecond, 2500 * time.Millisecond},
		{2, 3 * time.Second, 5 * time.Second},
		{5, 24 * time.Second, 40 * time.Second},
		{10, 45 * time.Second, 75 * time.Second},
		{20, 45 * time.Second, 75 * time.Second},
	}
	for _, tt := range tests {
		d := backoffDuration(tt.attempt)
		assert.GreaterOrEqual(t, d, tt.minExp, "attempt %d too short", tt.attempt)
		assert.LessOrEqual(t, d, tt.maxExp, "attempt %d too long", tt.attempt)
	}
}

func TestConnectWithRetry_CancelledContext(t *testing.T) {
	cl := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := cl.ConnectWithRetry(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}
