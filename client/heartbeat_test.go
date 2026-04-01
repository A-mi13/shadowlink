package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHeartbeatJitter(t *testing.T) {
	hb := NewHeartbeat(HeartbeatConfig{
		MinInterval: 3 * time.Second,
		MaxInterval: 7 * time.Second,
		MaxMissed:   3,
	})
	unique := map[time.Duration]bool{}
	for range 100 {
		d := hb.NextInterval()
		unique[d] = true
		assert.GreaterOrEqual(t, d, 3*time.Second)
		assert.Less(t, d, 7*time.Second)
	}
	assert.Greater(t, len(unique), 5, "intervals should vary with jitter")
}

func TestHeartbeatDeadDetection(t *testing.T) {
	hb := NewHeartbeat(HeartbeatConfig{
		MinInterval: time.Second,
		MaxInterval: 2 * time.Second,
		MaxMissed:   3,
	})

	assert.False(t, hb.IsDead())
	hb.RecordMiss()
	assert.False(t, hb.IsDead())
	assert.Equal(t, 1, hb.MissedCount())

	hb.RecordMiss()
	assert.False(t, hb.IsDead())

	hb.RecordMiss()
	assert.True(t, hb.IsDead(), "should be dead after 3 misses")
	assert.Equal(t, 3, hb.MissedCount())
}

func TestHeartbeatResetOnSuccess(t *testing.T) {
	hb := NewHeartbeat(HeartbeatConfig{
		MinInterval: time.Second,
		MaxInterval: 2 * time.Second,
		MaxMissed:   3,
	})

	hb.RecordMiss()
	hb.RecordMiss()
	assert.Equal(t, 2, hb.MissedCount())

	hb.RecordSuccess()
	assert.Equal(t, 0, hb.MissedCount())
	assert.False(t, hb.IsDead())
}

func TestHeartbeatReset(t *testing.T) {
	hb := NewHeartbeat(HeartbeatConfig{
		MinInterval: time.Second,
		MaxInterval: 2 * time.Second,
		MaxMissed:   3,
	})

	hb.RecordMiss()
	hb.RecordMiss()
	hb.RecordMiss()
	assert.True(t, hb.IsDead())

	hb.Reset()
	assert.False(t, hb.IsDead())
	assert.Equal(t, 0, hb.MissedCount())
}

func TestHeartbeatDefaultConfig(t *testing.T) {
	hb := NewHeartbeat(HeartbeatConfig{})
	d := hb.NextInterval()
	assert.GreaterOrEqual(t, d, 3*time.Second)
	assert.Less(t, d, 7*time.Second)
}

func TestHeartbeatConcurrency(t *testing.T) {
	hb := NewHeartbeat(DefaultHeartbeatConfig())

	done := make(chan struct{})
	go func() {
		for range 1000 {
			hb.RecordMiss()
			hb.RecordSuccess()
		}
		close(done)
	}()

	for range 1000 {
		hb.IsDead()
		hb.MissedCount()
	}
	<-done
	// No race — test passes if no panic
}
