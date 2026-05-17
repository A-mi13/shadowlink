package client

import (
	"math/rand/v2"
	"sync"
	"time"
)

// HeartbeatConfig controls keepalive and freeze detection parameters.
type HeartbeatConfig struct {
	// MinInterval and MaxInterval for heartbeat jitter (spec: 3-7 seconds).
	MinInterval time.Duration
	MaxInterval time.Duration

	// MaxMissed is the number of missed heartbeats before declaring transport dead.
	MaxMissed int
}

// DefaultHeartbeatConfig returns spec-compliant defaults.
func DefaultHeartbeatConfig() HeartbeatConfig {
	return HeartbeatConfig{
		MinInterval: 3 * time.Second,
		MaxInterval: 7 * time.Second,
		MaxMissed:   3,
	}
}

// Heartbeat manages keepalive probes with randomized jitter.
// Fixed intervals are a behavioral fingerprint — jitter is mandatory.
type Heartbeat struct {
	config HeartbeatConfig
	missed int
	mu     sync.Mutex
}

// NewHeartbeat creates a heartbeat manager.
func NewHeartbeat(config HeartbeatConfig) *Heartbeat {
	if config.MinInterval == 0 {
		config = DefaultHeartbeatConfig()
	}
	if config.MaxMissed == 0 {
		config.MaxMissed = 3
	}
	return &Heartbeat{config: config}
}

// NextInterval returns a randomized delay until the next heartbeat.
// Per spec: 3-7 seconds with jitter, never fixed.
func (h *Heartbeat) NextInterval() time.Duration {
	if h.config.MaxInterval <= h.config.MinInterval {
		return h.config.MinInterval
	}
	spread := h.config.MaxInterval - h.config.MinInterval
	jitter := time.Duration(rand.Int64N(int64(spread)))
	return h.config.MinInterval + jitter
}

// RecordMiss records a missed heartbeat response.
func (h *Heartbeat) RecordMiss() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.missed++
}

// RecordSuccess records a successful heartbeat response, resetting the miss counter.
func (h *Heartbeat) RecordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.missed = 0
}

// IsDead returns true if too many consecutive heartbeats have been missed.
func (h *Heartbeat) IsDead() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.missed >= h.config.MaxMissed
}

// MissedCount returns the current number of consecutive missed heartbeats.
func (h *Heartbeat) MissedCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.missed
}

// Reset clears the miss counter (e.g., after transport switch).
func (h *Heartbeat) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.missed = 0
}
