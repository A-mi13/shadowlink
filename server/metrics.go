package server

import (
	"encoding/json"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// Metrics tracks server performance and resource usage.
type Metrics struct {
	ActiveClients     atomic.Int64
	ActiveConnections atomic.Int64
	ChunksReceived    atomic.Uint64
	ChunksSent        atomic.Uint64
	BytesReceived     atomic.Uint64
	BytesSent         atomic.Uint64
	HandshakesTotal   atomic.Uint64
	HandshakesFailed  atomic.Uint64
	RejectedOverload  atomic.Uint64

	// Backpressure state
	backpressureActive atomic.Bool

	startTime time.Time
}

// NewMetrics creates a metrics tracker.
func NewMetrics() *Metrics {
	return &Metrics{startTime: time.Now()}
}

// Snapshot returns a point-in-time copy of all metrics.
type MetricsSnapshot struct {
	ActiveClients     int64   `json:"active_clients"`
	ActiveConnections int64   `json:"active_connections"`
	ChunksReceived    uint64  `json:"chunks_received"`
	ChunksSent        uint64  `json:"chunks_sent"`
	BytesReceived     uint64  `json:"bytes_received"`
	BytesSent         uint64  `json:"bytes_sent"`
	HandshakesTotal   uint64  `json:"handshakes_total"`
	HandshakesFailed  uint64  `json:"handshakes_failed"`
	RejectedOverload  uint64  `json:"rejected_overload"`
	UptimeSeconds     float64 `json:"uptime_seconds"`
	MemoryMB          float64 `json:"memory_mb"`
	GoRoutines        int     `json:"goroutines"`
	Backpressure      bool    `json:"backpressure_active"`
}

// Snapshot returns current metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return MetricsSnapshot{
		ActiveClients:     m.ActiveClients.Load(),
		ActiveConnections: m.ActiveConnections.Load(),
		ChunksReceived:    m.ChunksReceived.Load(),
		ChunksSent:        m.ChunksSent.Load(),
		BytesReceived:     m.BytesReceived.Load(),
		BytesSent:         m.BytesSent.Load(),
		HandshakesTotal:   m.HandshakesTotal.Load(),
		HandshakesFailed:  m.HandshakesFailed.Load(),
		RejectedOverload:  m.RejectedOverload.Load(),
		UptimeSeconds:     time.Since(m.startTime).Seconds(),
		MemoryMB:          float64(memStats.Alloc) / 1024 / 1024,
		GoRoutines:        runtime.NumGoroutine(),
		Backpressure:      m.backpressureActive.Load(),
	}
}

// BackpressureCheck evaluates memory pressure and updates backpressure state.
// Returns the recommended max connections per client.
// Per spec section 9:
//   - RAM > 80% → reduce max_conns_per_client to 4
//   - RAM > 90% → reject new connections (503)
func (m *Metrics) BackpressureCheck(maxConnsDefault int) (maxConns int, rejectNew bool) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Use Go's heap stats — Sys is total OS memory, Alloc is in-use
	// For a 2GB VPS, we target staying under ~1.5GB for Go process
	allocMB := float64(memStats.Alloc) / 1024 / 1024
	sysMB := float64(memStats.Sys) / 1024 / 1024

	// Adaptive thresholds based on system memory
	// Use Sys as rough indicator of available memory
	highThreshold := sysMB * 0.8
	critThreshold := sysMB * 0.9

	if allocMB > critThreshold {
		m.backpressureActive.Store(true)
		return 2, true // critical: reject new, minimal conns
	}

	if allocMB > highThreshold {
		m.backpressureActive.Store(true)
		return 4, false // high: reduce conns but allow new clients
	}

	m.backpressureActive.Store(false)
	return maxConnsDefault, false
}

// ServeHTTP handles metrics endpoint (for NixaVPN agent integration).
// Returns JSON with current metrics. NOT exposed to public — only internal.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	snap := m.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(snap)
}
