package server

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetricsSnapshot(t *testing.T) {
	m := NewMetrics()
	m.ActiveClients.Store(5)
	m.ChunksReceived.Add(100)
	m.ChunksSent.Add(200)
	m.BytesReceived.Add(50000)
	m.BytesSent.Add(100000)
	m.HandshakesTotal.Add(10)
	m.HandshakesFailed.Add(2)

	snap := m.Snapshot()
	assert.Equal(t, int64(5), snap.ActiveClients)
	assert.Equal(t, uint64(100), snap.ChunksReceived)
	assert.Equal(t, uint64(200), snap.ChunksSent)
	assert.Equal(t, uint64(50000), snap.BytesReceived)
	assert.Equal(t, uint64(100000), snap.BytesSent)
	assert.Equal(t, uint64(10), snap.HandshakesTotal)
	assert.Equal(t, uint64(2), snap.HandshakesFailed)
	assert.GreaterOrEqual(t, snap.UptimeSeconds, 0.0)
	assert.Greater(t, snap.MemoryMB, 0.0)
	assert.Greater(t, snap.GoRoutines, 0)
	assert.False(t, snap.Backpressure)
}

func TestMetricsAtomicIncrements(t *testing.T) {
	m := NewMetrics()

	m.ActiveClients.Add(1)
	m.ActiveClients.Add(1)
	m.ActiveClients.Add(-1)
	assert.Equal(t, int64(1), m.ActiveClients.Load())

	m.ChunksReceived.Add(5)
	m.ChunksReceived.Add(3)
	assert.Equal(t, uint64(8), m.ChunksReceived.Load())
}

func TestBackpressureCheckNormal(t *testing.T) {
	m := NewMetrics()

	// Under normal conditions, should return default
	maxConns, reject := m.BackpressureCheck(8)
	assert.Equal(t, 8, maxConns)
	assert.False(t, reject)
	assert.False(t, m.backpressureActive.Load())
}

func TestBackpressureStateTracking(t *testing.T) {
	m := NewMetrics()

	// Normal check should set backpressure to false
	m.backpressureActive.Store(true)
	m.BackpressureCheck(8)
	// Under normal memory, should clear backpressure
	assert.False(t, m.backpressureActive.Load())
}

func TestMetricsHTTPEndpoint(t *testing.T) {
	m := NewMetrics()
	m.ActiveClients.Store(3)
	m.ChunksReceived.Add(42)

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/metrics", nil)
	m.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var snap MetricsSnapshot
	err := json.Unmarshal(w.Body.Bytes(), &snap)
	require.NoError(t, err)
	assert.Equal(t, int64(3), snap.ActiveClients)
	assert.Equal(t, uint64(42), snap.ChunksReceived)
	assert.Greater(t, snap.MemoryMB, 0.0)
}

func TestMetricsJSON(t *testing.T) {
	m := NewMetrics()
	snap := m.Snapshot()

	data, err := json.Marshal(snap)
	require.NoError(t, err)

	// Should have all expected fields
	var parsed map[string]any
	json.Unmarshal(data, &parsed)
	expectedFields := []string{
		"active_clients", "active_connections",
		"chunks_received", "chunks_sent",
		"bytes_received", "bytes_sent",
		"handshakes_total", "handshakes_failed",
		"rejected_overload", "uptime_seconds",
		"memory_mb", "goroutines", "backpressure_active",
	}
	for _, f := range expectedFields {
		assert.Contains(t, parsed, f, "missing field: %s", f)
	}
}

func TestMetricsRejectedOverload(t *testing.T) {
	m := NewMetrics()
	m.RejectedOverload.Add(1)
	m.RejectedOverload.Add(1)
	m.RejectedOverload.Add(1)
	assert.Equal(t, uint64(3), m.RejectedOverload.Load())

	snap := m.Snapshot()
	assert.Equal(t, uint64(3), snap.RejectedOverload)
}
