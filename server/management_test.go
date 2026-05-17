package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testMgmtKey = "test-secret-key-42"

func newTestManagement() (*ManagementHandler, *ClientAuth) {
	ca := NewClientAuth([]string{"u1:d1", "u1:d2", "u2:d1"})
	ca.defaultMax = 3
	mh := NewManagementHandler(ca, NewMetrics(), testMgmtKey)
	return mh, ca
}

func mgmtRequest(t *testing.T, method, path string, body any, key string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		err := json.NewEncoder(&buf).Encode(body)
		require.NoError(t, err)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-Management-Key", key)
	}
	return req
}

func TestManagementBadKey(t *testing.T) {
	mh, _ := newTestManagement()

	tests := []struct {
		name string
		key  string
	}{
		{"empty key", ""},
		{"wrong key", "wrong-key"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := mgmtRequest(t, "GET", "/manage/status", nil, tc.key)
			rr := httptest.NewRecorder()
			mh.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusForbidden, rr.Code)
		})
	}
}

func TestManagementAddClient(t *testing.T) {
	mh, ca := newTestManagement()

	// Add a new client.
	body := map[string]string{"client_id": "u3:d1"}
	req := mgmtRequest(t, "POST", "/manage/clients", body, testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.True(t, ca.IsAuthorized("u3:d1"), "u3:d1 should be authorized after add")
}

func TestManagementAddClientMissingID(t *testing.T) {
	mh, _ := newTestManagement()

	body := map[string]string{}
	req := mgmtRequest(t, "POST", "/manage/clients", body, testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestManagementRemoveClient(t *testing.T) {
	mh, ca := newTestManagement()

	// Verify u1:d1 is authorized.
	require.True(t, ca.IsAuthorized("u1:d1"))

	// Create a session for u1:d1 to test cleanup.
	ca.OnSessionCreated("u1:d1", 100)
	require.Equal(t, 1, ca.ActiveSessionCount("u1"))

	req := mgmtRequest(t, "DELETE", "/manage/clients/u1:d1", nil, testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.False(t, ca.IsAuthorized("u1:d1"), "u1:d1 should be removed after delete")
}

func TestManagementSync(t *testing.T) {
	mh, ca := newTestManagement()

	// Create sessions for old clients.
	ca.OnSessionCreated("u1:d1", 100)
	ca.OnSessionCreated("u2:d1", 200)

	syncBody := struct {
		Clients []string       `json:"clients"`
		Limits  map[string]int `json:"limits"`
	}{
		Clients: []string{"u5:d1", "u5:d2", "u6:d1"},
		Limits:  map[string]int{"u5": 5, "u6": 2},
	}

	req := mgmtRequest(t, "POST", "/manage/sync", syncBody, testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Old clients should be gone.
	assert.False(t, ca.IsAuthorized("u1:d1"), "u1:d1 should be removed after sync")
	assert.False(t, ca.IsAuthorized("u2:d1"), "u2:d1 should be removed after sync")

	// New clients should be authorized.
	assert.True(t, ca.IsAuthorized("u5:d1"))
	assert.True(t, ca.IsAuthorized("u5:d2"))
	assert.True(t, ca.IsAuthorized("u6:d1"))

	// Old sessions should be cleaned up.
	assert.Equal(t, 0, ca.ActiveSessionCount("u1"))
	assert.Equal(t, 0, ca.ActiveSessionCount("u2"))
}

func TestManagementSetLimit(t *testing.T) {
	mh, ca := newTestManagement()

	// Create 3 sessions for u1 (at default limit).
	ca.OnSessionCreated("u1:d1", 100)
	ca.OnSessionCreated("u1:d2", 200)
	ca.OnSessionCreated("u1:d3", 300)

	// Adding a new client and checking limit — it should be blocked at default=3.
	ca.AddClient("u1:d4")
	assert.False(t, ca.CheckDeviceLimit("u1:d4"), "should be blocked at default limit=3")

	// Set limit to 5 via management API.
	body := struct {
		UserID     string `json:"user_id"`
		MaxDevices int    `json:"max_devices"`
	}{
		UserID:     "u1",
		MaxDevices: 5,
	}
	req := mgmtRequest(t, "POST", "/manage/set-limit", body, testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	// Now u1:d4 should be allowed.
	assert.True(t, ca.CheckDeviceLimit("u1:d4"), "should be allowed after set-limit to 5")
}

func TestManagementStatus(t *testing.T) {
	mh, ca := newTestManagement()

	ca.OnSessionCreated("u1:d1", 100)
	ca.OnSessionCreated("u2:d1", 200)

	req := mgmtRequest(t, "GET", "/manage/status", nil, testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var resp StatusResponse
	err := json.NewDecoder(rr.Body).Decode(&resp)
	require.NoError(t, err)

	assert.Equal(t, 3, resp.TotalClients, "should have 3 authorized clients")
	assert.Equal(t, 2, resp.ActiveSessions, "should have 2 active sessions")
	assert.Contains(t, resp.Clients, "u1:d1")
	assert.Contains(t, resp.Clients, "u1:d2")
	assert.Contains(t, resp.Clients, "u2:d1")
}

// TestManagementMetricsEndpoint verifies the /metrics route added in the H4
// deploy fix: GET /metrics with a valid management key serves Prometheus text
// format (via ?format=prom) and includes the migration counters.
func TestManagementMetricsEndpoint(t *testing.T) {
	mh, _ := newTestManagement()
	mh.metrics.NewPathHits.Add(9)
	mh.metrics.HandshakesNewTotal.Add(3)

	req := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	req.Header.Set("X-Management-Key", testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "shadowlink_new_path_hits_total 9")
	assert.Contains(t, body, "shadowlink_handshakes_new_total 3")
}

// TestManagementMetrics_XAPIKeyAlias verifies the convenience alias — some
// scraper tools only support the `X-API-Key` header name; we accept both.
func TestManagementMetrics_XAPIKeyAlias(t *testing.T) {
	mh, _ := newTestManagement()
	mh.metrics.NewPathHits.Add(5)

	req := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	req.Header.Set("X-API-Key", testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "shadowlink_new_path_hits_total 5")
}

// TestManagementMetrics_WrongKeyForbidden confirms that /metrics is gated by
// the same API key check as the rest of management.
func TestManagementMetrics_WrongKeyForbidden(t *testing.T) {
	mh, _ := newTestManagement()
	req := httptest.NewRequest("GET", "/metrics?format=prom", nil)
	req.Header.Set("X-Management-Key", "wrong")
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestManagementSetLimitMissingFields(t *testing.T) {
	mh, _ := newTestManagement()

	// Missing user_id.
	body := map[string]any{"max_devices": 5}
	req := mgmtRequest(t, "POST", "/manage/set-limit", body, testMgmtKey)
	rr := httptest.NewRecorder()
	mh.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusBadRequest, rr.Code)

	// Missing max_devices (will be 0).
	body2 := map[string]any{"user_id": "u1"}
	req2 := mgmtRequest(t, "POST", "/manage/set-limit", body2, testMgmtKey)
	rr2 := httptest.NewRecorder()
	mh.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusBadRequest, rr2.Code)
}
