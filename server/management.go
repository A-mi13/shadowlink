package server

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// ManagementHandler exposes an HTTP API for controlling client authorization
// and device limits at runtime. Protected by X-Management-Key header
// (X-API-Key also accepted as alias for Prometheus scrapers that only support
// the latter convention).
//
// Endpoints:
//
//	POST   /manage/clients       — add authorized client
//	DELETE /manage/clients/{id}  — remove client + destroy session
//	POST   /manage/sync          — full replacement of clients + limits
//	POST   /manage/set-limit     — set per-user device limit
//	GET    /manage/status        — list all clients, sessions, limits
//	GET    /metrics              — Prometheus / JSON metrics (migration counters)
type ManagementHandler struct {
	mux        *http.ServeMux
	clientAuth *ClientAuth
	metrics    *Metrics
	apiKey     string
}

// StatusResponse is returned by GET /manage/status.
type StatusResponse struct {
	TotalClients   int                 `json:"total_clients"`
	ActiveSessions int                 `json:"active_sessions"`
	Clients        []string            `json:"clients"`
	Sessions       map[string][]uint32 `json:"sessions"`
	Limits         map[string]int      `json:"limits"`
	DefaultMax     int                 `json:"default_max"`
}

// NewManagementHandler creates the management API handler. `metrics` MAY be
// nil — in which case the `/metrics` endpoint returns 503 but the rest of the
// management API still works.
func NewManagementHandler(clientAuth *ClientAuth, metrics *Metrics, apiKey string) *ManagementHandler {
	mh := &ManagementHandler{
		mux:        http.NewServeMux(),
		clientAuth: clientAuth,
		metrics:    metrics,
		apiKey:     apiKey,
	}
	mh.mux.HandleFunc("POST /manage/clients", mh.handleAddClient)
	mh.mux.HandleFunc("DELETE /manage/clients/", mh.handleRemoveClient)
	mh.mux.HandleFunc("POST /manage/sync", mh.handleSync)
	mh.mux.HandleFunc("POST /manage/set-limit", mh.handleSetLimit)
	mh.mux.HandleFunc("GET /manage/status", mh.handleStatus)
	// H4 deploy fix 2026-04-20: delegate /metrics to the Metrics handler so
	// Prometheus scrapers (and ops curl sessions) can pull migration counters.
	// Accepts `?format=prom` or `Accept: text/plain` for Prometheus text format;
	// JSON by default.
	mh.mux.HandleFunc("GET /metrics", mh.handleMetrics)
	return mh
}

// ServeHTTP checks the API key and delegates to the mux. Accepts the key on
// either `X-Management-Key` (original) or `X-API-Key` (alias used by some
// scraper tools). Both are checked in constant time.
func (mh *ManagementHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := []byte(mh.apiKey)
	// X-3 fix: constant-time comparison prevents timing side-channel attacks.
	// Run BOTH comparisons regardless of match, then OR results, so timing
	// cannot distinguish "wrong management header" from "wrong api-key header".
	mgmtOK := subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Management-Key")), key)
	apiOK := subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), key)
	if mgmtOK != 1 && apiOK != 1 {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}
	mh.mux.ServeHTTP(w, r)
}

// handleMetrics exposes the Metrics endpoint (Prometheus text or JSON).
func (mh *ManagementHandler) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if mh.metrics == nil {
		http.Error(w, `{"error":"metrics not wired"}`, http.StatusServiceUnavailable)
		return
	}
	mh.metrics.ServeHTTP(w, r)
}

// handleAddClient adds a client to the authorized set.
// POST /manage/clients  body: {"client_id":"u42:d1"}
func (mh *ManagementHandler) handleAddClient(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if req.ClientID == "" {
		http.Error(w, `{"error":"client_id is required"}`, http.StatusBadRequest)
		return
	}

	mh.clientAuth.AddClient(req.ClientID)
	slog.Info("management: client added", "client_id", req.ClientID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "client_id": req.ClientID})
}

// handleRemoveClient removes a client and cleans up its session.
// DELETE /manage/clients/{id}
func (mh *ManagementHandler) handleRemoveClient(w http.ResponseWriter, r *http.Request) {
	// Extract client ID from URL path: /manage/clients/u1:d1
	clientID := strings.TrimPrefix(r.URL.Path, "/manage/clients/")
	if clientID == "" {
		http.Error(w, `{"error":"client_id is required in URL"}`, http.StatusBadRequest)
		return
	}

	// Atomically remove authorization and clean up session tracking.
	mh.clientAuth.GetAndDestroyClientSession(clientID)

	slog.Info("management: client removed", "client_id", clientID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "client_id": clientID})
}

// handleSync performs atomic full replacement of clients and limits.
// POST /manage/sync  body: {"clients":["u1:d1","u2:d1"], "limits":{"u1":5,"u2":2}}
func (mh *ManagementHandler) handleSync(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Clients []string       `json:"clients"`
		Limits  map[string]int `json:"limits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}

	mh.clientAuth.SyncClients(req.Clients, req.Limits)

	slog.Info("management: sync completed",
		"clients", len(req.Clients),
		"limits", len(req.Limits))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"clients": len(req.Clients),
		"limits":  len(req.Limits),
	})
}

// handleSetLimit sets the device limit for a specific user.
// POST /manage/set-limit  body: {"user_id":"u42","max_devices":5}
func (mh *ManagementHandler) handleSetLimit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID     string `json:"user_id"`
		MaxDevices int    `json:"max_devices"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if req.UserID == "" {
		http.Error(w, `{"error":"user_id is required"}`, http.StatusBadRequest)
		return
	}
	if req.MaxDevices <= 0 {
		http.Error(w, `{"error":"max_devices must be > 0"}`, http.StatusBadRequest)
		return
	}

	mh.clientAuth.SetUserLimit(req.UserID, req.MaxDevices)

	slog.Info("management: limit set", "user_id", req.UserID, "max_devices", req.MaxDevices)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"status":      "ok",
		"user_id":     req.UserID,
		"max_devices": req.MaxDevices,
	})
}

// handleStatus returns current state of clients, sessions, and limits.
// GET /manage/status
func (mh *ManagementHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	mh.clientAuth.mu.RLock()
	defer mh.clientAuth.mu.RUnlock()

	clients := make([]string, 0, len(mh.clientAuth.authorized))
	for id := range mh.clientAuth.authorized {
		clients = append(clients, id)
	}

	// HIGH-5 fix: count sessions but don't expose session IDs in response
	totalSessions := 0
	for _, sids := range mh.clientAuth.activeSessions {
		totalSessions += len(sids)
	}

	// Copy limits map.
	limits := make(map[string]int, len(mh.clientAuth.userLimits))
	for uid, max := range mh.clientAuth.userLimits {
		limits[uid] = max
	}

	resp := StatusResponse{
		TotalClients:   len(clients),
		ActiveSessions: totalSessions,
		Clients:        clients,
		Sessions:       nil, // HIGH-5 fix: don't expose session IDs
		Limits:         limits,
		DefaultMax:     mh.clientAuth.defaultMax,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}
