package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxRateLimitEntries = 10000

// RateLimiter tracks handshake attempts per IP.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	maxRate  int           // max attempts per window
	window   time.Duration // time window
}

// NewRateLimiter creates a rate limiter.
// Default: 5 handshakes per minute per IP.
func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter {
	if maxRate == 0 {
		maxRate = 5
	}
	if window == 0 {
		window = time.Minute
	}
	return &RateLimiter{
		attempts: make(map[string][]time.Time),
		maxRate:  maxRate,
		window:   window,
	}
}

// Allow checks if the IP is allowed to make another handshake attempt.
// M6 audit fix: caps map at maxRateLimitEntries to prevent unbounded growth.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Cap: reject new IPs if map is full
	if _, exists := rl.attempts[ip]; !exists && len(rl.attempts) >= maxRateLimitEntries {
		return false
	}

	// Clean old entries
	times := rl.attempts[ip]
	valid := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.maxRate {
		rl.attempts[ip] = valid
		return false
	}

	rl.attempts[ip] = append(valid, now)
	return true
}

// Cleanup removes stale entries (call periodically).
func (rl *RateLimiter) Cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for ip, times := range rl.attempts {
		valid := times[:0]
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) == 0 {
			delete(rl.attempts, ip)
		} else {
			rl.attempts[ip] = valid
		}
	}
}

// ClientAuth manages authorized client IDs with per-user device limits.
// If no clients are configured, all clients are allowed (open mode for testing).
// Client IDs follow the format "userID:deviceID" (e.g., "u42:d1").
type ClientAuth struct {
	mu             sync.RWMutex
	authorized     map[string]bool     // clientID → authorized
	openMode       bool                // true = allow all (no whitelist configured)
	userLimits     map[string]int      // userID → max devices
	activeSessions map[string][]uint32 // userID → active sessionIDs
	clientSession  map[string]uint32   // clientID → sessionID
	defaultMax     int
}

// NewClientAuth creates a client authenticator.
// Pass nil or empty slice for open mode (all clients allowed).
func NewClientAuth(clientIDs []string) *ClientAuth {
	ca := &ClientAuth{
		authorized:     make(map[string]bool),
		userLimits:     make(map[string]int),
		activeSessions: make(map[string][]uint32),
		clientSession:  make(map[string]uint32),
		defaultMax:     3,
	}
	if len(clientIDs) == 0 {
		ca.openMode = true
		return ca
	}
	for _, id := range clientIDs {
		ca.authorized[id] = true
	}
	return ca
}

// IsAuthorized checks if a client_id is allowed.
func (ca *ClientAuth) IsAuthorized(clientID string) bool {
	if ca.openMode {
		return true
	}
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.authorized[clientID]
}

// AddClient authorizes a new client_id.
func (ca *ClientAuth) AddClient(clientID string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.authorized[clientID] = true
	ca.openMode = false
}

// RemoveClient deauthorizes a client_id.
func (ca *ClientAuth) RemoveClient(clientID string) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	delete(ca.authorized, clientID)
}

// parseUserID extracts the user part from a clientID.
// Format: "userID:deviceID" → "userID". If no colon, returns the entire string.
func parseUserID(clientID string) string {
	if idx := strings.IndexByte(clientID, ':'); idx >= 0 {
		return clientID[:idx]
	}
	return clientID
}

// SetUserLimit sets the maximum number of concurrent devices for a user.
func (ca *ClientAuth) SetUserLimit(userID string, max int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.userLimits[userID] = max
}

// CheckDeviceLimit returns true if the user (derived from clientID) has room
// for another device session. In open mode, always returns true.
// If the clientID already has an active session (reconnecting), always returns true.
func (ca *ClientAuth) CheckDeviceLimit(clientID string) bool {
	if ca.openMode {
		return true
	}
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	// Reconnecting client always allowed.
	if _, has := ca.clientSession[clientID]; has {
		return true
	}

	userID := parseUserID(clientID)
	limit := ca.defaultMax
	if ul, ok := ca.userLimits[userID]; ok {
		limit = ul
	}
	return len(ca.activeSessions[userID]) < limit
}

// OnSessionCreated records that clientID has established a session with the given ID.
func (ca *ClientAuth) OnSessionCreated(clientID string, sessionID uint32) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	userID := parseUserID(clientID)
	ca.activeSessions[userID] = append(ca.activeSessions[userID], sessionID)
	ca.clientSession[clientID] = sessionID
}

// OnSessionDestroyed removes the session record for clientID.
func (ca *ClientAuth) OnSessionDestroyed(clientID string, sessionID uint32) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	userID := parseUserID(clientID)

	// Remove sessionID from activeSessions slice.
	sessions := ca.activeSessions[userID]
	for i, sid := range sessions {
		if sid == sessionID {
			ca.activeSessions[userID] = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}
	if len(ca.activeSessions[userID]) == 0 {
		delete(ca.activeSessions, userID)
	}

	// Remove from clientSession.
	if ca.clientSession[clientID] == sessionID {
		delete(ca.clientSession, clientID)
	}
}

// SyncClients performs an atomic full replacement of the authorized client list
// and per-user device limits. Cleans up sessions for removed users.
func (ca *ClientAuth) SyncClients(clients []string, limits map[string]int) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Build new authorized set.
	newAuth := make(map[string]bool, len(clients))
	newUsers := make(map[string]bool) // track which userIDs remain
	for _, id := range clients {
		newAuth[id] = true
		newUsers[parseUserID(id)] = true
	}

	// Clean up sessions for removed users.
	for userID := range ca.activeSessions {
		if !newUsers[userID] {
			// Remove all clientSession entries for this user.
			for cid := range ca.clientSession {
				if parseUserID(cid) == userID {
					delete(ca.clientSession, cid)
				}
			}
			delete(ca.activeSessions, userID)
		}
	}

	ca.authorized = newAuth
	ca.openMode = false

	// Replace limits.
	ca.userLimits = make(map[string]int, len(limits))
	for uid, max := range limits {
		ca.userLimits[uid] = max
	}
}

// GetAndDestroyClientSession atomically retrieves the session ID for a client
// and removes it from the authorized set and session tracking.
// Returns the session ID and true if the client had an active session.
func (ca *ClientAuth) GetAndDestroyClientSession(clientID string) (uint32, bool) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	// Remove authorization.
	delete(ca.authorized, clientID)

	// Get and clean up session tracking atomically.
	sessionID, hasSession := ca.clientSession[clientID]
	if !hasSession {
		return 0, false
	}

	userID := parseUserID(clientID)

	// Remove sessionID from activeSessions slice.
	sessions := ca.activeSessions[userID]
	for i, sid := range sessions {
		if sid == sessionID {
			ca.activeSessions[userID] = append(sessions[:i], sessions[i+1:]...)
			break
		}
	}
	if len(ca.activeSessions[userID]) == 0 {
		delete(ca.activeSessions, userID)
	}

	// Remove from clientSession.
	delete(ca.clientSession, clientID)

	return sessionID, true
}

// ActiveSessionCount returns the number of active sessions for a user.
func (ca *ClientAuth) ActiveSessionCount(userID string) int {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return len(ca.activeSessions[userID])
}

// ClientIPFromRequest extracts the client IP from an HTTP request.
// M6 audit fix: behindProxy controls whether X-Forwarded-For is trusted.
// In direct mode (behindProxy=false), XFF is ignored to prevent spoofing.
func ClientIPFromRequest(r *http.Request, behindProxy bool) string {
	if behindProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// First IP in chain is the client
			for i := range len(xff) {
				if xff[i] == ',' {
					return xff[:i]
				}
			}
			return xff
		}
	}

	// Direct connection
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
