package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
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

// IsOpenMode reports whether the authenticator is running with no whitelist
// (all decrypting clientIDs authorized). LOW-2: a deployment footgun — callers
// should emit a loud startup WARN. Safe under concurrent SyncClients.
func (ca *ClientAuth) IsOpenMode() bool {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.openMode
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

// trustedProxySet is an immutable set of CIDR ranges considered trusted
// reverse-proxy / CDN hops. Loopback is always implicitly trusted so the
// common "nginx on localhost" deployment needs no extra config. HIGH-1.
type trustedProxySet struct {
	prefixes []netip.Prefix
}

// parseTrustedProxies builds a trustedProxySet from CIDR strings or bare IPs.
// Bare IPs are normalized to /32 (v4) or /128 (v6). Loopback (127.0.0.0/8,
// ::1) is always added implicitly. A nil/empty input yields a set that trusts
// only loopback. HIGH-1.
func parseTrustedProxies(cidrs []string) (*trustedProxySet, error) {
	s := &trustedProxySet{}
	// Implicit loopback.
	for _, lp := range []string{"127.0.0.0/8", "::1/128"} {
		p := netip.MustParsePrefix(lp)
		s.prefixes = append(s.prefixes, p)
	}
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			s.prefixes = append(s.prefixes, p)
			continue
		}
		if addr, err := netip.ParseAddr(raw); err == nil {
			s.prefixes = append(s.prefixes, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		return nil, fmt.Errorf("trusted proxy %q is neither a CIDR nor an IP", raw)
	}
	return s, nil
}

// contains reports whether ip (string form) falls in any trusted prefix.
// An unparseable ip is treated as NOT trusted (caller stops the walk there).
// A nil set trusts only loopback.
func (s *trustedProxySet) contains(ip string) bool {
	if s == nil {
		ip = strings.TrimSpace(ip)
		return ip == "127.0.0.1" || ip == "::1"
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	for _, p := range s.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// clientIPFromRequest extracts the client IP. In direct mode (behindProxy=false)
// XFF is ignored entirely (anti-spoof — unchanged). Behind a proxy it walks the
// XFF chain (plus RemoteAddr) from the RIGHT and returns the first hop NOT in
// the trusted-proxy set — the rightmost untrusted hop = real client. HIGH-1.
func clientIPFromRequest(r *http.Request, behindProxy bool, trusted *trustedProxySet) string {
	remoteHost := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		remoteHost = h
	}

	if !behindProxy {
		return remoteHost
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteHost
	}

	// Build chain left→right, then append the genuine peer so the walk is
	// robust whether or not nginx already appended it (and covers the
	// unix-socket case where RemoteAddr is empty/"@" → skipped).
	parts := strings.Split(xff, ",")
	chain := make([]string, 0, len(parts)+1)
	for _, p := range parts {
		chain = append(chain, strings.TrimSpace(p))
	}
	if remoteHost != "" && remoteHost != "@" {
		chain = append(chain, remoteHost)
	}

	// Walk from the right; first untrusted hop wins.
	for i := len(chain) - 1; i >= 0; i-- {
		if !trusted.contains(chain[i]) {
			return chain[i]
		}
	}

	// Every hop trusted → best-available leftmost token, else RemoteAddr.
	if len(parts) > 0 {
		if first := strings.TrimSpace(parts[0]); first != "" {
			return first
		}
	}
	return remoteHost
}

// ClientIPFromRequest is the legacy 2-arg shim retained for existing callers
// and tests during migration. It uses a loopback-only trust set (the safe
// nginx-on-localhost default). HIGH-1: prefer h.clientIP(r) which carries the
// configured trusted-proxy set.
func ClientIPFromRequest(r *http.Request, behindProxy bool) string {
	return clientIPFromRequest(r, behindProxy, nil)
}
