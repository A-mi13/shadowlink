package client

import (
	"math/rand/v2"
	"sync"
	"time"
)

// DomainPool tracks a set of domains with sticky picks and adaptive failover.
// Used by ConnManager to rotate between equivalent CDN-fronted domains for the
// same ShadowLink server. On TCP/TLS/HTTP error, MarkFailed adds the domain to
// a blacklist for blacklistTTL; subsequent Pick calls return a different alive
// domain. When all domains are blacklisted, the blacklist is cleared and Pick
// retries (last-resort recovery).
type DomainPool struct {
	mu           sync.Mutex
	domains      []string
	blacklist    map[string]time.Time // domain → blacklist expiry
	sticky       string               // current sticky pick
	blacklistTTL time.Duration
}

// NewDomainPool returns a new pool. If blacklistTTL is 0, defaults to 5 minutes.
// Domains slice is copied — caller can mutate after construction.
func NewDomainPool(domains []string, blacklistTTL time.Duration) *DomainPool {
	if blacklistTTL == 0 {
		blacklistTTL = 5 * time.Minute
	}
	return &DomainPool{
		domains:      append([]string{}, domains...),
		blacklist:    make(map[string]time.Time),
		blacklistTTL: blacklistTTL,
	}
}

// Pick returns a domain (sticky if alive, else random alive choice).
// If all domains blacklisted, blacklist is cleared and a fresh choice is made.
// Returns "" only if the pool itself is empty.
func (p *DomainPool) Pick() string {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	p.expireBlacklistedAtLocked(now)

	if p.sticky != "" && !p.isBlacklistedAtLocked(p.sticky, now) {
		return p.sticky
	}

	alive := p.aliveAtLocked(now)
	if len(alive) == 0 {
		// All domains currently blacklisted — clear the blacklist and retry.
		p.blacklist = make(map[string]time.Time)
		alive = append([]string{}, p.domains...)
	}
	if len(alive) == 0 {
		return ""
	}
	p.sticky = alive[rand.IntN(len(alive))]
	return p.sticky
}

// MarkFailed adds the given domain to the blacklist for blacklistTTL.
// If it was the sticky pick, the next Pick will choose a different domain.
//
// Callers should consider error type before calling: marking on every transient
// timeout/EOF can blacklist the entire pool during a flap. The pool self-heals
// (Pick clears the blacklist when all domains are failed), but thrash is
// avoidable by gating on persistent errors only.
func (p *DomainPool) MarkFailed(domain string) {
	if domain == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.blacklist[domain] = time.Now().Add(p.blacklistTTL)
	if p.sticky == domain {
		p.sticky = ""
	}
}

// Reset clears sticky pick and blacklist. Use on session restart.
func (p *DomainPool) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sticky = ""
	p.blacklist = make(map[string]time.Time)
}

// Size returns total domains in the pool.
func (p *DomainPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.domains)
}

// BlacklistSize returns currently-blacklisted (non-expired) domain count.
// As a side effect, expired entries are removed from the blacklist on each
// call — this matches the lazy-expiry pattern used elsewhere in the pool.
func (p *DomainPool) BlacklistSize() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireBlacklistedAtLocked(time.Now())
	return len(p.blacklist)
}

// --- internal helpers (require lock held) ---

func (p *DomainPool) isBlacklistedAtLocked(d string, now time.Time) bool {
	expiry, ok := p.blacklist[d]
	if !ok {
		return false
	}
	if now.After(expiry) {
		delete(p.blacklist, d)
		return false
	}
	return true
}

func (p *DomainPool) expireBlacklistedAtLocked(now time.Time) {
	for d, exp := range p.blacklist {
		if now.After(exp) {
			delete(p.blacklist, d)
		}
	}
}

func (p *DomainPool) aliveAtLocked(now time.Time) []string {
	out := make([]string, 0, len(p.domains))
	for _, d := range p.domains {
		if !p.isBlacklistedAtLocked(d, now) {
			out = append(out, d)
		}
	}
	return out
}
