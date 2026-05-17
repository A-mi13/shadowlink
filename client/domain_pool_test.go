package client

import (
	"testing"
	"time"
)

// TestDomainPool_PickFromAlive — pool with 3 domains; over 100 Reset+Pick
// iterations we must observe at least 2 distinct domains (proves randomness).
func TestDomainPool_PickFromAlive(t *testing.T) {
	domains := []string{"a.example.com", "b.example.com", "c.example.com"}
	p := NewDomainPool(domains, time.Minute)

	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		p.Reset()
		d := p.Pick()
		if d == "" {
			t.Fatalf("iter %d: Pick returned empty string for non-empty pool", i)
		}
		seen[d] = true
	}
	if len(seen) < 2 {
		t.Errorf("expected ≥2 distinct domains over 100 iterations, got %d: %v", len(seen), seen)
	}
}

// TestDomainPool_StickyAcrossPicks — first Pick result equals all subsequent
// 10 picks without any Reset or MarkFailed in between.
func TestDomainPool_StickyAcrossPicks(t *testing.T) {
	p := NewDomainPool([]string{"x.example.com", "y.example.com", "z.example.com"}, time.Minute)

	first := p.Pick()
	if first == "" {
		t.Fatal("Pick returned empty string for non-empty pool")
	}
	for i := 1; i <= 10; i++ {
		got := p.Pick()
		if got != first {
			t.Errorf("pick %d: expected sticky %q, got %q", i, first, got)
		}
	}
}

// TestDomainPool_FailoverAfterMarkFailed — after marking the sticky domain
// failed, Pick must return a DIFFERENT domain.
func TestDomainPool_FailoverAfterMarkFailed(t *testing.T) {
	p := NewDomainPool([]string{"a.example.com", "b.example.com", "c.example.com"}, time.Minute)

	first := p.Pick()
	if first == "" {
		t.Fatal("Pick returned empty string")
	}

	p.MarkFailed(first)

	next := p.Pick()
	if next == "" {
		t.Fatal("Pick returned empty string after MarkFailed")
	}
	if next == first {
		t.Errorf("expected a different domain after MarkFailed(%q), still got %q", first, next)
	}
}

// TestDomainPool_BlacklistExpires — with a 50ms TTL: after expiry the single
// domain becomes alive again and Pick returns it.
func TestDomainPool_BlacklistExpires(t *testing.T) {
	ttl := 50 * time.Millisecond
	p := NewDomainPool([]string{"only.example.com"}, ttl)

	first := p.Pick()
	if first != "only.example.com" {
		t.Fatalf("unexpected pick: %q", first)
	}

	p.MarkFailed(first)

	// Immediately after mark: blacklist not expired, all-blacklist fallback
	// triggers but we just wait for the proper expiry path.
	time.Sleep(150 * time.Millisecond)

	// Blacklist should have expired; Pick must return the same (only) domain.
	got := p.Pick()
	if got != "only.example.com" {
		t.Errorf("after blacklist expiry expected %q, got %q", "only.example.com", got)
	}
}

// TestDomainPool_AllBlacklistedClearsAndRetries — with a long TTL, mark all
// domains failed; Pick must still return one of them (blacklist-clear recovery).
func TestDomainPool_AllBlacklistedClearsAndRetries(t *testing.T) {
	domains := []string{"p.example.com", "q.example.com"}
	p := NewDomainPool(domains, time.Hour)

	// Blacklist all domains directly via MarkFailed.
	for _, d := range domains {
		p.MarkFailed(d)
	}

	if p.BlacklistSize() != 2 {
		t.Fatalf("expected 2 blacklisted domains, got %d", p.BlacklistSize())
	}

	got := p.Pick()
	if got == "" {
		t.Fatal("Pick returned empty string after all-blacklist recovery")
	}
	found := false
	for _, d := range domains {
		if d == got {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Pick returned %q which is not in the pool %v", got, domains)
	}
	// Blacklist must have been cleared.
	if p.BlacklistSize() != 0 {
		t.Errorf("expected blacklist cleared after recovery, got BlacklistSize=%d", p.BlacklistSize())
	}
}

// TestDomainPool_DistributionUniform — 5 domains, 5000 picks with Reset
// between each; each domain must be chosen 800-1200 times (~20% variance).
func TestDomainPool_DistributionUniform(t *testing.T) {
	domains := []string{
		"d1.example.com",
		"d2.example.com",
		"d3.example.com",
		"d4.example.com",
		"d5.example.com",
	}
	p := NewDomainPool(domains, time.Minute)

	counts := make(map[string]int, len(domains))
	const iterations = 5000
	for i := 0; i < iterations; i++ {
		p.Reset()
		d := p.Pick()
		if d == "" {
			t.Fatalf("iter %d: Pick returned empty string", i)
		}
		counts[d]++
	}

	expected := iterations / len(domains) // 1000
	lo := expected * 80 / 100             // 800
	hi := expected * 120 / 100            // 1200

	for _, d := range domains {
		c := counts[d]
		if c < lo || c > hi {
			t.Errorf("domain %q: count=%d, want [%d, %d] (±20%% of %d)",
				d, c, lo, hi, expected)
		}
	}
}

// TestDomainPool_EmptyPool — NewDomainPool with nil slice returns "" from Pick.
func TestDomainPool_EmptyPool(t *testing.T) {
	p := NewDomainPool(nil, time.Minute)

	if p.Size() != 0 {
		t.Fatalf("expected Size()=0, got %d", p.Size())
	}
	got := p.Pick()
	if got != "" {
		t.Errorf("expected empty string from empty pool, got %q", got)
	}
}
