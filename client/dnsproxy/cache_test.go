package dnsproxy

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeClock provides controllable time for deterministic TTL tests.
type fakeClock struct {
	t time.Time
}

func (f *fakeClock) now() time.Time { return f.t }

func (f *fakeClock) advance(d time.Duration) { f.t = f.t.Add(d) }

// makeMsg builds a DNS response with a single A record and the given TTL (in seconds).
func makeMsg(name string, ttl uint32) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.Response = true
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(name),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: []byte{1, 2, 3, 4},
	}
	m.Answer = append(m.Answer, rr)
	return m
}

// newTestCache creates a cache with an injected clock.
func newTestCache(clk *fakeClock) *dnsCache {
	c := newDNSCache()
	c.now = clk.now
	return c
}

func answerTTL(t *testing.T, m *dns.Msg) uint32 {
	t.Helper()
	if len(m.Answer) == 0 {
		t.Fatalf("ожидался непустой Answer")
	}
	return m.Answer[0].Header().Ttl
}

// Test 1: lower-bound clamp — TTL=5s must live at least 30s.
func TestCache_ClampLower(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeA}

	c.put(key, makeMsg("example.com", 5))

	got, ok := c.get(key)
	if !ok {
		t.Fatal("ожидался hit сразу после put")
	}
	// elapsed=0 → TTL must be the clamped value 30, not 5.
	if ttl := answerTTL(t, got); ttl != 30 {
		t.Fatalf("ожидался TTL=30 (clamp нижний), получено %d", ttl)
	}
}

// Test 2: upper-bound clamp — TTL=100000s is clamped to 3600.
func TestCache_ClampUpper(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeA}

	c.put(key, makeMsg("example.com", 100000))

	got, ok := c.get(key)
	if !ok {
		t.Fatal("ожидался hit")
	}
	if ttl := answerTTL(t, got); ttl != 3600 {
		t.Fatalf("ожидался TTL=3600 (clamp верхний), получено %d", ttl)
	}
}

// Test 3: expiry — after the lifetime elapses, get returns a miss.
func TestCache_Expiry(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeA}

	c.put(key, makeMsg("example.com", 5)) // clamp→30s
	clk.advance(31 * time.Second)

	if _, ok := c.get(key); ok {
		t.Fatal("ожидался miss после истечения TTL")
	}
}

// Test 4: decrement-on-read — after 10s the answer TTL is ≈20s (30-10).
func TestCache_DecrementOnRead(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeA}

	c.put(key, makeMsg("example.com", 30))
	clk.advance(10 * time.Second)

	got, ok := c.get(key)
	if !ok {
		t.Fatal("ожидался hit")
	}
	if ttl := answerTTL(t, got); ttl != 20 {
		t.Fatalf("ожидался TTL=20 после decrement-on-read, получено %d", ttl)
	}
}

// Test 5: miss on an absent key.
func TestCache_MissOnAbsent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("nope.example"), qtype: dns.TypeA}

	if _, ok := c.get(key); ok {
		t.Fatal("ожидался miss на отсутствующий ключ")
	}
}

// Test 6: different qtypes of the same name do not collide.
func TestCache_QtypeIsolation(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	keyA := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeA}
	keyAAAA := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeAAAA}

	c.put(keyA, makeMsg("example.com", 30))

	if _, ok := c.get(keyAAAA); ok {
		t.Fatal("AAAA не должен попадать на запись A того же имени")
	}
	if _, ok := c.get(keyA); !ok {
		t.Fatal("A-запись должна быть в кэше")
	}
}

// Test 7: a copy is returned, not an alias — mutating the answer does not affect the cache.
func TestCache_ReturnsCopyNotAlias(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("example.com"), qtype: dns.TypeA}

	c.put(key, makeMsg("example.com", 60))

	got1, ok := c.get(key)
	if !ok {
		t.Fatal("ожидался hit")
	}
	// Mutate the returned answer.
	got1.Answer[0].Header().Ttl = 999
	got1.Answer = nil

	got2, ok := c.get(key)
	if !ok {
		t.Fatal("ожидался повторный hit")
	}
	// The second get must yield a fresh decrement from the original (elapsed=0 → 60).
	if ttl := answerTTL(t, got2); ttl != 60 {
		t.Fatalf("мутация первого ответа не должна влиять на кэш; ожидался TTL=60, получено %d", ttl)
	}
}

// Test 8: the key is case-insensitive.
func TestCache_CaseInsensitiveKey(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)

	// put with a mixed-case name, get with a lower-case name.
	putKey := cacheKey{name: dns.CanonicalName("Example.COM."), qtype: dns.TypeA}
	getKey := cacheKey{name: dns.CanonicalName("example.com."), qtype: dns.TypeA}

	c.put(putKey, makeMsg("example.com", 30))

	if _, ok := c.get(getKey); !ok {
		t.Fatal("ключ должен быть нечувствителен к регистру")
	}
}

// Test 9: NODATA (empty Answer) is cached with the minimum TTL of 30s.
func TestCache_NodataMinTTL(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1000, 0)}
	c := newTestCache(clk)
	key := cacheKey{name: dns.Fqdn("empty.example"), qtype: dns.TypeA}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("empty.example"), dns.TypeA)
	m.Response = true
	// Empty Answer → NODATA.

	c.put(key, m)

	// Immediately — hit.
	if _, ok := c.get(key); !ok {
		t.Fatal("ожидался hit для NODATA сразу после put")
	}
	// After 31s — miss (minimum TTL 30s).
	clk.advance(31 * time.Second)
	if _, ok := c.get(key); ok {
		t.Fatal("ожидался miss для NODATA после 31s (min TTL 30s)")
	}
}
