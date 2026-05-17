package bypassroute

import (
	"net/netip"
)

// Trie is a binary radix tree of IPv4 CIDR prefixes.
//
// Concurrency: Insert is NOT safe with concurrent readers. Build the trie
// during startup (sequential Insert calls), then publish *Trie via atomic.Pointer
// to readers — Match is read-only and safe with no synchronization.
type Trie struct {
	root *node
	size int
}

type node struct {
	child [2]*node
	leaf  bool
}

// New creates an empty trie.
func New() *Trie {
	return &Trie{root: &node{}}
}

// Insert adds an IPv4 prefix. v6 prefixes are silently skipped.
// Idempotent — re-inserting an existing prefix is a no-op.
func (t *Trie) Insert(p netip.Prefix) {
	if !p.Addr().Is4() {
		return
	}
	bits := p.Bits()
	if bits < 0 || bits > 32 {
		return
	}
	addr := p.Addr().As4()
	cur := t.root
	for i := range bits {
		bit := bitAt(addr, i)
		if cur.child[bit] == nil {
			cur.child[bit] = &node{}
		}
		cur = cur.child[bit]
	}
	if !cur.leaf {
		cur.leaf = true
		t.size++
	}
}

// Match returns true if ip is covered by any inserted prefix.
// Lookup walks at most 32 steps. Read-only, safe for concurrent use.
func (t *Trie) Match(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	addr := ip.As4()
	cur := t.root
	if cur.leaf { // 0.0.0.0/0
		return true
	}
	for i := range 32 {
		bit := bitAt(addr, i)
		next := cur.child[bit]
		if next == nil {
			return false
		}
		if next.leaf {
			return true
		}
		cur = next
	}
	return false
}

// Size returns the number of distinct prefixes inserted.
func (t *Trie) Size() int { return t.size }

func bitAt(addr [4]byte, i int) byte {
	byteIdx := i / 8
	bitIdx := 7 - (i % 8)
	return (addr[byteIdx] >> bitIdx) & 1
}
