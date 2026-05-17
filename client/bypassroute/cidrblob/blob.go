package cidrblob

import (
	"fmt"
	"net/netip"
)

// Encode writes prefixes in compact 5-byte form.
// Returns error if any prefix is not IPv4.
func Encode(prefixes []netip.Prefix) ([]byte, error) {
	out := make([]byte, 0, len(prefixes)*5)
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("cidrblob: only IPv4 supported, got %s", p)
		}
		bits := p.Bits()
		if bits < 0 || bits > 32 {
			return nil, fmt.Errorf("cidrblob: invalid bits %d for %s", bits, p)
		}
		ip := p.Addr().As4()
		out = append(out, ip[:]...)
		out = append(out, byte(bits))
	}
	return out, nil
}

// Decode reads back into a slice of prefixes.
func Decode(blob []byte) ([]netip.Prefix, error) {
	if len(blob)%5 != 0 {
		return nil, fmt.Errorf("cidrblob: malformed length %d (must be multiple of 5)", len(blob))
	}
	n := len(blob) / 5
	out := make([]netip.Prefix, 0, n)
	for i := range n {
		off := i * 5
		var ip [4]byte
		copy(ip[:], blob[off:off+4])
		bits := int(blob[off+4])
		addr := netip.AddrFrom4(ip)
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	return out, nil
}
