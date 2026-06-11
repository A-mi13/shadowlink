package leakguard

import (
	"net/netip"
	"testing"
)

// Task 8a — pure buildWFPConds (build-tag нейтральный — без syscall).

func TestBuildWFPConds_MapsPrefixToAddrMask(t *testing.T) {
	conds := buildWFPConds([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("2a00:1450::/32"), // v6 → skip
	})
	if len(conds) != 2 {
		t.Fatalf("len=%d want 2 (v6 skipped)", len(conds))
	}
	if conds[0].Mask != 0xFF000000 {
		t.Errorf("/8 mask=%#x", conds[0].Mask)
	}
	if conds[0].Addr != 10<<24 {
		t.Errorf("/8 addr=%#x", conds[0].Addr)
	}
	if conds[1].Mask != 0xFFFFFF00 {
		t.Errorf("/24 mask=%#x", conds[1].Mask)
	}
}

func TestBuildWFPConds_NormalizesHostBits(t *testing.T) {
	// 77.88.5.5/18 должен нормализоваться в сеть 77.88.0.0 (addr&mask)
	conds := buildWFPConds([]netip.Prefix{netip.MustParsePrefix("77.88.5.5/18")})
	if conds[0].Addr != (77<<24 | 88<<16) {
		t.Errorf("addr=%#x not network-normalized", conds[0].Addr)
	}
}
