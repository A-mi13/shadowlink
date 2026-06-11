package leakguard

import "net/netip"

// wfpFilterCond — платформо-нейтральное описание одного WFP-условия по
// IPv4-подсети (FWP_V4_ADDR_AND_MASK). Сериализуемо, тестируемо без fwpuclnt.
type wfpFilterCond struct {
	Addr uint32 // network byte order host-uint32 (big-endian addr as uint32)
	Mask uint32 // prefix mask, e.g. /18 → 0xFFFFC000
}

// buildWFPConds детерминированно маппит []netip.Prefix (RU snapshot, уже
// dedup/v4-only из BuildKillSwitchPlan) в []wfpFilterCond. Чистая функция:
// никаких вызовов WFP. Не-IPv4 пропускаются (страховка). Host-биты
// нормализуются (addr&mask). Порядок стабилен.
func buildWFPConds(prefixes []netip.Prefix) []wfpFilterCond {
	out := make([]wfpFilterCond, 0, len(prefixes))
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			continue
		}
		a := p.Addr().As4()
		addr := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		bits := p.Bits()
		var mask uint32
		if bits > 0 {
			mask = ^uint32(0) << (32 - bits)
		}
		out = append(out, wfpFilterCond{Addr: addr & mask, Mask: mask})
	}
	return out
}
