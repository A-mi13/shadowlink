package client

import (
	"testing"

	"github.com/nixavpn/shadowlink/client/bypassroute"
)

// TestDoHServerIP_MatchesBypassrouteGuard — сшивка двух констант, разведённых
// import cycle'ом: client дайлит dohServerIP (ech.go), а маршрутная защита в
// bypassroute.route() сравнивает с bypassroute.DoHResolverIP. bypassroute не
// может импортировать client (client уже импортирует bypassroute), поэтому IP
// продублирован там литералом — а этот тест, живущий на стороне, которой
// импорт ДОСТУПЕН, гарантирует, что дубликаты не разъедутся.
//
// Если тест красный: кто-то сменил один из двух пинов. Защита route()
// (TestDoHServerIP_AdminOverrideCannotExposeIt в client/bypassroute) в этот
// момент охраняет НЕ тот адрес, который реально дайлит DoH-клиент, то есть
// admin override снова может увести DoH-хендшейк на физический NIC. Чинить —
// синхронизацией обеих констант (и dohServerIPLiteral в doh_route_test.go),
// а не ослаблением этого сравнения.
func TestDoHServerIP_MatchesBypassrouteGuard(t *testing.T) {
	if bypassroute.DoHResolverIP != dohServerIP {
		t.Fatalf("bypassroute.DoHResolverIP = %q, client.dohServerIP = %q — "+
			"маршрутная защита DoH-пина охраняет не тот адрес, который дайлит "+
			"DoH-клиент; синхронизируйте константы", bypassroute.DoHResolverIP, dohServerIP)
	}
}
