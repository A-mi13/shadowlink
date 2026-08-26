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
	if bypassroute.DoHBackupResolverIP != dohBackupServerIP {
		t.Fatalf("bypassroute.DoHBackupResolverIP = %q, client.dohBackupServerIP = %q — "+
			"резервный апстрим охраняется не по тому адресу, который дайлится; "+
			"синхронизируйте константы", bypassroute.DoHBackupResolverIP, dohBackupServerIP)
	}
}

// TestDoHUpstreams_AllPinnedInBypassroute — вторая половина сшивки, и она про
// ПОЛНОТУ, а не про равенство отдельных значений.
//
// Предыдущий тест сверяет две пары констант поимённо, поэтому ТРЕТИЙ апстрим,
// добавленный в DoHUpstreams(), прошёл бы мимо него молча: обе существующие
// пары остались бы согласованы, а новый адрес не был бы защищён guard'ом в
// route() — то есть ровно тот дефект, который ревью нашло у резервного
// (guard знал один адрес из двух), повторился бы на следующем добавлении.
//
// Здесь проверяется включение: КАЖДЫЙ апстрим из живого списка должен быть
// известен маршрутной защите. Строковое сравнение — намеренно: bypassroute
// экспортирует пины как строки, и разбор их в netip.Addr здесь дублировал бы
// логику, которую и проверяем.
func TestDoHUpstreams_AllPinnedInBypassroute(t *testing.T) {
	pinned := map[string]bool{
		bypassroute.DoHResolverIP:       true,
		bypassroute.DoHBackupResolverIP: true,
	}
	ups := DoHUpstreams()
	if len(ups) == 0 {
		t.Fatal("DoHUpstreams() пуст — сверять нечего, проверьте источник")
	}
	for _, u := range ups {
		if !pinned[u.IP] {
			t.Errorf("DoH-апстрим %s (%s, SNI %s) НЕ известен bypassroute — "+
				"route() не короткозамкнёт его на туннель, и admin override сможет "+
				"увести его хендшейк на физический NIC открытым текстом. Добавьте "+
				"константу в bypassroute и в dohResolverAddrs.", u.IP, u.Label, u.SNI)
		}
	}
}
