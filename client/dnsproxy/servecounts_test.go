package dnsproxy

// Наблюдаемость ревью блоков 3/4 (2026-06-12): два serve-пути вне лестницы
// арбитража не учитывались счётчиками веток — NXDOMAIN short-circuit (DNS-H1)
// и неарбитрированный Yandex-only (DNS-H2). ServeCounts закрывает дыру.

import (
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// NXDOMAIN short-circuit (DNS-H1): usable NXDOMAIN от CF отдан до лестницы →
// nxdomain-счётчик ровно 1, unarbitrated не тронут.
func TestServeCounts_NXDOMAINShortCircuit(t *testing.T) {
	match := matchSet("89.221.226.6") // Yandex-IP не в snapshot (foreign)
	y := &mockResolver{resp: answerA(t, "ghost.test", "142.250.1.1")}
	c := &mockResolver{resp: nxdomainMsg(t, "ghost.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(match, y, c)

	f.ServeDNS(&captureWriter{}, aQuery("ghost.test"))
	if nx, unarb := f.ServeCounts(); nx != 1 || unarb != 0 {
		t.Fatalf("NXDOMAIN short-circuit: ожидалось (nxdomain=1, unarbitrated=0), получено (%d,%d)", nx, unarb)
	}
}

// RU-исключение внутри NXDOMAIN short-circuit (CF NXDOMAIN, Yandex честный
// RU split-horizon ответ) — это неарбитрированный Yandex-serve → unarbitrated=1.
func TestServeCounts_NXDOMAINException_Unarbitrated(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ru-internal.test", "87.250.250.242")}
	c := &mockResolver{resp: nxdomainMsg(t, "ru-internal.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(match, y, c)

	f.ServeDNS(&captureWriter{}, aQuery("ru-internal.test"))
	if nx, unarb := f.ServeCounts(); nx != 0 || unarb != 1 {
		t.Fatalf("NXDOMAIN RU-исключение: ожидалось (nxdomain=0, unarbitrated=1), получено (%d,%d)", nx, unarb)
	}
}

// Yandex-only ветка (DNS-H2, yOK && !cOK, RU-classified) — unarbitrated=1.
func TestServeCounts_YandexOnly_Unarbitrated(t *testing.T) {
	match := matchSet("87.250.250.242")
	y := &mockResolver{resp: answerA(t, "ya.test", "87.250.250.242")}
	c := &mockResolver{err: errors.New("cf down")}
	f := newTestForwarder(match, y, c)

	resp, err := f.handleQuery(context.Background(), aQuery("ya.test"),
		cacheKey{name: dns.Fqdn("ya.test"), qtype: dns.TypeA})
	if err != nil || resp == nil {
		t.Fatalf("ожидался успех Yandex-only ветки: %v", err)
	}
	if nx, unarb := f.ServeCounts(); nx != 0 || unarb != 1 {
		t.Fatalf("Yandex-only: ожидалось (nxdomain=0, unarbitrated=1), получено (%d,%d)", nx, unarb)
	}
}

// Ровно один инкремент на резолв: повтор из кэша счётчики не двигает.
func TestServeCounts_CacheHitDoesNotIncrement(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "ghost.test", "142.250.1.1")}
	c := &mockResolver{resp: nxdomainMsg(t, "ghost.test", dns.TypeA, 3600, 300)}
	f := newTestForwarder(match, y, c)

	f.ServeDNS(&captureWriter{}, aQuery("ghost.test"))
	f.ServeDNS(&captureWriter{}, aQuery("ghost.test")) // negative cache hit
	if nx, unarb := f.ServeCounts(); nx != 1 || unarb != 0 {
		t.Fatalf("повтор из кэша не должен инкрементить: ожидалось (1,0), получено (%d,%d)", nx, unarb)
	}
}

// Арбитражные ветки (здесь censored) НЕ двигают serve-счётчики — они учтены
// своими BranchCounts.
func TestServeCounts_ArbitrationDoesNotIncrement(t *testing.T) {
	match := matchSet("89.221.226.6")
	y := &mockResolver{resp: answerA(t, "linkedin.test", "89.221.226.6")}
	c := &mockResolver{resp: answerA(t, "linkedin.test", "104.18.41.41")}
	f := newTestForwarder(match, y, c)

	f.ServeDNS(&captureWriter{}, aQuery("linkedin.test"))
	if nx, unarb := f.ServeCounts(); nx != 0 || unarb != 0 {
		t.Fatalf("арбитражная ветка не должна двигать serve-счётчики: получено (%d,%d)", nx, unarb)
	}
}
