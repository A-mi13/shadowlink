package server

import (
	"net"
	"testing"
)

// H-12 (раунд 18): privateCIDRs не покрывал unspecified-адрес и IPv6
// transition-диапазоны.
//
// `FlagConnect` с target `[::]:6379` проходил проверку (isPrivateIP=false), а на
// Linux подключение к unspecified идёт на loopback → доступ к локальному
// Redis/PostgreSQL/admin-API на том же VPS. IPv4-форма `0.0.0.0` блокировалась
// (она попадала в 0.0.0.0/8), IPv6-форма — нет: асимметрия.
//
// Клиентский аналог (proxy/socks5/direct.go:29) с самого начала использовал
// методы net.IP и `IsUnspecified()` уже покрывал — серверный список отставал.
//
// Тот же список используется для UDP (handler.go, websocket.go), поэтому фикс
// закрывает все три пути.

func TestSafeDial_BlockedRanges(t *testing.T) {
	blocked := []struct {
		ip  string
		why string
	}{
		// H-12: то, что раньше проходило.
		{"::", "IPv6 unspecified — на Linux dial уходит на loopback"},
		{"64:ff9b::7f00:1", "NAT64 well-known prefix → 127.0.0.1"},
		{"64:ff9b::a00:1", "NAT64 → 10.0.0.1"},
		{"2002:7f00:1::", "6to4 → 127.0.0.1"},
		{"2002:a00:1::", "6to4 → 10.0.0.1"},
		{"224.0.0.1", "IPv4 multicast"},
		{"239.255.255.250", "IPv4 multicast (SSDP)"},
		{"ff02::1", "IPv6 multicast"},
		{"255.255.255.255", "IPv4 broadcast"},
		{"198.18.0.1", "benchmark (RFC 2544) — совпадает с нашим TUN → петля"},
		{"198.19.255.255", "benchmark, верхняя граница"},
		{"2001::1", "Teredo"},
		{"100::1", "discard-only (RFC 6666)"},

		// Регрессия: то, что блокировалось и должно продолжать.
		{"0.0.0.0", "IPv4 unspecified"},
		{"127.0.0.1", "loopback"},
		{"127.0.0.53", "systemd-resolved"},
		{"10.0.0.1", "RFC1918"},
		{"172.16.0.1", "RFC1918"},
		{"192.168.1.1", "RFC1918"},
		{"169.254.169.254", "AWS/GCP metadata"},
		{"100.64.0.1", "CGNAT"},
		{"::1", "IPv6 loopback"},
		{"fc00::1", "IPv6 ULA"},
		{"fe80::1", "IPv6 link-local"},
		{"::ffff:127.0.0.1", "IPv4-mapped loopback"},
		{"::ffff:169.254.169.254", "IPv4-mapped metadata"},
	}

	for _, c := range blocked {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("не разобрался IP %q", c.ip)
		}
		if !isPrivateIP(ip) {
			t.Errorf("%s ДОЛЖЕН блокироваться (%s), но isPrivateIP=false", c.ip, c.why)
		}
	}
}

// Контроль: публичные адреса не должны попасть под расширенный список.
// Без этого теста легко «закрыть» SSRF, заблокировав пол-интернета.
func TestSafeDial_PublicAllowed(t *testing.T) {
	allowed := []string{
		"8.8.8.8",              // Google DNS
		"1.1.1.1",              // Cloudflare
		"77.88.8.8",            // Yandex DNS
		"93.184.216.34",        // example.com
		"2606:4700::1111",      // Cloudflare IPv6
		"2001:4860:4860::8888", // Google DNS IPv6
		"9.9.9.9",              // Quad9
		"199.18.0.1",           // соседний с 198.18/15 — НЕ benchmark
		"197.255.255.255",      // соседний снизу
		"223.255.255.255",      // соседний с multicast 224/4 снизу
		"240.0.0.1",            // 240/4 зарезервирован IANA, но не наш периметр
		"2003::1",              // соседний с 2002::/16
		"100:1::1",             // соседний с 100::/64 discard
		"101.64.0.1",           // соседний с CGNAT 100.64/10
		"99.255.255.255",       // соседний с CGNAT снизу

		// TEST-NET (RFC 5737) намеренно НЕ блокируется: диапазоны
		// зарезервированы, но никуда не маршрутизируются, то есть локальный
		// сервис через них недостижим — критерий не «зарезервировано», а
		// «даёт доступ к локальному». Сервер использует 203.0.113.1 как
		// заглушку публичного IP в своих же тестах и decoy-фикстурах.
		"192.0.2.1",    // TEST-NET-1
		"198.51.100.1", // TEST-NET-2
		"203.0.113.1",  // TEST-NET-3
	}
	for _, s := range allowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("не разобрался IP %q", s)
		}
		if isPrivateIP(ip) {
			t.Errorf("%s — публичный адрес, НЕ должен блокироваться", s)
		}
	}
}

// Явная проверка на асимметрию mapped/native форм: обе должны вести себя одинаково.
func TestSafeDial_MappedNativeParity(t *testing.T) {
	pairs := [][2]string{
		{"127.0.0.1", "::ffff:127.0.0.1"},
		{"169.254.169.254", "::ffff:169.254.169.254"},
		{"10.0.0.1", "::ffff:10.0.0.1"},
		{"0.0.0.0", "::ffff:0.0.0.0"},
		{"224.0.0.1", "::ffff:224.0.0.1"},
	}
	for _, p := range pairs {
		native, mapped := net.ParseIP(p[0]), net.ParseIP(p[1])
		gotN, gotM := isPrivateIP(native), isPrivateIP(mapped)
		if gotN != gotM {
			t.Errorf("асимметрия: %s=%v против mapped %s=%v", p[0], gotN, p[1], gotM)
		}
	}
}
