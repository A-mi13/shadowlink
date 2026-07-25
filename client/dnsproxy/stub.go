package dnsproxy

import (
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// stubIPsEnvVar — env-переменная для полевого расширения списка stub-IP БЕЗ
// пересборки клиента: запятая-разделённый список IPv4-адресов, ДОБАВЛЯЕТСЯ
// к builtinStubIPs (не заменяет его).
const stubIPsEnvVar = "SHADOWLINK_DNS_STUB_IPS"

// builtinStubIPs — известные IP заглушек блок-страниц цензуры. Единый источник
// истины (DNS-H2, 2026-06-12). Ключевой факт: заглушка 89.221.226.6 САМА входит
// в RU snapshot, поэтому yandexIsRU(stub)==true — без явного фильтра ветки
// «доверяем Yandex без сверки с CF» отдавали бы клиенту блок-страницу (тот
// самый ERR_CERT-симптом, который форвардер существует чтобы лечить), и она
// залипала бы в кэше. Новые заглушки добавлять сюда ИЛИ через env выше.
var builtinStubIPs = []string{
	"89.221.226.6", // РКН-заглушка (полевое подтверждение: LinkedIn → ERR_CERT)
}

// knownStubIPs — эффективное множество stub-IP (builtin + env), собирается
// один раз при инициализации пакета.
var knownStubIPs = buildStubIPSet(os.Getenv(stubIPsEnvVar))

// buildStubIPSet собирает множество stub-IP из builtinStubIPs плюс
// запятая-разделённого extra (значение env). Невалидные записи пропускаются
// с WARN — опечатка в env не должна ронять клиента.
func buildStubIPSet(extra string) map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, len(builtinStubIPs)+2)
	for _, s := range builtinStubIPs {
		set[netip.MustParseAddr(s).Unmap()] = struct{}{}
	}
	for _, s := range strings.Split(extra, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr, err := netip.ParseAddr(s)
		if err != nil {
			slog.Warn("dnsproxy: некорректный IP в "+stubIPsEnvVar+" — пропущен", "value", s)
			continue
		}
		set[addr.Unmap()] = struct{}{}
	}
	return set
}

// isStubIP reports whether ip is a known censorship block-page stub.
func isStubIP(ip netip.Addr) bool {
	_, ok := knownStubIPs[ip]
	return ok
}

// setContainsStub reports whether any address of the set is a known stub IP.
func setContainsStub(set map[netip.Addr]struct{}) bool {
	for ip := range set {
		if isStubIP(ip) {
			return true
		}
	}
	return false
}

// containsStubIP reports whether any A record in msg's Answer carries a known
// stub IP. Used by the unarbitrated trust paths (CF down / CF NXDOMAIN
// split-horizon): an answer containing a stub is rejected wholesale — without
// Cloudflare to cross-check, the honest records cannot be told apart from the
// injected ones.
func containsStubIP(msg *dns.Msg) bool {
	return setContainsStub(a4Set(msg))
}
