package bypassroute

import (
	"net/netip"
)

// extraRussianPrefixes holds CIDR ranges that legitimately belong to
// Russian operators / services but are NOT included in the RIPE-NCC
// `delegated-stats-extended` country=RU snapshot — typically because the
// upstream registrar (ARIN legacy / RIPE-EU corporate parent) recorded
// the delegation under a different country code.
//
// Field-test 2026-05-05 показал, что без этой надстройки массовая часть
// российского трафика (Telegram MTProto, MTS пользовательские пулы,
// крупные мессенджеры) всё равно уходит через VPN. Дыры в snapshot
// определялись через `snapshot_check_test.go` + наблюдением WS CONNECT
// destination пакетов в реальной сессии.
//
// Ручная whitelist не претендует на полноту — это «top-up» поверх RIPE
// snapshot для известных дыр. Дальнейшее расширение должно делаться
// через admin override (Phase B Master Roadmap), а не правкой этого
// файла, чтобы новые дыры закрывались без re-deploy клиента.
//
// Sources:
//   - VK / Mail.Ru:       мажоритарно покрыты RIPE-RU, добавлены лишь
//     фрагменты с международной делегацией
//
// !!! Telegram + MTS user-pool IPs RETIRED 2026-05-05 evening !!!
//
//	Bypass'ить Telegram (149.154.160.0/20, 91.108.4.0/22 и др.) и MTS
//	user-pool 91.105.192.0/23 ОКАЗАЛОСЬ ВРЕДОМ: у российских пользователей
//	эти IP **физически недоступны** через ISP NIC — TSPU/провайдер режут
//	Telegram на пути к их серверам. ShadowLink VPN был единственным
//	рабочим путём до этих сервисов. Когда мы отправили их через bypass
//	direct dialer, Telegram отвалился целиком (i/o timeout). Поэтому
//	блок убран обратно — Telegram продолжает идти через VPN, как и до
//	этого фикса. Подобные "RU-зарегистрированные но физически
//	заблокированные" IP'ы — отдельная категория, для них правильное
//	поведение это VPN, а не bypass.
//
// Format: prefix string + comment. Пустой список безопасен — bypass
// fall-back на RIPE snapshot. Корректность parse'а проверяется тестом
// `TestExtraRussianPrefixes_AllParse` чтобы случайная опечатка не
// привела к silent drop.
var extraRussianPrefixes = []string{
	// Сейчас пусто. Добавлять только те RU prefix'ы, которые
	// (а) НЕ в RIPE-RU snapshot AND
	// (б) физически достижимы через ISP NIC у конечного пользователя
	//     (т.е. НЕ заблокированы TSPU / провайдером).
}

// extraRussianNetipPrefixes returns the parsed []netip.Prefix; entries
// that fail to parse are silently skipped (test pins the contract that
// every entry must parse — invalid entries get caught at CI, not in
// production).
func extraRussianNetipPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(extraRussianPrefixes))
	for _, s := range extraRussianPrefixes {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out
}
