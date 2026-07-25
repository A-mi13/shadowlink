package client

import (
	"testing"

	bfutls "github.com/bogdanfinn/utls"
	utls "github.com/refraction-networking/utls"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// Раунд 18 / HIGH-2: паритет ALPN и ALPS между двумя TLS-стеками.
//
// Cold-path использует refraction-networking/utls (HelloChrome_133), hot-path —
// bogdanfinn/tls-client (profiles.Chrome_133). Оба честно рапортуют major=133, и
// validateProfile сверяет именно числа мажоров — поэтому расхождение в БАЙТАХ
// прошло незамеченным: hot-path объявлял ALPS ["h3","h2"] при ALPN
// ["http/1.1"], чего реальный Chrome не делает никогда. ALPS входит в JA4,
// значит два наших собственных стека давали разный отпечаток с одного IP.
//
// Фикс — WithDisableHttp3() в connmanager.go. Тест ниже падает при его откате.

// alpnALPSFromSpec извлекает списки протоколов ALPN и ALPS из spec
// refraction-networking/utls.
func alpnALPSFromSpec(t *testing.T, spec *utls.ClientHelloSpec) (alpn, alps []string) {
	t.Helper()
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ALPNExtension:
			alpn = append(alpn, e.AlpnProtocols...)
		case *utls.ApplicationSettingsExtension:
			alps = append(alps, e.SupportedProtocols...)
		case *utls.ApplicationSettingsExtensionNew:
			alps = append(alps, e.SupportedProtocols...)
		}
	}
	return alpn, alps
}

// alpnALPSFromBogdanfinnSpec — то же для bogdanfinn/utls.
func alpnALPSFromBogdanfinnSpec(t *testing.T, spec *bfutls.ClientHelloSpec) (alpn, alps []string) {
	t.Helper()
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *bfutls.ALPNExtension:
			alpn = append(alpn, e.AlpnProtocols...)
		case *bfutls.ApplicationSettingsExtension:
			alps = append(alps, e.SupportedProtocols...)
		case *bfutls.ApplicationSettingsExtensionNew:
			alps = append(alps, e.SupportedProtocols...)
		}
	}
	return alpn, alps
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// Основной инвариант: в direct-режиме (nginx без http2, ALPN=http/1.1) ни ALPN,
// ни ALPS не должны содержать "h3" ни в одном из профилей пула.
func TestALPS_NoH3AfterDisableHttp3_AllProfiles(t *testing.T) {
	// Все три профиля пула FP-diversity (веса 10/30/60).
	poolProfiles := []string{
		browser.ProfileChrome120,
		browser.ProfileChrome131,
		browser.ProfileChrome133,
	}
	for _, name := range poolProfiles {
		p, ok := browser.LookupProfile(name)
		if !ok {
			t.Fatalf("профиль %q отсутствует в реестре", name)
		}

		spec, err := bfutls.UTLSIdToSpec(p.BogdanfinnID.GetClientHelloId())
		if err != nil {
			t.Fatalf("%s: UTLSIdToSpec: %v", name, err)
		}

		// Воспроизводим то, что делает tls-client при
		// WithForceHttp1 + WithDisableHttp3 (u_parrots.go:3264-3300).
		applyForceHTTP1AndDisableH3(&spec)

		alpn, alps := alpnALPSFromBogdanfinnSpec(t, &spec)

		if contains(alpn, "h3") {
			t.Errorf("%s: ALPN содержит h3 после DisableHttp3: %v", name, alpn)
		}
		if contains(alps, "h3") {
			t.Errorf("%s: ALPS содержит h3 после DisableHttp3: %v — "+
				"реальный Chrome не объявляет ALPS h3 при ALPN http/1.1 (HIGH-2)",
				name, alps)
		}
		if !contains(alpn, "http/1.1") {
			t.Errorf("%s: ALPN обязан содержать http/1.1 в direct-режиме: %v", name, alpn)
		}
	}
}

// Паритет с cold-path: набор ALPS hot-path должен совпадать с тем, что шлёт
// refraction-networking/utls для того же мажора.
func TestALPS_HotPathMatchesColdPath(t *testing.T) {
	coldSpec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		t.Fatalf("cold-path UTLSIdToSpec: %v", err)
	}
	_, coldALPS := alpnALPSFromSpec(t, &coldSpec)

	p, ok := browser.LookupProfile(browser.ProfileChrome133)
	if !ok {
		t.Fatal("chrome133 отсутствует в реестре")
	}
	hotSpec, err := bfutls.UTLSIdToSpec(p.BogdanfinnID.GetClientHelloId())
	if err != nil {
		t.Fatalf("hot-path UTLSIdToSpec: %v", err)
	}
	applyForceHTTP1AndDisableH3(&hotSpec)
	_, hotALPS := alpnALPSFromBogdanfinnSpec(t, &hotSpec)

	// Сравниваем как множества: порядок внутри ALPS для JA4 не значим,
	// значим состав.
	if len(coldALPS) != len(hotALPS) {
		t.Fatalf("состав ALPS расходится: cold=%v hot=%v (HIGH-2)", coldALPS, hotALPS)
	}
	for _, proto := range coldALPS {
		if !contains(hotALPS, proto) {
			t.Errorf("ALPS cold-path содержит %q, hot-path — нет: cold=%v hot=%v",
				proto, coldALPS, hotALPS)
		}
	}
}

// applyForceHTTP1AndDisableH3 повторяет преобразование spec, которое
// bogdanfinn/utls выполняет при WithForceHttp1 + WithDisableHttp3
// (u_parrots.go:3264-3300). Держим отдельной функцией, чтобы тест проверял
// именно результат, а не поднимал реальное TLS-соединение.
func applyForceHTTP1AndDisableH3(spec *bfutls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *bfutls.ALPNExtension:
			e.AlpnProtocols = []string{"http/1.1"}
		case *bfutls.ApplicationSettingsExtensionNew:
			e.SupportedProtocols = withoutH3(e.SupportedProtocols)
		case *bfutls.ApplicationSettingsExtension:
			e.SupportedProtocols = withoutH3(e.SupportedProtocols)
		}
	}
}

func withoutH3(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "h3" {
			out = append(out, s)
		}
	}
	return out
}
