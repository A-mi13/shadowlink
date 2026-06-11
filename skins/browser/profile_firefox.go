//go:build sl_firefox

package browser

import (
	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
)

// registerFirefoxIfEnabled регистрирует Firefox ТОЛЬКО при сборке с тегом
// sl_firefox (эксперименты вне РФ). НЕ собирать так для РФ-флота — Firefox
// uTLS-FP в РФ банится первым.
func registerFirefoxIfEnabled() {
	register(BrowserProfile{
		Name:         "firefox",
		Family:       FamilyFirefox,
		Major:        148,
		UTLSHelloID:  utls.HelloFirefox_148,
		BogdanfinnID: profiles.Firefox_147,
		UAString:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0",
		CHUA:         nil,
		PQKeyShare:   false,
	})
}
