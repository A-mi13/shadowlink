package browser

import (
	"testing"

	"github.com/bogdanfinn/tls-client/profiles"
	utls "github.com/refraction-networking/utls"
)

func TestValidateProfile_RejectsMajorMismatch(t *testing.T) {
	// UA говорит 120, но Major=133 и sec-ch-ua=133 — рассинхрон.
	bad := BrowserProfile{
		Name: "chromebad", Family: FamilyChrome, Major: 133,
		UTLSHelloID:  utls.HelloChrome_133,
		BogdanfinnID: profiles.Chrome_133,
		UAString:     ChromeUAForMajor(120), // mismatch
		CHUA:         ChromeCHUAForMajor(133),
		PQKeyShare:   true,
	}
	if err := validateProfile(bad); err == nil {
		t.Fatal("validateProfile accepted UA-major mismatch, want error")
	}
}

func TestValidateProfile_RejectsCHUAMismatch(t *testing.T) {
	bad := BrowserProfile{
		Name: "chromebad2", Family: FamilyChrome, Major: 131,
		UTLSHelloID:  utls.HelloChrome_131,
		BogdanfinnID: profiles.Chrome_131,
		UAString:     ChromeUAForMajor(131),
		CHUA:         ChromeCHUAForMajor(120), // mismatch
		PQKeyShare:   true,
	}
	if err := validateProfile(bad); err == nil {
		t.Fatal("validateProfile accepted sec-ch-ua-major mismatch, want error")
	}
}

func TestValidateProfile_AcceptsConsistentChrome(t *testing.T) {
	good := BrowserProfile{
		Name: "chrome131", Family: FamilyChrome, Major: 131,
		UTLSHelloID:  utls.HelloChrome_131,
		BogdanfinnID: profiles.Chrome_131,
		UAString:     ChromeUAForMajor(131),
		CHUA:         ChromeCHUAForMajor(131),
		PQKeyShare:   true,
	}
	if err := validateProfile(good); err != nil {
		t.Fatalf("validateProfile rejected consistent chrome131: %v", err)
	}
}

func TestValidateProfile_BogdanfinnMajorMatches(t *testing.T) {
	// Major=131, но BogdanfinnID=Chrome_133 → строка hello содержит "133" != "131".
	bad := BrowserProfile{
		Name: "chromebad3", Family: FamilyChrome, Major: 131,
		UTLSHelloID:  utls.HelloChrome_131,
		BogdanfinnID: profiles.Chrome_133, // mismatch
		UAString:     ChromeUAForMajor(131),
		CHUA:         ChromeCHUAForMajor(131),
		PQKeyShare:   true,
	}
	if err := validateProfile(bad); err == nil {
		t.Fatal("validateProfile accepted bogdanfinn-major mismatch, want error")
	}
}
