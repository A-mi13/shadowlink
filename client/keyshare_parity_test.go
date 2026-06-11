package client

import (
	"testing"

	bdtls "github.com/bogdanfinn/utls"
	utls "github.com/refraction-networking/utls"

	"github.com/nixavpn/shadowlink/skins/browser"
)

// x25519mlkem768 is the numeric CurveID for X25519MLKEM768 (4588 = 0x11ec).
// Both refraction-utls and bogdanfinn-vendored-utls define CurveID as a uint16
// with this same value (O-1): the two libraries vendor distinct utls forks, so
// the typed constants are incompatible — we compare by numeric value.
const x25519mlkem768 = uint16(0x11ec)

// coldKeyShareHasMLKEM scans a refraction-utls cold-path spec's KeyShareExtension
// for X25519MLKEM768 (numeric), ignoring GREASE placeholders.
func coldKeyShareHasMLKEM(spec utls.ClientHelloSpec) bool {
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*utls.KeyShareExtension); ok {
			for _, e := range ks.KeyShares {
				if isGREASEUint16(uint16(e.Group)) {
					continue
				}
				if uint16(e.Group) == x25519mlkem768 {
					return true
				}
			}
		}
	}
	return false
}

// hotKeyShareHasMLKEM scans a bogdanfinn-utls hot-path spec's KeyShareExtension
// for X25519MLKEM768 (numeric), ignoring GREASE placeholders.
func hotKeyShareHasMLKEM(spec bdtls.ClientHelloSpec) bool {
	for _, ext := range spec.Extensions {
		if ks, ok := ext.(*bdtls.KeyShareExtension); ok {
			for _, e := range ks.KeyShares {
				if isGREASEUint16(uint16(e.Group)) {
					continue
				}
				if uint16(e.Group) == x25519mlkem768 {
					return true
				}
			}
		}
	}
	return false
}

// isGREASEUint16 reports whether a 16-bit group id is a GREASE placeholder
// (RFC 8701: 0x0a0a, 0x1a1a, ... — both bytes equal and low nibble == 0x?a).
func isGREASEUint16(c uint16) bool {
	return (c & 0x0f0f) == 0x0a0a
}

// TestClientHelloKeyShareParity_ColdVsHot — для КАЖДОГО chrome-профиля членство
// X25519MLKEM768 в key_share одинаково на cold-path (refraction-utls, как в
// dial) и hot-path (bogdanfinn профиль). Закрывает H-D3 (cross-path рассинхрон).
func TestClientHelloKeyShareParity_ColdVsHot(t *testing.T) {
	cases := []struct {
		name      string
		wantMLKEM bool
	}{
		{browser.ProfileChrome120, false},
		{browser.ProfileChrome131, true},
		{browser.ProfileChrome133, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ok := browser.LookupProfile(c.name)
			if !ok {
				t.Fatalf("%s not in registry", c.name)
			}
			if p.PQKeyShare != c.wantMLKEM {
				t.Fatalf("%s PQKeyShare=%v want %v", c.name, p.PQKeyShare, c.wantMLKEM)
			}

			fp := browser.NewFingerprintForProfile(c.name)

			// Cold-path spec: воспроизводим логику dial — usePQ по PQKeyShare.
			helloID := utlsProfileForFingerprint(fp)
			var coldSpec utls.ClientHelloSpec
			var err error
			if pqEnabled() && fp.Profile().PQKeyShare {
				coldSpec, err = pqClientHelloSpec(helloID)
			} else {
				coldSpec, err = utls.UTLSIdToSpec(helloID)
			}
			if err != nil {
				t.Fatalf("cold spec derive: %v", err)
			}
			coldMLKEM := coldKeyShareHasMLKEM(coldSpec)
			if coldMLKEM != c.wantMLKEM {
				t.Errorf("%s cold-path MLKEM=%v, want %v", c.name, coldMLKEM, c.wantMLKEM)
			}

			// Hot-path spec: bogdanfinn профиль.
			hotSpec, err := fp.Profile().BogdanfinnID.GetClientHelloSpec()
			if err != nil {
				t.Fatalf("hot spec derive: %v", err)
			}
			hotMLKEM := hotKeyShareHasMLKEM(hotSpec)

			// ПАРНОСТЬ: членство MLKEM в key_share одинаково на cold и hot.
			if coldMLKEM != hotMLKEM {
				t.Errorf("%s key_share MLKEM mismatch: cold=%v hot=%v — cross-path signal",
					c.name, coldMLKEM, hotMLKEM)
			}
		})
	}
}
