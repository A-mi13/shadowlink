package browser

import (
	"strconv"
	"strings"
	"testing"
)

func TestChromeUAForMajor(t *testing.T) {
	for _, m := range []int{120, 131, 133} {
		ua := ChromeUAForMajor(m)
		want := "Chrome/" + strconv.Itoa(m) + ".0.0.0"
		if !strings.Contains(ua, want) {
			t.Errorf("ChromeUAForMajor(%d) = %q, missing %q", m, ua, want)
		}
		if strings.Contains(ua, "Firefox/") {
			t.Errorf("ChromeUAForMajor(%d) leaked Firefox/", m)
		}
	}
}

func TestChromeCHUAForMajor(t *testing.T) {
	kv := ChromeCHUAForMajor(120)()
	var secch string
	for _, p := range kv {
		if p[0] == "sec-ch-ua" {
			secch = p[1]
		}
	}
	if !strings.Contains(secch, `v="120"`) {
		t.Errorf("CHUA(120) sec-ch-ua = %q, missing v=\"120\"", secch)
	}
}
