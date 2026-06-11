//go:build !sl_firefox

package browser

import "testing"

func TestFirefox_AbsentInDefaultBuild(t *testing.T) {
	if _, ok := LookupProfile("firefox"); ok {
		t.Error("firefox present in default (RU) build — must be gated behind sl_firefox tag")
	}
}
