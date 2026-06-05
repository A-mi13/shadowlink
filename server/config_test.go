package server

import "testing"

func TestOriginDeathTeardownEnabledOrDefault_NilOff(t *testing.T) {
	var c Config
	if c.originDeathTeardownEnabledOrDefault() {
		t.Fatal("nil must default OFF (first-canary safety)")
	}
}

func TestOriginDeathTeardownEnabledOrDefault_Explicit(t *testing.T) {
	on, off := true, false
	if c := (Config{OriginDeathTeardown: &on}); !c.originDeathTeardownEnabledOrDefault() {
		t.Fatal("explicit *true must enable")
	}
	if c := (Config{OriginDeathTeardown: &off}); c.originDeathTeardownEnabledOrDefault() {
		t.Fatal("explicit *false must stay off")
	}
}
