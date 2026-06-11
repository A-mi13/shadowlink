package main

import (
	"os"
	"testing"
)

func TestSplitTunnelEnabledFromEnv(t *testing.T) {
	cases := map[string]bool{
		"":        false, // default OFF (fail-secure)
		"0":       false,
		"off":     false,
		"garbage": false,
		"1":       true,
		"true":    true,
		"YES":     true,
		"On":      true,
	}
	for in, want := range cases {
		t.Setenv("SHADOWLINK_SPLIT_TUNNEL", in)
		if got := splitTunnelEnabledFromEnv(); got != want {
			t.Errorf("splitTunnelEnabledFromEnv(%q)=%v want %v", in, got, want)
		}
	}
	_ = os.Unsetenv("SHADOWLINK_SPLIT_TUNNEL")
}

func TestLeakguardStrictFromEnv(t *testing.T) {
	cases := map[string]bool{
		"":     false,
		"0":    false,
		"no":   false,
		"1":    true,
		"true": true,
		"on":   true,
	}
	for in, want := range cases {
		t.Setenv("SHADOWLINK_LEAKGUARD_STRICT", in)
		if got := leakguardStrictFromEnv(); got != want {
			t.Errorf("leakguardStrictFromEnv(%q)=%v want %v", in, got, want)
		}
	}
}
