package socks5

import (
	"testing"
	"time"
)

// TestReassemblyEnvDefaults pins the env-helper defaults for the Bug #9 downlink
// reassembler (§7). The helpers (reassemblyGapTimeout / reassemblyMaxBufferedFromEnv)
// were introduced by Task 14 in this package; Task 19 fixes the contract on their
// defaults so a typo'd env var or a future refactor can't silently change the
// 2s gap-backstop / 4 MiB reorder cap.
func TestReassemblyEnvDefaults(t *testing.T) {
	t.Setenv("SHADOWLINK_REASSEMBLY_GAP_TIMEOUT", "")
	if got := reassemblyGapTimeout(); got != 2*time.Second {
		t.Fatalf("default gap timeout = %v, want 2s", got)
	}

	t.Setenv("SHADOWLINK_REASSEMBLY_BUFFER", "")
	if got := reassemblyMaxBufferedFromEnv(); got != 4<<20 {
		t.Fatalf("default buffer = %d, want %d (4 MiB)", got, 4<<20)
	}
}

// TestReassemblyEnvOverrides confirms the helpers honor valid env overrides and
// fall back to the default on invalid input (parse-or-default pattern, mirrors
// flowWindowFromEnv).
func TestReassemblyEnvOverrides(t *testing.T) {
	t.Setenv("SHADOWLINK_REASSEMBLY_GAP_TIMEOUT", "5s")
	if got := reassemblyGapTimeout(); got != 5*time.Second {
		t.Fatalf("override gap timeout = %v, want 5s", got)
	}
	t.Setenv("SHADOWLINK_REASSEMBLY_GAP_TIMEOUT", "garbage")
	if got := reassemblyGapTimeout(); got != 2*time.Second {
		t.Fatalf("invalid gap timeout = %v, want 2s default", got)
	}

	t.Setenv("SHADOWLINK_REASSEMBLY_BUFFER", "8388608")
	if got := reassemblyMaxBufferedFromEnv(); got != 8<<20 {
		t.Fatalf("override buffer = %d, want %d", got, 8<<20)
	}
	t.Setenv("SHADOWLINK_REASSEMBLY_BUFFER", "-1")
	if got := reassemblyMaxBufferedFromEnv(); got != 4<<20 {
		t.Fatalf("invalid buffer = %d, want %d default", got, 4<<20)
	}
}
