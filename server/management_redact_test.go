package server

import (
	"os"
	"strings"
	"testing"
)

// clientID doubles as an authentication secret (it is mixed into the session-key
// HKDF — core/crypto.go:118-124, and see core/server_auth_test.go for what that
// buys) and as the authorization key checked here (handler.go:717). Management
// log lines used to write it in full, putting an authentication secret into log
// files and log shipping. redactClientID is what keeps it out.

func TestRedactClientID_DoesNotLeakFullValue(t *testing.T) {
	const id = "u42:d1-abcdef0123456789"

	got := redactClientID(id)

	if strings.Contains(got, id) {
		t.Fatalf("redaction returned the full client_id: %q", got)
	}
	if !strings.Contains(got, "redacted") {
		t.Errorf("redacted value should be self-describing in a log line, got %q", got)
	}
	// Enough head to correlate "added" with "removed" for the same tenant.
	if !strings.HasPrefix(got, "u42:") {
		t.Errorf("expected a usable prefix for ops correlation, got %q", got)
	}
	// And no more than that: the tail must be gone.
	if strings.Contains(got, "abcdef") {
		t.Errorf("secret tail survived redaction: %q", got)
	}
}

// A short id has too little head to show without showing nearly all of it.
// Truncating "u1:d1" to "u1:d" would be theatre, not redaction.
func TestRedactClientID_ShortValuesFullyRedacted(t *testing.T) {
	for _, id := range []string{"", "u1", "u1:d1", "u42:d1x"} {
		got := redactClientID(id)
		if got != "[redacted]" {
			t.Errorf("redactClientID(%q) = %q, want fully redacted — a short id "+
				"cannot be partially shown without disclosing it", id, got)
		}
	}
}

// The guard that actually matters at the call sites: no management handler may
// pass a raw client_id to slog. Checked against the source, because a behavioural
// test cannot see which argument a log call received.
func TestManagementHandlers_DoNotLogRawClientID(t *testing.T) {
	raw, err := os.ReadFile("management.go")
	if err != nil {
		t.Fatalf("read management.go: %v", err)
	}

	// Every slog call mentioning client_id must route through redactClientID.
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") {
			continue
		}
		if !strings.Contains(trimmed, "slog.") || !strings.Contains(trimmed, "client_id") {
			continue
		}
		if !strings.Contains(trimmed, "redactClientID") {
			t.Errorf("management.go logs client_id without redaction:\n  %s", trimmed)
		}
	}
}
