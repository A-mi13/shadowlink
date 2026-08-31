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
	// The format actually used in production, from the management API docs.
	// A prefix-based redaction fails precisely here: six characters cannot be
	// partially shown, so the earlier implementation suppressed the whole thing
	// and left the log with no correlation handle at all.
	for _, id := range []string{"u42:d1", "u1:d5", "test:dev", "u42:d1-abcdef0123456789"} {
		got := redactClientID(id)

		if strings.Contains(got, id) {
			t.Errorf("redaction returned the full client_id: %q", got)
		}
		// No substring of the secret may survive. Checked over every window of
		// 3+ characters rather than a hand-picked tail, so a future change that
		// re-introduces a prefix is caught for short ids too.
		for n := 3; n <= len(id); n++ {
			for i := 0; i+n <= len(id); i++ {
				if window := id[i : i+n]; strings.Contains(got, window) {
					t.Errorf("redactClientID(%q) = %q leaks the substring %q",
						id, got, window)
				}
			}
		}
	}
}

// Correlation is the whole point of logging anything at all: an operator must be
// able to match "client added" with the later "client removed". A hash gives
// that for every id length, which a prefix could not.
func TestRedactClientID_IsStableAndDistinguishing(t *testing.T) {
	const a, b = "u42:d1", "u42:d2"

	if redactClientID(a) != redactClientID(a) {
		t.Error("redaction is not stable — added/removed lines could not be correlated")
	}
	if redactClientID(a) == redactClientID(b) {
		t.Errorf("two different client_ids rendered identically (%q) — neighbouring "+
			"devices of one user must stay distinguishable", redactClientID(a))
	}
	// Self-describing, so nobody mistakes the token for the id itself.
	if got := redactClientID(a); !strings.HasPrefix(got, "sha256:") {
		t.Errorf("expected a self-describing token, got %q", got)
	}
}

func TestRedactClientID_Empty(t *testing.T) {
	if got := redactClientID(""); got != "[empty]" {
		t.Errorf("redactClientID(\"\") = %q, want [empty] — hashing the empty "+
			"string would print a constant that looks like a real client", got)
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
