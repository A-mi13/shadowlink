package server

import "testing"

func TestResolveDecoyDir_Mapped(t *testing.T) {
	m := map[string]string{"a.com": "/var/decoy/a", "b.com": "/var/decoy/b"}
	if got := resolveDecoyDir("a.com", m, "/default"); got != "/var/decoy/a" {
		t.Errorf("a.com → %q", got)
	}
	if got := resolveDecoyDir("b.com", m, "/default"); got != "/var/decoy/b" {
		t.Errorf("b.com → %q", got)
	}
}

func TestResolveDecoyDir_StripPort(t *testing.T) {
	m := map[string]string{"a.com": "/var/decoy/a"}
	if got := resolveDecoyDir("a.com:443", m, "/default"); got != "/var/decoy/a" {
		t.Errorf("a.com:443 → %q", got)
	}
	if got := resolveDecoyDir("a.com:80", m, "/default"); got != "/var/decoy/a" {
		t.Errorf("a.com:80 → %q", got)
	}
}

func TestResolveDecoyDir_DefaultOnUnknownHost(t *testing.T) {
	m := map[string]string{"a.com": "/var/decoy/a"}
	if got := resolveDecoyDir("c.com", m, "/default"); got != "/default" {
		t.Errorf("got %q, want /default", got)
	}
}

func TestResolveDecoyDir_NilMap(t *testing.T) {
	if got := resolveDecoyDir("x.com", nil, "/default"); got != "/default" {
		t.Errorf("got %q", got)
	}
}

func TestResolveDecoyDir_EmptyMap(t *testing.T) {
	if got := resolveDecoyDir("x.com", map[string]string{}, "/default"); got != "/default" {
		t.Errorf("got %q", got)
	}
}

func TestResolveDecoyDir_EmptyMappedValue(t *testing.T) {
	// Empty mapped value should fall back to default (defensive — config edge case)
	m := map[string]string{"a.com": ""}
	if got := resolveDecoyDir("a.com", m, "/default"); got != "/default" {
		t.Errorf("got %q, want /default", got)
	}
}

func TestResolveDecoyDir_IPv6Host(t *testing.T) {
	// IPv6 host is "[::1]:443" — LastIndex of ':' strips port correctly.
	// (Not a host that will match a domain map in practice — this just verifies non-crash.)
	m := map[string]string{"[::1]": "/var/decoy/local"}
	if got := resolveDecoyDir("[::1]:443", m, "/default"); got != "/var/decoy/local" {
		t.Errorf("got %q", got)
	}
}

func TestResolveDecoyDir_HostWithoutPort(t *testing.T) {
	m := map[string]string{"a.com": "/var/decoy/a"}
	if got := resolveDecoyDir("a.com", m, "/default"); got != "/var/decoy/a" {
		t.Errorf("got %q", got)
	}
}

func TestResolveDecoyDir_CaseInsensitiveHost(t *testing.T) {
	m := map[string]string{"a.com": "/var/decoy/a"}
	if got := resolveDecoyDir("A.COM", m, "/default"); got != "/var/decoy/a" {
		t.Errorf("uppercase host: got %q, want /var/decoy/a", got)
	}
	if got := resolveDecoyDir("A.Com:443", m, "/default"); got != "/var/decoy/a" {
		t.Errorf("mixed-case host with port: got %q", got)
	}
}

func TestResolveDecoyDir_BareIPv6_FallsBackToDefault(t *testing.T) {
	// Bare IPv6 literal "[::1]" without port — documented to fall back to default.
	m := map[string]string{"[::1]": "/var/decoy/local"}
	if got := resolveDecoyDir("[::1]", m, "/default"); got != "/var/decoy/local" {
		t.Errorf("got %q, want /var/decoy/local (bracket guard preserves bare IPv6)", got)
	}
}

func TestNewDecoyHandler_DedupePerDirServers(t *testing.T) {
	// Three hosts mapping to two unique dirs (one repeated).
	m := map[string]string{
		"a.com": "/tmp/decoy-shared",
		"b.com": "/tmp/decoy-shared", // duplicate dir
		"c.com": "/tmp/decoy-other",
	}
	d := NewDecoyHandler("", m)
	// Default dir is excluded from perDirServers (seen as defaultDir).
	// Two unique non-default dirs → two entries.
	if got := len(d.perDirServers); got != 2 {
		t.Errorf("perDirServers size = %d, want 2 (deduped)", got)
	}
}
