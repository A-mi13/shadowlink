package server

import "strings"

// resolveDecoyDir picks a decoy directory based on the request Host header.
// If a mapping for the host exists, returns the mapped directory.
// Host header may include a port suffix ("host:port") — stripped before lookup.
// Host is matched case-insensitively per RFC 7230 §5.4 (the map MUST
// contain lowercase keys; orchestrator normalizes at population time).
// Returns defaultDir when m is nil/empty, when the host is not in the map,
// or when the mapped value is empty.
//
// IPv6 hosts: bracketed forms like "[::1]:443" → "[::1]" via LastIndex(':').
// Bare bracketed IPv6 ("[::1]") without port: LastIndex(':') falls inside the
// literal, leaving "[:" — that miss is documented and falls back to defaultDir
// (production never receives bracket-bare IPv6 in Host: HTTP/1.1 mandates the
// port be present when a non-default port is used, otherwise the address is
// not bracketed).
func resolveDecoyDir(host string, m map[string]string, defaultDir string) string {
	if len(m) == 0 {
		return defaultDir
	}
	h := host
	// Strip port. For "[::1]:443" or "host:443" both work via LastIndex.
	// For bare "[::1]" we'd corrupt the literal — guard with bracket check.
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		// Bare IPv6 literal, no port — leave as-is.
	} else if i := strings.LastIndex(h, ":"); i > 0 {
		h = h[:i]
	}
	h = strings.ToLower(h)
	if mapped, ok := m[h]; ok && mapped != "" {
		return mapped
	}
	return defaultDir
}
