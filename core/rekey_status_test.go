package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Rekey and RekeyNeeded are implemented, tested, and NOT wired into production
// (integration review, 2026-08-31). Their docstrings promised "rekey every hour
// or as sendSeq approaches 2^32", which described a policy nothing enforces —
// the same defect class this repo already tracks for startCreditSender.
//
// This guard exists because the failure mode is silent in BOTH directions:
//
//   - if the promise is restored in a comment without a caller, readers again
//     believe in a guarantee the system lacks;
//   - if a caller IS added, the May-audit C13 blocker fires — session tokens are
//     sealed with the server RecvKey and never re-issued, while
//     findSessionByHint verifies the client's token against the current key
//     (server/handler.go:1837), so every WS upgrade after a rekey fails.
//
// So the test asserts the CURRENT state and points at what to do if it changes,
// rather than trying to forbid the change.
func TestRekey_NotWiredInProduction(t *testing.T) {
	root := repoRootForRekeyScan(t)

	// Directories that make up the production surface.
	dirs := []string{"core", "client", "server", "engine", "mobile", "proxy", "cmd", "skins"}

	var callers []string
	for _, dir := range dirs {
		walkGoFiles(t, filepath.Join(root, dir), func(path string, src string) {
			// Skip tests: Rekey is legitimately exercised there.
			if strings.HasSuffix(path, "_test.go") {
				return
			}
			for i, line := range strings.Split(src, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
					continue
				}
				// The definitions themselves live in core/session.go.
				if strings.Contains(trimmed, "func (s *Session) Rekey") ||
					strings.Contains(trimmed, "func (s *Session) RekeyNeeded") {
					continue
				}
				if strings.Contains(trimmed, ".Rekey(") || strings.Contains(trimmed, ".RekeyNeeded(") {
					rel, _ := filepath.Rel(root, path)
					callers = append(callers, rel+":"+itoaLine(i+1)+": "+trimmed)
				}
			}
		})
	}

	if len(callers) > 0 {
		t.Fatalf("Rekey/RekeyNeeded now have production callers:\n  %s\n\n"+
			"If this is intentional, the May-audit C13 blocker must be closed first: "+
			"session tokens are sealed with the server RecvKey and are not re-issued "+
			"on rekey, while findSessionByHint (server/handler.go:1837) verifies the "+
			"client token against the CURRENT key — so WS upgrades break after the "+
			"first rekey. Then update the docstrings in core/session.go, which "+
			"currently state that this is not wired, and delete this test.",
			strings.Join(callers, "\n  "))
	}

	// The other half: the docstrings must keep saying so, or the next reader
	// re-acquires the false belief that removing the caller-check was meant to fix.
	sessionSrc := readRepoFile(t, filepath.Join(root, "core", "session.go"))
	if !strings.Contains(sessionSrc, "NOT WIRED IN PRODUCTION") {
		t.Error("core/session.go no longer documents that Rekey is unwired — " +
			"either wire it (see C13 above) or restore the warning")
	}
}

func itoaLine(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func repoRootForRekeyScan(t *testing.T) string {
	t.Helper()
	// Tests run in the package dir (core/), so the repo root is one level up.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Dir(wd)
}

func readRepoFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

func walkGoFiles(t *testing.T, dir string, fn func(path, src string)) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // package may not exist on this platform layout
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			walkGoFiles(t, p, fn)
			continue
		}
		if !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		fn(p, string(raw))
	}
}
