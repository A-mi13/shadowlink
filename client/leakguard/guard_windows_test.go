//go:build windows

package leakguard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records exec calls instead of running them.
type fakeRunner struct {
	calls [][]string
}

func (f *fakeRunner) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return "", nil
}

func (f *fakeRunner) calledDelete(rule string) bool {
	for _, c := range f.calls {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "delete rule") && strings.Contains(joined, "name="+rule) {
			return true
		}
	}
	return false
}

// fakeWFP records DeleteByProvider / ApplyRU.
type fakeWFP struct {
	applyCalls  [][]wfpFilterCond
	deleteCalls int
}

func (f *fakeWFP) ApplyRU(conds []wfpFilterCond) error {
	f.applyCalls = append(f.applyCalls, conds)
	return nil
}

func (f *fakeWFP) DeleteByProvider() error {
	f.deleteCalls++
	return nil
}

// Task 8 — Windows crash recovery removes SL-Block-All + WFP filters and
// deletes the state file before any network activity.
func TestWindowsNew_StaleState_TriggersRecovery(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "leakguard.state")
	if err := SaveState(statePath, &State{
		Platform: "windows",
		KillSwitch: KillSwitchState{
			Rules:   []string{"SL-Block-All"},
			Backend: "netsh-advfirewall",
		},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	fake := &fakeRunner{}
	fwfp := &fakeWFP{}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: fwfp}
	if err := g.crashRecover(); err != nil {
		t.Fatalf("crashRecover: %v", err)
	}

	if !fake.calledDelete("SL-Block-All") {
		t.Fatalf("crash recovery did not remove SL-Block-All; calls=%v", fake.calls)
	}
	if fwfp.deleteCalls == 0 {
		t.Fatalf("crash recovery did not call WFP DeleteByProvider")
	}
	if StateExists(statePath) {
		t.Fatalf("state must be deleted after recovery")
	}
}

// Crash recovery with corrupt/unreadable state still removes by well-known
// names + WFP filters, then clears state.
func TestWindowsCrashRecover_CorruptState_BlindCleanup(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "leakguard.state")
	// Write garbage so LoadState fails.
	if err := os.WriteFile(statePath, []byte("not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &fakeRunner{}
	fwfp := &fakeWFP{}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: fwfp}
	if err := g.crashRecover(); err != nil {
		t.Fatalf("crashRecover: %v", err)
	}
	// removeKillSwitchByName must have tried SL-Block-All.
	if !fake.calledDelete("SL-Block-All") {
		t.Fatalf("blind cleanup did not delete SL-Block-All; calls=%v", fake.calls)
	}
	if fwfp.deleteCalls == 0 {
		t.Fatalf("blind cleanup did not call WFP DeleteByProvider")
	}
	if StateExists(statePath) {
		t.Fatalf("state must be deleted")
	}
}
