//go:build windows

package leakguard

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// fakeRunner records exec calls instead of running them. Optional fields:
// outputs maps a substring of the joined command to a canned stdout; failOn
// makes any command whose joined form contains the substring return an error;
// onRun is invoked at execution time (for ordering assertions vs. disk state).
type fakeRunner struct {
	calls   [][]string
	outputs map[string]string
	failOn  string
	onRun   func(joined string)
}

func (f *fakeRunner) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	joined := strings.Join(append([]string{name}, args...), " ")
	if f.onRun != nil {
		f.onRun(joined)
	}
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return "", errors.New("fake runner: forced failure")
	}
	for sub, out := range f.outputs {
		if strings.Contains(joined, sub) {
			return out, nil
		}
	}
	return "", nil
}

// called reports whether any recorded call's joined form contains all substrings.
func (f *fakeRunner) called(subs ...string) bool {
	for _, c := range f.calls {
		joined := strings.Join(c, " ")
		all := true
		for _, s := range subs {
			if !strings.Contains(joined, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
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

// T8 — shouldSkipDNSIface table: TUN is skipped only when resolvable and the
// entry index matches; an empty tunIdx (TUN not yet up) skips nothing.
func TestShouldSkipDNSIface(t *testing.T) {
	cases := []struct {
		name     string
		entryIdx string
		tunIdx   string
		want     bool
	}{
		{"empty tunIdx skips nothing (PreLock, TUN not up)", "12", "", false},
		{"empty tunIdx and empty entry", "", "", false},
		{"match → skip TUN", "23", "23", true},
		{"no match → force physical NIC", "12", "23", false},
		{"different indices", "5", "9", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldSkipDNSIface(tc.entryIdx, tc.tunIdx); got != tc.want {
				t.Fatalf("shouldSkipDNSIface(%q,%q)=%v want %v", tc.entryIdx, tc.tunIdx, got, tc.want)
			}
		})
	}
}

// dnsSetIfaces returns the interface indices for which setDNS issued a
// Set-DnsClientServerAddress force command.
func (f *fakeRunner) dnsSetIfaces() []string {
	var got []string
	for _, c := range f.calls {
		joined := strings.Join(c, " ")
		if !strings.Contains(joined, "Set-DnsClientServerAddress") || !strings.Contains(joined, "1.1.1.1,8.8.8.8") {
			continue
		}
		// Extract "-InterfaceIndex <idx>".
		if i := strings.Index(joined, "-InterfaceIndex "); i >= 0 {
			rest := joined[i+len("-InterfaceIndex "):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				got = append(got, fields[0])
			}
		}
	}
	return got
}

// T8 — with no resolvable TUN (tunName empty), setDNS forces safe DNS on every
// backed-up interface (legacy behaviour preserved). net.InterfaceByName is the
// real syscall; an empty tunName short-circuits before it, so this case is
// deterministic without mocking the OS.
func TestSetDNS_NoTun_ForcesAllIfaces(t *testing.T) {
	fake := &fakeRunner{}
	g := &windowsGuard{runner: fake}
	backup := DNSBackup{Entries: []DNSEntry{
		{InterfaceName: "12"},
		{InterfaceName: "23"},
	}}
	g.setDNS(backup, "", false)

	got := fake.dnsSetIfaces()
	if len(got) != 2 {
		t.Fatalf("expected force on both ifaces, got %v (calls=%v)", got, fake.calls)
	}
	want := map[string]bool{"12": true, "23": true}
	for _, idx := range got {
		if !want[idx] {
			t.Fatalf("unexpected forced iface %q; got=%v", idx, got)
		}
	}
}

// T8 — when tunName resolves to a real interface, that interface's index is
// excluded from the force while all others are still forced. Uses the host's
// loopback interface as a stand-in "TUN" (guaranteed to resolve on Windows);
// the backup carries that real index plus a synthetic physical-NIC index.
func TestSetDNS_ResolvableTun_SkipsTunIface(t *testing.T) {
	// Pick any real interface to play the TUN role.
	ifaces, err := net.Interfaces()
	if err != nil || len(ifaces) == 0 {
		t.Skip("no network interfaces available to resolve a TUN stand-in")
	}
	tunIface := ifaces[0]
	tunIdx := strconv.Itoa(tunIface.Index)

	// A physical-NIC index guaranteed not to collide with the TUN index.
	physIdx := strconv.Itoa(tunIface.Index + 1000)

	fake := &fakeRunner{}
	g := &windowsGuard{runner: fake}
	backup := DNSBackup{Entries: []DNSEntry{
		{InterfaceName: tunIdx},  // TUN → must be skipped
		{InterfaceName: physIdx}, // physical NIC → must be forced
	}}
	g.setDNS(backup, tunIface.Name, true)

	got := fake.dnsSetIfaces()
	for _, idx := range got {
		if idx == tunIdx {
			t.Fatalf("TUN iface %q must NOT be forced; got=%v", tunIdx, got)
		}
	}
	foundPhys := false
	for _, idx := range got {
		if idx == physIdx {
			foundPhys = true
		}
	}
	if !foundPhys {
		t.Fatalf("physical NIC %q must be forced; got=%v", physIdx, got)
	}
}

// ---------------------------------------------------------------------------
// LG-H1 — default outbound firewall POLICY instead of an explicit block rule
// ---------------------------------------------------------------------------

// fwProfilesCSV mimics `Get-NetFirewallProfile | Select-Object Name,
// DefaultInboundAction,DefaultOutboundAction | ConvertTo-Csv -NoTypeInformation`.
const fwProfilesCSV = "\"Name\",\"DefaultInboundAction\",\"DefaultOutboundAction\"\r\n" +
	"\"Domain\",\"NotConfigured\",\"NotConfigured\"\r\n" +
	"\"Private\",\"Block\",\"Allow\"\r\n" +
	"\"Public\",\"Block\",\"Block\"\r\n"

func fwProfilesBackup() []FirewallProfilePolicy {
	return []FirewallProfilePolicy{
		{Name: "Domain", Inbound: "NotConfigured", Outbound: "NotConfigured"},
		{Name: "Private", Inbound: "Block", Outbound: "Allow"},
		{Name: "Public", Inbound: "Block", Outbound: "Block"},
	}
}

// fwProfilesPoisonedCSV is what Get-NetFirewallProfile reads back while the
// kill-switch policy is still armed (Block/Block on every profile) — e.g.
// after a crash inside the arming window.
const fwProfilesPoisonedCSV = "\"Name\",\"DefaultInboundAction\",\"DefaultOutboundAction\"\r\n" +
	"\"Domain\",\"Block\",\"Block\"\r\n" +
	"\"Private\",\"Block\",\"Block\"\r\n" +
	"\"Public\",\"Block\",\"Block\"\r\n"

// (a) Enable path flips the default outbound policy to Block and does NOT
// create any explicit block rule (block rules always beat allow rules).
func TestEnableKillSwitch_SetsBlockOutboundPolicy_NoBlockRule(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	fake := &fakeRunner{outputs: map[string]string{"Get-NetFirewallProfile": fwProfilesCSV}}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}

	var state State
	if err := g.enableKillSwitch(baseCfg(), &state); err != nil {
		t.Fatalf("enableKillSwitch: %v", err)
	}
	if !fake.called("netsh", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound") {
		t.Fatalf("default outbound policy was not set to block; calls=%v", fake.calls)
	}
	if fake.called("add rule", "action=block") {
		t.Fatalf("explicit block rule must not be created; calls=%v", fake.calls)
	}
	if !reflect.DeepEqual(state.FirewallPolicyBackup, fwProfilesBackup()) {
		t.Fatalf("policy backup mismatch: got=%+v want=%+v", state.FirewallPolicyBackup, fwProfilesBackup())
	}
	for _, r := range state.KillSwitch.Rules {
		if r == "SL-Block-All" {
			t.Fatalf("SL-Block-All must not be in applied rules: %v", state.KillSwitch.Rules)
		}
	}
}

// If the policy SET fails, the kill switch is not armed — Enable must
// return an error (strict mode must see it) and roll the added rules back.
func TestEnableKillSwitch_PolicySetFails_ReturnsError(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	fake := &fakeRunner{
		outputs: map[string]string{"Get-NetFirewallProfile": fwProfilesCSV},
		failOn:  "blockinbound,blockoutbound",
	}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}

	var state State
	if err := g.enableKillSwitch(baseCfg(), &state); err == nil {
		t.Fatal("enableKillSwitch must fail when the policy set fails")
	}
	if !fake.calledDelete("SL-Allow-TUN") {
		t.Fatalf("added rules must be rolled back on policy failure; calls=%v", fake.calls)
	}
	// The captured backup must be re-applied.
	if !fake.called("set privateprofile firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("policy restore from backup must be attempted; calls=%v", fake.calls)
	}
}

// Disable restores the backed-up per-profile policy. Explicit actions are
// restored verbatim; NotConfigured maps to the EFFECTIVE direction default
// (inbound→blockinbound, outbound→allowoutbound) because netsh rejects the
// "notconfigured" keyword for the local store (BLOCKER 1).
func TestDisable_RestoresBackedUpPolicyVerbatim(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "leakguard.state")
	if err := SaveState(statePath, &State{
		Platform: "windows",
		KillSwitch: KillSwitchState{
			Rules:   []string{"SL-Allow-TUN", "SL-Allow-DNS-RU"},
			Backend: "netsh-advfirewall",
		},
		FirewallPolicyBackup: fwProfilesBackup(),
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	fake := &fakeRunner{}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}
	if err := g.Disable(); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	wantCalls := [][]string{
		// Domain is NotConfigured/NotConfigured in the backup → effective
		// defaults (netsh rejects "notconfigured" for the local store).
		{"set domainprofile firewallpolicy blockinbound,allowoutbound"},
		{"set privateprofile firewallpolicy blockinbound,allowoutbound"},
		{"set publicprofile firewallpolicy blockinbound,blockoutbound"},
	}
	for _, w := range wantCalls {
		if !fake.called(w...) {
			t.Errorf("missing policy restore call %v; calls=%v", w, fake.calls)
		}
	}
	if fake.called("notconfigured") {
		t.Fatalf("netsh must never be sent the local-store-invalid 'notconfigured' keyword; calls=%v", fake.calls)
	}
	// No factory-default fallback when a backup exists.
	if fake.called("set allprofiles firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("factory default must not be applied when backup exists; calls=%v", fake.calls)
	}
	// (e) the DNS-RU permit is removed on disable.
	if !fake.calledDelete("SL-Allow-DNS-RU") {
		t.Fatalf("SL-Allow-DNS-RU must be deleted on disable; calls=%v", fake.calls)
	}
}

// (c) Restore without a backup falls back to the Windows factory default
// (blockinbound,allowoutbound) — never leaves blockoutbound stuck.
func TestRestoreFirewallPolicy_NoBackup_FactoryDefault(t *testing.T) {
	fake := &fakeRunner{}
	g := &windowsGuard{runner: fake}
	g.restoreFirewallPolicy(nil)
	if !fake.called("netsh", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound") {
		t.Fatalf("factory default restore missing; calls=%v", fake.calls)
	}
}

// (d) Enable persists the policy backup into State; crashRecover restores it.
func TestEnable_PersistsPolicyBackup_AndCrashRecoverRestores(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "leakguard.state")
	fake := &fakeRunner{outputs: map[string]string{"Get-NetFirewallProfile": fwProfilesCSV}}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}

	if err := g.Enable(baseCfg()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !reflect.DeepEqual(state.FirewallPolicyBackup, fwProfilesBackup()) {
		t.Fatalf("persisted backup mismatch: got=%+v want=%+v",
			state.FirewallPolicyBackup, fwProfilesBackup())
	}

	// Simulate restart-after-crash: a fresh guard recovers from the state file.
	fake2 := &fakeRunner{}
	g2 := &windowsGuard{statePath: statePath, runner: fake2, wfp: &fakeWFP{}}
	if err := g2.crashRecover(); err != nil {
		t.Fatalf("crashRecover: %v", err)
	}
	if !fake2.called("set publicprofile firewallpolicy blockinbound,blockoutbound") {
		t.Fatalf("crash recovery must restore the persisted policy; calls=%v", fake2.calls)
	}
	if StateExists(statePath) {
		t.Fatalf("state must be deleted after recovery")
	}
}

// A PreLock-only state (no kill-switch rules, no policy backup) means the
// policy was never touched — recovery must not reset it to factory default.
func TestCrashRecover_PreLockOnlyState_DoesNotTouchPolicy(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "leakguard.state")
	if err := SaveState(statePath, &State{Platform: "windows"}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	fake := &fakeRunner{}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}
	if err := g.crashRecover(); err != nil {
		t.Fatalf("crashRecover: %v", err)
	}
	if fake.called("firewallpolicy") {
		t.Fatalf("policy must not be touched for a PreLock-only state; calls=%v", fake.calls)
	}
}

// Corrupt state → blind cleanup must still un-stick the policy via the
// factory default (we cannot know the original; over-block must not persist).
func TestCrashRecover_CorruptState_FactoryDefaultPolicy(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "leakguard.state")
	if err := os.WriteFile(statePath, []byte("not json"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	fake := &fakeRunner{}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}
	if err := g.crashRecover(); err != nil {
		t.Fatalf("crashRecover: %v", err)
	}
	if !fake.called("set allprofiles firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("blind cleanup must restore factory default policy; calls=%v", fake.calls)
	}
}

// Locale-independence: the PS CSV parser works off numeric-free enum names and
// profile names, never localized netsh text.
func TestParsePSFirewallProfiles(t *testing.T) {
	got := parsePSFirewallProfiles(fwProfilesCSV)
	if !reflect.DeepEqual(got, fwProfilesBackup()) {
		t.Fatalf("parse mismatch: got=%+v want=%+v", got, fwProfilesBackup())
	}
	if out := parsePSFirewallProfiles(""); out != nil {
		t.Fatalf("empty input must parse to nil, got %+v", out)
	}
	// Garbage rows are skipped.
	if out := parsePSFirewallProfiles("garbage\r\n\"OnlyTwo\",\"Fields\"\r\n"); out != nil {
		t.Fatalf("garbage input must parse to nil, got %+v", out)
	}
}

// Unknown profile/action values in a backup must not leave the policy stuck:
// the per-profile restore falls back to factory default for that profile.
func TestRestoreFirewallPolicy_UnknownValues_FactoryPerProfile(t *testing.T) {
	fake := &fakeRunner{}
	g := &windowsGuard{runner: fake}
	g.restoreFirewallPolicy([]FirewallProfilePolicy{
		{Name: "Private", Inbound: "Mystery", Outbound: "Values"},
	})
	if !fake.called("set privateprofile firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("unmappable actions must fall back to factory default for the profile; calls=%v", fake.calls)
	}
}

// ---------------------------------------------------------------------------
// BLOCKER 1 — NotConfigured restore must work on a live netsh
// ---------------------------------------------------------------------------

// (a) All-NotConfigured backup (the Windows DEFAULT state of
// Get-NetFirewallProfile) must restore via the EFFECTIVE direction defaults
// (inbound→blockinbound, outbound→allowoutbound) per profile — netsh rejects
// "notconfigured" for the local store — with NO allprofiles factory fallback.
func TestRestoreFirewallPolicy_AllNotConfigured_EffectiveDefaults(t *testing.T) {
	fake := &fakeRunner{}
	g := &windowsGuard{runner: fake}
	g.restoreFirewallPolicy([]FirewallProfilePolicy{
		{Name: "Domain", Inbound: "NotConfigured", Outbound: "NotConfigured"},
		{Name: "Private", Inbound: "NotConfigured", Outbound: "NotConfigured"},
		{Name: "Public", Inbound: "NotConfigured", Outbound: "NotConfigured"},
	})
	for _, profile := range []string{"domainprofile", "privateprofile", "publicprofile"} {
		if !fake.called("set " + profile + " firewallpolicy blockinbound,allowoutbound") {
			t.Errorf("profile %s must be restored to the effective defaults; calls=%v", profile, fake.calls)
		}
	}
	if fake.called("notconfigured") {
		t.Fatalf("netsh must never be sent 'notconfigured'; calls=%v", fake.calls)
	}
	if fake.called("set allprofiles") {
		t.Fatalf("per-profile restore succeeded — allprofiles factory fallback must not fire; calls=%v", fake.calls)
	}
}

// (b) MIXED backup (one profile explicit, one NotConfigured): the
// NotConfigured profile must get the effective default — previously its
// restore errored on live netsh while restored>=1 suppressed the factory
// fallback, leaving that profile stuck on blockoutbound.
func TestRestoreFirewallPolicy_MixedBackup_NotConfiguredEffectiveDefault(t *testing.T) {
	fake := &fakeRunner{}
	g := &windowsGuard{runner: fake}
	g.restoreFirewallPolicy([]FirewallProfilePolicy{
		{Name: "Private", Inbound: "Block", Outbound: "Allow"},
		{Name: "Public", Inbound: "NotConfigured", Outbound: "NotConfigured"},
	})
	if !fake.called("set privateprofile firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("explicit profile must restore verbatim; calls=%v", fake.calls)
	}
	if !fake.called("set publicprofile firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("NotConfigured profile must restore to effective defaults; calls=%v", fake.calls)
	}
	if fake.called("notconfigured") {
		t.Fatalf("netsh must never be sent 'notconfigured'; calls=%v", fake.calls)
	}
}

// (c) A per-profile netsh restore failure must retry THAT profile with the
// factory default instead of skipping it — no profile may remain on
// blockoutbound just because its exact restore command errored.
func TestRestoreFirewallPolicy_PerProfileFailure_FactoryRetry(t *testing.T) {
	// The exact restore for Public is blockinbound,blockoutbound — force it
	// to fail; the factory-default retry must then be issued and succeed.
	fake := &fakeRunner{failOn: "blockinbound,blockoutbound"}
	g := &windowsGuard{runner: fake}
	g.restoreFirewallPolicy([]FirewallProfilePolicy{
		{Name: "Public", Inbound: "Block", Outbound: "Block"},
	})
	if !fake.called("set publicprofile firewallpolicy blockinbound,blockoutbound") {
		t.Fatalf("exact restore must be attempted first; calls=%v", fake.calls)
	}
	if !fake.called("set publicprofile firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("failed per-profile restore must be retried with the factory default; calls=%v", fake.calls)
	}
	if fake.called("set allprofiles") {
		t.Fatalf("factory retry succeeded — allprofiles fallback must not fire; calls=%v", fake.calls)
	}
}

// ---------------------------------------------------------------------------
// BLOCKER 2 — crash window between policy SET and SaveState
// ---------------------------------------------------------------------------

// (d) The checkpoint state (policy backup + planned rule names) must already
// be ON DISK at the moment the arming netsh command executes — a crash right
// after the SET must find everything crashRecover needs.
func TestEnable_CheckpointPersistedBeforePolicySet(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	fake := &fakeRunner{outputs: map[string]string{"Get-NetFirewallProfile": fwProfilesCSV}}
	var checkpointAtArm *State
	armSeen := false
	fake.onRun = func(joined string) {
		if strings.Contains(joined, "set allprofiles firewallpolicy blockinbound,blockoutbound") {
			armSeen = true
			if st, err := LoadState(statePath); err == nil {
				checkpointAtArm = st
			}
		}
	}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}
	if err := g.Enable(baseCfg()); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !armSeen {
		t.Fatalf("policy was never armed; calls=%v", fake.calls)
	}
	if checkpointAtArm == nil {
		t.Fatal("no readable state file on disk at the moment the policy was armed")
	}
	if !reflect.DeepEqual(checkpointAtArm.FirewallPolicyBackup, fwProfilesBackup()) {
		t.Fatalf("checkpoint must carry the policy backup before arming: got=%+v want=%+v",
			checkpointAtArm.FirewallPolicyBackup, fwProfilesBackup())
	}
	if len(checkpointAtArm.KillSwitch.Rules) == 0 {
		t.Fatalf("checkpoint must carry the applied rule names before arming: %+v", checkpointAtArm.KillSwitch)
	}
}

// (e) A checkpoint-shaped state (rules + policy backup persisted, final
// SaveState never ran — crash inside the arming window) must make
// crashRecover restore the policy.
func TestCrashRecover_CheckpointState_RestoresPolicy(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	if err := SaveState(statePath, &State{
		Platform: "windows",
		KillSwitch: KillSwitchState{
			Rules:   []string{"SL-Allow-TUN", "SL-Allow-DNS-RU"},
			Backend: "netsh-advfirewall",
		},
		FirewallPolicyBackup: fwProfilesBackup(),
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	fake := &fakeRunner{}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}
	if err := g.crashRecover(); err != nil {
		t.Fatalf("crashRecover: %v", err)
	}
	if !fake.called("set publicprofile firewallpolicy blockinbound,blockoutbound") {
		t.Fatalf("crash recovery must restore the explicit backed-up policy; calls=%v", fake.calls)
	}
	if !fake.called("set domainprofile firewallpolicy blockinbound,allowoutbound") {
		t.Fatalf("crash recovery must restore NotConfigured profiles to effective defaults; calls=%v", fake.calls)
	}
	if StateExists(statePath) {
		t.Fatalf("state must be deleted after recovery")
	}
}

// (f) If the checkpoint SaveState fails, the policy must NEVER be armed and
// Enable must error — fail-secure but recoverable (rules removed, policy
// untouched), never blockoutbound without a persisted restore path.
func TestEnable_CheckpointSaveFails_PolicyNeverSet(t *testing.T) {
	// statePath inside a nonexistent directory → SaveState fails.
	statePath := filepath.Join(t.TempDir(), "no-such-dir", "leakguard.state")
	fake := &fakeRunner{outputs: map[string]string{"Get-NetFirewallProfile": fwProfilesCSV}}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}

	if err := g.Enable(baseCfg()); err == nil {
		t.Fatal("Enable must fail when the checkpoint state cannot be persisted")
	}
	if fake.called("set allprofiles firewallpolicy blockinbound,blockoutbound") {
		t.Fatalf("policy must never be armed without a persisted checkpoint; calls=%v", fake.calls)
	}
	if !fake.calledDelete("SL-Allow-TUN") {
		t.Fatalf("added rules must be rolled back when the checkpoint save fails; calls=%v", fake.calls)
	}
}

// (g) Re-Enable while the previous (crashed) enable's policy is still armed:
// the fresh backup read returns Block/Block on all profiles. The persisted
// good backup must win — otherwise a later Disable "restores" blockoutbound
// forever (stuck-broken-host).
func TestEnable_AfterCrash_PrefersPersistedBackupOverPoisonedRead(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	// Persisted state from the crashed enable holds the good backup.
	if err := SaveState(statePath, &State{
		Platform: "windows",
		KillSwitch: KillSwitchState{
			Rules:   []string{"SL-Allow-TUN"},
			Backend: "netsh-advfirewall",
		},
		FirewallPolicyBackup: fwProfilesBackup(),
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	fake := &fakeRunner{outputs: map[string]string{"Get-NetFirewallProfile": fwProfilesPoisonedCSV}}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}
	if err := g.Enable(baseCfg()); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !reflect.DeepEqual(state.FirewallPolicyBackup, fwProfilesBackup()) {
		t.Fatalf("poisoned Block/Block read must not overwrite the persisted good backup: got=%+v want=%+v",
			state.FirewallPolicyBackup, fwProfilesBackup())
	}
}

// A FAILED fresh policy read must not clobber a good persisted backup either —
// otherwise a later restore degrades to the factory default instead of the
// host's original policy.
func TestEnable_AfterCrash_PrefersPersistedBackupOverFailedRead(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "leakguard.state")
	if err := SaveState(statePath, &State{
		Platform: "windows",
		KillSwitch: KillSwitchState{
			Rules:   []string{"SL-Allow-TUN"},
			Backend: "netsh-advfirewall",
		},
		FirewallPolicyBackup: fwProfilesBackup(),
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	fake := &fakeRunner{failOn: "Get-NetFirewallProfile"}
	g := &windowsGuard{statePath: statePath, runner: fake, wfp: &fakeWFP{}}
	if err := g.Enable(baseCfg()); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if !reflect.DeepEqual(state.FirewallPolicyBackup, fwProfilesBackup()) {
		t.Fatalf("failed policy read must not overwrite the persisted good backup: got=%+v want=%+v",
			state.FirewallPolicyBackup, fwProfilesBackup())
	}
}

// MEDIUM 3 — header skip must be content-based: a BOM and/or leading blank
// line must not let the header row parse as a profile {Name:"Name"}.
func TestParsePSFirewallProfiles_BOMAndLeadingBlankLine(t *testing.T) {
	cases := map[string]string{
		"BOM on header":            "\ufeff" + fwProfilesCSV,
		"blank line then BOM":      "\r\n\ufeff" + fwProfilesCSV,
		"BOM line then blank line": "\ufeff\r\n\r\n" + fwProfilesCSV,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			got := parsePSFirewallProfiles(input)
			if !reflect.DeepEqual(got, fwProfilesBackup()) {
				t.Fatalf("parse mismatch: got=%+v want=%+v", got, fwProfilesBackup())
			}
		})
	}
}
