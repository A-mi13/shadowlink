package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// ---------- test plumbing ----------

// useTempResolvConf redirects resolvConfPath (and the systemd stub path) into a
// tempdir for the duration of the test, so the backup/restore state machine is
// exercised as pure file I/O on any platform (INT-L3a).
func useTempResolvConf(t *testing.T) (resolvPath, stubPath string) {
	t.Helper()
	dir := t.TempDir()
	resolvPath = filepath.Join(dir, "resolv.conf")
	stubPath = filepath.Join(dir, "stub-resolv.conf")

	oldResolv, oldStub := resolvConfPath, systemdStubResolvConf
	resolvConfPath = resolvPath
	systemdStubResolvConf = stubPath
	t.Cleanup(func() {
		resolvConfPath = oldResolv
		systemdStubResolvConf = oldStub
	})
	return resolvPath, stubPath
}

// stubExecTUNDNS replaces the exec seam with a recorder backed by a
// per-argv-key response table. Key = strings.Join(argv, " ").
type execResponse struct {
	out string
	err error
}

func stubExecTUNDNS(t *testing.T, responses map[string]execResponse) *[][]string {
	t.Helper()
	var calls [][]string
	old := execTUNDNSCmd
	execTUNDNSCmd = func(argv []string) (string, error) {
		cp := append([]string(nil), argv...)
		calls = append(calls, cp)
		if r, ok := responses[strings.Join(argv, " ")]; ok {
			return r.out, r.err
		}
		return "", nil
	}
	t.Cleanup(func() { execTUNDNSCmd = old })
	return &calls
}

type fakeExecErr string

func (e fakeExecErr) Error() string { return string(e) }

// ---------- Fix 1 + Fix 6a: resolv.conf marker + backup/restore state machine ----------

// TestBuildResolvConfContent pins the on-disk shape we write: the ownership
// marker as the FIRST line, then one nameserver line per provided IP (Fix 2:
// ALL entries, not just [0]).
func TestBuildResolvConfContent(t *testing.T) {
	got := buildResolvConfContent([]string{"77.88.8.8", "77.88.8.1", "1.1.1.1"})
	want := resolvConfMarker + "\n" +
		"nameserver 77.88.8.8\n" +
		"nameserver 77.88.8.1\n" +
		"nameserver 1.1.1.1\n"
	if got != want {
		t.Fatalf("resolv.conf content:\n got=%q\nwant=%q", got, want)
	}
	if !isNixaManagedResolvConf([]byte(got)) {
		t.Fatalf("our own content must be recognized as nixavpn-managed")
	}
	if isNixaManagedResolvConf([]byte("nameserver 192.168.1.1\n")) {
		t.Fatalf("foreign content must NOT be recognized as nixavpn-managed")
	}
}

// TestResolvConf_RegularOriginal_BackupWriteRestore is the happy-path state
// machine: a real original regular file is backed up, our marker file replaces
// it, and restore brings the original back byte-for-byte.
func TestResolvConf_RegularOriginal_BackupWriteRestore(t *testing.T) {
	resolvPath, _ := useTempResolvConf(t)
	original := "nameserver 192.168.1.1\nsearch lan\n"
	if err := os.WriteFile(resolvPath, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}

	tn := &Tunnel{}
	tn.writeResolvConf([]string{"198.18.0.1"})

	if !tn.resolvConfTouched {
		t.Fatalf("touched must be set after write")
	}
	if string(tn.resolvConfBackup) != original {
		t.Fatalf("backup mismatch: got=%q want=%q", tn.resolvConfBackup, original)
	}
	data, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatal(err)
	}
	if !isNixaManagedResolvConf(data) {
		t.Fatalf("written file must carry the marker, got %q", data)
	}
	if !strings.Contains(string(data), "nameserver 198.18.0.1\n") {
		t.Fatalf("written file must contain forwarder nameserver, got %q", data)
	}

	tn.restoreResolvConf()
	data, err = os.ReadFile(resolvPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("restore mismatch: got=%q want=%q", data, original)
	}
	if tn.resolvConfTouched || tn.resolvConfBackup != nil {
		t.Fatalf("state must be reset after restore")
	}
}

// TestResolvConf_SymlinkOriginal_TargetUntouchedAndRelinked (recheck HIGH):
// systemd-resolved layout — /etc/resolv.conf is a SYMLINK to the stub file.
// The write must NOT follow the symlink (a plain os.WriteFile would overwrite
// the STUB ITSELF with our forwarder IP, and restore would then recreate the
// symlink pointing at the poisoned stub → host DNS broken after Stop).
// Required behaviour: (a) the stub target stays byte-identical, (b) resolv.conf
// becomes our REGULAR marker file (symlink replaced), (c) restore recreates
// the symlink to the original target.
func TestResolvConf_SymlinkOriginal_TargetUntouchedAndRelinked(t *testing.T) {
	resolvPath, stubPath := useTempResolvConf(t)
	stubContent := "nameserver 127.0.0.53\noptions edns0 trust-ad\n"
	if err := os.WriteFile(stubPath, []byte(stubContent), 0644); err != nil {
		t.Fatal(err)
	}
	// Symlink creation may be unavailable on Windows without privileges —
	// follow the self-skipping probe convention.
	if err := os.Symlink(stubPath, resolvPath); err != nil {
		t.Skipf("os.Symlink unavailable on this host: %v", err)
	}

	tn := &Tunnel{}
	tn.writeResolvConf([]string{"198.18.0.1"})

	// Backup must have recorded the symlink, not file contents.
	if !tn.resolvConfWasSymlink || tn.resolvConfSymlinkDest != stubPath {
		t.Fatalf("backup must record symlink dest %q, got wasSymlink=%v dest=%q",
			stubPath, tn.resolvConfWasSymlink, tn.resolvConfSymlinkDest)
	}

	// (a) The stub TARGET must be untouched — write-through poisons it.
	data, err := os.ReadFile(stubPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != stubContent {
		t.Fatalf("stub target was modified (write followed the symlink):\n got=%q\nwant=%q", data, stubContent)
	}

	// (b) resolv.conf must now be a REGULAR file carrying our marker.
	fi, err := os.Lstat(resolvPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("resolv.conf must be a regular file after write, still a symlink")
	}
	data, err = os.ReadFile(resolvPath)
	if err != nil {
		t.Fatal(err)
	}
	if !isNixaManagedResolvConf(data) || !strings.Contains(string(data), "nameserver 198.18.0.1\n") {
		t.Fatalf("written file must be our marker file with the forwarder IP, got %q", data)
	}

	// (c) Restore recreates the symlink to the ORIGINAL target.
	tn.restoreResolvConf()
	fi, err = os.Lstat(resolvPath)
	if err != nil {
		t.Fatalf("resolv.conf must exist after restore: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("restored resolv.conf must be a symlink, mode=%v", fi.Mode())
	}
	dest, err := os.Readlink(resolvPath)
	if err != nil {
		t.Fatal(err)
	}
	if dest != stubPath {
		t.Fatalf("symlink dest: got=%q want=%q", dest, stubPath)
	}
	data, err = os.ReadFile(stubPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != stubContent {
		t.Fatalf("stub target changed across the cycle: got=%q want=%q", data, stubContent)
	}
}

// TestResolvConf_MarkerFile_NotTreatedAsOriginal is the INT-H3 regression
// guard: a leftover nixavpn-managed resolv.conf from a crashed session MUST NOT
// be captured as the "original" — otherwise the poison (forwarder IP) would be
// "restored" on Stop and host DNS stays broken forever.
func TestResolvConf_MarkerFile_NotTreatedAsOriginal(t *testing.T) {
	resolvPath, _ := useTempResolvConf(t)
	poisoned := buildResolvConfContent([]string{"198.18.0.1"})
	if err := os.WriteFile(resolvPath, []byte(poisoned), 0644); err != nil {
		t.Fatal(err)
	}

	tn := &Tunnel{}
	tn.backupResolvConf()

	if !tn.resolvConfTouched {
		t.Fatalf("touched must be set")
	}
	if tn.resolvConfBackup != nil {
		t.Fatalf("poisoned marker file must NOT be saved as backup, got %q", tn.resolvConfBackup)
	}
	if tn.resolvConfWasSymlink {
		t.Fatalf("marker file is not a symlink")
	}

	// Restore (no stub present) → our file is removed, host returns to "no
	// resolv.conf" rather than keeping the poison.
	tn.writeResolvConf([]string{"198.18.0.1"})
	tn.restoreResolvConf()
	if _, err := os.Lstat(resolvPath); !os.IsNotExist(err) {
		t.Fatalf("poisoned file must be removed on restore, stat err=%v", err)
	}
}

// TestResolvConf_MarkerFile_RestoresSystemdStubSymlink: when the default
// restore branch has no backup but the systemd-resolved stub exists, we
// recreate the conventional symlink so the host gets working DNS back.
func TestResolvConf_MarkerFile_RestoresSystemdStubSymlink(t *testing.T) {
	resolvPath, stubPath := useTempResolvConf(t)
	if err := os.WriteFile(stubPath, []byte("nameserver 127.0.0.53\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Probe: symlink creation may be unavailable on Windows without privileges.
	probe := filepath.Join(filepath.Dir(resolvPath), "probe-link")
	if err := os.Symlink(stubPath, probe); err != nil {
		t.Skipf("os.Symlink unavailable on this host: %v", err)
	}
	_ = os.Remove(probe)

	poisoned := buildResolvConfContent([]string{"198.18.0.1"})
	if err := os.WriteFile(resolvPath, []byte(poisoned), 0644); err != nil {
		t.Fatal(err)
	}

	tn := &Tunnel{}
	tn.writeResolvConf([]string{"198.18.0.1"})
	if tn.resolvConfBackup != nil {
		t.Fatalf("marker file must not become backup")
	}
	tn.restoreResolvConf()

	fi, err := os.Lstat(resolvPath)
	if err != nil {
		t.Fatalf("resolv.conf must exist as restored symlink: %v", err)
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("restored resolv.conf must be a symlink, mode=%v", fi.Mode())
	}
	dest, err := os.Readlink(resolvPath)
	if err != nil {
		t.Fatal(err)
	}
	if dest != stubPath {
		t.Fatalf("symlink dest: got=%q want=%q", dest, stubPath)
	}
}

// TestResolvConf_AbsentOriginal_RemovedOnRestore: original file absent →
// backup records nothing; restore removes our file (host returns to the
// pre-VPN "no resolv.conf" state).
func TestResolvConf_AbsentOriginal_RemovedOnRestore(t *testing.T) {
	resolvPath, _ := useTempResolvConf(t)

	tn := &Tunnel{}
	tn.writeResolvConf([]string{"198.18.0.1"})

	if !tn.resolvConfTouched {
		t.Fatalf("touched must be set")
	}
	if tn.resolvConfBackup != nil || tn.resolvConfWasSymlink {
		t.Fatalf("absent original must record no backup")
	}
	if _, err := os.Stat(resolvPath); err != nil {
		t.Fatalf("our file must have been written: %v", err)
	}

	tn.restoreResolvConf()
	if _, err := os.Lstat(resolvPath); !os.IsNotExist(err) {
		t.Fatalf("our file must be removed on restore, stat err=%v", err)
	}
}

// TestResolvConf_ForeignOverwrite_LeftAlone: ownership guard — if something
// else (NetworkManager, the user) rewrote resolv.conf after us WITHOUT our
// marker, the no-backup restore branch must NOT delete their file.
func TestResolvConf_ForeignOverwrite_LeftAlone(t *testing.T) {
	resolvPath, _ := useTempResolvConf(t)

	tn := &Tunnel{}
	tn.writeResolvConf([]string{"198.18.0.1"})
	foreign := "nameserver 10.0.0.1\n"
	if err := os.WriteFile(resolvPath, []byte(foreign), 0644); err != nil {
		t.Fatal(err)
	}

	tn.restoreResolvConf()
	data, err := os.ReadFile(resolvPath)
	if err != nil {
		t.Fatalf("foreign file must survive restore: %v", err)
	}
	if string(data) != foreign {
		t.Fatalf("foreign file content changed: got=%q want=%q", data, foreign)
	}
}

// ---------- Fix 2 + Fix 6b: split-DNS ⇒ setTUNDNS argument invariant ----------

// TestTunDNSPlan_SplitOn: split-DNS ON ⇒ setTUNDNS receives EXACTLY the
// forwarder listen IP on every platform.
func TestTunDNSPlan_SplitOn(t *testing.T) {
	for _, goos := range []string{"linux", "windows", "darwin"} {
		got := tunDNSPlan(true, goos, "198.18.0.1")
		if !reflect.DeepEqual(got, []string{"198.18.0.1"}) {
			t.Fatalf("%s split-on: got=%v want=[198.18.0.1]", goos, got)
		}
	}
}

// TestTunDNSPlan_LegacyLinuxUntouched: split-DNS OFF on Linux ⇒ nil plan —
// resolv.conf is NOT touched at all (pre-integration behaviour, INT-L2).
func TestTunDNSPlan_LegacyLinuxUntouched(t *testing.T) {
	if got := tunDNSPlan(false, "linux", ""); got != nil {
		t.Fatalf("legacy linux must not touch DNS, got=%v", got)
	}
}

// TestTunDNSPlan_LegacyTriple: split-DNS OFF on Windows/darwin keeps the
// historical Yandex-primary + Cloudflare-fallback triple, derived from the
// same source as the escape routes (yandexDNSIPs, invariant N2).
func TestTunDNSPlan_LegacyTriple(t *testing.T) {
	want := append(append([]string{}, yandexDNSIPs...), "1.1.1.1")
	for _, goos := range []string{"windows", "darwin"} {
		got := tunDNSPlan(false, goos, "")
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s legacy: got=%v want=%v", goos, got, want)
		}
	}
}

// ---------- Fix 3: darwin DNS ownership (backup → set → restore) ----------

func TestParseDarwinNetworkServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\n" +
		"Wi-Fi\n" +
		"Ethernet\n" +
		"*Thunderbolt Bridge\n" +
		"\n"
	got := parseDarwinNetworkServices(out)
	want := []string{"Wi-Fi", "Ethernet"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("services: got=%v want=%v (disabled * entries must be skipped)", got, want)
	}
}

func TestParseDarwinDNSServers(t *testing.T) {
	if got := parseDarwinDNSServers("There aren't any DNS Servers set on Wi-Fi.\n"); got != nil {
		t.Fatalf("sentinel must map to nil (automatic/DHCP), got=%v", got)
	}
	got := parseDarwinDNSServers("8.8.8.8\n8.8.4.4\n")
	want := []string{"8.8.8.8", "8.8.4.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("servers: got=%v want=%v", got, want)
	}
}

func TestBuildDarwinSetDNSArgs(t *testing.T) {
	got := buildDarwinSetDNSArgs("Wi-Fi", nil)
	want := []string{"networksetup", "-setdnsservers", "Wi-Fi", "Empty"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("empty restore: got=%v want=%v", got, want)
	}
	got = buildDarwinSetDNSArgs("Ethernet", []string{"8.8.8.8", "8.8.4.4"})
	want = []string{"networksetup", "-setdnsservers", "Ethernet", "8.8.8.8", "8.8.4.4"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with servers: got=%v want=%v", got, want)
	}
}

// TestSetDarwinDNS_BackupSetRestore drives the full darwin ownership cycle
// through the exec seam: enumerate services, back up each service's current
// DNS (sentinel → nil → "Empty" on restore), set the new DNS, then restore the
// originals in Stop's restoreDarwinDNSState.
func TestSetDarwinDNS_BackupSetRestore(t *testing.T) {
	calls := stubExecTUNDNS(t, map[string]execResponse{
		"networksetup -listallnetworkservices": {
			out: "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet\n*Thunderbolt Bridge\n",
		},
		"networksetup -getdnsservers Wi-Fi":    {out: "There aren't any DNS Servers set on Wi-Fi.\n"},
		"networksetup -getdnsservers Ethernet": {out: "8.8.8.8\n8.8.4.4\n"},
	})

	tn := &Tunnel{}
	if !tn.setDarwinDNS([]string{"127.0.0.1"}) {
		t.Fatalf("setDarwinDNS must report applied=true when services were set")
	}

	if !tn.darwinDNSTouched {
		t.Fatalf("darwinDNSTouched must be set")
	}
	wantBackup := []darwinDNSEntry{
		{service: "Wi-Fi", servers: nil},
		{service: "Ethernet", servers: []string{"8.8.8.8", "8.8.4.4"}},
	}
	if !reflect.DeepEqual(tn.darwinDNSBackup, wantBackup) {
		t.Fatalf("backup: got=%+v want=%+v", tn.darwinDNSBackup, wantBackup)
	}

	// Both enabled services must have been set; disabled one untouched.
	var setCalls [][]string
	for _, c := range *calls {
		if len(c) > 1 && c[1] == "-setdnsservers" {
			setCalls = append(setCalls, c)
		}
	}
	wantSet := [][]string{
		{"networksetup", "-setdnsservers", "Wi-Fi", "127.0.0.1"},
		{"networksetup", "-setdnsservers", "Ethernet", "127.0.0.1"},
	}
	if !reflect.DeepEqual(setCalls, wantSet) {
		t.Fatalf("set calls: got=%v want=%v", setCalls, wantSet)
	}

	// Restore: Wi-Fi back to automatic ("Empty"), Ethernet to its servers.
	*calls = nil
	tn.restoreDarwinDNSState()
	wantRestore := [][]string{
		{"networksetup", "-setdnsservers", "Wi-Fi", "Empty"},
		{"networksetup", "-setdnsservers", "Ethernet", "8.8.8.8", "8.8.4.4"},
	}
	if !reflect.DeepEqual(*calls, wantRestore) {
		t.Fatalf("restore calls: got=%v want=%v", *calls, wantRestore)
	}
	if tn.darwinDNSTouched || tn.darwinDNSBackup != nil {
		t.Fatalf("state must be reset after restore")
	}

	// Second restore is a no-op.
	*calls = nil
	tn.restoreDarwinDNSState()
	if len(*calls) != 0 {
		t.Fatalf("second restore must be a no-op, got calls=%v", *calls)
	}
}

// TestSetDarwinDNS_BackupFailSkipsService: ownership rule — a service whose
// current DNS we could not read is NOT modified (we never change what we
// cannot restore).
func TestSetDarwinDNS_BackupFailSkipsService(t *testing.T) {
	calls := stubExecTUNDNS(t, map[string]execResponse{
		"networksetup -listallnetworkservices": {out: "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\nEthernet\n"},
		"networksetup -getdnsservers Wi-Fi":    {out: "", err: fakeExecErr("boom")},
		"networksetup -getdnsservers Ethernet": {out: "1.1.1.1\n"},
	})

	tn := &Tunnel{}
	tn.setDarwinDNS([]string{"127.0.0.1"})

	for _, c := range *calls {
		if len(c) > 2 && c[1] == "-setdnsservers" && c[2] == "Wi-Fi" {
			t.Fatalf("Wi-Fi must NOT be set when its backup failed: %v", c)
		}
	}
	wantBackup := []darwinDNSEntry{{service: "Ethernet", servers: []string{"1.1.1.1"}}}
	if !reflect.DeepEqual(tn.darwinDNSBackup, wantBackup) {
		t.Fatalf("backup: got=%+v want=%+v", tn.darwinDNSBackup, wantBackup)
	}
}

// TestSetDarwinDNS_EnumerationFailNoChanges: if we cannot enumerate services,
// nothing is changed at all (and nothing will need restoring).
func TestSetDarwinDNS_EnumerationFailNoChanges(t *testing.T) {
	calls := stubExecTUNDNS(t, map[string]execResponse{
		"networksetup -listallnetworkservices": {out: "", err: fakeExecErr("no networksetup")},
	})

	tn := &Tunnel{}
	if tn.setDarwinDNS([]string{"127.0.0.1"}) {
		t.Fatalf("setDarwinDNS must report applied=false on enumeration failure (recheck NIT: the caller must not log success)")
	}

	if tn.darwinDNSTouched || tn.darwinDNSBackup != nil {
		t.Fatalf("no state must be recorded on enumeration failure")
	}
	if len(*calls) != 1 {
		t.Fatalf("only the enumeration call expected, got=%v", *calls)
	}
}

// ---------- Fix 4: Windows primary `set dns` failure must surface ----------

// TestSetWindowsTUNDNS_PrimaryFailureReturnsError: when STEP 0 (the primary
// `netsh ... set dns ... static <ip>`) fails, the TUN keeps no/old DNS and the
// forwarder is useless — setTUNDNS must return the error instead of lying nil.
func TestSetWindowsTUNDNS_PrimaryFailureReturnsError(t *testing.T) {
	stubExecTUNDNS(t, map[string]execResponse{
		"netsh interface ip set dns NixaVPN static 198.18.0.1": {
			out: "The requested operation requires elevation.", err: fakeExecErr("exit status 1"),
		},
	})
	err := setWindowsTUNDNS("NixaVPN", []string{"198.18.0.1"})
	if err == nil {
		t.Fatalf("primary set dns failure must return an error")
	}
	if !strings.Contains(err.Error(), "set dns") {
		t.Fatalf("error must mention the failed primary step, got: %v", err)
	}
}

// TestSetWindowsTUNDNS_SecondaryFailureBestEffort: secondary/metric steps stay
// best-effort — their failures are logged, not returned.
func TestSetWindowsTUNDNS_SecondaryFailureBestEffort(t *testing.T) {
	calls := stubExecTUNDNS(t, map[string]execResponse{
		"netsh interface ip add dns NixaVPN 77.88.8.1 index=2": {err: fakeExecErr("exit status 1")},
		"netsh interface ip set interface NixaVPN metric=1":    {err: fakeExecErr("exit status 1")},
	})
	err := setWindowsTUNDNS("NixaVPN", []string{"77.88.8.8", "77.88.8.1", "1.1.1.1"})
	if err != nil {
		t.Fatalf("secondary failures must stay best-effort, got err: %v", err)
	}
	// All steps must still have been attempted (incl. flushdns at the end).
	last := (*calls)[len(*calls)-1]
	if !reflect.DeepEqual(last, []string{"ipconfig", "/flushdns"}) {
		t.Fatalf("flushdns must run last, got=%v", last)
	}
}

// ---------- Fix 5: exact Name-column match in netsh interface output ----------

// TestFindNetshInterfaceIndex_ExactNameNotSubstring: "NixaVPN" must not match a
// stale "NixaVPN 2" adapter row (and vice versa), in either row order. The Name
// column is the LAST column and may contain spaces.
func TestFindNetshInterfaceIndex_ExactNameNotSubstring(t *testing.T) {
	header := "Idx     Met         MTU          State                Name\n" +
		"---  ----------  ----------  ------------  ---------------------------\n"
	rowMain := "  15          25        1400  connected     NixaVPN\n"
	rowStale := "  22          25        1400  disconnected  NixaVPN 2\n"
	rowLoop := "   1          75  4294967295  connected     Loopback Pseudo-Interface 1\n"

	for name, out := range map[string]string{
		"stale_first": header + rowStale + rowMain + rowLoop,
		"main_first":  header + rowMain + rowStale + rowLoop,
	} {
		t.Run(name, func(t *testing.T) {
			idx, ok := findNetshInterfaceIndex(out, "NixaVPN")
			if !ok || idx != "15" {
				t.Fatalf("NixaVPN: got idx=%q ok=%v, want 15/true", idx, ok)
			}
			idx, ok = findNetshInterfaceIndex(out, "NixaVPN 2")
			if !ok || idx != "22" {
				t.Fatalf("NixaVPN 2: got idx=%q ok=%v, want 22/true", idx, ok)
			}
			idx, ok = findNetshInterfaceIndex(out, "Loopback Pseudo-Interface 1")
			if !ok || idx != "1" {
				t.Fatalf("multi-word name: got idx=%q ok=%v, want 1/true", idx, ok)
			}
			if _, ok := findNetshInterfaceIndex(out, "NixaVPN 22"); ok {
				t.Fatalf("nonexistent name must not match")
			}
			if _, ok := findNetshInterfaceIndex(out, "VPN"); ok {
				t.Fatalf("substring of a name must not match")
			}
		})
	}
}
