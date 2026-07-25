package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client/dnsproxy"
)

// TestBuildWindowsSetDNSCommands_SingleForwarder covers the split-DNS-ON shape:
// a single forwarder DNS becomes the sole static resolver, no secondaries.
func TestBuildWindowsSetDNSCommands_SingleForwarder(t *testing.T) {
	got := buildWindowsSetDNSCommands("NixaVPN", []string{"198.18.0.1"})
	want := [][]string{
		{"netsh", "interface", "ip", "set", "dns", "NixaVPN", "static", "198.18.0.1"},
		{"netsh", "interface", "ip", "set", "interface", "NixaVPN", "metric=1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("single DNS:\n got=%v\nwant=%v", got, want)
	}
}

// TestBuildWindowsSetDNSCommands_LegacyTriple covers the split-DNS-OFF shape:
// it must reproduce the legacy Yandex-primary + secondary + Cloudflare-fallback
// command sequence exactly (static primary, then index=2, index=3, then metric).
func TestBuildWindowsSetDNSCommands_LegacyTriple(t *testing.T) {
	got := buildWindowsSetDNSCommands("NixaVPN", []string{"77.88.8.8", "77.88.8.1", "1.1.1.1"})
	want := [][]string{
		{"netsh", "interface", "ip", "set", "dns", "NixaVPN", "static", "77.88.8.8"},
		{"netsh", "interface", "ip", "add", "dns", "NixaVPN", "77.88.8.1", "index=2"},
		{"netsh", "interface", "ip", "add", "dns", "NixaVPN", "1.1.1.1", "index=3"},
		{"netsh", "interface", "ip", "set", "interface", "NixaVPN", "metric=1"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("legacy triple DNS:\n got=%v\nwant=%v", got, want)
	}
}

// TestSplitDNSCandidates_Order pins the listener preference: TUN gateway first,
// loopback fallback second. startSplitDNS relies on this ordering.
func TestSplitDNSCandidates_Order(t *testing.T) {
	if len(splitDNSCandidates) != 2 {
		t.Fatalf("ожидалось 2 кандидата, got %d", len(splitDNSCandidates))
	}
	if splitDNSCandidates[0].ip != "198.18.0.1" || splitDNSCandidates[0].addr != "198.18.0.1:53" {
		t.Fatalf("первый кандидат должен быть TUN gateway, got %+v", splitDNSCandidates[0])
	}
	if splitDNSCandidates[1].ip != "127.0.0.1" || splitDNSCandidates[1].addr != "127.0.0.1:53" {
		t.Fatalf("второй кандидат должен быть loopback, got %+v", splitDNSCandidates[1])
	}
}

// TestYandexDNSIPs_MatchResolvers guards the N2 single-source-of-truth invariant:
// the escape-route Yandex IPs (yandexDNSIPs) MUST be derived from
// dnsproxy.DefaultYandexIPs(), not a parallel literal. If the dnsproxy source
// gains/loses/reorders a resolver, this test forces the escape list to follow
// (otherwise a new resolver would have no /32 escape route → UDP loops into TUN).
// We also pin the expected concrete value so an accidental change to the source
// is caught here too.
func TestYandexDNSIPs_MatchResolvers(t *testing.T) {
	if !reflect.DeepEqual(yandexDNSIPs, dnsproxy.DefaultYandexIPs()) {
		t.Fatalf("yandexDNSIPs not derived from dnsproxy source: got=%v src=%v",
			yandexDNSIPs, dnsproxy.DefaultYandexIPs())
	}
	want := []string{"77.88.8.8", "77.88.8.1"}
	if !reflect.DeepEqual(yandexDNSIPs, want) {
		t.Fatalf("yandexDNSIPs drift: got=%v want=%v", yandexDNSIPs, want)
	}
}

// TestBuildWindowsSetTUNAddrCommand pins the netsh argv for assigning the static
// TUN IP on Windows: `set address` (not `add`), name=<tun>, static <ip> <mask>,
// no gateway. assignTUNAddrWindows depends on this exact shape.
func TestBuildWindowsSetTUNAddrCommand(t *testing.T) {
	got := buildWindowsSetTUNAddrCommand("NixaVPN")
	want := []string{"netsh", "interface", "ip", "set", "address",
		"name=NixaVPN", "static", "198.18.0.1", "255.255.255.0"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("set tun addr:\n got=%v\nwant=%v", got, want)
	}
}

// TestSplitDNSBindAttempts pins the retry policy: the TUN gateway candidate
// (198.18.0.1) gets many bind attempts because Windows registers the freshly
// netsh-set address in the IP stack ASYNCHRONOUSLY (the field-proven delay can
// run to several seconds), while loopback and any other address get a single
// attempt. This is condition-based-waiting — the loop polls a real bind until it
// succeeds (success ⇔ address is registered). The total wait budget must stay
// under ~10.5s so Start never blocks too long in the anomalous worst case.
func TestSplitDNSBindAttempts(t *testing.T) {
	if got := splitDNSBindAttempts("198.18.0.1"); got != 20 {
		t.Fatalf("TUN gateway attempts: got %d, want 20", got)
	}
	if got := splitDNSBindAttempts("127.0.0.1"); got != 1 {
		t.Fatalf("loopback attempts: got %d, want 1", got)
	}
	if got := splitDNSBindAttempts("8.8.8.8"); got != 1 {
		t.Fatalf("other-address attempts: got %d, want 1", got)
	}
	// Бюджет ожидания: (attempts-1) пауз между попытками не должны превышать ~10.5с.
	maxWait := time.Duration(splitDNSBindAttempts("198.18.0.1")-1) * splitDNSBindRetryDelay
	if maxWait > 10500*time.Millisecond {
		t.Fatalf("retry budget слишком велик: %v (>10.5s) — Start повиснет", maxWait)
	}
}

// TestSplitDNSCandidates_GatewayIsTunStaticAddr ties the first candidate's IP to
// the tunStaticAddr constant used by assignTUNAddrWindows — the address we assign
// to the TUN MUST be the address the forwarder prefers to bind, otherwise the
// Windows fix and the bind would target different IPs.
func TestSplitDNSCandidates_GatewayIsTunStaticAddr(t *testing.T) {
	if splitDNSCandidates[0].ip != tunStaticAddr {
		t.Fatalf("первый candidate (%s) должен совпадать с tunStaticAddr (%s)",
			splitDNSCandidates[0].ip, tunStaticAddr)
	}
}

// TestRollbackStart_StopsForwarderAndWatcher is the regression guard for the
// forwarder-leak BLOCKER: when Start fails after the split-DNS forwarder and
// NIC watcher came up, the deferred rollbackStart() must stop the forwarder
// (t.dnsFwd == nil afterwards) and close + nil the watcher channel so the
// goroutine exits and :53 is released. engine.Stop() is a global no-op here
// (no engine was inserted) and is safe to invoke.
func TestRollbackStart_StopsForwarderAndWatcher(t *testing.T) {
	// Bind a real forwarder on an ephemeral loopback port (not :53, which may
	// be privileged) — rollbackStart only needs it to be a started Forwarder.
	fwd := dnsproxy.NewForwarder("127.0.0.1:0", nil)
	if err := fwd.Start(); err != nil {
		t.Fatalf("forwarder Start: %v", err)
	}

	stopCh := make(chan struct{})
	tn := &Tunnel{
		dnsFwd:         fwd,
		nicWatcherStop: stopCh,
	}

	tn.rollbackStart()

	if tn.dnsFwd != nil {
		t.Fatalf("rollbackStart должен обнулить dnsFwd, got non-nil")
	}
	if tn.nicWatcherStop != nil {
		t.Fatalf("rollbackStart должен обнулить nicWatcherStop, got non-nil")
	}
	// Канал watcher'а должен быть закрыт (горутина получит сигнал выхода).
	select {
	case <-stopCh:
		// закрыт — ок
	default:
		t.Fatalf("nicWatcherStop канал должен быть закрыт")
	}
}

// TestRollbackStart_IdempotentOnNil ensures rollbackStart is a safe no-op when
// nothing was created (the early Start error paths, e.g. createTUNLinux fail,
// hit the defer before any rollback-managed resource exists) and that a second
// call after a real rollback does not panic (double-close guard via nil-ing).
func TestRollbackStart_IdempotentOnNil(t *testing.T) {
	tn := &Tunnel{} // all nil

	// First call: pure no-op (forwarder/watcher nil; engine.Stop global no-op).
	tn.rollbackStart()

	// Bring up only the watcher channel, roll back, then roll back again —
	// the second call must not double-close (nil'd after the first).
	tn.nicWatcherStop = make(chan struct{})
	tn.rollbackStart()
	tn.rollbackStart() // must not panic

	if tn.nicWatcherStop != nil {
		t.Fatalf("nicWatcherStop должен остаться nil после двойного rollback")
	}
}
