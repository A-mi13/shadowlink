package main

import (
	"testing"
	"time"

	"github.com/nixavpn/shadowlink/client/dnsproxy"
)

// TestRunNICWatcher_ExitsViaCapturedChannel pins INT-H1: the NIC watcher must
// select on a stop channel captured by value at launch (same pattern as
// dnsproxy.Forwarder.runBranchLog), NOT re-read t.nicWatcherStop each loop
// iteration. The old implementation raced with Stop/rollbackStart (which do
// `close(ch); t.nicWatcherStop = nil` under mu): if the watcher was inside the
// ticker branch during Stop, its next select read the now-nil field and blocked
// forever on a nil-channel receive — the goroutine leaked, kept exec'ing
// getDefaultGateway every 30s and could clobber tunsdialer.DefaultDialer state
// of a subsequent Start. Here we nil the field FIRST, then close the captured
// channel: only a by-value capture observes the close and exits.
func TestRunNICWatcher_ExitsViaCapturedChannel(t *testing.T) {
	stop := make(chan struct{})
	tn := &Tunnel{nicWatcherStop: stop}

	done := make(chan struct{})
	go func() {
		tn.runNICWatcher(0, stop)
		close(done)
	}()

	// Simulate the Stop() sequence with the worst-case interleaving: the field
	// is nil'd before the watcher's next select iteration.
	tn.nicWatcherStop = nil
	close(stop)

	select {
	case <-done:
		// exited promptly — channel was captured by value
	case <-time.After(2 * time.Second):
		t.Fatal("NIC watcher не завершился после close(stop) — канал не захвачен by value")
	}
}

// TestRollbackStart_CleansRoutesWhenAttempted pins INT-M1: a fatal setupRoutes
// error (escape /32s, Yandex DNS /32s and the /16 CIDR sweep already installed
// via the PHYSICAL gateway, then addSplitRoutes failed) must trigger
// cleanupRoutes from rollbackStart — those routes live in the OS routing table
// until reboot and are NOT torn down with the engine. The routesDirty flag is
// set by Start before calling setupRoutes; rollbackStart consumes it exactly
// once (second rollback must not re-run cleanup).
func TestRollbackStart_CleansRoutesWhenAttempted(t *testing.T) {
	calls := 0
	var gotDevice string
	var gotIPs []string
	orig := cleanupRoutesFn
	cleanupRoutesFn = func(device string, serverIPs []string) error {
		calls++
		gotDevice = device
		gotIPs = serverIPs
		return nil
	}
	defer func() { cleanupRoutesFn = orig }()

	tn := &Tunnel{
		serverIPs:   []string{"104.222.177.67"},
		routesDirty: true,
	}
	tn.rollbackStart()

	if calls != 1 {
		t.Fatalf("cleanupRoutes должен быть вызван ровно 1 раз, got %d", calls)
	}
	if gotDevice != tunDeviceName() {
		t.Fatalf("cleanupRoutes device: got %q, want %q", gotDevice, tunDeviceName())
	}
	if len(gotIPs) != 1 || gotIPs[0] != "104.222.177.67" {
		t.Fatalf("cleanupRoutes serverIPs: got %v", gotIPs)
	}
	if tn.routesDirty {
		t.Fatal("routesDirty должен быть сброшен после cleanup")
	}

	// Idempotency: a second rollback must not re-invoke cleanup.
	tn.rollbackStart()
	if calls != 1 {
		t.Fatalf("повторный rollbackStart не должен повторять cleanup, got %d calls", calls)
	}
}

// TestRollbackStart_SkipsRouteCleanupWhenNotAttempted guards the early Start
// error paths (createTUNLinux fail, tun2socks fail, TUN not ready): setupRoutes
// was never reached, so rollbackStart must NOT exec route-delete commands.
func TestRollbackStart_SkipsRouteCleanupWhenNotAttempted(t *testing.T) {
	calls := 0
	orig := cleanupRoutesFn
	cleanupRoutesFn = func(device string, serverIPs []string) error {
		calls++
		return nil
	}
	defer func() { cleanupRoutesFn = orig }()

	tn := &Tunnel{serverIPs: []string{"104.222.177.67"}} // routesDirty false
	tn.rollbackStart()

	if calls != 0 {
		t.Fatalf("cleanupRoutes не должен вызываться без routesDirty, got %d calls", calls)
	}
}

// TestStop_SharedTeardownAndRouteCleanup covers INT-I3: Stop must release the
// forwarder and NIC watcher through the same teardown helper as rollbackStart
// (forwarder → watcher, both nil'd under mu so a second Stop is a no-op),
// clean routes, and clear started/routesDirty.
func TestStop_SharedTeardownAndRouteCleanup(t *testing.T) {
	calls := 0
	orig := cleanupRoutesFn
	cleanupRoutesFn = func(device string, serverIPs []string) error {
		calls++
		return nil
	}
	defer func() { cleanupRoutesFn = orig }()

	fwd := dnsproxy.NewForwarder("127.0.0.1:0", nil)
	if err := fwd.Start(); err != nil {
		t.Fatalf("forwarder Start: %v", err)
	}

	stopCh := make(chan struct{})
	tn := &Tunnel{
		started:        true,
		dnsFwd:         fwd,
		nicWatcherStop: stopCh,
		routesDirty:    true,
		serverIPs:      []string{"104.222.177.67"},
	}

	if err := tn.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if tn.dnsFwd != nil {
		t.Fatal("Stop должен обнулить dnsFwd")
	}
	if tn.nicWatcherStop != nil {
		t.Fatal("Stop должен обнулить nicWatcherStop")
	}
	select {
	case <-stopCh:
		// closed — watcher получит сигнал выхода
	default:
		t.Fatal("nicWatcherStop канал должен быть закрыт")
	}
	if calls != 1 {
		t.Fatalf("cleanupRoutes должен быть вызван ровно 1 раз, got %d", calls)
	}
	if tn.started {
		t.Fatal("started должен быть сброшен")
	}
	if tn.routesDirty {
		t.Fatal("routesDirty должен быть сброшен")
	}

	// Second Stop short-circuits on !started — no second cleanup.
	if err := tn.Stop(); err != nil {
		t.Fatalf("повторный Stop: %v", err)
	}
	if calls != 1 {
		t.Fatalf("повторный Stop не должен повторять cleanup, got %d calls", calls)
	}
}
