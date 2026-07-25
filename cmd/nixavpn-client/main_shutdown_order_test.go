package main

import (
	"reflect"
	"testing"
)

// ---------- recheck MEDIUM: shutdown ordering tun.Stop BEFORE lg.Disable ----------

type orderRecorder struct {
	events []string
}

type fakeTunStopper struct {
	rec *orderRecorder
	err error
}

func (f *fakeTunStopper) Stop() error {
	f.rec.events = append(f.rec.events, "tun.Stop")
	return f.err
}

type fakeLGDisabler struct {
	rec *orderRecorder
	err error
}

func (f *fakeLGDisabler) Disable() error {
	f.rec.events = append(f.rec.events, "lg.Disable")
	return f.err
}

// TestShutdownTunnelAndGuard_TunStopBeforeLGDisable pins the shutdown
// invariant: tun.Stop BEFORE lg.Disable. LeakGuard owns the TRUE original DNS
// (PreLock ran before the tunnel ever touched DNS), so its restore must land
// LAST — the tunnel's darwin backup holds the LOCK values (1.1.1.1/8.8.8.8),
// and restoring them AFTER lg.Disable would permanently replace the user's
// DHCP/automatic DNS with the lock values.
func TestShutdownTunnelAndGuard_TunStopBeforeLGDisable(t *testing.T) {
	rec := &orderRecorder{}
	shutdownTunnelAndGuard(&fakeTunStopper{rec: rec}, &fakeLGDisabler{rec: rec})
	want := []string{"tun.Stop", "lg.Disable"}
	if !reflect.DeepEqual(rec.events, want) {
		t.Fatalf("shutdown order: got=%v want=%v", rec.events, want)
	}
}

// TestShutdownTunnelAndGuard_TunStopErrorStillDisablesLG: a tun.Stop failure
// must not skip the LeakGuard restore (best-effort, both always attempted).
func TestShutdownTunnelAndGuard_TunStopErrorStillDisablesLG(t *testing.T) {
	rec := &orderRecorder{}
	shutdownTunnelAndGuard(
		&fakeTunStopper{rec: rec, err: fakeExecErr("stop boom")},
		&fakeLGDisabler{rec: rec, err: fakeExecErr("disable boom")},
	)
	want := []string{"tun.Stop", "lg.Disable"}
	if !reflect.DeepEqual(rec.events, want) {
		t.Fatalf("errors must not short-circuit: got=%v want=%v", rec.events, want)
	}
}

// TestShutdownTunnelAndGuard_NilSafe pins the lg==nil semantics: when lg is
// nil, PreLock never ran, so the tunnel's own backup holds the TRUE user
// values and tun.Stop alone is the complete and correct restore. Symmetrically
// a nil tun must still disable lg, and both-nil must not panic.
func TestShutdownTunnelAndGuard_NilSafe(t *testing.T) {
	rec := &orderRecorder{}
	shutdownTunnelAndGuard(&fakeTunStopper{rec: rec}, nil)
	if !reflect.DeepEqual(rec.events, []string{"tun.Stop"}) {
		t.Fatalf("lg==nil: got=%v want=[tun.Stop]", rec.events)
	}

	rec = &orderRecorder{}
	shutdownTunnelAndGuard(nil, &fakeLGDisabler{rec: rec})
	if !reflect.DeepEqual(rec.events, []string{"lg.Disable"}) {
		t.Fatalf("tun==nil: got=%v want=[lg.Disable]", rec.events)
	}

	shutdownTunnelAndGuard(nil, nil) // must not panic
}
