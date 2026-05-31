package server

import (
	"strings"
	"testing"
	"time"
)

// TestMigrateMetricsExist verifies the FULL Bug #9 §4.3 metric table is present
// on *Metrics (Task 11 added the four core counters; Task 18 finalizes the
// reason-split + orphan + FD-budget counters and the OrphanedRelaysActive gauge)
// and that every one of them increments. The four Task 11 counters
// (MigrateOK/ResumeOK/MigrateFail/MigrateGraceExpired) are exercised alongside
// the Task 18 additions so a regression that drops/renames either set fails.
func TestMigrateMetricsExist(t *testing.T) {
	m := NewMetrics()

	// Task 11 core counters.
	m.MigrateOK.Add(1)
	m.ResumeOK.Add(1)
	m.MigrateFail.Add(1)
	m.MigrateGraceExpired.Add(1)

	// Task 18 reason-split fail counters (on *Metrics).
	m.MigrateFailNotFound.Add(1)
	m.MigrateFailBadProof.Add(1)
	m.MigrateFailGraceExpired.Add(1)

	// Task 18 tail instrumentation (on *Metrics).
	m.MigrateTailResent.Add(1)
	m.MigrateTailBufferedBytes.Add(64)

	// Task 18 orphan / FD-budget counters live on the relay registry (single
	// source of truth — they're mutated on the admit/evict hot paths). The
	// Snapshot reads them through the attached registry; verify they increment
	// on the registry rather than expecting duplicate fields on *Metrics.
	reg := newRelayRegistry()
	reg.orphanedEvictedLimit.Add(1)
	reg.orphanFDRejected.Add(1)

	if m.MigrateOK.Load() != 1 || m.ResumeOK.Load() != 1 ||
		m.MigrateFail.Load() != 1 || m.MigrateGraceExpired.Load() != 1 {
		t.Fatalf("Task 11 core counters did not increment")
	}
	if m.MigrateFailNotFound.Load() != 1 || m.MigrateFailBadProof.Load() != 1 ||
		m.MigrateFailGraceExpired.Load() != 1 {
		t.Fatalf("Task 18 reason-split counters did not increment")
	}
	if m.MigrateTailResent.Load() != 1 || m.MigrateTailBufferedBytes.Load() != 64 {
		t.Fatalf("Task 18 tail counters did not increment")
	}
	if reg.orphanedEvictedLimit.Load() != 1 || reg.orphanFDRejected.Load() != 1 {
		t.Fatalf("Task 18 registry orphan/FD counters did not increment")
	}
}

// TestMigrateMetricsExposed verifies the Bug #9 §4.3 counters surface through
// BOTH the JSON snapshot and the Prometheus text exporter (the exposition that
// Task 11 deferred). The registry-sourced counters (OrphanedRelaysActive gauge,
// OrphanFDBudgetRejected, OrphanedEvictedLimit) are wired through a registry the
// snapshot reads — set up a registry so the snapshot reflects non-zero values.
func TestMigrateMetricsExposed(t *testing.T) {
	m := NewMetrics()
	reg := newRelayRegistry()
	reg.setLimits(4, 16, 8)
	m.AttachRelayRegistry(reg)

	// Drive registry counters.
	reg.orphanFDRejected.Store(3)
	reg.orphanedEvictedLimit.Store(2)
	reg.orphanedFDInUse.Store(5) // OrphanedRelaysActive gauge

	m.MigrateOK.Store(7)
	m.ResumeOK.Store(9)
	m.MigrateFailNotFound.Store(11)
	m.MigrateTailResent.Store(4)
	m.MigrateTailBufferedBytes.Store(123)

	snap := m.Snapshot()
	if snap.MigrateOK != 7 || snap.ResumeOK != 9 {
		t.Fatalf("snapshot Migrate/Resume OK wrong: %+v", snap)
	}
	if snap.MigrateFailNotFound != 11 {
		t.Fatalf("snapshot MigrateFailNotFound=%d want 11", snap.MigrateFailNotFound)
	}
	if snap.OrphanedRelaysActive != 5 {
		t.Fatalf("snapshot OrphanedRelaysActive=%d want 5 (from registry orphanedFDInUse)", snap.OrphanedRelaysActive)
	}
	if snap.OrphanFDBudgetRejected != 3 {
		t.Fatalf("snapshot OrphanFDBudgetRejected=%d want 3 (from registry)", snap.OrphanFDBudgetRejected)
	}
	if snap.OrphanedEvictedLimit != 2 {
		t.Fatalf("snapshot OrphanedEvictedLimit=%d want 2 (from registry)", snap.OrphanedEvictedLimit)
	}
	if snap.MigrateTailResent != 4 || snap.MigrateTailBufferedBytes != 123 {
		t.Fatalf("snapshot tail counters wrong: %+v", snap)
	}

	var sb strings.Builder
	writePromMetrics(&sb, &snap)
	out := sb.String()
	for _, name := range []string{
		"shadowlink_migrate_ok_total",
		"shadowlink_resume_ok_total",
		"shadowlink_migrate_fail_total",
		"shadowlink_migrate_grace_expired_total",
		"shadowlink_orphaned_relays_active",
		"shadowlink_orphan_fd_budget_rejected_total",
		"shadowlink_orphaned_evicted_limit_total",
		"shadowlink_migrate_tail_resent_total",
		"shadowlink_migrate_tail_buffered_bytes",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("prom exposition missing series %q", name)
		}
	}
}

// TestMigrateEnvDefaults pins the Bug #9 §7 config defaults: migration ON,
// grace 8s, per-client 16, total 1024.
func TestMigrateEnvDefaults(t *testing.T) {
	c := DefaultConfig()

	if !c.streamMigrationEnabledOrDefault() {
		t.Errorf("StreamMigrationEnabled default = false, want true")
	}
	if got := c.migrateGracePeriodOrDefault(); got != 8*time.Second {
		t.Errorf("migrateGracePeriodOrDefault() = %v, want 8s", got)
	}
	if got := c.maxOrphanedPerClientOrDefault(); got != 16 {
		t.Errorf("maxOrphanedPerClientOrDefault() = %d, want 16", got)
	}
	if got := c.maxOrphanedTotalOrDefault(); got != 1024 {
		t.Errorf("maxOrphanedTotalOrDefault() = %d, want 1024", got)
	}
}
