package client

import (
	"bytes"
	"testing"
)

// TestClientMigrateStatsExist fixes the contract that every Bug #9 client-side
// counter exists on the Stats registry and increments. The names here are the
// REAL field names landed across Tasks 14-17 (the plan sketch used shorthand
// like ResumeOK/MigrateOK — the implemented names are
// MigrateResumeOnDeathOK / MigrateOK / etc.). Task 19 finalizes the set by
// adding the StreamReassemblyBufferedBytes gauge and wiring every counter into
// the Prometheus text exposition.
func TestClientMigrateStatsExist(t *testing.T) {
	// Reassembler (Task 14).
	Stats.StreamReassemblyOverflow.Add(1)
	Stats.StreamReassemblyGapTimeout.Add(1)
	Stats.StreamReassemblyBufferedBytes.Store(4096) // gauge added by Task 19

	// MIGRATE/RESUME send-side ack outcomes (Task 15).
	Stats.MigrateAttempt.Add(1)
	Stats.MigrateOK.Add(1)
	Stats.MigrateFail.Add(1)
	Stats.MigrateTimeout.Add(1)
	Stats.MigrateCapabilityDropped.Add(1)

	// Preemptive age-watchdog scheduling (Task 16).
	Stats.MigrateScheduled.Add(1)

	// Reactive RESUME-on-slot-death outcomes (Task 17).
	Stats.MigrateResumeOnDeathOK.Add(1)
	Stats.MigrateResumeOnDeathFail.Add(1)

	if Stats.MigrateOK.Load() == 0 ||
		Stats.MigrateResumeOnDeathOK.Load() == 0 ||
		Stats.StreamReassemblyBufferedBytes.Load() != 4096 {
		t.Fatal("Bug #9 client counters not wired")
	}
}

// TestClientMigrateMetricsExposed asserts every Bug #9 client counter appears in
// the hand-rolled Prometheus text exposition (WritePromMetrics). Task 14 already
// exposed the two reassembly counters; Task 19 adds the migrate/resume series and
// the buffered-bytes gauge.
func TestClientMigrateMetricsExposed(t *testing.T) {
	var buf bytes.Buffer
	WritePromMetrics(&buf)
	out := buf.String()

	for _, series := range []string{
		"shadowlink_stream_reassembly_overflow_total",
		"shadowlink_stream_reassembly_gap_timeout_total",
		"shadowlink_stream_reassembly_buffered_bytes",
		"shadowlink_migrate_attempt_total",
		"shadowlink_migrate_ok_total",
		"shadowlink_migrate_fail_total",
		"shadowlink_migrate_timeout_total",
		"shadowlink_migrate_capability_dropped_total",
		"shadowlink_migrate_scheduled_total",
		"shadowlink_migrate_resume_on_death_ok_total",
		"shadowlink_migrate_resume_on_death_fail_total",
	} {
		if !bytes.Contains(buf.Bytes(), []byte(series)) {
			t.Errorf("WritePromMetrics missing series %q\n---\n%s", series, out)
		}
	}
}
