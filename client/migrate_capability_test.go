package client

import (
	"os"
	"testing"
)

func TestStreamMigrationEnabledFromEnv(t *testing.T) {
	t.Setenv("SHADOWLINK_STREAM_MIGRATION", "")
	if !streamMigrationEnabledFromEnv() {
		t.Error("default (unset) should be ON")
	}
	for _, off := range []string{"0", "false", "no", "off", "OFF"} {
		os.Setenv("SHADOWLINK_STREAM_MIGRATION", off)
		if streamMigrationEnabledFromEnv() {
			t.Errorf("%q should disable migration", off)
		}
	}
	t.Setenv("SHADOWLINK_STREAM_MIGRATION", "1")
	if !streamMigrationEnabledFromEnv() {
		t.Error("=1 should be ON")
	}
}

func TestMigrateAckTimeout_Value(t *testing.T) {
	if migrateAckTimeout <= 0 {
		t.Fatal("migrateAckTimeout must be positive")
	}
}
