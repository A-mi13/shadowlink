package leakguard

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStateSaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leakguard.json")

	now := time.Now().Truncate(time.Second)

	orig := &State{
		EnabledAt: now,
		Platform:  "windows",
		DNSBackup: DNSBackup{
			Entries: []DNSEntry{
				{InterfaceName: "Ethernet", Servers: []string{"8.8.8.8", "8.8.4.4"}},
				{InterfaceName: "Wi-Fi", Servers: []string{"1.1.1.1"}},
			},
		},
		IPv6Backup: IPv6Backup{
			DisabledInterfaces: []string{"Ethernet", "Wi-Fi"},
			OriginalSysctl:     "net.ipv6.conf.all.disable_ipv6=0",
		},
		KillSwitch: KillSwitchState{
			Rules:      []string{"rule1", "rule2"},
			ServerIP:   "203.0.113.1",
			ServerPort: 443,
			TunName:    "tun0",
			Backend:    "netsh",
		},
	}

	require.NoError(t, SaveState(path, orig))

	loaded, err := LoadState(path)
	require.NoError(t, err)

	assert.True(t, orig.EnabledAt.Equal(loaded.EnabledAt), "EnabledAt mismatch")
	assert.Equal(t, orig.Platform, loaded.Platform)
	assert.Equal(t, orig.DNSBackup, loaded.DNSBackup)
	assert.Equal(t, orig.IPv6Backup, loaded.IPv6Backup)
	assert.Equal(t, orig.KillSwitch, loaded.KillSwitch)
}

func TestLoadState_NotExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.json")

	_, err := LoadState(path)
	assert.Error(t, err)
}

func TestStateExists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "leakguard.json")

	assert.False(t, StateExists(path), "should be false when file missing")

	require.NoError(t, os.WriteFile(path, []byte("{}"), 0600))

	assert.True(t, StateExists(path), "should be true when file exists")
}
