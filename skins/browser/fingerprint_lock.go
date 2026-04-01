package browser

import (
	"encoding/json"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"
)

const lockDuration = 7 * 24 * time.Hour // rotate profile weekly

// FingerprintLease persists a browser profile to disk so all connections
// from this device use the same TLS fingerprint. Rotates weekly.
// Each user device generates its own random profile — with 1000 users,
// the distribution looks like real internet traffic.
type FingerprintLease struct {
	Profile  string    `json:"profile"`   // "chrome", "safari", "firefox"
	Seed     int64     `json:"seed"`      // random seed for per-connection variation
	LockedAt time.Time `json:"locked_at"` // when this profile was selected
	RotateAt time.Time `json:"rotate_at"` // when to pick a new profile
}

// LoadOrCreateLease loads a persisted fingerprint lease from disk.
// If no lease exists or it's expired, creates a new one with weighted random selection.
func LoadOrCreateLease(stateDir string) *FingerprintLease {
	path := filepath.Join(stateDir, "fingerprint.json")

	// Try loading existing lease
	if data, err := os.ReadFile(path); err == nil {
		var lease FingerprintLease
		if json.Unmarshal(data, &lease) == nil && lease.Profile != "" {
			if time.Now().Before(lease.RotateAt) {
				slog.Info("fingerprint: loaded existing lease",
					"profile", lease.Profile,
					"expires_in", time.Until(lease.RotateAt).Round(time.Hour))
				return &lease
			}
			slog.Info("fingerprint: lease expired, rotating", "old_profile", lease.Profile)
		}
	}

	// Create new lease with weighted random
	lease := &FingerprintLease{
		Profile:  weightedRandomProfile(),
		Seed:     rand.Int64(),
		LockedAt: time.Now(),
		RotateAt: time.Now().Add(lockDuration),
	}

	// Persist to disk
	os.MkdirAll(stateDir, 0700)
	if data, err := json.MarshalIndent(lease, "", "  "); err == nil {
		if err := os.WriteFile(path, data, 0600); err != nil {
			slog.Warn("fingerprint: failed to save lease", "error", err)
		}
	}

	slog.Info("fingerprint: new lease created",
		"profile", lease.Profile,
		"rotate_at", lease.RotateAt.Format("2006-01-02"))
	return lease
}

// ToFingerprint converts the lease to a Fingerprint for use in connections.
func (l *FingerprintLease) ToFingerprint() *Fingerprint {
	return NewFingerprint(l.Profile)
}

// weightedRandomProfile selects a browser profile matching real-world market share:
// ~70% Chrome, ~18% Safari, ~12% Firefox
func weightedRandomProfile() string {
	r := rand.IntN(100)
	switch {
	case r < 70:
		return ProfileChrome
	case r < 88:
		return ProfileSafari
	default:
		return ProfileFirefox
	}
}
