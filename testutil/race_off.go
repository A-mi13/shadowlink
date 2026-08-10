//go:build !race

package testutil

// RaceEnabled — см. race_on.go. Здесь false: сборка без -race.
const RaceEnabled = false
