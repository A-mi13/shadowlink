package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// L3 (2026-06-11): the normal path returns a 32-byte non-zero key (the former
// "return zeros on unreachable HKDF-fail" is gone — a zero key is deterministic
// and predictable, enabling proof forgery if the path ever fired on one side).
// The panic branch is unreachable by construction (HKDF-Expand SHA-256 for 32
// bytes = one block, cannot fail), so it is covered by code review rather than a
// fake mock — this test fixes only the non-zero invariant of the normal path.
func TestDeriveServerPerClientKey_NonZero(t *testing.T) {
	k := DeriveServerPerClientKey([]byte("master-key-32-bytes-............."), "user_1")
	require.Len(t, k, 32)
	allZero := true
	for _, b := range k {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "per-client key must never be all-zero")
}
