package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTryServers_ReturnsFirstSuccess verifies that tryServers stops at the
// first server whose connect function succeeds, and does not attempt
// subsequent servers.
func TestTryServers_ReturnsFirstSuccess(t *testing.T) {
	var attempts []string
	connector := func(_ context.Context, s string) error {
		attempts = append(attempts, s)
		if s == "srv2" {
			return nil
		}
		return errors.New("simulated failure")
	}

	got, err := tryServers(context.Background(),
		[]string{"srv1", "srv2", "srv3"}, connector)

	require.NoError(t, err)
	assert.Equal(t, "srv2", got)
	assert.Equal(t, []string{"srv1", "srv2"}, attempts,
		"srv3 must NOT be tried once srv2 succeeded")
}

// TestTryServers_AllFailed verifies that when every connector invocation
// fails, tryServers returns a joined error and lists all attempts.
func TestTryServers_AllFailed(t *testing.T) {
	connector := func(_ context.Context, s string) error {
		return errors.New("fail " + s)
	}

	got, err := tryServers(context.Background(),
		[]string{"srv1", "srv2"}, connector)

	require.Error(t, err)
	assert.Empty(t, got)
	assert.Contains(t, err.Error(), "srv1")
	assert.Contains(t, err.Error(), "srv2")
}

// TestTryServers_SingleServer verifies that a single-server list with no
// backups works identically to direct connect (backward compatibility).
func TestTryServers_SingleServer(t *testing.T) {
	calls := 0
	connector := func(_ context.Context, s string) error {
		calls++
		return nil
	}

	got, err := tryServers(context.Background(), []string{"only"}, connector)

	require.NoError(t, err)
	assert.Equal(t, "only", got)
	assert.Equal(t, 1, calls)
}

// TestTryServers_EmptyList verifies an error is returned when no servers
// are provided (defensive programming against misconfiguration).
func TestTryServers_EmptyList(t *testing.T) {
	connector := func(_ context.Context, s string) error { return nil }

	got, err := tryServers(context.Background(), nil, connector)

	require.Error(t, err)
	assert.Empty(t, got)
}

// TestTryServers_RespectsContextCancellation verifies that cancelling the
// context aborts the fallback loop before trying more servers.
func TestTryServers_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	var attempts []string
	connector := func(_ context.Context, s string) error {
		attempts = append(attempts, s)
		cancel() // cancel after first attempt
		return errors.New("fail")
	}

	_, err := tryServers(ctx, []string{"srv1", "srv2", "srv3"}, connector)

	require.Error(t, err)
	assert.Len(t, attempts, 1, "subsequent servers should not be tried after ctx cancel")
}
