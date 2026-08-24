package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// tryServers invokes connect for each server in order until one succeeds.
// Returns the first server that connected, or an aggregated error listing
// every failed attempt.
//
// Honors context cancellation: if ctx is cancelled (including as a side
// effect of a previous connect attempt), no further servers are tried.
//
// This is the fallback primitive used by ShadowLink multi-domain failover:
// when the primary CF domain is blocked by ТСПУ SNI filtering, the client
// iterates through backup_servers until one passes the handshake.
func tryServers(ctx context.Context, servers []string,
	connect func(context.Context, string) error) (string, error) {

	if len(servers) == 0 {
		return "", errors.New("tryServers: no servers provided")
	}

	var attemptErrors []string
	for _, s := range servers {
		if err := ctx.Err(); err != nil {
			attemptErrors = append(attemptErrors,
				fmt.Sprintf("%s: context cancelled before attempt", s))
			break
		}
		if err := connect(ctx, s); err == nil {
			return s, nil
		} else {
			attemptErrors = append(attemptErrors,
				fmt.Sprintf("%s: %v", s, err))
		}
	}

	return "", fmt.Errorf("tryServers: all %d servers failed: %s",
		len(servers), strings.Join(attemptErrors, "; "))
}
