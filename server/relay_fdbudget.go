//go:build unix

package server

import "golang.org/x/sys/unix"

// readFDSoftLimit returns the process RLIMIT_NOFILE soft limit, or 0 on error.
// Task 12 (F5): the orphan FD budget is derived from this so the server never
// holds more orphaned egress conns through the grace window than it has file
// descriptors to spare — an orphaned relay keeps a real socket open with no WS
// behind it, which is exactly the resource an attacker tries to exhaust.
func readFDSoftLimit() uint64 {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return rl.Cur
}
