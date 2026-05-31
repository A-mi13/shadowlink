//go:build !unix

package server

// readFDSoftLimit: no RLIMIT_NOFILE concept on non-unix (Windows dev hosts).
// Returns 0 so the caller falls back to the configured maxOrphanedTotal as the
// FD budget — Task 12 (F5). Production runs on Linux where the unix build tag
// provides the real getrlimit-backed limit.
func readFDSoftLimit() uint64 { return 0 }
