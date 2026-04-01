// Package call implements the Call Skin transport for ShadowLink Phase 2.
// It tunnels encrypted VPN chunks through TURN relay servers (like VK/OK video calls).
// DPI sees UDP to whitelisted IPs = allowed.
package call

const (
	DefaultTURNPort   = 3478
	DefaultServerUDP  = 56000
	MaxUDPPayload     = 1100  // safe payload below typical MTU
	AllocLifetimeSec  = 600   // TURN allocation lifetime
	RefreshIntervalSec = 300  // refresh before expiry
)
