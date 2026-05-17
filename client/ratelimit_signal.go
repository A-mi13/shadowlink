package client

import (
	"errors"
	"fmt"
	"time"
)

// RateLimitSignal — normalized rate-limit info extracted from server response.
type RateLimitSignal struct {
	Bucket     string        // "handshake" | "ws_upgrade" | "data" | "none" (baseline)
	RefillIn   time.Duration // server-directed wait time; 0 if not carried
	BurstLeft  int           // remaining tokens in bucket; -1 if unknown
	Exempt     bool          // §C4 ClientID exemption flag
	Carrier    string        // "body" | "header_v1" | "header_legacy" | "fallback" — for metrics
	DetectedAt time.Time
}

// ErrRateLimited — sentinel error for errors.Is checks (back-compat with existing transport.go).
var ErrRateLimited = errors.New("rate limited")

// RateLimitError — wraps Signal so callers can extract via errors.As.
type RateLimitError struct {
	Signal *RateLimitSignal
}

func (e *RateLimitError) Error() string {
	if e.Signal == nil {
		return "rate limited (no signal)"
	}
	return fmt.Sprintf("rate limited (carrier=%s bucket=%s refill_in=%s)",
		e.Signal.Carrier, e.Signal.Bucket, e.Signal.RefillIn)
}

func (e *RateLimitError) Is(target error) bool { return target == ErrRateLimited }
func (e *RateLimitError) Unwrap() error        { return ErrRateLimited }
