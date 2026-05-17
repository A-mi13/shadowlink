package client

import (
	"strconv"
	"strings"
	"time"
)

// parseRLStateValue parses the semicolon-separated rate-limit state string.
// Format: "v1;bucket=X;refill_in=N;burst_left=M;exempt=K[;...trailing pad]"
//
// Returns nil if:
//   - format invalid (missing fields, wrong version)
//   - bucket == "none" (baseline placeholder, NOT a rate-limit signal)
//
// Empty entries between `;;` are ignored (they're padding in body carrier).
func parseRLStateValue(s string) *RateLimitSignal {
	sig := &RateLimitSignal{BurstLeft: -1}
	found := map[string]string{}
	for kv := range strings.SplitSeq(s, ";") {
		kv = strings.TrimSpace(kv)
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			// Bare version token like "v1"
			if strings.HasPrefix(kv, "v") {
				found["v"] = kv[1:]
			}
			continue
		}
		found[k] = v
	}
	// Version check
	if v, ok := found["v"]; !ok || v != "1" {
		return nil
	}
	sig.Bucket = found["bucket"]
	if sig.Bucket == "" || sig.Bucket == "none" {
		return nil // baseline placeholder, not a real signal
	}
	if v := found["refill_in"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			sig.RefillIn = time.Duration(n) * time.Second
		}
	}
	if v := found["burst_left"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			sig.BurstLeft = n
		}
	}
	sig.Exempt = found["exempt"] == "1"
	return sig
}

// parseRLStateLegacyHeader parses the OLD comma-separated header format from
// writeRateLimitSentinelV2: "bucket=X,burst_left=N,refill_in=Ns,exempt=K"
// Used as back-compat for servers running pre-Phase-1 binaries.
func parseRLStateLegacyHeader(s string) *RateLimitSignal {
	sig := &RateLimitSignal{BurstLeft: -1}
	found := map[string]string{}
	for kv := range strings.SplitSeq(s, ",") {
		kv = strings.TrimSpace(kv)
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		found[k] = v
	}
	sig.Bucket = found["bucket"]
	if sig.Bucket == "" || sig.Bucket == "none" {
		return nil
	}
	if v := found["refill_in"]; v != "" {
		v = strings.TrimSuffix(v, "s") // legacy format has "Ns" suffix
		if n, err := strconv.Atoi(v); err == nil {
			sig.RefillIn = time.Duration(n) * time.Second
		}
	}
	if v := found["burst_left"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			sig.BurstLeft = n
		}
	}
	sig.Exempt = found["exempt"] == "1"
	return sig
}
